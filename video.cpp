/*
  The per-entry video child. See video.h for why it is independent of
  the MAVLink session.

  Phase 1 scope: process lifecycle, port binding, publisher admission
  and connections.tdb rows. There is no media path yet -- accepted
  bytes are counted and discarded -- so the process-model risk lands
  and can be tested on its own.
 */
#include "video.h"

#include <initializer_list>
#include <memory>
#include <vector>

#include <errno.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "conntdb.h"
#include "util.h"
#include "videoauth.h"
#include "videostream.h"
#include "videorec.h"
#include "videots.h"
#include "videortmp.h"
#include "videortsp.h"
#include "videoview.h"

#define VIDEO_MAX_EPOLL_EVENTS 64

// A publisher that goes quiet for this long releases its slot, so a
// replacement can take over after a genuine disconnect.
#define VIDEO_PUB_IDLE_S 10

/*
  Viewer table entries one source address may hold. Publishers are
  classified from a viewer slot, so without a cap a flood from one host
  fills the table and denies publishing outright. An operator watching
  three slots with a reconnect in flight needs a handful.
 */
#define VIDEO_MAX_VIEWERS_PER_IP 8

/*
  Concurrent RTMP handshakes per slot. More than one so a squatter
  cannot lock the camera out, few enough that the parser work an
  unauthenticated peer can start is bounded.
 */
#define VIDEO_MAX_PENDING_RTMP 4

// How often the child re-reads its own keys.tdb record and re-writes
// its connections.tdb rows. Matches the MAVLink child's cadence.
#define VIDEO_TICK_S 5

// Rate limit for "rejected" logging, so a flood of unauthorised packets
// can't turn into a flood of stdout writes (which would block the child
// once the pipe fills).
#define VIDEO_LOG_MIN_INTERVAL_S 1

bool video_entry_wants_child(uint32_t flags, const uint32_t *video_ports)
{
    if ((flags & KEY_FLAG_VIDEO) == 0) {
        return false;
    }
    for (int i = 0; i < KEY_MAX_VIDEO_PORTS; i++) {
        if (video_ports[i] != 0) {
            return true;
        }
    }
    return false;
}

namespace {

/*
  One direction of the splice.

  The relay used to retry a short write by sleeping inside the event
  loop. That loop is the only thread: it also drains ffmpeg's stdout, so
  sleeping there deadlocks -- the publisher fills the socket to ffmpeg,
  we stop servicing epoll, ffmpeg's stdout pipe fills, ffmpeg stops
  reading its input, and the socket never drains. A paced publisher
  (ffmpeg -re, as the tests use) never triggers it; a real camera bursts.
 */
struct SpliceQueue {
    std::vector<uint8_t> buf;
    size_t sent = 0;
    bool armed = false;          // EPOLLOUT currently armed on the sink

    size_t pending(void) const { return buf.size() - sent; }
    void clear(void) { buf.clear(); sent = 0; armed = false; }
    void compact(void)
    {
        if (sent == buf.size()) {
            buf.clear();
            sent = 0;
        } else if (sent > 65536) {
            buf.erase(buf.begin(), buf.begin() + long(sent));
            sent = 0;
        }
    }
};

// Stop reading a direction once this much is already queued for it, so
// the backlog is bounded and TCP applies the backpressure upstream
// instead of this process buffering without limit.
#define SPLICE_QUEUE_MAX (1u * 1024 * 1024)

/*
  One RTMP handshake that has not published yet.

  It owns nothing but its socket: no slot, no backend, no ring. Only
  when publish arrives and passes admission is one of these promoted.
 */
struct PendingRtmp {
    int fd = -1;
    std::unique_ptr<RtmpSession> sess;
    SpliceQueue out;            // responses owed to this peer
    time_t since = 0;
    uint32_t ip_be = 0;
    uint16_t port_be = 0;

    bool active(void) const { return fd >= 0; }
};

struct Slot {
    uint32_t port = 0;
    int udp_fd = -1;
    int tcp_fd = -1;

    // current publisher, if any
    bool has_pub = false;
    uint32_t pub_ip_be = 0;
    uint16_t pub_port_be = 0;
    time_t pub_since = 0;
    time_t pub_last = 0;
    uint64_t pub_bytes = 0;

    // rate-limited rejection logging
    time_t last_reject_log = 0;
    uint32_t rejects = 0;

    // RTSP or RTMP publisher, while one holds the slot
    RtspBackend rtsp;
    int rtsp_client_fd = -1;
    SpliceQueue to_backend;   // bytes read from the client, owed to ffmpeg
    SpliceQueue to_client;    // and the other way
    /*
      The RTMP session that owns the slot, once one has published and
      been admitted. Null until then.
     */
    std::unique_ptr<RtmpSession> rtmp;

    /*
      Handshakes in progress. These deliberately do NOT hold the slot.

      Classification costs one byte, so if a pending handshake owned the
      slot an unauthenticated peer could take it, wait out its deadline
      and reconnect, denying publishing indefinitely -- and letting a
      newcomer evict the incumbent only turns that into last-arrival
      wins, which is the same denial. Several negotiate side by side
      instead, and the slot is awarded on publish, after admission.
     */
    PendingRtmp pending[VIDEO_MAX_PENDING_RTMP];

    // media
    VideoRing ring;
    TSScanner scanner;
    VideoWriter rec;
    VideoViewer viewers[VIDEO_MAX_VIEWERS];
    bool viewer_out_armed[VIDEO_MAX_VIEWERS] {};
    uint32_t viewers_seen = 0;
    uint32_t viewers_dropped = 0;
    bool recording = false;
    uint64_t last_anchor = 0;
    bool had_anchor = false;
    uint64_t bad_datagrams = 0;
    bool warned_204 = false;
};

class VideoChild {
public:
    VideoChild(int port2, int ready_fd) :
        port2_(port2), ready_fd_(ready_fd), auth_(port2) {}

    void run(void) __attribute__((noreturn));

private:
    int port2_;
    int ready_fd_;
    VideoAuth auth_;
    struct KeyEntry ke_ {};
    Slot slots_[KEY_MAX_VIDEO_PORTS];
    int epfd_ = -1;
    time_t last_tick_ = 0;

    bool load_entry(void);
    int bind_slots(void);
    void signal_ready(int err);
    void handle_udp(Slot &s, int idx);
    void handle_tcp(Slot &s, int idx);
    void tick(time_t now);
    void write_conn_rows(time_t now);
    void log_reject(Slot &s, int idx, uint32_t ip_be, video_admit_t r,
                    time_t now);
    void ingest(Slot &s, int idx, const uint8_t *buf, size_t n);
    void ingest_stream(Slot &s, int idx, const uint8_t *buf, size_t n);
    void handle_rtsp(Slot &s, int idx, int fd,
                     struct sockaddr_in &from, time_t now,
                     splice_proto_t proto);
    void close_rtsp(Slot &s, int idx, const char *why);
    bool pump_rtsp(Slot &s, int idx, int fd, time_t now);
    bool pump_rtmp(Slot &s, int idx, int fd, time_t now);
    bool rtmp_start_backend(Slot &s, int idx);
    bool rtmp_drain_owner(Slot &s, int idx, bool alive);
    void close_pending(Slot &s, int idx, PendingRtmp &p, const char *why);
    bool pump_pending(Slot &s, int idx, PendingRtmp &p, time_t now);
    bool promote_pending(Slot &s, int idx, PendingRtmp &p, time_t now);
    void latch_publisher(Slot &s, int idx, time_t now);
    bool splice_flush(int to_fd, SpliceQueue &q);
    void splice_arm(int to_fd, SpliceQueue &q);
    void epoll_add_viewer(VideoViewer &v);
    void epoll_sync_viewer(VideoViewer &v, bool &armed);
    void drop_viewer(Slot &s, int idx, VideoViewer &v);
    void end_stream(Slot &s, int idx, const char *why);
    void pump_viewers(Slot &s, int idx, time_t now);
};

bool VideoChild::load_entry(void)
{
    auto *db = db_open();
    if (db == nullptr) {
        return false;
    }
    struct KeyEntry k {};
    bool ok = db_load_key(db, port2_, k);
    db_close(db);
    if (ok) {
        ke_ = k;
    }
    return ok;
}

void VideoChild::signal_ready(int err)
{
    if (ready_fd_ < 0) {
        return;
    }
    uint8_t b = uint8_t(err > 255 ? 255 : err);
    ssize_t n = ::write(ready_fd_, &b, 1);
    (void)n;
    close(ready_fd_);
    ready_fd_ = -1;
}

int VideoChild::bind_slots(void)
{
    int first_err = 0;
    for (int i = 0; i < KEY_MAX_VIDEO_PORTS; i++) {
        const uint32_t port = ke_.video_ports[i];
        if (port == 0) {
            continue;
        }
        slots_[i].port = port;
        slots_[i].udp_fd = open_socket_in_udp(int(port));
        if (slots_[i].udp_fd == -1 && first_err == 0) {
            first_err = errno ? errno : EADDRINUSE;
        }
        slots_[i].tcp_fd = open_socket_in_tcp(int(port));
        if (slots_[i].tcp_fd == -1 && first_err == 0) {
            first_err = errno ? errno : EADDRINUSE;
        }
        if (slots_[i].udp_fd != -1 || slots_[i].tcp_fd != -1) {
            printf("[%d] video slot %d listening on %u%s\n",
                   port2_, i, unsigned(port),
                   (slots_[i].udp_fd == -1 || slots_[i].tcp_fd == -1)
                   ? " (partially)" : "");
        } else {
            printf("[%d] video slot %d failed to bind %u - %s\n",
                   port2_, i, unsigned(port), strerror(errno));
        }
    }
    return first_err;
}

void VideoChild::log_reject(Slot &s, int idx, uint32_t ip_be,
                            video_admit_t r, time_t now)
{
    s.rejects++;
    if (now - s.last_reject_log < VIDEO_LOG_MIN_INTERVAL_S) {
        return;
    }
    s.last_reject_log = now;
    struct in_addr a {};
    a.s_addr = ip_be;
    printf("[%d] video slot %d rejected %s: %s (%u so far)\n",
           port2_, idx, inet_ntoa(a), video_admit_str(r), unsigned(s.rejects));
}

/*
  Accept one datagram's worth of publisher bytes.

  A datagram must be a whole number of 188-byte TS packets starting with
  the sync byte -- that is what every MPEG-TS/UDP sender produces (7
  packets, 1316 bytes, is the norm). Anything else is dropped and
  counted rather than fed to the scanner, so a misconfigured sender
  shows up as a clear count instead of a stream that half works.
 */
void VideoChild::ingest(Slot &s, int idx, const uint8_t *buf, size_t n)
{
    if (n < TS_PACKET_SIZE || buf[0] != TS_SYNC_BYTE
        || (n % TS_PACKET_SIZE) != 0
        || (n > TS_PACKET_SIZE && buf[TS_PACKET_SIZE] != TS_SYNC_BYTE)) {
        // 204-byte packets are DVB's TS-with-Reed-Solomon. Feeding them
        // to a 188-byte parser produces nonsense, so say so once.
        if (!s.warned_204 && (n % 204) == 0 && n >= 204
            && buf[0] == TS_SYNC_BYTE) {
            s.warned_204 = true;
            printf("[%d] video slot %d: 204-byte (DVB) packets are not "
                   "supported; send 188-byte MPEG-TS\n", port2_, idx);
        }
        s.bad_datagrams++;
        return;
    }
    s.pub_bytes += n;
    // Scanner first: it needs the offset this data will occupy, and the
    // ring write is what makes that offset meaningful.
    const uint64_t before = s.ring.write_pos();
    s.scanner.feed(buf, n, before);
    s.ring.write(buf, n);

    if (!s.recording || s.rec.stopped()) {
        return;
    }
    const time_t now = time(nullptr);

    /*
      Cut segments at a join boundary so every segment is playable from
      its first byte. The anchor only moves when a new random access
      point arrives, so "the anchor advanced into this datagram" is the
      signal that we are standing on one.

      A stream whose muxer never signals one must still rotate, hence
      the overshoot fallback -- otherwise the segment grows forever and
      the quota pass can never evict it.
     */
    if (s.rec.rotation_due(now)) {
        uint64_t anchor = 0;
        const bool have = s.scanner.join_offset(anchor);
        const bool at_boundary = have && s.had_anchor && anchor > s.last_anchor
            && anchor >= before;
        if (at_boundary || s.rec.rotation_overdue(now)) {
            s.rec.rotate(now, at_boundary);
        }
    }
    uint64_t anchor_now = 0;
    if (s.scanner.join_offset(anchor_now)) {
        s.last_anchor = anchor_now;
        s.had_anchor = true;
    }
    s.rec.write(buf, n, now);
}

/*
  Byte-stream ingest, for a source that is not datagram-framed (the
  RTSP backend's stdout). The 188-alignment rule that guards the UDP
  path does not apply -- packets straddle reads by nature -- and the
  scanner and ring already carry partial packets across calls.
 */
void VideoChild::ingest_stream(Slot &s, int idx, const uint8_t *buf, size_t n)
{
    s.pub_bytes += n;
    const uint64_t before = s.ring.write_pos();
    s.scanner.feed(buf, n, before);
    s.ring.write(buf, n);

    if (!s.recording || s.rec.stopped()) {
        return;
    }
    const time_t now = time(nullptr);
    if (s.rec.rotation_due(now)) {
        uint64_t anchor = 0;
        const bool have = s.scanner.join_offset(anchor);
        const bool at_boundary = have && s.had_anchor && anchor > s.last_anchor
            && anchor >= before;
        if (at_boundary || s.rec.rotation_overdue(now)) {
            s.rec.rotate(now, at_boundary);
        }
    }
    uint64_t anchor_now = 0;
    if (s.scanner.join_offset(anchor_now)) {
        s.last_anchor = anchor_now;
        s.had_anchor = true;
    }
    s.rec.write(buf, n, now);
    (void)idx;
}

void VideoChild::handle_udp(Slot &s, int idx)
{
    uint8_t buf[2048];
    struct sockaddr_in from {};
    socklen_t fromlen = sizeof(from);
    ssize_t n = recvfrom(s.udp_fd, buf, sizeof(buf), 0,
                         (struct sockaddr *)&from, &fromlen);
    if (n <= 0) {
        return;
    }
    const time_t now = time(nullptr);

    // A datagram from the established publisher needs no re-check: the
    // admission decision was made when the tuple latched.
    if (s.has_pub && s.pub_ip_be == uint32_t(from.sin_addr.s_addr)
        && s.pub_port_be == from.sin_port) {
        s.pub_last = now;
        ingest(s, idx, buf, size_t(n));
        return;
    }

    // Plain MPEG-TS over UDP carries no credential, so path A can't
    // apply here; admit() falls through to the MAVLink-session check
    // unless a publish password is set, in which case UDP can't satisfy
    // it and the datagram is refused.
    video_admit_t r = auth_.admit(ke_, uint32_t(from.sin_addr.s_addr),
                                  nullptr, now);
    if (r != VIDEO_ADMIT_OK) {
        log_reject(s, idx, uint32_t(from.sin_addr.s_addr), r, now);
        return;
    }
    if ((s.has_pub && now - s.pub_last <= VIDEO_PUB_IDLE_S)
        || s.rtsp.running() || s.rtsp_client_fd >= 0) {
        // One publisher at a time: a second sender behind the same NAT
        // must not be able to interleave into the stream. This is not
        // an authorisation failure -- the sender may be perfectly
        // entitled to publish -- so it gets its own reason rather than
        // borrowing one that would send an operator hunting an address
        // mismatch that isn't there.
        //
        // The connection tests are part of it, not just has_pub: a
        // spliced or RTMP publisher owns the slot for as long as its
        // connection lives, and testing has_pub alone let a UDP sender
        // latch on top of a live one and mix two streams into one ring.
        // rtsp_client_fd covers an RTMP handshake still in progress,
        // which has no backend and no latched publisher yet.
        log_reject(s, idx, uint32_t(from.sin_addr.s_addr),
                   VIDEO_ADMIT_SLOT_BUSY, now);
        return;
    }
    s.has_pub = true;
    s.pub_ip_be = uint32_t(from.sin_addr.s_addr);
    s.pub_port_be = from.sin_port;
    s.pub_since = now;
    s.pub_last = now;
    s.pub_bytes = 0;
    s.ring.init(video_ring_bytes());
    s.scanner = TSScanner();
    s.had_anchor = false;
    s.recording = (video_slot_opts(ke_.video_flags, unsigned(idx))
                   & VIDEO_SLOT_RECORD) != 0;
    if (s.recording) {
        s.rec.configure(uint32_t(port2_), idx,
                        (ke_.flags & KEY_FLAG_USE_TZ) != 0,
                        ke_.tz_offset_hours, "logs", ke_.video_quota_mb);
    }
    printf("[%d] video slot %d publisher %s\n",
           port2_, idx, addr_to_str(from));
    ingest(s, idx, buf, size_t(n));
    last_tick_ = 0;   // snapshot connections.tdb promptly
}

void VideoChild::handle_tcp(Slot &s, int idx)
{
    struct sockaddr_in from {};
    socklen_t fromlen = sizeof(from);
    int fd = accept(s.tcp_fd, (struct sockaddr *)&from, &fromlen);
    if (fd == -1) {
        return;
    }
    const time_t now = time(nullptr);

    /*
      A TCP connection here is a viewer. Viewers are not publishers and
      are not subject to the publisher admission check: they present a
      viewer password (or the slot is open), and in either case they can
      only ever reach a stream that an authorised publisher is feeding.
     */
    /*
      A publisher arrives through this table too -- RTSP and RTMP are
      only recognised once bytes arrive, so the connection has to be
      held somewhere first. That means a flood of connections can fill
      the table and stop a publisher from even being classified.

      Cap how many one address may hold. It cannot be a reserve for
      "probable publishers": a publisher is indistinguishable at accept
      time, since the credential it might carry arrives later. A per
      address cap needs none of that, and one host can no longer take
      the table on its own.
     */
    int free_slot = -1;
    int from_this_ip = 0;
    for (int v = 0; v < VIDEO_MAX_VIEWERS; v++) {
        if (s.viewers[v].active()
            && s.viewers[v].peer_ip_be() == uint32_t(from.sin_addr.s_addr)) {
            from_this_ip++;
        }
    }
    if (from_this_ip < VIDEO_MAX_VIEWERS_PER_IP) {
        for (int v = 0; v < VIDEO_MAX_VIEWERS; v++) {
            if (!s.viewers[v].active()) {
                free_slot = v;
                break;
            }
        }
    }
    if (free_slot < 0) {
        // Say why rather than dropping silently; a viewer that just
        // disconnects with no explanation is impossible to diagnose.
        const std::string body = http_simple_response(
            503, "too many viewers", "text/plain",
            "This stream already has the maximum number of viewers.\n");
        (void)::send(fd, body.data(), body.size(), MSG_NOSIGNAL);
        close(fd);
        printf("[%d] video slot %d viewer from %s refused: slot full\n",
               port2_, idx, addr_to_str(from));
        return;
    }
    s.viewers[free_slot].start(fd, port2_, uint32_t(from.sin_addr.s_addr),
                               from.sin_port, now);
    s.viewer_out_armed[free_slot] = false;
    s.viewers_seen++;
    epoll_add_viewer(s.viewers[free_slot]);
    printf("[%d] video slot %d viewer from %s connected\n",
           port2_, idx, addr_to_str(from));
}

/*
  Take a slot for a publisher whose media arrives on the backend's
  stdout rather than as datagrams. Everything downstream -- the ring,
  the scanner, the recorder, the ConnEntry row -- is the same.
 */
void VideoChild::latch_publisher(Slot &s, int idx, time_t now)
{
    s.has_pub = true;
    s.pub_since = now;
    s.pub_last = now;
    s.pub_bytes = 0;
    s.ring.init(video_ring_bytes());
    s.scanner = TSScanner();
    s.had_anchor = false;
    s.recording = (video_slot_opts(ke_.video_flags, unsigned(idx))
                   & VIDEO_SLOT_RECORD) != 0;
    if (s.recording) {
        s.rec.configure(uint32_t(port2_), idx,
                        (ke_.flags & KEY_FLAG_USE_TZ) != 0,
                        ke_.tz_offset_hours, "logs", ke_.video_quota_mb);
    }
    last_tick_ = 0;
}

void VideoChild::handle_rtsp(Slot &s, int idx, int fd,
                             struct sockaddr_in &from, time_t now,
                             splice_proto_t proto)
{
    /*
      RTMP is not spliced: we speak it ourselves, and the credential
      only arrives with publish. So the connection is parked in the
      pending pool, which owns no part of the slot, and admission
      happens later.
     */
    if (proto == SPLICE_RTMP) {
        int free_i = -1;
        int oldest_i = -1;
        for (int i = 0; i < VIDEO_MAX_PENDING_RTMP; i++) {
            if (!s.pending[i].active()) {
                free_i = i;
                break;
            }
            if (oldest_i < 0 || s.pending[i].since < s.pending[oldest_i].since) {
                oldest_i = i;
            }
        }
        if (free_i < 0) {
            // Pool full: drop the oldest, which has had the longest to
            // publish and has not. Bounded either way, and a squatter
            // cannot pin every entry against a camera that retries.
            close_pending(s, idx, s.pending[oldest_i], "pending pool full");
            free_i = oldest_i;
        }
        PendingRtmp &p = s.pending[free_i];
        fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
        p.fd = fd;
        p.sess.reset(new RtmpSession());
        p.out.clear();
        p.since = now;
        p.ip_be = uint32_t(from.sin_addr.s_addr);
        p.port_be = from.sin_port;
        printf("[%d] video slot %d RTMP publisher %s connecting\n",
               port2_, idx, addr_to_str(from));
        struct epoll_event ev {};
        ev.events = EPOLLIN | EPOLLRDHUP;
        ev.data.fd = fd;
        epoll_ctl(epfd_, EPOLL_CTL_ADD, fd, &ev);
        return;
    }

    /*
      Read a publish password out of the request-line URI, if there is
      one, e.g. rtsp://host:port/cam?pw=secret. Peek only -- the splice
      must still see the exchange from byte zero.

      This is the one place RTSP can carry a credential without us
      answering anything: proper Basic auth would mean replying 401 and
      renumbering CSeq, which is exactly what makes the opaque splice
      work. ffmpeg passes the query through untouched (verified) and
      its own listener ignores it.

      A password in a URL is normally a bad idea, but this URL is
      configured on an aircraft rather than typed into a browser, so it
      does not end up in history or a Referer header.
     */
    uint8_t line[512] {};
    std::string pw;
    const ssize_t ln = ::recv(fd, line, sizeof(line) - 1, MSG_PEEK);
    if (ln > 0) {
        const std::string req(reinterpret_cast<char *>(line), size_t(ln));
        const size_t eol = req.find('\r');
        const std::string first = req.substr(0, eol == std::string::npos
                                             ? req.size() : eol);
        const size_t q = first.find("?pw=");
        if (q != std::string::npos) {
            size_t end = first.find_first_of(" &", q + 4);
            if (end == std::string::npos) {
                end = first.size();
            }
            pw = http_url_decode(first.substr(q + 4, end - (q + 4)));
        }
    }

    // Publishers are authorised; viewers are not, and on this port an
    // RTSP connection is a publisher (we do not parse enough to tell
    // them apart -- see videortsp.h).
    const video_admit_t r = auth_.admit(ke_, uint32_t(from.sin_addr.s_addr),
                                        pw.c_str(), now);
    if (r != VIDEO_ADMIT_OK) {
        log_reject(s, idx, uint32_t(from.sin_addr.s_addr), r, now);
        close(fd);
        return;
    }
    if (s.rtsp.running() || s.rtsp_client_fd >= 0
        || (s.has_pub && now - s.pub_last <= VIDEO_PUB_IDLE_S)) {
        log_reject(s, idx, uint32_t(from.sin_addr.s_addr),
                   VIDEO_ADMIT_SLOT_BUSY, now);
        close(fd);
        return;
    }

    const bool want_audio =
        (video_entry_opts(ke_.video_flags) & VIDEO_OPT_AUDIO) != 0;
    if (!s.rtsp.start(port2_, idx, want_audio, proto)) {
        close(fd);
        return;
    }
    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
    s.rtsp_client_fd = fd;
    s.pub_ip_be = uint32_t(from.sin_addr.s_addr);
    s.pub_port_be = from.sin_port;
    latch_publisher(s, idx, now);
    printf("[%d] video slot %d %s publisher %s\n",
           port2_, idx, splice_proto_name(proto), addr_to_str(from));

    for (int watch : { s.rtsp_client_fd, s.rtsp.backend_fd(),
                       s.rtsp.media_fd() }) {
        if (watch < 0) {
            continue;
        }
        struct epoll_event ev {};
        ev.events = EPOLLIN | EPOLLRDHUP;
        ev.data.fd = watch;
        epoll_ctl(epfd_, EPOLL_CTL_ADD, watch, &ev);
    }
    last_tick_ = 0;
}

void VideoChild::close_rtsp(Slot &s, int idx, const char *why)
{
    if (!s.rtsp.running() && s.rtsp_client_fd < 0 && !s.rtmp) {
        return;
    }
    // The backend's proto is only meaningful once it started, and an
    // RTMP session can end before that -- during the handshake, or on a
    // refused publish.
    printf("[%d] video slot %d %s publisher gone (%s)\n",
           port2_, idx,
           s.rtmp ? "RTMP" : splice_proto_name(s.rtsp.proto()), why);
    for (int watch : { s.rtsp_client_fd, s.rtsp.backend_fd(),
                       s.rtsp.media_fd() }) {
        if (watch >= 0) {
            epoll_ctl(epfd_, EPOLL_CTL_DEL, watch, nullptr);
        }
    }
    if (s.rtsp_client_fd >= 0) {
        close(s.rtsp_client_fd);
        s.rtsp_client_fd = -1;
    }
    s.rtmp.reset();
    s.to_backend.clear();
    s.to_client.clear();
    s.rtsp.stop();
    s.rec.close_segment();
    s.recording = false;
    s.has_pub = false;
    // Same reasoning as the UDP idle-release path: the next publisher
    // is a different stream, so viewers have to be ended rather than
    // spliced onto it. Missing it here left RTSP -- the transport a
    // publish password forces you onto -- with the original bug.
    end_stream(s, idx, "publisher gone");
}

/*
  Move bytes between the publisher and the backend, and pull muxed
  MPEG-TS off the backend's stdout into the normal ingest path.
  Returns false when the session is over.
 */
/*
  Push whatever is queued for one direction. Never waits: a short write
  leaves the remainder queued and EPOLLOUT armed.
 */
bool VideoChild::splice_flush(int to_fd, SpliceQueue &q)
{
    while (q.pending() > 0) {
        const ssize_t w = ::send(to_fd, q.buf.data() + q.sent, q.pending(),
                                 MSG_NOSIGNAL);
        if (w > 0) {
            q.sent += size_t(w);
            continue;
        }
        if (w < 0 && errno == EINTR) {
            continue;
        }
        if (w < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            break;              // still owed; EPOLLOUT will bring us back
        }
        // A zero return is not progress either -- looping on it spun
        // forever in the previous version, because the offset never
        // advanced.
        return false;
    }
    q.compact();
    return true;
}

// EPOLLOUT only while something is queued. Armed unconditionally it
// would make epoll_wait return immediately for ever on an idle splice,
// which is the same idle-viewer CPU burn measured earlier.
void VideoChild::splice_arm(int to_fd, SpliceQueue &q)
{
    const bool want = q.pending() > 0;
    if (want == q.armed || to_fd < 0) {
        return;
    }
    struct epoll_event ev {};
    ev.events = uint32_t(EPOLLIN | EPOLLRDHUP)
        | (want ? uint32_t(EPOLLOUT) : 0u);
    ev.data.fd = to_fd;
    if (epoll_ctl(epfd_, EPOLL_CTL_MOD, to_fd, &ev) == 0) {
        q.armed = want;
    }
}

/*
  Close one pending handshake and forget it. It owns no slot state, so
  there is nothing else to unwind.
 */
void VideoChild::close_pending(Slot &s, int idx, PendingRtmp &p,
                               const char *why)
{
    (void)s;
    if (!p.active()) {
        return;
    }
    struct in_addr a {};
    a.s_addr = p.ip_be;
    printf("[%d] video slot %d RTMP handshake from %s ended (%s)\n",
           port2_, idx, inet_ntoa(a), why);
    epoll_ctl(epfd_, EPOLL_CTL_DEL, p.fd, nullptr);
    close(p.fd);
    p.fd = -1;
    p.sess.reset();
    p.out.clear();
    p.since = 0;
}

/*
  A pending handshake has published. Authorise it and, if the slot is
  free, hand it over.

  Returns false if this connection is finished either way.
 */
bool VideoChild::promote_pending(Slot &s, int idx, PendingRtmp &p,
                                 time_t now)
{
    RtmpSession &r = *p.sess;

    const video_admit_t a = auth_.admit(ke_, p.ip_be, r.password().c_str(),
                                        now);
    if (a != VIDEO_ADMIT_OK) {
        log_reject(s, idx, p.ip_be, a, now);
        r.reject_publish("NetStream.Publish.Denied", video_admit_str(a));
        return false;
    }

    /*
      An RTMP path on the slot is an optional restriction: we read the
      app and stream off the wire rather than telling ffmpeg what to
      expect. Left blank the slot takes whatever is published.
     */
    char want[sizeof(ke_.video_rtmp_path[0]) + 1] {};
    memcpy(want, ke_.video_rtmp_path[idx], sizeof(ke_.video_rtmp_path[idx]));
    want[sizeof(want) - 1] = '\0';
    if (want[0] != '\0' && r.path() != want) {
        printf("[%d] video slot %d RTMP publisher refused: published %s, "
               "slot expects %s\n", port2_, idx, r.path().c_str(), want);
        r.reject_publish("NetStream.Publish.Denied",
                         "stream path does not match this slot");
        return false;
    }

    // Authorised -- but the slot may have been taken while this one was
    // still negotiating.
    if (s.rtsp.running() || s.rtsp_client_fd >= 0
        || (s.has_pub && now - s.pub_last <= VIDEO_PUB_IDLE_S)) {
        log_reject(s, idx, p.ip_be, VIDEO_ADMIT_SLOT_BUSY, now);
        r.reject_publish("NetStream.Publish.Denied",
                         "another publisher holds this slot");
        return false;
    }

    // Hand the socket and the session to the slot.
    s.rtsp_client_fd = p.fd;
    s.rtmp = std::move(p.sess);
    s.to_client = std::move(p.out);
    s.to_backend.clear();
    p.fd = -1;
    p.out.clear();
    p.since = 0;

    s.pub_ip_be = p.ip_be;
    s.pub_port_be = p.port_be;
    s.rtmp->accept_publish();
    latch_publisher(s, idx, now);
    printf("[%d] video slot %d RTMP publishing %s\n",
           port2_, idx, s.rtmp->path().c_str());
    /*
      Parsing stopped at publish so this authorisation could happen in
      order. Whatever the publisher pipelined behind it -- for a client
      that does not wait for onStatus, that includes the sequence header
      and its parameter sets -- is still buffered, so pick it up now
      rather than waiting for a read that may never come.
     */
    if (!rtmp_drain_owner(s, idx, s.rtmp->resume())) {
        close_rtsp(s, idx, "RTMP session ended during promotion");
        return true;
    }
    /*
      Push the responses out. accept_publish() queued the
      NetStream.Publish.Start the client is waiting on, and nothing else
      runs until the next epoll event -- which a publisher that waits
      for onStatus before sending anything will never cause. Leaving it
      queued is exactly the stall this whole path exists to fix.
     */
    if (!splice_flush(s.rtsp_client_fd, s.to_client)) {
        close_rtsp(s, idx, "connection closed");
        return true;
    }
    splice_arm(s.rtsp_client_fd, s.to_client);
    return true;
}

/*
  Drive one pending handshake. Returns false when it is finished.
 */
bool VideoChild::pump_pending(Slot &s, int idx, PendingRtmp &p, time_t now)
{
    if (!splice_flush(p.fd, p.out)) {
        return false;
    }
    uint8_t buf[8192];
    const ssize_t n = ::recv(p.fd, buf, sizeof(buf), 0);
    if (n == 0) {
        return false;
    }
    if (n < 0) {
        if (!(errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) {
            return false;
        }
        splice_arm(p.fd, p.out);
        return true;
    }

    RtmpSession &r = *p.sess;
    bool alive = r.feed(buf, size_t(n), now);
    bool promoted = false;
    if (r.publish_pending()) {
        promoted = promote_pending(s, idx, p, now);
        if (promoted) {
            return false;   // the slot owns it now; stop pumping as pending
        }
        alive = false;      // refused: flush the status, then close
    }
    if (!r.to_peer().empty()) {
        p.out.buf.insert(p.out.buf.end(), r.to_peer().begin(),
                         r.to_peer().end());
        r.to_peer().clear();
    }
    // Media before publish is not ours to keep, and the session drops it.
    r.to_flv().clear();
    if (!splice_flush(p.fd, p.out)) {
        return false;
    }
    if (!alive) {
        if (r.error()[0] != '\0') {
            printf("[%d] video slot %d RTMP: %s\n", port2_, idx, r.error());
        }
        return false;
    }
    splice_arm(p.fd, p.out);
    return true;
}

/*
  Start the backend now that the publisher's codec is known. Returns
  false if it could not be started.
 */
bool VideoChild::rtmp_start_backend(Slot &s, int idx)
{
    /*
      h264_metadata rewrites the NAL units, which drops the zero-length
      one ffmpeg's own AVCC to Annex-B conversion puts ahead of every
      access unit for this camera. Chrome's MP4 parser refuses a sample
      containing it ("Failed to prepare video sample for decode");
      Firefox plays it. It is H.264-only, hence the codec test.
     */
    const char *vbsf = s.rtmp->video_codec() == RTMP_VCODEC_H264
        ? "h264_metadata" : nullptr;
    const bool want_audio =
        (video_entry_opts(ke_.video_flags) & VIDEO_OPT_AUDIO) != 0;
    if (!s.rtsp.start(port2_, idx, want_audio, SPLICE_RTMP, vbsf)) {
        return false;
    }
    for (int watch : { s.rtsp.backend_fd(), s.rtsp.media_fd() }) {
        if (watch < 0) {
            continue;
        }
        struct epoll_event ev {};
        ev.events = EPOLLIN | EPOLLRDHUP;
        ev.data.fd = watch;
        epoll_ctl(epfd_, EPOLL_CTL_ADD, watch, &ev);
    }
    return true;
}

/*
  Drive a native RTMP publisher: client bytes in, responses out, FLV to
  the backend. Returns false when the session is over.
 */
/*
  Move what the owning session produced into the queues, and start the
  backend once the stream has named its codec.

  `alive` is what feed()/resume() returned. Shared with promotion,
  which has to run exactly this after accepting a publish: the client
  may have pipelined its sequence header into the same segment, and
  parsing stops at publish so authorisation can happen in order.
 */
bool VideoChild::rtmp_drain_owner(Slot &s, int idx, bool alive)
{
    RtmpSession &r = *s.rtmp;
    // A second publish on the owning connection is a protocol error the
    // session rejects; there is nothing to authorise here, because
    // promotion did that before this session reached the slot.
    const bool refused = r.publish_pending();

    if (!r.to_peer().empty()) {
        s.to_client.buf.insert(s.to_client.buf.end(),
                               r.to_peer().begin(), r.to_peer().end());
        r.to_peer().clear();
    }
    /*
      Queue unconditionally. The backend may not exist yet -- it waits
      for the codec -- and the FLV header and sequence header arrive
      before it does; dropping them left the backend with a stream it
      could not open. Reads are gated on SPLICE_QUEUE_MAX, so this stays
      bounded.
     */
    if (!r.to_flv().empty()) {
        s.to_backend.buf.insert(s.to_backend.buf.end(),
                                r.to_flv().begin(), r.to_flv().end());
        r.to_flv().clear();
    }
    if (r.publishing() && !s.rtsp.running()
        && r.video_codec() != RTMP_VCODEC_NONE
        && !rtmp_start_backend(s, idx)) {
        return false;
    }
    if (refused || !alive) {
        splice_flush(s.rtsp_client_fd, s.to_client);
        if (r.error()[0] != '\0') {
            printf("[%d] video slot %d RTMP: %s\n", port2_, idx, r.error());
        }
        return false;
    }
    return true;
}

bool VideoChild::pump_rtmp(Slot &s, int idx, int fd, time_t now)
{
    uint8_t buf[16384];
    if (fd == s.rtsp.media_fd()) {
        const ssize_t n = ::read(fd, buf, sizeof(buf));
        if (n == 0) {
            return false;
        }
        if (n < 0) {
            return errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR;
        }
        s.pub_last = now;
        ingest_stream(s, idx, buf, size_t(n));
        return true;
    }

    // The backend's stdin: write-only, so an event here is either room
    // to write or the backend having gone away.
    if (fd == s.rtsp.backend_fd()) {
        if (!splice_flush(fd, s.to_backend)) {
            return false;
        }
        splice_arm(fd, s.to_backend);
        return true;
    }

    if (fd != s.rtsp_client_fd || !s.rtmp) {
        return true;
    }

    if (!splice_flush(fd, s.to_client)) {
        return false;
    }
    if (s.rtsp.running() && !splice_flush(s.rtsp.backend_fd(), s.to_backend)) {
        return false;
    }

    /*
      Read only while both queues have room. Gating on the backend alone
      let a peer that stops reading its responses keep sending commands,
      turning its own bounded input into an unbounded to_client.
     */
    if (s.to_backend.pending() < SPLICE_QUEUE_MAX
        && s.to_client.pending() < SPLICE_QUEUE_MAX) {
        const ssize_t n = ::recv(fd, buf, sizeof(buf), 0);
        if (n == 0) {
            return false;
        }
        if (n < 0 && !(errno == EAGAIN || errno == EWOULDBLOCK
                       || errno == EINTR)) {
            return false;
        }
        if (n > 0) {
            s.pub_last = now;
            if (!rtmp_drain_owner(s, idx, s.rtmp->feed(buf, size_t(n), now))) {
                return false;
            }
        }
    }

    if (!splice_flush(fd, s.to_client)) {
        return false;
    }
    if (s.rtsp.running()) {
        if (!splice_flush(s.rtsp.backend_fd(), s.to_backend)) {
            return false;
        }
        splice_arm(s.rtsp.backend_fd(), s.to_backend);
    }
    splice_arm(fd, s.to_client);
    return true;
}

bool VideoChild::pump_rtsp(Slot &s, int idx, int fd, time_t now)
{
    if (s.rtmp) {
        return pump_rtmp(s, idx, fd, now);
    }
    uint8_t buf[16384];
    if (fd == s.rtsp_client_fd || fd == s.rtsp.backend_fd()) {
        const int from_fd = fd;
        const int to_fd = (fd == s.rtsp_client_fd) ? s.rtsp.backend_fd()
                                                   : s.rtsp_client_fd;
        if (to_fd < 0) {
            return false;
        }
        SpliceQueue &out = (fd == s.rtsp_client_fd) ? s.to_backend
                                                    : s.to_client;
        SpliceQueue &in = (fd == s.rtsp_client_fd) ? s.to_client
                                                   : s.to_backend;

        // Drain anything owed in both directions first: this fd may have
        // woken us for EPOLLOUT rather than EPOLLIN.
        if (!splice_flush(to_fd, out)) {
            return false;
        }
        if (!splice_flush(from_fd, in)) {
            return false;
        }

        // Only read while the sink has room. Leaving bytes in the socket
        // is what pushes back on the publisher, instead of buffering
        // without limit here.
        if (out.pending() < SPLICE_QUEUE_MAX) {
            const ssize_t n = ::recv(from_fd, buf, sizeof(buf), 0);
            if (n == 0) {
                return false;
            }
            if (n < 0 && !(errno == EAGAIN || errno == EWOULDBLOCK
                           || errno == EINTR)) {
                return false;
            }
            if (n > 0) {
                out.buf.insert(out.buf.end(), buf, buf + n);
                if (!splice_flush(to_fd, out)) {
                    return false;
                }
                s.pub_last = now;
            }
        }

        splice_arm(to_fd, out);
        splice_arm(from_fd, in);
        return true;
    }
    if (fd == s.rtsp.media_fd()) {
        const ssize_t n = ::read(fd, buf, sizeof(buf));
        if (n == 0) {
            return false;
        }
        if (n < 0) {
            return errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR;
        }
        s.pub_last = now;
        // The backend writes a byte stream, not datagrams, so packets
        // straddle reads -- which the scanner and ring already handle.
        ingest_stream(s, idx, buf, size_t(n));
        return true;
    }
    return true;
}

void VideoChild::epoll_add_viewer(VideoViewer &v)
{
    struct epoll_event ev {};
    ev.events = EPOLLIN | EPOLLRDHUP;
    ev.data.fd = v.fd();
    epoll_ctl(epfd_, EPOLL_CTL_ADD, v.fd(), &ev);
}

// Arm or disarm EPOLLOUT to match whether this viewer is blocked.
// Leaving it armed permanently makes epoll_wait return immediately for
// any writable socket, which burns a core per idle viewer.
void VideoChild::epoll_sync_viewer(VideoViewer &v, bool &armed)
{
    const bool want = v.wants_write();
    if (want == armed) {
        return;
    }
    struct epoll_event ev {};
    ev.events = uint32_t(EPOLLIN | EPOLLRDHUP)
        | (want ? uint32_t(EPOLLOUT) : 0u);
    ev.data.fd = v.fd();
    if (epoll_ctl(epfd_, EPOLL_CTL_MOD, v.fd(), &ev) == 0) {
        armed = want;
    }
}

void VideoChild::drop_viewer(Slot &s, int idx, VideoViewer &v)
{
    if (!v.active()) {
        return;
    }
    printf("[%d] video slot %d viewer disconnected after %llu KiB (%s)\n",
           port2_, idx, (unsigned long long)(v.bytes_sent() / 1024),
           v.drop_reason()[0] ? v.drop_reason() : "closed");
    epoll_ctl(epfd_, EPOLL_CTL_DEL, v.fd(), nullptr);
    v.close();
    s.viewers_dropped++;
    last_tick_ = 0;
}

/*
  End the current stream on a slot.

  A publisher going away ends the stream its viewers are watching. The
  next publisher is a *different* stream: PSI, continuity counters and
  PTS/PCR all restart, so its bytes cannot simply be appended to what
  the viewers have already been given. A player fed that sees time jump
  backwards and stalls for good -- which looks exactly like "the video
  never came back" rather than like a disconnect.

  So viewers are closed here and get a clean end of stream. A client
  that wants to keep watching reconnects and joins the new stream at its
  own first keyframe. The ring and scanner are reset with them, so no
  stale anchor from the old stream can be handed to whoever joins next.
 */
void VideoChild::end_stream(Slot &s, int idx, const char *why)
{
    for (int v = 0; v < VIDEO_MAX_VIEWERS; v++) {
        VideoViewer &vw = s.viewers[v];
        if (vw.active()) {
            vw.set_drop_reason(why);
            drop_viewer(s, idx, vw);
        }
    }
    s.ring.reset();
    s.scanner.reset();
    s.last_anchor = 0;
    s.had_anchor = false;
    s.bad_datagrams = 0;
    s.warned_204 = false;
    s.pub_bytes = 0;
}

// Push ring bytes to every viewer on this slot. Called after ingest and
// on every loop iteration, so a viewer whose socket drained between
// epoll wakeups still makes progress.
void VideoChild::pump_viewers(Slot &s, int idx, time_t now)
{
    for (int v = 0; v < VIDEO_MAX_VIEWERS; v++) {
        VideoViewer &vw = s.viewers[v];
        if (!vw.active()) {
            continue;
        }
        if (vw.kind() == VVK_RTSP || vw.kind() == VVK_RTMP) {
            // A publisher, not a viewer. Take the socket -- untouched,
            // since the detect phase only ever peeked -- and splice it.
            struct sockaddr_in from {};
            from.sin_family = AF_INET;
            from.sin_addr.s_addr = vw.peer_ip_be();
            from.sin_port = vw.peer_port_be();
            const splice_proto_t proto = vw.kind() == VVK_RTMP
                ? SPLICE_RTMP : SPLICE_RTSP;
            const int fd = vw.release_fd();
            epoll_ctl(epfd_, EPOLL_CTL_DEL, fd, nullptr);
            s.viewer_out_armed[v] = false;
            handle_rtsp(s, idx, fd, from, now, proto);
            continue;
        }
        if (vw.state() == VV_DETECT && vw.kind() == VVK_WS) {
            if (!vw.begin_ws_pump(ke_, idx, s.ring, s.scanner, now)) {
                drop_viewer(s, idx, vw);
            }
            continue;
        }
        if (vw.state() == VV_DETECT) {
            if (now - vw.connected_at() >= VIDEO_DETECT_SILENCE_S) {
                if (!vw.detect_timeout(ke_, idx, s.ring, s.scanner, now)) {
                    drop_viewer(s, idx, vw);
                    continue;
                }
            } else {
                continue;
            }
        }
        if (!vw.on_writable(s.ring, now)) {
            drop_viewer(s, idx, vw);
            continue;
        }
        epoll_sync_viewer(vw, s.viewer_out_armed[v]);
    }
}

void VideoChild::write_conn_rows(time_t now)
{
    auto *db = conn_db_open_transaction();
    if (db == nullptr) {
        return;
    }
    // Only our own index range: the MAVLink child snapshots 0..999 the
    // same way, and whole-port2 deletes here would erase its rows.
    conn_delete_index_range(db, port2_, VIDEO_CONN_INDEX_BASE, INT32_MAX);
    for (int i = 0; i < KEY_MAX_VIDEO_PORTS; i++) {
        Slot &s = slots_[i];
        if (!s.has_pub) {
            continue;
        }
        struct ConnEntry e {};
        e.magic = CONN_MAGIC;
        e.connected_at = uint64_t(s.pub_since);
        e.last_update = uint64_t(now);
        e.port2 = port2_;
        e.conn_index = VIDEO_PUB_INDEX(i);
        e.pid = uint32_t(getpid());
        e.rx_msgs = uint32_t(s.pub_bytes / 1024);   // KiB for video rows
        e.peer_ip_be = s.pub_ip_be;
        e.peer_port_be = s.pub_port_be;
        /*
          Report what the publisher actually is. Every video row used to
          say UDP/MPEG-TS, which is only true of the datagram path -- an
          operator looking at a stuck RTSP or RTMP publisher was told it
          was something it was not.
         */
        const bool tcp_pub = s.rtmp || s.rtsp.running() ||
                             s.rtsp_client_fd >= 0;
        e.transport = tcp_pub ? CONN_TRANSPORT_TCP : CONN_TRANSPORT_UDP;
        e.is_user = 0;
        e.role = CONN_ROLE_VIDEO_PUB;
        e.stream_idx = uint8_t(i);
        e.app_proto = s.rtmp ? CONN_APP_RTMP
                    : (tcp_pub ? CONN_APP_RTSP : CONN_APP_MPEGTS);
        conn_write(db, e);
    }
    conn_db_close_commit(db);
}

void VideoChild::tick(time_t now)
{
    // Policy that doesn't need a rebind (credentials, grace, quota) is
    // picked up here. Anything that changes binding -- the enable bit,
    // the ports, the slot options -- makes the parent re-fork us
    // instead, so we never have to rebind under our own feet.
    if (load_entry()) {
        auth_.invalidate();
    }
    // Sample the MAVLink session while it is alive, so the grace window
    // still has a last-known-good to age out once the session child
    // exits and its connections.tdb row disappears.
    auth_.observe(now);
    for (int i = 0; i < KEY_MAX_VIDEO_PORTS; i++) {
        Slot &s = slots_[i];
        if (s.rtsp.running() && s.rtsp.reap()) {
            close_rtsp(s, i, "backend exited");
        }
        /*
          Time out handshakes that never publish. The session bounds
          itself once bytes arrive; this covers the peer that connects
          and then says nothing at all.
         */
        for (int k = 0; k < VIDEO_MAX_PENDING_RTMP; k++) {
            PendingRtmp &p = s.pending[k];
            if (p.active() && p.since != 0
                && now - p.since > RTMP_PREPUBLISH_MAX_S) {
                close_pending(s, i, p, "handshake timed out");
            }
        }
        /*
          Accepted, but never said what it is sending. There is no
          backend and no media, yet its control messages keep refreshing
          the idle timer, so nothing else would ever reclaim the slot.
         */
        if (s.rtmp && s.rtmp->publishing() && !s.rtsp.running()
            && s.rtmp->publishing_since() != 0
            && now - s.rtmp->publishing_since() > RTMP_CODEC_DEADLINE_S) {
            close_rtsp(s, i, "no video codec after publish");
            continue;
        }
        if (s.has_pub && now - s.pub_last > VIDEO_PUB_IDLE_S) {
            printf("[%d] video slot %d publisher idle, releasing\n",
                   port2_, i);
            /*
              A spliced publisher has to be torn down, not just
              forgotten. Clearing has_pub alone left the client socket,
              the backend socket and the ffmpeg all alive, so
              rtsp.running() went on refusing every replacement as
              slot-busy until the child was killed by hand -- and UDP
              admission, which tests only has_pub, could meanwhile claim
              the slot underneath a splice that was still feeding it.
             */
            if (s.rtsp.running() || s.rtsp_client_fd >= 0) {
                close_rtsp(s, i, "publisher idle");
                continue;    // close_rtsp does the rest, including
                             // end_stream and the recorder
            }
            s.has_pub = false;
            // Close the segment on disconnect rather than leaving it
            // open: the file is complete, and an open file is not
            // evictable by the quota pass.
            s.rec.close_segment();
            s.recording = false;
            end_stream(s, i, "publisher gone");
        }
    }
    // One line per active publisher. This is the only window onto the
    // scanner until viewers exist, so it carries what a operator (and
    // the tests) need: whether a viewer could join, and why not.
    for (int i = 0; i < KEY_MAX_VIDEO_PORTS; i++) {
        Slot &s = slots_[i];
        if (!s.has_pub) {
            continue;
        }
        const TSStats &st = s.scanner.stats();
        uint64_t join = 0;
        const bool can_join = s.scanner.join_offset(join);
        printf("[%d] video slot %d stats: %llu KiB, %llu pkts, pat=%llu "
               "pmt=%llu rai=%llu cc_err=%llu crc_err=%llu bad_dgram=%llu "
               "vpid=0x%x stype=0x%02x join=%s\n",
               port2_, i,
               (unsigned long long)(s.pub_bytes / 1024),
               (unsigned long long)st.packets,
               (unsigned long long)st.pat_seen,
               (unsigned long long)st.pmt_seen,
               (unsigned long long)st.rai_seen,
               (unsigned long long)st.cc_errors,
               (unsigned long long)st.crc_errors,
               (unsigned long long)s.bad_datagrams,
               unsigned(s.scanner.video_pid()),
               unsigned(s.scanner.video_stream_type()),
               can_join ? "ready" : "waiting");
    }
    write_conn_rows(now);
    last_tick_ = now;
}

void VideoChild::run(void)
{
    if (!load_entry()) {
        printf("[%d] video: no keys.tdb entry\n", port2_);
        signal_ready(ENOENT);
        _exit(1);
    }

    int err = bind_slots();
    signal_ready(err);

    epfd_ = epoll_create1(0);
    if (epfd_ == -1) {
        printf("[%d] video: epoll_create1 failed - %s\n",
               port2_, strerror(errno));
        _exit(1);
    }
    for (int i = 0; i < KEY_MAX_VIDEO_PORTS; i++) {
        for (int fd : { slots_[i].udp_fd, slots_[i].tcp_fd }) {
            if (fd == -1) {
                continue;
            }
            struct epoll_event ev {};
            ev.events = EPOLLIN;
            ev.data.fd = fd;
            epoll_ctl(epfd_, EPOLL_CTL_ADD, fd, &ev);
        }
    }

    while (true) {
        struct epoll_event events[VIDEO_MAX_EPOLL_EVENTS];
        int nev = epoll_wait(epfd_, events, VIDEO_MAX_EPOLL_EVENTS, 1000);
        if (nev == -1 && errno != EINTR) {
            printf("[%d] video: epoll_wait failed - %s\n",
                   port2_, strerror(errno));
            break;
        }
        const time_t evnow = time(nullptr);
        for (int e = 0; e < nev; e++) {
            const int fd = events[e].data.fd;
            bool matched = false;
            for (int i = 0; i < KEY_MAX_VIDEO_PORTS && !matched; i++) {
                if (slots_[i].udp_fd == fd) {
                    handle_udp(slots_[i], i);
                    matched = true;
                } else if (slots_[i].tcp_fd == fd) {
                    handle_tcp(slots_[i], i);
                    matched = true;
                }
            }
            if (matched) {
                continue;
            }
            // a pending RTMP handshake: owns no slot state, so it is
            // matched before the splice fds and closed on its own.
            for (int i = 0; i < KEY_MAX_VIDEO_PORTS && !matched; i++) {
                Slot &s = slots_[i];
                for (int k = 0; k < VIDEO_MAX_PENDING_RTMP; k++) {
                    PendingRtmp &p = s.pending[k];
                    if (!p.active() || p.fd != fd) {
                        continue;
                    }
                    matched = true;
                    if ((events[e].events & (EPOLLHUP | EPOLLERR))
                        || !pump_pending(s, i, p, evnow)) {
                        // Promotion moves the fd out and clears p, so an
                        // entry that is no longer active was handed on
                        // rather than dropped.
                        if (p.active()) {
                            close_pending(s, i, p, "connection closed");
                        }
                    }
                    break;
                }
            }
            if (matched) {
                continue;
            }
            // an RTSP splice fd
            for (int i = 0; i < KEY_MAX_VIDEO_PORTS && !matched; i++) {
                Slot &s = slots_[i];
                if (fd != s.rtsp_client_fd && fd != s.rtsp.backend_fd()
                    && fd != s.rtsp.media_fd()) {
                    continue;
                }
                matched = true;
                if ((events[e].events & (EPOLLHUP | EPOLLERR))
                    || !pump_rtsp(s, i, fd, evnow)) {
                    close_rtsp(s, i, "connection closed");
                }
            }
            if (matched) {
                continue;
            }
            // a viewer socket
            for (int i = 0; i < KEY_MAX_VIDEO_PORTS && !matched; i++) {
                Slot &s = slots_[i];
                for (int v = 0; v < VIDEO_MAX_VIEWERS; v++) {
                    VideoViewer &vw = s.viewers[v];
                    if (!vw.active() || vw.fd() != fd) {
                        continue;
                    }
                    matched = true;
                    bool ok = true;
                    if (events[e].events & (EPOLLHUP | EPOLLERR)) {
                        ok = false;
                    } else {
                        if (events[e].events & (EPOLLIN | EPOLLRDHUP)) {
                            ok = vw.on_readable(ke_, i, s.ring, s.scanner,
                                                evnow);
                        }
                        if (ok && (events[e].events & EPOLLOUT)) {
                            ok = vw.on_writable(s.ring, evnow);
                        }
                    }
                    if (!ok) {
                        drop_viewer(s, i, vw);
                    }
                    break;
                }
            }
        }

        // Push to viewers every iteration, not only on EPOLLOUT: new
        // ring data has no fd event of its own, and a viewer whose
        // socket had room all along would otherwise never be fed.
        const time_t now = time(nullptr);
        for (int i = 0; i < KEY_MAX_VIDEO_PORTS; i++) {
            if (slots_[i].udp_fd != -1 || slots_[i].tcp_fd != -1) {
                pump_viewers(slots_[i], i, now);
            }
        }
        if (now - last_tick_ >= VIDEO_TICK_S) {
            tick(now);
        }
        // The parent may have died between our PDEATHSIG being armed
        // and now; PDEATHSIG only fires on a parent that was alive when
        // it was set.
        if (getppid() == 1) {
            break;
        }
    }

    conn_remove_video(port2_);
    _exit(0);
}

}  // namespace

void video_child_main(int port2, int ready_fd)
{
    VideoChild child(port2, ready_fd);
    child.run();
}
