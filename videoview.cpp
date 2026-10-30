/*
  Video viewers. See videoview.h.
 */
#include "videoview.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <unistd.h>

#include "videoauth.h"

bool video_viewer_authorised(const struct KeyEntry &ke,
                             const std::string &password)
{
    bool has_pw = false;
    for (int i = 0; i < 32; i++) {
        has_pw |= ke.video_viewer_key[i] != 0;
    }
    if (!has_pw) {
        return true;   // open viewing
    }
    return video_password_matches(ke.video_viewer_key, password);
}

void VideoViewer::start(int fd, int port2, uint32_t peer_ip_be,
                        uint16_t peer_port_be, time_t now)
{
    fd_ = fd;
    port2_ = port2;
    state_ = VV_DETECT;
    kind_ = VVK_UNKNOWN;
    peer_ip_be_ = peer_ip_be;
    peer_port_be_ = peer_port_be;
    connected_at_ = now;
    last_progress_ = now;
    behind_since_ = 0;
    out_.clear();
    prefix_.clear(); prefix_sent_ = 0;
    out_sent_ = 0;
    read_pos_ = 0;
    streaming_ = false;
    bytes_sent_ = 0;
    blocked_ = false;
    ws_ = nullptr;
    ws_ready_ = false;
    hls_ = false;
    authorised_ = false;
    announced_ = false;
    token_.clear();
    token_checked_ = now;
    drop_reason_ = "";

    int one = 1;
    setsockopt(fd_, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    // Deliberately modest: a large kernel buffer hides backpressure and
    // we would not notice a viewer falling behind until much later.
    int snd = 256 * 1024;
    setsockopt(fd_, SOL_SOCKET, SO_SNDBUF, &snd, sizeof(snd));
    fcntl(fd_, F_SETFL, fcntl(fd_, F_GETFL, 0) | O_NONBLOCK);
}

void VideoViewer::close(void)
{
    // A response cut short never reaches the release in flush().
    release_out();
    delete rtsp_view_;
    rtsp_view_ = nullptr;
    if (ws_ != nullptr) {
        delete ws_;          // frees SSL objects; the fd is ours to close
        ws_ = nullptr;
    }
    if (fd_ >= 0) {
        ::close(fd_);
        fd_ = -1;
    }
    state_ = VV_CLOSING;
}

void VideoViewer::fail(int code, const char *reason, const char *text)
{
    if (kind_ == VVK_HTTP) {
        out_ = http_simple_response(code, reason, "text/plain",
                                    std::string(text) + "\n");
    }
    drop_reason_ = reason;
    out_sent_ = 0;
    state_ = VV_RESPONDING;
    streaming_ = false;
}

static uint32_t hls_incarnation = 0;

void video_hls_set_incarnation(uint32_t inc)
{
    hls_incarnation = inc;
}

// "/v<number>-<incarnation>-<seq>.ts" -> seq. A name from another
// incarnation is not ours to serve.
static bool hls_segment_path(const std::string &path, int number, uint32_t &seq)
{
    char prefix[40];
    const int plen = snprintf(prefix, sizeof(prefix), "/v%d-%u-", number,
                              hls_incarnation);
    const size_t head = size_t(plen);
    if (path.size() < head + 4 || path.compare(0, head, prefix) != 0
        || path.compare(path.size() - 3, 3, ".ts") != 0) {
        return false;
    }
    const std::string digits = path.substr(head, path.size() - 3 - head);
    if (digits.empty() || digits.size() > 10) {
        return false;
    }
    uint64_t v = 0;
    for (char c : digits) {
        if (c < '0' || c > '9') {
            return false;
        }
        v = v * 10 + uint64_t(c - '0');
    }
    if (v > UINT32_MAX) {
        return false;
    }
    seq = uint32_t(v);
    return true;
}

// A player starts fetching a segment seconds after reading the playlist,
// so one the ring is about to overwrite is not worth advertising.
static bool hls_segment_fresh(const VideoRing &ring, uint64_t off)
{
    return ring.resident(off)
        && ring.write_pos() - off <= ring.capacity() / 4 * 3;
}

void VideoViewer::respond_ok(const char *type, const char *cache,
                             const std::string &body, time_t now)
{
    char head[256];
    snprintf(head, sizeof(head),
             "HTTP/1.1 200 OK\r\n"
             "Content-Type: %s\r\n"
             "Content-Length: %zu\r\n"
             "Cache-Control: %s\r\n"
             "Connection: close\r\n"
             "\r\n",
             type, body.size(), cache);
    out_ = head;
    out_ += body;
    out_sent_ = 0;
    bytes_sent_ = out_.size();
    streaming_ = false;
    state_ = VV_RESPONDING;
    last_progress_ = now;
    drop_reason_ = "hls";
    hls_ = true;
}

bool VideoViewer::serve_hls_playlist(int slot, const VideoRing &ring,
                                     const VideoScanner &scanner, time_t now)
{
    size_t n = 0;
    const HlsBoundary *b = scanner.hls_boundaries(n);
    // Segment i is complete once boundary i+1 exists.
    const size_t last = n >= 2 ? n - 1 : 0;
    // Newest first: keep adding older segments until the list spans
    // enough target durations, runs out of fresh segments, or is full.
    // The list is one epoch, so the timestamps are comparable.
    const uint64_t want_span =
        uint64_t(HLS_PLAYLIST_MIN_TARGETS) * HLS_TARGET_DURATION_S * 90000u;
    size_t first = last;
    while (first > 0 && last - first < HLS_PLAYLIST_SEGMENTS
           && hls_segment_fresh(ring, b[first - 1].off)
           && (first == last
               || ((b[last].pts - b[first].pts) & 0x1FFFFFFFFull) < want_span)) {
        first--;
    }
    if (first >= last) {
        fail(503, "stream not ready", "No complete HLS segment yet.");
        return true;
    }
    // RFC 8216 4.3.3.1: the value must not change during the life of the
    // playlist, and the scanner admits no longer segment than this.
    const unsigned target = HLS_TARGET_DURATION_S;

    // A client that authenticated with ?t= fetches the segments the same
    // way: a relative URI drops the query, and with a password set the
    // segment would be a 401.
    std::string uri_query;
    if (!token_.empty()) {
        uri_query = "?t=" + token_;
    }

    // A segment from a new publisher follows a discontinuity. When the
    // list starts on it the tag is emitted, otherwise it has already
    // scrolled off and only the counter remembers it.
    const uint32_t epoch = scanner.hls_epoch();
    const bool starts_epoch = epoch > 0
        && b[first].seq == scanner.hls_epoch_first_seq();

    char line[96];
    std::string pl = "#EXTM3U\n#EXT-X-VERSION:3\n";
    snprintf(line, sizeof(line), "#EXT-X-TARGETDURATION:%u\n", target);
    pl += line;
    snprintf(line, sizeof(line), "#EXT-X-MEDIA-SEQUENCE:%u\n", b[first].seq);
    pl += line;
    if (epoch > 0) {
        snprintf(line, sizeof(line), "#EXT-X-DISCONTINUITY-SEQUENCE:%u\n",
                 starts_epoch ? epoch - 1 : epoch);
        pl += line;
    }
    for (size_t i = first; i < last; i++) {
        if (i == first && starts_epoch) {
            pl += "#EXT-X-DISCONTINUITY\n";
        }
        const uint64_t d = (b[i + 1].pts - b[i].pts) & 0x1FFFFFFFFull;
        snprintf(line, sizeof(line), "#EXTINF:%.3f,\nv%d-%u-%u.ts",
                 double(d) / 90000.0, slot + 1, hls_incarnation, b[i].seq);
        pl += line;
        pl += uri_query;
        pl += "\n";
    }
    respond_ok("application/vnd.apple.mpegurl", "no-cache", pl, now);
    return true;
}

bool VideoViewer::serve_hls_segment(uint32_t seq, const VideoRing &ring,
                                    const VideoScanner &scanner, time_t now)
{
    size_t n = 0;
    const HlsBoundary *b = scanner.hls_boundaries(n);
    for (size_t i = 0; i + 1 < n; i++) {
        if (b[i].seq != seq) {
            continue;
        }
        if (!ring.resident(b[i].off)) {
            break;
        }
        // Resident, so no longer than the ring.
        const size_t len = size_t(b[i + 1].off - b[i].off);
        std::string body(len, '\0');
        if (ring.read_at(b[i].off, reinterpret_cast<uint8_t *>(&body[0]), len) != len) {
            break;
        }
        respond_ok("video/mp2t", "public, max-age=60", body, now);
        return true;
    }
    fail(404, "not found", "Segment is no longer available.");
    return true;
}

bool VideoViewer::begin_stream(const struct KeyEntry &ke, int slot,
                               const VideoRing &ring, const VideoScanner &scanner,
                               bool http, time_t now)
{
    uint64_t anchor = 0;
    if (!scanner.join_offset(anchor)) {
        // Refusing beats serving from an arbitrary point: without a
        // PAT, a PMT and a random access point ahead of it, the client
        // decodes garbage and the stream looks broken rather than
        // not-ready-yet.
        fail(503, "stream not ready",
             "No decodable start point yet. The publisher has not sent a "
             "keyframe with program information.");
        return true;
    }
    if (!ring.resident(anchor)) {
        fail(503, "stream not ready", "Join point is no longer buffered.");
        return true;
    }
    prefix_ = scanner.prefix; prefix_sent_ = 0;
    read_pos_ = anchor;
    streaming_ = true;
    last_progress_ = now;
    behind_since_ = 0;

    if (http) {
        // No Content-Length: the stream is unbounded and ends when the
        // connection does.
        out_ = "HTTP/1.1 200 OK\r\n"
               "Content-Type: video/mp2t\r\n"
               "Cache-Control: no-store\r\n"
               "Connection: close\r\n"
               "\r\n";
        if (scanner.matroska) {
            const auto pos = out_.find("video/mp2t");
            out_.replace(pos, strlen("video/mp2t"), "video/x-matroska");
        }
        out_sent_ = 0;
        state_ = VV_RESPONDING;
    } else {
        out_.clear();
        out_sent_ = 0;
        state_ = VV_STREAMING;
    }
    (void)ke;
    (void)slot;
    return true;
}

bool VideoViewer::on_readable(const struct KeyEntry &ke, int slot,
                              const VideoRing &ring, const VideoScanner &scanner,
                              time_t now)
{
    if (rtsp_view_) return rtsp_view_->on_readable(ke, slot, ring, scanner, now);
    if (state_ != VV_DETECT) {
        if (kind_ == VVK_WS) {
            // Let the WebSocket consume control frames (ping/close).
            uint8_t sink[2048];
            const ssize_t got = ws_->recv(sink, sizeof(sink));
            if (got < 0) {
                drop_reason_ = "websocket closed";
                return false;
            }
            return true;
        }
        // A streaming viewer has nothing to say; drain and ignore rather
        // than letting it steer us.
        uint8_t sink[2048];
        const ssize_t got = ::recv(fd_, sink, sizeof(sink), 0);
        if (got == 0) {
            drop_reason_ = "peer closed";
            return false;
        }
        return true;
    }

    /*
      Classify once. A WebSocket viewer stays in VV_DETECT for the whole
      handshake, so the state check above is not enough on its own: a
      later read would see a mid-handshake TLS record (0x17...) rather
      than the ClientHello, fail the TLS test, and re-classify the
      connection as HTTP. The WebSocket then never gets driven and the
      viewer is dropped by the silence timeout.
     */
    if (kind_ == VVK_WS) {
        // Already handed to WebSocket; it drives itself from the pump.
        // Note this must NOT short-circuit an HTTP viewer: its request
        // may arrive fragmented, and the parse below has to see the
        // rest of it.
        return true;
    }

    /*
      Peek, do not consume. A WebSocket upgrade has to stay in the
      socket: the WebSocket class reads and answers the handshake
      itself. Only a plain-HTTP request is read off, once we know that
      is what it is.
     */
    uint8_t buf[2048];
    holding_bytes_ = false;
    const ssize_t n = ::recv(fd_, buf, sizeof(buf), MSG_PEEK);
    if (n == 0) {
        drop_reason_ = "peer closed";
        return false;
    }
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
            return true;
        }
        drop_reason_ = "read error";
        return false;
    }

    /*
      RTSP playback uses the reserved /view/ namespace. Other targets
      remain untouched for the publisher splice, including OPTIONS.
      It has to be recognised here rather than at accept(): a publisher
      connects and only then sends OPTIONS, so at accept there is
      usually nothing to look at, and classifying on an empty peek
      misfiled publishers as viewers -- which then answered their
      OPTIONS with "405 method not allowed".
     */
    static const char *rtsp_methods[] = {
        "OPTIONS ", "ANNOUNCE ", "DESCRIBE ", "SETUP ", "PLAY ",
        "RECORD ", "PAUSE ", "TEARDOWN ", "GET_PARAMETER ", "SET_PARAMETER ",
    };
    for (const char *m : rtsp_methods) {
        const size_t len = strlen(m);
        if (size_t(n) >= len && memcmp(buf, m, len) == 0) {
            // The request target carries the publish credential. Do not hand
            // the socket off while that target can still be split across TCP
            // segments: an early decision would turn a supplied password into
            // "absent" and permit the session fallback. The peek is bounded,
            // so a line that fills it without ending is malformed.
            if (memchr(buf, '\n', size_t(n)) == nullptr) {
                if (size_t(n) == sizeof(buf)) {
                    drop_reason_ = "RTSP request line too long";
                    return false;
                }
                holding_bytes_ = true;
                return true;
            }
            const std::string line(reinterpret_cast<const char *>(buf), size_t(n));
            const size_t sp = line.find(' ', len);
            if (sp != std::string::npos &&
                RtspViewer::playback_target(line.substr(len, sp-len))) {
                kind_ = VVK_RTSP_VIEW;
                state_ = VV_STREAMING;
                rtsp_view_ = new RtspViewer(fd_, port2_, now);
                return rtsp_view_->on_readable(ke, slot, ring, scanner, now);
            }
            kind_ = VVK_RTSP;
            return true;   // the child takes the socket from here
        }
    }

    /*
      RTMP publish. The client speaks first with handshake C0, a single
      version byte, effectively always 0x03. One byte is enough to be
      unambiguous here: MPEG-TS starts 0x47, every RTSP and HTTP method
      is an ASCII letter, and a TLS ClientHello starts 0x16 (its 0x03 is
      the *second* byte, not the first).
     */
    if (n >= 1 && buf[0] == 0x03) {
        kind_ = VVK_RTMP;
        return true;   // the child takes the socket from here
    }

    // TLS ClientHello: WebSocket handles the whole thing from here.
    static const uint8_t tls_hello[3] = { 0x16, 0x03, 0x01 };
    if (n >= 3 && memcmp(buf, tls_hello, 3) == 0) {
        kind_ = VVK_WS;
        return true;   // begin_ws() runs from the pump once bytes arrive
    }

    kind_ = VVK_HTTP;
    HttpRequest peek;
    const int r = peek.feed(buf, size_t(n));
    if (r < 0) {
        fail(400, "bad request", "Malformed request.");
        (void)::recv(fd_, buf, size_t(n), 0);
        return true;
    }
    if (r == 0) {
        holding_bytes_ = true;
        return true;   // wait for the rest, still unconsumed
    }

    if (peek.method() == "PUT") {
        kind_ = VVK_MKV;
        return true; // parent consumes only the header after authenticating
    }

    // A WebSocket upgrade: hand the untouched socket to WebSocket.
    if (!peek.header("Upgrade").empty()
        && peek.header("Upgrade").find("ebsocket") != std::string::npos) {
        if (!ws_authorise(ke, slot, peek)) {
            // No handshake, no upgrade: an unauthorised browser gets a
            // plain HTTP error it can actually display.
            (void)::recv(fd_, buf, size_t(n), 0);
            kind_ = VVK_HTTP;
            fail(401, "unauthorized", "A viewer token or password is required.");
            return true;
        }
        kind_ = VVK_WS;
        return true;
    }

    // Plain HTTP from here: now it is safe to consume the request.
    (void)::recv(fd_, buf, size_t(n), 0);
    req_ = peek;

    if (req_.method() != "GET") {
        fail(405, "method not allowed", "Only GET is served here.");
        return true;
    }

    // HLS: /v1.m3u8 and /v1-<seq>.ts, cut from the ring without copying
    // the stream anywhere else. Not offered for Matroska.
    {
        char playlist[32];
        snprintf(playlist, sizeof(playlist), "/v%d.m3u8", slot + 1);
        uint32_t seg_seq = 0;
        const bool is_playlist = req_.path() == playlist;
        const bool is_segment = hls_segment_path(req_.path(), slot + 1, seg_seq);
        if (is_playlist || is_segment) {
            // Before any refusal: a client looping on a 401 must not be
            // logged and ticked as a session per request either.
            hls_ = true;
            // Authorise first: the stream type is not for anonymous
            // callers to probe.
            if (!ws_authorise(ke, slot, req_)) {
                fail(401, "unauthorized", "A viewer token or password is required.");
                return true;
            }
            if (scanner.matroska) {
                fail(404, "not found", "HLS is not available for this stream.");
                return true;
            }
            return is_playlist ? serve_hls_playlist(slot, ring, scanner, now)
                               : serve_hls_segment(seg_seq, ring, scanner, now);
        }
    }

    // Path selects the slot: /v1.ts .. /v3.ts. The connection already
    // arrived on this slot's port, so the path only has to agree.
    char want[32];
    snprintf(want, sizeof(want), "/v%d.%s", slot + 1, scanner.matroska ? "mkv" : "ts");
    if (req_.path() != want && req_.path() != "/" && req_.path() != "/stream.ts") {
        fail(404, "not found", "Try /v1.ts on this port.");
        return true;
    }

    std::string pw = req_.query("pw");
    if (pw.empty()) {
        pw = http_basic_password(req_.header("Authorization"));
    }
    if (!ws_authorise(ke, slot, req_)) {
        fail(401, "unauthorized", "A viewer password is required.");
        return true;
    }
    return begin_stream(ke, slot, ring, scanner, true, now);
}

bool VideoViewer::detect_timeout(const struct KeyEntry &ke, int slot,
                                 const VideoRing &ring,
                                 const VideoScanner &scanner, time_t now)
{
    if (state_ != VV_DETECT) {
        return true;
    }
    // Silence means a raw client: ffplay tcp://host:port connects and
    // waits. There is nowhere in an opaque byte stream to carry a
    // credential, so this is only offered when the slot allows it and
    // no viewer password is set.
    kind_ = VVK_RAW;
    const uint32_t opts = video_slot_opts_of(ke, unsigned(slot));
    if ((opts & VIDEO_SLOT_RAW_TCP) == 0) {
        drop_reason_ = "raw-TCP viewers not enabled on this slot";
        return false;
    }
    bool has_pw = false;
    for (int i = 0; i < 32; i++) {
        has_pw |= ke.video_viewer_key[i] != 0;
    }
    if (has_pw) {
        drop_reason_ = "raw TCP cannot carry the viewer password";
        return false;
    }
    return begin_stream(ke, slot, ring, scanner, false, now);
}

// Forget the pending response, and give back a large buffer.
void VideoViewer::release_out(void)
{
    if (out_.capacity() > 64 * 1024) {
        std::string().swap(out_);
    } else {
        out_.clear();
    }
    out_sent_ = 0;
}

bool VideoViewer::flush(time_t now)
{
    while (out_sent_ < out_.size()) {
        const ssize_t w = ::send(fd_, out_.data() + out_sent_,
                                 out_.size() - out_sent_, MSG_NOSIGNAL);
        if (w < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                blocked_ = true;
                return true;
            }
            if (errno == EINTR) {
                continue;
            }
            drop_reason_ = "write error";
            return false;
        }
        out_sent_ += size_t(w);
        last_progress_ = now;
    }
    // clear() keeps the capacity, and a viewer that has served an HLS
    // segment would otherwise sit on a buffer that size (several MB) for
    // as long as its connection lives.
    release_out();
    blocked_ = false;
    return true;
}

bool VideoViewer::on_writable(const VideoRing &ring, time_t now)
{
    if (rtsp_view_) return rtsp_view_->on_writable(ring, now);
    if (!flush(now)) {
        return false;
    }
    if (state_ == VV_RESPONDING) {
        if (out_.empty()) {
            if (streaming_) {
                state_ = VV_STREAMING;
            } else {
                // an error response has gone out; we are done
                return false;
            }
        } else {
            // An HLS segment is a megabyte or more; a client that stops
            // reading must not hold a viewer slot for ever.
            if (now - last_progress_ > VIDEO_VIEWER_STUCK_S) {
                drop_reason_ = "stalled";
                return false;
            }
            return true;
        }
    }
    if (state_ != VV_STREAMING) {
        return true;
    }

    // Lapped: the bytes this viewer still needs have been overwritten.
    // Resyncing in place would leave a silent gap, which is worse than
    // a clean disconnect -- every client reconnects, none recovers from
    // a hole it was not told about.
    if (!ring.resident(read_pos_)) {
        drop_reason_ = "fell too far behind (lapped)";
        return false;
    }

    // Send codec setup before any ring bytes, through the same framing as
    // the viewer. A slow joiner is subject to the same bounded buffering.
    while (prefix_sent_ < prefix_.size()) {
        const size_t n = std::min(size_t(16384), prefix_.size()-prefix_sent_);
        const uint8_t *p = reinterpret_cast<const uint8_t *>(prefix_.data()+prefix_sent_);
        ssize_t w = ws_ ? ws_->send(p, n) : ::send(fd_, p, n, MSG_NOSIGNAL);
        if (w < 0 && errno == EINTR) continue;
        if ((w < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) || (w == 0 && ws_)) {
            blocked_ = true;
            return now-last_progress_ <= VIDEO_VIEWER_STUCK_S;
        }
        if (w <= 0) return false;
        prefix_sent_ += size_t(w); last_progress_ = now;
    }
    size_t budget = VIDEO_VIEWER_WRITE_CHUNK;
    while (budget > 0 && read_pos_ < ring.write_pos()) {
        uint8_t chunk[16384];
        const size_t want = budget < sizeof(chunk) ? budget : sizeof(chunk);
        const size_t got = ring.read_at(read_pos_, chunk, want);
        if (got == 0) {
            break;
        }
        const ssize_t w = ws_ != nullptr
            ? ws_->send(chunk, got)
            : ::send(fd_, chunk, got, MSG_NOSIGNAL);
        if (w == 0 && ws_ != nullptr) {
            blocked_ = true;
            break;      // queued inside the WebSocket, retry later
        }
        if (w < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                blocked_ = true;
                break;
            }
            if (errno == EINTR) {
                continue;
            }
            drop_reason_ = "write error";
            return false;
        }
        read_pos_ += uint64_t(w);
        bytes_sent_ += uint64_t(w);
        budget -= size_t(w);
        last_progress_ = now;
        if (size_t(w) < got) {
            blocked_ = true;
            break;   // socket full
        }
        blocked_ = false;
    }
    if (read_pos_ >= ring.write_pos()) {
        blocked_ = false;   // caught up: nothing is waiting on the socket
    }

    const uint64_t lag = ring.write_pos() - read_pos_;
    if (lag > ring.capacity() / 2) {
        if (behind_since_ == 0) {
            behind_since_ = now;
        } else if (now - behind_since_ > 5) {
            // Chronically behind: drop it before it is lapped, so the
            // disconnect is clean rather than mid-gap.
            drop_reason_ = "chronically behind";
            return false;
        }
    } else {
        behind_since_ = 0;
    }
    if (lag > 0 && now - last_progress_ > VIDEO_VIEWER_STUCK_S) {
        drop_reason_ = "stalled";
        return false;
    }
    return true;
}

bool VideoViewer::wants_write(void) const
{
    if (rtsp_view_) return rtsp_view_->wants_write();
    return blocked_ || out_sent_ < out_.size();
}

bool VideoViewer::still_authorised(const struct KeyEntry &ke, int slot,
                                   time_t now)
{
    if (token_.empty() || now == token_checked_) {
        return true;
    }
    token_checked_ = now;
    if (video_token_session_valid(ke, port2_, slot, token_.c_str(), now)) {
        return true;
    }
    drop_reason_ = "link expired or key changed";
    return false;
}

bool VideoViewer::authorise(const struct KeyEntry &ke, int slot,
                            const std::string &tok, std::string pw)
{
    // A token is the normal path for the browser player: it keeps the
    // viewer password out of a URL that lands in history and logs.
    //
    // The token is echoed into HLS playlists and re-checked for as long
    // as the viewer stays. strtol() is lenient about what it accepts as a
    // hex pair (whitespace, a sign), so a variant spelling of a valid
    // token must not be admitted: it would be neither safe to echo nor
    // reliably re-checked.
    if (!tok.empty()
        && tok.find_first_not_of("0123456789.abcdef") == std::string::npos
        && video_token_valid(ke, port2_, slot, tok.c_str(), time(nullptr))) {
        token_ = tok;
        authorised_ = true;
        return true;
    }
    authorised_ = video_viewer_authorised(ke, pw);
    return authorised_;
}

bool VideoViewer::ws_authorise(const struct KeyEntry &ke, int slot,
                               const HttpRequest &req)
{
    std::string pw = req.query("pw");
    if (pw.empty()) {
        pw = http_basic_password(req.header("Authorization"));
    }
    return authorise(ke, slot, req.query("t"), pw);
}

bool VideoViewer::begin_ws(const struct KeyEntry &ke, int slot,
                           const VideoRing &ring, const VideoScanner &scanner,
                           time_t now)
{
    if (ws_ == nullptr) {
        // WebSocket reads and answers the handshake off the socket
        // itself, which is why the detect phase only peeked.
        ws_ = new WebSocket(fd_);
    }
    if (!ws_ready_) {
        // Pump the handshake along. recv() returning < 0 means the
        // link failed; 0 just means "not finished yet".
        uint8_t sink[512];
        const ssize_t r = ws_->recv(sink, sizeof(sink));
        if (r < 0) {
            drop_reason_ = "websocket handshake failed";
            return false;
        }
        if (ws_->request_target().empty()) {
            return true;   // handshake still in progress
        }
        ws_ready_ = true;
        /*
          A TLS client's request is inside the encryption, so on_readable()
          could not see it: this is the first place it can be judged. (A
          plain ws:// upgrade was judged there, with its headers.) The
          upgrade has been answered already, so a refusal is a close.
         */
        if (!authorised_) {
            const std::string &target = ws_->request_target();
            std::string tok, pw;
            (void)http_query_value(target, "t", tok);
            (void)http_query_value(target, "pw", pw);
            if (!authorise(ke, slot, tok, pw)) {
                drop_reason_ = "unauthorized";
                return false;
            }
        }
        // Redacted: a viewer may authenticate with ?pw=, which is a
        // long-lived credential, and the log is both kept on disk and
        // rendered into the admin server page.
        printf("video: websocket viewer on %s%s\n",
               http_redact_target(ws_->request_target()).c_str(),
               ws_->is_SSL() ? " (TLS)" : "");
    }
    uint64_t anchor = 0;
    if (!scanner.join_offset(anchor)) {
        return true;    // wait for a decodable start point
    }
    if (!ring.resident(anchor)) {
        fail(503, "stream not ready", "Join point is no longer buffered.");
        return true;
    }
    prefix_ = scanner.prefix; prefix_sent_ = 0;
    read_pos_ = anchor;
    streaming_ = true;
    state_ = VV_STREAMING;
    last_progress_ = now;
    (void)ke;
    (void)slot;
    return true;
}
