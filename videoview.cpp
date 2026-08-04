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
    return video_password_matches(ke.video_viewer_key, password.c_str());
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
    out_sent_ = 0;
    read_pos_ = 0;
    streaming_ = false;
    bytes_sent_ = 0;
    blocked_ = false;
    ws_ = nullptr;
    ws_ready_ = false;
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

bool VideoViewer::begin_stream(const struct KeyEntry &ke, int slot,
                               const VideoRing &ring, const TSScanner &scanner,
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
        anchor = ring.oldest();
    }
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
                              const VideoRing &ring, const TSScanner &scanner,
                              time_t now)
{
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
      An RTSP request line means this is a publisher, not a viewer.
      It has to be recognised here rather than at accept(): a publisher
      connects and only then sends OPTIONS, so at accept there is
      usually nothing to look at, and classifying on an empty peek
      misfiled publishers as viewers -- which then answered their
      OPTIONS with "405 method not allowed".
     */
    static const char *rtsp_methods[] = {
        "OPTIONS ", "ANNOUNCE ", "DESCRIBE ", "SETUP ", "PLAY ",
        "RECORD ", "TEARDOWN ", "GET_PARAMETER ", "SET_PARAMETER ",
    };
    for (const char *m : rtsp_methods) {
        const size_t len = strlen(m);
        if (size_t(n) >= len && memcmp(buf, m, len) == 0) {
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
        return true;   // wait for the rest, still unconsumed
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

    // Path selects the slot: /v1.ts .. /v3.ts. The connection already
    // arrived on this slot's port, so the path only has to agree.
    char want[32];
    snprintf(want, sizeof(want), "/v%d.ts", slot + 1);
    if (req_.path() != want && req_.path() != "/" && req_.path() != "/stream.ts") {
        fail(404, "not found", "Try /v1.ts on this port.");
        return true;
    }

    std::string pw = req_.query("pw");
    if (pw.empty()) {
        pw = http_basic_password(req_.header("Authorization"));
    }
    if (!video_viewer_authorised(ke, pw)) {
        fail(401, "unauthorized", "A viewer password is required.");
        return true;
    }
    return begin_stream(ke, slot, ring, scanner, true, now);
}

bool VideoViewer::detect_timeout(const struct KeyEntry &ke, int slot,
                                 const VideoRing &ring,
                                 const TSScanner &scanner, time_t now)
{
    if (state_ != VV_DETECT) {
        return true;
    }
    // Silence means a raw client: ffplay tcp://host:port connects and
    // waits. There is nowhere in an opaque byte stream to carry a
    // credential, so this is only offered when the slot allows it and
    // no viewer password is set.
    kind_ = VVK_RAW;
    const uint32_t opts = video_slot_opts(ke.video_flags, unsigned(slot));
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
    out_.clear();
    out_sent_ = 0;
    blocked_ = false;
    return true;
}

bool VideoViewer::on_writable(const VideoRing &ring, time_t now)
{
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
    return blocked_ || out_sent_ < out_.size();
}

bool VideoViewer::ws_authorise(const struct KeyEntry &ke, int slot,
                               const HttpRequest &req)
{
    // A token is the normal path for the browser player: it keeps the
    // viewer password out of a URL that lands in history and logs.
    const std::string tok = req.query("t");
    if (!tok.empty()
        && video_token_valid(ke, port2_, slot, tok.c_str(), time(nullptr))) {
        return true;
    }
    std::string pw = req.query("pw");
    if (pw.empty()) {
        pw = http_basic_password(req.header("Authorization"));
    }
    return video_viewer_authorised(ke, pw);
}

bool VideoViewer::begin_ws(const struct KeyEntry &ke, int slot,
                           const VideoRing &ring, const TSScanner &scanner,
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
        anchor = ring.oldest();
    }
    read_pos_ = anchor;
    streaming_ = true;
    state_ = VV_STREAMING;
    last_progress_ = now;
    (void)ke;
    (void)slot;
    return true;
}
