/*
  Video viewers.

  A viewer receives the publisher's bytes verbatim. It starts at the
  join anchor the scanner computed -- the PAT before the most recent
  confirmed random access point -- so the stream is decodable from the
  first byte it sees rather than from wherever "now" happens to be.

  The publisher never waits on a viewer. Each viewer holds an absolute
  position into the ring and is dropped if it falls far enough behind
  that its data has been overwritten. That is the whole reason the ring
  uses absolute offsets: "you have been lapped" is arithmetic, not a
  guess about wrap.
 */
#pragma once

#include <stddef.h>
#include <stdint.h>
#include <time.h>

#include <string>

#include "httpreq.h"
#include "websocket.h"
#include "keydb.h"
#include "videostream.h"
#include "videomkv.h"
#include "videortspview.h"

// Per-slot viewer cap. The limit that bites first is egress bandwidth,
// not CPU: 32 viewers of an 8 Mbit/s stream is 256 Mbit/s.
#define VIDEO_MAX_VIEWERS 32

// Segments listed in an HLS playlist, at most. The ring bounds it too.
#define HLS_PLAYLIST_SEGMENTS (HLS_MAX_BOUNDARIES - 1)
// RFC 8216 6.2.2: a live playlist should span at least this many target
// durations, so the list grows to this before it stops adding segments.
#define HLS_PLAYLIST_MIN_TARGETS 3

// Names the run of the video child that cut an HLS segment. A segment
// name is cacheable for a minute and lives under a link that outlasts
// the child, so a re-forked child must never reissue one.
void video_hls_set_incarnation(uint32_t inc);

// How much to hand one viewer per loop iteration. Bounds the latency
// every other viewer and the publisher see.
#define VIDEO_VIEWER_WRITE_CHUNK 65536

// Queue past which a viewer is considered wedged rather than slow.
#define VIDEO_VIEWER_STUCK_S 10

// A connection that says nothing at all for this long is a raw viewer:
// ffplay tcp://... connects and waits. Every other client we serve
// speaks first.
#define VIDEO_DETECT_SILENCE_S 2

enum viewer_state {
    VV_DETECT = 0,      // deciding what this connection is
    VV_RESPONDING,      // sending an HTTP response header or an error
    VV_STREAMING,       // handing out ring bytes
    VV_CLOSING,         // flush what is queued, then close
};

enum viewer_kind {
    VVK_UNKNOWN = 0,
    VVK_HTTP,           // GET /vN.ts
    VVK_RAW,            // raw TCP, no framing
    VVK_WS,             // WebSocket (or WSS), binary frames
    VVK_RTSP,           // RTSP: handed to the ingest splice, not served
    VVK_MKV,            // HTTP chunked Matroska publisher
    VVK_RTMP,           // RTMP publish: same, a different backend
    VVK_RTSP_VIEW,      // RTSP playback on /view/vN
};

class VideoViewer {
public:
    void start(int fd, int port2, uint32_t peer_ip_be,
               uint16_t peer_port_be, time_t now);
    void close(void);
    ~VideoViewer(void) { close(); }

    /*
      Give up the socket without closing it. Used when the connection
      turns out to be an RTSP publisher: classification only happens
      once bytes arrive, so it necessarily starts life in a viewer slot.
     */
    int release_fd(void)
    {
        const int fd = fd_;
        fd_ = -1;
        state_ = VV_CLOSING;
        return fd;
    }
    bool active(void) const { return fd_ >= 0; }
    int fd(void) const { return fd_; }

    // Readable: consume the request. Returns false if the viewer should
    // be dropped.
    bool on_readable(const struct KeyEntry &ke, int slot,
                     const VideoRing &ring, const VideoScanner &scanner,
                     time_t now);

    // Writable (or just a poll tick): push bytes. Returns false when the
    // viewer should be dropped.
    bool on_writable(const VideoRing &ring, time_t now);

    // Called when the detect deadline passes with nothing received.
    bool detect_timeout(const struct KeyEntry &ke, int slot,
                        const VideoRing &ring, const VideoScanner &scanner,
                        time_t now);

    /*
      True only when we have bytes we could not push -- i.e. the socket
      applied backpressure. EPOLLOUT must not be armed simply because a
      viewer exists: a caught-up viewer on a quiet stream would then
      make epoll_wait return immediately for ever, which measured as a
      full CPU core burned by one idle viewer.

      New ring data needs no EPOLLOUT of its own: the ingest socket
      wakes the loop, and the pump runs on every iteration.
     */
    // Drive a WebSocket viewer's handshake and start of stream.
    bool begin_ws_pump(const struct KeyEntry &ke, int slot,
                       const VideoRing &ring, const VideoScanner &scanner,
                       time_t now)
    {
        return begin_ws(ke, slot, ring, scanner, now);
    }

    bool wants_write(void) const;

    // A viewer admitted by a token is re-checked against the entry as it
    // is now, so a share link that expires or a key that changes ends
    // the viewing it admitted. Cheap enough to call every loop pass.
    bool still_authorised(const struct KeyEntry &ke, int slot, time_t now);

    // A one-shot HLS playlist or segment fetch: a request, not a viewing
    // session, so it is neither logged nor worth a stats tick.
    bool is_hls(void) const { return hls_; }
    bool announced(void) const { return announced_; }
    void set_announced(void) { announced_ = true; }
    viewer_state state(void) const { return state_; }
    // Bytes deliberately left in the socket until more arrive (a split
    // request line). Level-triggered EPOLLIN would re-fire on them
    // continuously, so the child arms edge-triggered while this holds.
    bool holding_bytes(void) const { return holding_bytes_; }
    viewer_kind kind(void) const { return kind_; }
    uint32_t peer_ip_be(void) const { return peer_ip_be_; }
    uint16_t peer_port_be(void) const { return peer_port_be_; }
    time_t connected_at(void) const { return connected_at_; }
    uint64_t bytes_sent(void) const { return rtsp_view_ ? rtsp_view_->bytes_sent() : bytes_sent_; }
    const char *drop_reason(void) const {
        return drop_reason_[0] || !rtsp_view_ ? drop_reason_ : rtsp_view_->drop_reason();
    }

    // Only ever a string literal: the field is a borrowed pointer and
    // outlives nothing.
    void set_drop_reason(const char *why) { drop_reason_ = why; }

private:
    int fd_ = -1;
    int port2_ = 0;
    viewer_state state_ = VV_DETECT;
    viewer_kind kind_ = VVK_UNKNOWN;
    bool holding_bytes_ = false;
    uint32_t peer_ip_be_ = 0;
    uint16_t peer_port_be_ = 0;
    time_t connected_at_ = 0;
    time_t last_progress_ = 0;
    time_t behind_since_ = 0;

    HttpRequest req_;
    std::string prefix_;       // codec header, also sent inside WebSocket framing
    size_t prefix_sent_ = 0;
    std::string out_;          // pending response bytes
    size_t out_sent_ = 0;
    void release_out(void);

    uint64_t read_pos_ = 0;
    bool streaming_ = false;
    uint64_t bytes_sent_ = 0;
    bool blocked_ = false;   // last send hit EAGAIN
    /*
      Set for a WebSocket viewer. The handshake is left in the socket
      for WebSocket to consume: it reads and answers the upgrade
      itself, so the detect phase peeks rather than consuming, and
      only a plain-HTTP viewer's request is actually read off.
     */
    WebSocket *ws_ = nullptr;
    RtspViewer *rtsp_view_ = nullptr;
    bool ws_ready_ = false;
    bool hls_ = false;
    bool authorised_ = false;   // ws_authorise() passed on the plain request
    bool announced_ = false;
    std::string token_;          // the viewer token that admitted us, if any
    time_t token_checked_ = 0;
    const char *drop_reason_ = "";

    bool begin_stream(const struct KeyEntry &ke, int slot,
                      const VideoRing &ring, const VideoScanner &scanner,
                      bool http, time_t now);
    void fail(int code, const char *reason, const char *text);
    void respond_ok(const char *type, const char *cache,
                    const std::string &body, time_t now);
    bool serve_hls_playlist(int slot, const VideoRing &ring,
                            const VideoScanner &scanner, time_t now);
    bool serve_hls_segment(uint32_t seq, const VideoRing &ring,
                           const VideoScanner &scanner, time_t now);
    bool flush(time_t now);
    // A WS viewer must present a token (or the viewer password) before
    // we complete the upgrade.
    bool ws_authorise(const struct KeyEntry &ke, int slot,
                      const HttpRequest &req);
    bool authorise(const struct KeyEntry &ke, int slot,
                   const std::string &tok, std::string pw);
    bool begin_ws(const struct KeyEntry &ke, int slot, const VideoRing &ring,
                  const VideoScanner &scanner, time_t now);
};

/*
  Is this viewer credential acceptable for the entry?

  An unset viewer password means open viewing -- but note that a viewer
  still cannot reach a stream that has no publisher, and a publisher
  still had to be authorised, so "open" is narrower than it sounds.
 */
bool video_viewer_authorised(const struct KeyEntry &ke,
                             const std::string &password);
