/*
  Native RTMP publish ingest.

  ffmpeg cannot be the RTMP server for real cameras. Its listener exists
  to talk to its own client, so it answers FCPublish with a bare
  "onFCPublish" -- the command name and nothing else, no transaction id,
  no null, no status object -- and answers publish with nothing at all.
  Measured against the Phoenix camera: the negotiation completes, ffmpeg
  grants stream id 1, and the camera then waits 5 s for a response it can
  parse and hangs up without sending a frame. A byte-identical exchange
  reproduced against a local ffmpeg, and the same camera published 74 MB
  to a server that answers properly, so the fault is not in the relay.

  Linking libavformat instead of forking ffmpeg would not help: that is
  the same rtmpproto.c on the wire.

  So we speak RTMP ourselves -- handshake, chunk demux, and the six
  commands a publisher uses -- and convert the media messages to FLV,
  which ffmpeg is happy to demux from a pipe. That drops the loopback
  port the splice needed, and with it the connect race and the TOCTOU
  window on a multi-user host.

  Only the publish direction is implemented. This is not an RTMP server:
  it never plays, seeks or pauses, and a client that asks to is dropped.

  An unauthorised peer drives this parser -- admission needs the password
  out of connect/publish, which arrive after the handshake -- so the
  pre-publish phase is bounded in both bytes and seconds, every length
  from the wire is checked against what is actually buffered, and message
  assembly is capped.
 */
#pragma once

#include <stddef.h>
#include <stdint.h>
#include <time.h>

#include <string>
#include <vector>

// What we announce, and the largest outbound chunk we write. Every
// message we send is smaller, so outbound messages are single-chunk.
#define RTMP_OUT_CHUNK_SIZE 4096

// The protocol default until a peer says otherwise.
#define RTMP_DEFAULT_CHUNK_SIZE 128

// A publisher that has not reached publish inside these bounds is
// dropped: until then it is unauthenticated.
#define RTMP_PREPUBLISH_MAX_BYTES (256u * 1024)
#define RTMP_PREPUBLISH_MAX_S 20

// Largest single RTMP message we will assemble.
#define RTMP_MAX_MESSAGE_BYTES (4u * 1024 * 1024)

/*
  Refuse a peer-announced chunk size above this. The spec allows up to
  2^31-1, but a chunk has to be buffered whole before it can be parsed,
  so honouring that would let three bytes from an unauthenticated peer
  set the size of our input buffer. Real senders use 4 KiB (ffmpeg,
  OBS) to 64 KiB.
 */
#define RTMP_MAX_CHUNK_SIZE (1u * 1024 * 1024)

/*
  Highest chunk stream id we keep state for. The 2-byte form can express
  65599, and each one costs a ChunkStream, so the cap is what stops a
  3-byte header allocating megabytes. Publishers use single digits.
 */
#define RTMP_MAX_CHUNK_STREAM 255

/*
  Total bytes held in partial messages across every chunk stream.

  RTMP_MAX_MESSAGE_BYTES is per chunk stream, so without this a peer can
  open one partial message on each of them and hold the product -- and
  none of it completes, so the backend queue stays empty and nothing
  downstream notices. Before publish the cumulative input limit covers
  it; after publish only this does.
 */
#define RTMP_MAX_ASSEMBLY_BYTES (8u * 1024 * 1024)

/*
  Cap on responses owed to the peer. A client that stops reading while
  still sending commands would otherwise turn its own bounded input into
  unbounded memory here.
 */
#define RTMP_MAX_OUT_BYTES (256u * 1024)

/*
  A publisher that has been accepted but has not said what codec it is
  sending by now is not going to. Until it does there is no backend and
  no media, but it holds the slot -- and control messages alone keep
  refreshing the idle timer.
 */
#define RTMP_CODEC_DEADLINE_S 15

/*
  Which video codec the publisher is sending, once a video tag has said
  so. The backend needs this before it starts: ffmpeg's own AVCC to
  Annex-B conversion emits a zero-length NAL unit ahead of each access
  unit for this camera's stream shape (one NAL per frame, parameter sets
  only in the sequence header). Chrome's MP4 parser rejects that --
  "Failed to prepare video sample for decode" -- while Firefox tolerates
  it. -bsf:v h264_metadata rewrites the units and removes them, but it
  is H.264-only, so it must not be applied blind.
 */
enum rtmp_vcodec_t {
    RTMP_VCODEC_NONE = 0,   // no video tag seen yet
    RTMP_VCODEC_H264,
    RTMP_VCODEC_OTHER,      // HEVC and friends, via enhanced RTMP
};

enum rtmp_state {
    RTMP_WANT_C0C1 = 0,
    RTMP_WANT_C2,
    RTMP_CHUNKS,
    RTMP_DEAD,
};

/*
  One publisher's connection state.

  feed() takes bytes off the socket and appends to two output buffers the
  caller drains: to_peer() for RTMP responses, to_flv() for media. The
  session never writes to a descriptor itself, so the caller keeps all
  the backpressure and epoll logic it already has for the RTSP splice.
 */
class RtmpSession {
public:
    // Consume client bytes. False means the session is over.
    bool feed(const uint8_t *buf, size_t n, time_t now);

    /*
      Continue on already-buffered bytes. feed() stops as soon as publish
      arrives so the caller can authorise in order; call this once it
      has, or anything the publisher pipelined behind publish sits
      unparsed until the next read.
     */
    bool resume(void);

    // True once the client has issued publish and been accepted.
    bool publishing(void) const { return publishing_; }

    /*
      Set once publish arrives, before publishing() goes true: the caller
      authorises the stream and then calls accept_publish() or reject().
     */
    bool publish_pending(void) const { return publish_pending_; }
    const std::string &app(void) const { return app_; }
    const std::string &stream(void) const { return stream_; }
    const std::string &password(void) const { return password_; }

    // "app/stream", for matching against a configured path.
    std::string path(void) const;

    void accept_publish(void);
    void reject_publish(const char *code, const char *description);

    std::vector<uint8_t> &to_peer(void) { return to_peer_; }
    std::vector<uint8_t> &to_flv(void) { return to_flv_; }

    uint64_t media_bytes(void) const { return media_bytes_; }
    const char *error(void) const { return error_; }

    // Set once the first video tag names a codec.
    rtmp_vcodec_t video_codec(void) const { return vcodec_; }

    // When publish was accepted, for the codec deadline. 0 until then.
    time_t publishing_since(void) const { return publishing_since_; }

private:
    struct ChunkStream {
        uint32_t ts = 0;            // absolute, after applying deltas
        uint32_t delta = 0;         // last delta, reused by fmt 3
        uint32_t len = 0;
        uint8_t type = 0;
        uint32_t sid = 0;
        bool ext_ts = false;        // header carried an extended timestamp
        std::vector<uint8_t> acc;   // partial message
    };

    rtmp_state state_ = RTMP_WANT_C0C1;
    std::vector<uint8_t> in_;
    size_t in_pos_ = 0;
    std::vector<uint8_t> to_peer_;
    std::vector<uint8_t> to_flv_;

    uint32_t in_chunk_ = RTMP_DEFAULT_CHUNK_SIZE;
    /*
      Acknowledgement window the peer asked for, and how much we have
      taken since the last acknowledgement we sent. A publisher that
      sets a window and never sees a type-3 back is entitled to stop
      sending, which shows up as a camera that streams for a while and
      then stalls.
     */
    uint32_t ack_window_ = 0;
    uint64_t bytes_in_ = 0;
    uint64_t acked_ = 0;
    std::vector<ChunkStream> cs_;   // indexed by chunk stream id

    std::string app_;
    std::string stream_;
    std::string password_;
    double publish_txn_ = 0;
    uint32_t publish_sid_ = 1;
    bool publishing_ = false;
    bool publish_pending_ = false;
    bool connected_ = false;        // connect already answered
    time_t publishing_since_ = 0;
    size_t assembly_bytes_ = 0;     // sum of every chunk stream's acc
    rtmp_vcodec_t vcodec_ = RTMP_VCODEC_NONE;
    bool flv_header_written_ = false;
    bool saw_c0c1_ = false;
    time_t started_ = 0;
    time_t now_ = 0;            // last time seen by feed()
    uint64_t total_in_ = 0;
    uint64_t media_bytes_ = 0;
    const char *error_ = "";

    bool run_parser(void);
    bool fail(const char *why);
    void compact(void);
    size_t avail(void) const { return in_.size() - in_pos_; }
    const uint8_t *cur(void) const { return in_.data() + in_pos_; }

    bool do_handshake(void);
    bool parse_chunks(void);
    bool on_message(ChunkStream &c, const uint8_t *p, size_t n);
    bool on_command(ChunkStream &c, const uint8_t *p, size_t n);
    void on_media(uint8_t type, uint32_t ts, const uint8_t *p, size_t n);

    void send_msg(uint8_t csid, uint8_t type, uint32_t sid,
                  const uint8_t *p, size_t n, uint32_t ts = 0);
    void send_amf(uint8_t csid, uint32_t sid, const std::vector<uint8_t> &b);
    void write_flv_header(void);
    void write_flv_tag(uint8_t type, uint32_t ts,
                       const uint8_t *p, size_t n);
};
