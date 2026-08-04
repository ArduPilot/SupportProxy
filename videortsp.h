/*
  RTSP and RTMP ingest, by splicing to a loopback ffmpeg.

  SupportProxy parses no RTSP at all. It keeps the public port, does the
  admission check on the source address, then hands the connection --
  untouched, from its very first byte -- to an ffmpeg bound on
  127.0.0.1, and reads MPEG-TS back from its stdout.

  The spike established why it has to work this way. RTSP is
  request/response, so waiting to see ANNOUNCE before classifying
  deadlocks: the publisher sends OPTIONS and waits for a reply that
  never comes. Answering OPTIONS ourselves fails differently -- ffmpeg's
  listener requires the first request it sees to be CSeq 1, so it
  rejects an ANNOUNCE numbered 2. Splicing from byte zero sidesteps
  both: ffmpeg sees the whole exchange, starting at CSeq 1.

  Consequence, and the reason RTSP *egress* is a separate phase: with no
  RTSP parsing we cannot tell a publisher from a viewer, so an RTSP
  connection to a video port is treated as a publisher.

  A native RTP depacketiser plus TS muxer was measured at ~2300-3000
  lines against ~150 for this, would still not carry the PCM audio the
  Phoenix camera sends, and an H.264-only cut would not even cover the
  workload (one of the two real streams is HEVC).

  RTMP does not splice. ffmpeg's RTMP listener answers a real camera
  badly enough that it never sends a frame (see videortmp.h), so
  SupportProxy speaks RTMP itself and hands the backend FLV on stdin.
  The backend is still an ffmpeg child with the same sandbox; only the
  input side differs, and RTMP needs no loopback port at all.
 */
#pragma once

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#include <time.h>

#include <string>

// Give up if the backend has not become connectable in this long.
#define RTSP_BACKEND_READY_MS 3000

// Resource limits applied to the backend: it parses untrusted SDP, RTP
// and codec bitstreams, and fixed argv only stops shell injection, not
// a bug in those parsers. Note RLIMIT_NPROC is *not* among them -- it
// is per-UID rather than per-process, so it breaks the child without
// bounding anything useful.
#define RTSP_BACKEND_MEM_BYTES (512u * 1024 * 1024)
#define RTSP_BACKEND_CPU_SECONDS 3600

enum splice_proto_t {
    SPLICE_RTSP = 0,
    SPLICE_RTMP,
};

const char *splice_proto_name(splice_proto_t p);

class RtspBackend {
public:
    ~RtspBackend(void);

    /*
      Launch ffmpeg. For RTSP it also connects to the backend's loopback
      listener; for RTMP the backend reads FLV from a pipe we own, so
      there is nothing to connect to. Returns false if it could not be
      started.
     */
    /*
      `vbsf`, when set, is a video bitstream filter applied on the way
      through -- h264_metadata for RTMP H.264, which rewrites the NAL
      units and drops the zero-length one ffmpeg's own AVCC to Annex-B
      conversion emits for some cameras. It is codec-specific, so the
      caller must know the codec before passing it.
     */
    bool start(int port2, int slot, bool want_audio,
               splice_proto_t proto = SPLICE_RTSP,
               const char *vbsf = nullptr);

    splice_proto_t proto(void) const { return proto_; }

    bool running(void) const { return pid_ > 0; }

    /*
      Where the publisher's bytes go: a socket spliced with the client
      for RTSP, the write end of the backend's stdin for RTMP. Only the
      RTSP one is readable.
     */
    int backend_fd(void) const { return backend_fd_; }
    bool backend_readable(void) const { return proto_ == SPLICE_RTSP; }
    int media_fd(void) const { return media_fd_; }
    pid_t pid(void) const { return pid_; }

    // Reap if the child has exited. Returns true if it is now gone.
    bool reap(void);

    void stop(void);

private:
    pid_t pid_ = -1;
    int backend_fd_ = -1;   // RTSP control/data, spliced with the client
    int media_fd_ = -1;     // ffmpeg stdout: MPEG-TS
    int port2_ = 0;
    int slot_ = 0;
    splice_proto_t proto_ = SPLICE_RTSP;

    static int pick_loopback_port(void);
};
