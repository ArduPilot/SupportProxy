/*
  Video segment recording.

  Segments are written raw: the publisher's own bytes, byte for byte,
  into logs/<port2>/<date>/<session>.v<slot>.ts. That makes a recording
  a file VLC and ffplay open by double-click, append-only, and
  truncation-tolerant -- a killed process leaves a playable file with
  no finalisation step, which fragmented MP4 does not.

  Each segment is its own timestamped file rather than a part of a
  numbered set, so retention, natural sorting and the download route in
  the web UI all work on it unmodified.

  Why segments at all: the quota pass cannot delete the file currently
  being written (mtime within ACTIVE_FILE_GRACE_S), so one long file
  per session would make the whole session un-evictable and the quota
  pass would find nothing to free. Ten-minute segments bound the
  un-evictable working set at (segment + grace) * bitrate.
 */
#pragma once

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#include <time.h>

#include <string>

// Cut a segment after this long, or this many bytes, whichever first.
#define VIDEO_SEGMENT_SECONDS_DEFAULT 600
#define VIDEO_SEGMENT_BYTES_DEFAULT (512u * 1024 * 1024)

// Once a rotation is due, wait this long for a clean cut point before
// cutting anyway. A stream whose muxer never signals a random access
// point must still rotate, or the segment grows without bound.
#define VIDEO_ROTATE_OVERSHOOT_S 30

class VideoWriter {
public:
    ~VideoWriter(void);

    void configure(uint32_t port2, int slot, bool use_tz, float tz_offset,
                   const char *base_dir, uint32_t quota_mb);

    bool is_open(void) const { return fd_ >= 0; }

    // Append. Returns false if recording has stopped (disk full); the
    // caller keeps streaming regardless -- losing the recording must
    // never take the live stream with it.
    bool write(const uint8_t *buf, size_t n, time_t now);

    // True when this segment has run long enough or grown big enough.
    // Not const: it records *when* rotation first became due, which is
    // what the overshoot fallback below measures against.
    bool rotation_due(time_t now);

    // True once we have waited long enough that the next write should
    // cut whether or not it is a clean boundary.
    bool rotation_overdue(time_t now) const;

    // Close the current segment and start a new one on the next write.
    // `clean` records whether the cut landed on a join boundary.
    void rotate(time_t now, bool clean);

    void close_segment(void);

    const std::string &path(void) const { return path_; }
    uint64_t segment_bytes(void) const { return seg_bytes_; }
    uint64_t total_bytes(void) const { return total_bytes_; }
    uint32_t segments(void) const { return segments_; }
    bool stopped(void) const { return stopped_; }

private:
    uint32_t port2_ = 0;
    int slot_ = 0;
    bool use_tz_ = false;
    float tz_offset_ = 0;
    std::string base_dir_ = "logs";
    uint32_t quota_mb_ = 0;

    int fd_ = -1;
    std::string path_;
    std::string date_dir_;
    time_t seg_start_ = 0;
    time_t rotate_wanted_ = 0;   // when rotation first became due
    uint64_t seg_bytes_ = 0;
    uint64_t total_bytes_ = 0;
    uint32_t segments_ = 0;
    uint64_t fadvise_mark_ = 0;
    bool stopped_ = false;       // disk full; no further segments

    bool open_segment(time_t now);
};

// Segment limits, overridable for tests.
uint32_t video_segment_seconds(void);
uint64_t video_segment_bytes(void);
