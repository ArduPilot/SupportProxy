/*
  Per-slot stream buffering.

  The publisher's bytes go into a ring and nothing else happens to them:
  fan-out and recording both hand out the original bytes, so the write
  path must never block, allocate, or look at viewer state. That is what
  makes "one slow viewer cannot stall the publisher or the others" true
  by construction rather than by care.

  Positions are absolute stream offsets, not indices, so a viewer that
  falls behind is detected by arithmetic (write_pos - read_pos > size)
  rather than by trying to reason about wrap.
 */
#pragma once

#include <stddef.h>
#include <stdint.h>
#include <vector>

// Default ring size. The rule that matters is
//   ring >= 2 * GOP_seconds * bitrate
// or a late viewer has no random access point to start from. Measured
// on the Phoenix camera: ~4 s GOP at ~2.45 Mbit/s, so 8 MiB holds about
// 26 s -- roughly six GOPs. A higher-bitrate publisher with a long GOP
// needs the rule applied, not this constant.
#define VIDEO_RING_DEFAULT (8u * 1024 * 1024)

// Ring size actually used, honouring SUPPORTPROXY_VIDEO_RING_BYTES.
// Overridable because lapping a viewer is otherwise only reachable by
// pushing megabytes through a test.
size_t video_ring_bytes(void);

class VideoRing {
public:
    bool init(size_t bytes);

    // Append. Never blocks and never fails; the oldest bytes are simply
    // overwritten. A write larger than the ring keeps only its tail.
    void write(const uint8_t *buf, size_t n);

    uint64_t write_pos(void) const { return write_pos_; }
    size_t capacity(void) const { return buf_.size(); }

    // Earliest offset still held.
    uint64_t oldest(void) const;

    // True if `pos` is still resident (and not in the future).
    bool resident(uint64_t pos) const;

    // Copy up to `n` bytes from `pos`. Returns how many were copied,
    // which is 0 if `pos` has already been overwritten.
    size_t read_at(uint64_t pos, uint8_t *out, size_t n) const;

    // Drop everything held and restart the offset space at 0.
    //
    // Only safe with no viewers attached: they hold absolute offsets,
    // and rewinding write_pos_ under one would make its position look
    // like the far future. The caller drops viewers first.
    void reset(void) { write_pos_ = 0; }

private:
    std::vector<uint8_t> buf_;
    uint64_t write_pos_ = 0;
};

int videostream_selftest(void);
