/*
  MPEG-TS scanner.

  Watches a transport stream going past and works out where a late
  viewer may safely start. It never modifies the stream: fan-out and
  recording hand out the publisher's bytes verbatim, so everything here
  is observation only.

  A viewer cannot just start at "now". It needs, in order:

    PAT   to learn which PID carries the program map
    PMT   to learn which PID carries video, and its codec
    a random access point, so the decoder has a frame to start from

  Measured against both real publishers (a Phoenix camera via RTSP and
  a gstreamer mpegtsmux/udpsink pipeline): PAT repeats about every
  0.1 s, and the adaptation field's random_access_indicator is set on
  exactly the keyframes. Parameter sets (SPS/PPS) repeat at every IDR
  in both, so a viewer starting at PAT->PMT->RAI has everything it
  needs. That is not guaranteed by the spec, so the RAI is confirmed by
  looking for an access-unit delimiter or parameter set in the payload
  rather than trusted on its own.
 */
#pragma once

#include <stddef.h>
#include <stdint.h>

#define TS_PACKET_SIZE 188
#define TS_SYNC_BYTE 0x47

// PSI section sizes: section_length is 12 bits, and the 3 bytes before
// it are not counted, so a section is at most 1024+3 bytes.
#define TS_MAX_SECTION 1027

// MPEG-2 stream_type values we care about telling apart.
#define TS_STREAM_MPEG2_VIDEO 0x02
#define TS_STREAM_PRIVATE     0x06
#define TS_STREAM_AAC_ADTS    0x0F
#define TS_STREAM_AAC_LATM    0x11
#define TS_STREAM_H264        0x1B
#define TS_STREAM_HEVC        0x24

struct TSStats {
    uint64_t bytes = 0;
    uint64_t packets = 0;
    uint64_t bad_sync = 0;      // packets that did not start with 0x47
    uint64_t resyncs = 0;       // times we had to hunt for the sync byte
    uint64_t cc_errors = 0;     // continuity counter discontinuities
    uint64_t pat_seen = 0;
    uint64_t pmt_seen = 0;
    uint64_t rai_seen = 0;      // random access points on the video PID
    uint64_t crc_errors = 0;    // PSI sections that failed CRC
};

/*
  Reassembles one PSI section spread across TS packets. A PAT or a small
  PMT usually fits in a single packet, but nothing guarantees it, and a
  scanner that assumed so would silently misparse a larger PMT.
 */
class PSIAssembler {
public:
    void reset(void) { len_ = 0; want_ = 0; active_ = false; }
    // Feed one packet's PSI payload. Returns a complete, CRC-checked
    // section (and its length) or nullptr.
    const uint8_t *feed(const uint8_t *payload, size_t n, bool pusi,
                        size_t &out_len, uint64_t &crc_errors);

private:
    uint8_t buf_[TS_MAX_SECTION] {};
    size_t len_ = 0;
    size_t want_ = 0;
    bool active_ = false;
};

class TSScanner {
public:
    // Feed a contiguous run of stream bytes. `base` is the absolute
    // stream offset of buf[0] -- the same coordinate the ring uses, so
    // a join offset can be handed straight to a viewer.
    void feed(const uint8_t *buf, size_t n, uint64_t base);

    // True once a PAT and a matching PMT have been parsed.
    bool have_program(void) const { return have_pmt_; }

    // Absolute offset a late viewer should start at. False when no
    // usable anchor has been seen (yet, or ever).
    bool join_offset(uint64_t &out) const;

    uint16_t video_pid(void) const { return video_pid_; }
    uint8_t video_stream_type(void) const { return video_stream_type_; }
    uint16_t pmt_pid(void) const { return pmt_pid_; }
    const TSStats &stats(void) const { return stats_; }

    // True if this stream_type is one a browser MSE player can use.
    static bool stream_type_playable(uint8_t st);

    // Forget everything about the current stream.
    //
    // A new publisher is a new stream: its PSI, continuity counters and
    // timestamps all restart. Carrying the old state over would hand a
    // joiner an anchor pointing into the previous stream's bytes, and
    // would count every counter restart as a continuity error.
    void reset(void);

private:
    TSStats stats_;
    PSIAssembler pat_asm_;
    PSIAssembler pmt_asm_;

    uint16_t pmt_pid_ = 0;
    bool have_pat_ = false;
    bool have_pmt_ = false;
    uint8_t pat_version_ = 0xFF;
    uint8_t pmt_version_ = 0xFF;

    uint16_t video_pid_ = 0;
    uint8_t video_stream_type_ = 0;

    // Offsets of the most recent PAT and PMT packets, and the anchor
    // computed when a random access point follows both.
    uint64_t last_pat_off_ = 0;
    uint64_t last_pmt_off_ = 0;
    bool have_pat_off_ = false;
    bool have_pmt_off_ = false;
    uint64_t anchor_ = 0;
    bool have_anchor_ = false;

    // continuity counters, indexed by PID
    uint8_t cc_[8192] {};
    bool cc_seen_[8192] {};

    // partial packet carried across feed() calls
    uint8_t partial_[TS_PACKET_SIZE] {};
    size_t partial_len_ = 0;
    uint64_t partial_off_ = 0;
    bool synced_ = false;

    void packet(const uint8_t *p, uint64_t off);
    void parse_pat(const uint8_t *sec, size_t n, uint64_t off);
    void parse_pmt(const uint8_t *sec, size_t n, uint64_t off);
};

// MPEG-2 section CRC32 (poly 0x04C11DB7, MSB-first, init 0xFFFFFFFF).
uint32_t ts_crc32(const uint8_t *data, size_t n);

// True if a video-PID payload starting at `p` looks like a real random
// access point: an access-unit delimiter, a parameter set, or an IRAP
// slice. Used to confirm the adaptation field's RAI bit.
bool ts_payload_is_random_access(const uint8_t *p, size_t n,
                                 uint8_t stream_type);

// Run the in-process scanner self-checks. Returns 0 on success.
int videots_selftest(void);

/*
  Mutation fuzz over the scanner. Builds a valid stream, corrupts it in
  a seeded, reproducible way, feeds it in randomly-sized chunks and
  checks the scanner neither crashes nor reports an anchor it cannot
  back up. PSI parsing with lengths and CRCs taken from the wire is
  exactly the code where a hand-written happy-path test proves least.

  Returns 0 if every iteration held.
 */
int videots_fuzz(unsigned iterations, uint32_t seed);
