/*
  MPEG-TS scanner. See videots.h for what it is for.

  Every multi-byte field is assembled a byte at a time. Casting a packet
  buffer to a wider integer is undefined for an unaligned address and
  trips -Wcast-align, and packet buffers are never aligned in general.
 */
#include "videots.h"

#include <string.h>
#include <vector>

// ---------------------------------------------------------------- CRC

static uint32_t crc_table[256];
static bool crc_table_built = false;

static void build_crc_table(void)
{
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t c = i << 24;
        for (int k = 0; k < 8; k++) {
            c = (c & 0x80000000u) ? ((c << 1) ^ 0x04C11DB7u) : (c << 1);
        }
        crc_table[i] = c;
    }
    crc_table_built = true;
}

uint32_t ts_crc32(const uint8_t *data, size_t n)
{
    if (!crc_table_built) {
        build_crc_table();
    }
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < n; i++) {
        crc = (crc << 8) ^ crc_table[((crc >> 24) ^ data[i]) & 0xFF];
    }
    return crc;
}

// ------------------------------------------------------- PSIAssembler

const uint8_t *PSIAssembler::feed(const uint8_t *payload, size_t n, bool pusi,
                                  size_t &out_len, uint64_t &crc_errors)
{
    if (n == 0) {
        return nullptr;
    }
    if (pusi) {
        // A unit start carries a pointer_field: the number of bytes of
        // the *previous* section still to come before this one starts.
        const uint8_t ptr = payload[0];
        if (size_t(ptr) + 1 > n) {
            reset();
            return nullptr;
        }
        payload += 1 + ptr;
        n -= 1 + ptr;
        len_ = 0;
        active_ = true;
        want_ = 0;
    } else if (!active_) {
        // Continuation with no section open: nothing to append to.
        return nullptr;
    }

    if (n == 0) {
        return nullptr;
    }
    const size_t space = sizeof(buf_) - len_;
    const size_t take = n < space ? n : space;
    memcpy(buf_ + len_, payload, take);
    len_ += take;

    if (want_ == 0) {
        if (len_ < 3) {
            return nullptr;
        }
        // section_length is 12 bits and excludes the 3 bytes before it
        want_ = (size_t(buf_[1] & 0x0F) << 8 | buf_[2]) + 3;
        if (want_ > sizeof(buf_) || want_ < 4) {
            reset();
            return nullptr;
        }
    }
    if (len_ < want_) {
        return nullptr;
    }

    const size_t seclen = want_;
    active_ = false;
    len_ = 0;
    want_ = 0;

    // The trailing 4 bytes are the CRC, and it covers everything before
    // them. A section that fails is dropped: acting on a corrupt PMT
    // would point the scanner at the wrong PID.
    if (ts_crc32(buf_, seclen) != 0) {
        crc_errors++;
        return nullptr;
    }
    out_len = seclen;
    return buf_;
}

// ------------------------------------------------------ random access

bool ts_payload_is_random_access(const uint8_t *p, size_t n,
                                 uint8_t stream_type)
{
    if (stream_type != TS_STREAM_H264 && stream_type != TS_STREAM_HEVC) {
        // Only H.264/HEVC are inspected; for anything else fall back to
        // trusting the RAI bit.
        return true;
    }
    // Walk Annex-B start codes. The payload here begins with a PES
    // header, so scan rather than assuming an offset.
    for (size_t i = 0; i + 4 < n; i++) {
        if (p[i] != 0 || p[i + 1] != 0 || p[i + 2] != 1) {
            continue;
        }
        const uint8_t b = p[i + 3];
        if (stream_type == TS_STREAM_H264) {
            const uint8_t nal = b & 0x1F;
            // 9 = access unit delimiter, 7 = SPS, 8 = PPS, 5 = IDR
            if (nal == 9 || nal == 7 || nal == 8 || nal == 5) {
                return true;
            }
        } else {
            const uint8_t nal = (b >> 1) & 0x3F;
            // 35 = AUD, 32/33/34 = VPS/SPS/PPS, 16..21 = IRAP slices
            if (nal == 35 || (nal >= 32 && nal <= 34)
                || (nal >= 16 && nal <= 21)) {
                return true;
            }
        }
    }
    return false;
}

void TSScanner::reset(void)
{
    stats_ = TSStats();
    pat_asm_.reset();
    pmt_asm_.reset();
    pmt_pid_ = 0;
    have_pat_ = false;
    have_pmt_ = false;
    pat_version_ = 0xFF;
    pmt_version_ = 0xFF;
    video_pid_ = 0;
    video_stream_type_ = 0;
    last_pat_off_ = 0;
    last_pmt_off_ = 0;
    have_pat_off_ = false;
    have_pmt_off_ = false;
    anchor_ = 0;
    have_anchor_ = false;
    memset(cc_, 0, sizeof(cc_));
    memset(cc_seen_, 0, sizeof(cc_seen_));
    partial_len_ = 0;
    partial_off_ = 0;
    synced_ = false;
}

bool TSScanner::stream_type_playable(uint8_t st)
{
    // What a browser MSE player can make use of. HEVC is deliberately
    // excluded: mpegts.js can demux it but MSE support is absent on
    // most desktops.
    return st == TS_STREAM_H264 || st == TS_STREAM_AAC_ADTS
        || st == TS_STREAM_AAC_LATM;
}

// ----------------------------------------------------------- scanning

void TSScanner::parse_pat(const uint8_t *sec, size_t n, uint64_t off)
{
    if (n < 12 || sec[0] != 0x00) {
        return;
    }
    const uint8_t version = (sec[5] >> 1) & 0x1F;
    const bool current = (sec[5] & 1) != 0;
    if (!current) {
        return;
    }
    stats_.pat_seen++;
    last_pat_off_ = off;
    have_pat_off_ = true;

    if (have_pat_ && version == pat_version_) {
        return;   // unchanged; nothing to re-parse
    }
    pat_version_ = version;

    // program entries run from byte 8 to the CRC
    const size_t end = n - 4;
    for (size_t i = 8; i + 4 <= end; i += 4) {
        const uint16_t prog = uint16_t(sec[i]) << 8 | sec[i + 1];
        const uint16_t pid = (uint16_t(sec[i + 2] & 0x1F) << 8) | sec[i + 3];
        if (prog != 0) {
            if (pmt_pid_ != pid) {
                // program moved: the old PMT no longer describes us
                have_pmt_ = false;
                pmt_version_ = 0xFF;
                pmt_asm_.reset();
            }
            pmt_pid_ = pid;
            have_pat_ = true;
            return;   // single-program streams only, which is what we get
        }
    }
}

void TSScanner::parse_pmt(const uint8_t *sec, size_t n, uint64_t off)
{
    if (n < 16 || sec[0] != 0x02) {
        return;
    }
    const uint8_t version = (sec[5] >> 1) & 0x1F;
    const bool current = (sec[5] & 1) != 0;
    if (!current) {
        return;
    }
    stats_.pmt_seen++;
    last_pmt_off_ = off;
    have_pmt_off_ = true;

    if (have_pmt_ && version == pmt_version_) {
        return;
    }
    pmt_version_ = version;

    const size_t prog_info_len = (size_t(sec[10] & 0x0F) << 8) | sec[11];
    size_t i = 12 + prog_info_len;
    const size_t end = n - 4;
    uint16_t vpid = 0;
    uint8_t vst = 0;
    while (i + 5 <= end) {
        const uint8_t st = sec[i];
        const uint16_t pid = (uint16_t(sec[i + 1] & 0x1F) << 8) | sec[i + 2];
        const size_t es_len = (size_t(sec[i + 3] & 0x0F) << 8) | sec[i + 4];
        if (vpid == 0 && (st == TS_STREAM_H264 || st == TS_STREAM_HEVC
                          || st == TS_STREAM_MPEG2_VIDEO)) {
            vpid = pid;
            vst = st;
        }
        i += 5 + es_len;
    }
    if (vpid != 0) {
        video_pid_ = vpid;
        video_stream_type_ = vst;
        have_pmt_ = true;
    }
}

void TSScanner::packet(const uint8_t *p, uint64_t off)
{
    stats_.packets++;
    if (p[0] != TS_SYNC_BYTE) {
        stats_.bad_sync++;
        synced_ = false;
        return;
    }
    const bool pusi = (p[1] & 0x40) != 0;
    const uint16_t pid = (uint16_t(p[1] & 0x1F) << 8) | p[2];
    const uint8_t afc = (p[3] >> 4) & 0x03;
    const uint8_t cc = p[3] & 0x0F;

    if (afc == 0 || afc == 2) {
        // no payload; CC does not advance
    } else {
        if (cc_seen_[pid] && cc != uint8_t((cc_[pid] + 1) & 0x0F)) {
            stats_.cc_errors++;
        }
        cc_[pid] = cc;
        cc_seen_[pid] = true;
    }

    size_t off_in = 4;
    bool rai = false;
    if (afc == 2 || afc == 3) {
        const uint8_t af_len = p[4];
        if (af_len > 0 && 5 + size_t(af_len) <= TS_PACKET_SIZE) {
            rai = (p[5] & 0x40) != 0;
        }
        off_in = 5 + size_t(af_len);
        if (off_in > TS_PACKET_SIZE) {
            return;
        }
    }
    if (afc == 0 || afc == 2 || off_in >= TS_PACKET_SIZE) {
        return;   // no payload
    }
    const uint8_t *payload = p + off_in;
    const size_t plen = TS_PACKET_SIZE - off_in;

    if (pid == 0) {
        size_t seclen = 0;
        const uint8_t *sec = pat_asm_.feed(payload, plen, pusi, seclen,
                                           stats_.crc_errors);
        if (sec != nullptr) {
            parse_pat(sec, seclen, off);
        }
        return;
    }
    if (have_pat_ && pid == pmt_pid_) {
        size_t seclen = 0;
        const uint8_t *sec = pmt_asm_.feed(payload, plen, pusi, seclen,
                                           stats_.crc_errors);
        if (sec != nullptr) {
            parse_pmt(sec, seclen, off);
        }
        return;
    }
    if (have_pmt_ && pid == video_pid_ && rai) {
        // Confirm the RAI bit against the payload. A muxer may set it
        // inaccurately, and serving a viewer from a point the decoder
        // cannot start at looks exactly like a broken stream.
        if (!pusi || ts_payload_is_random_access(payload, plen,
                                                 video_stream_type_)) {
            stats_.rai_seen++;
            if (have_pat_off_ && have_pmt_off_
                && last_pat_off_ <= off && last_pmt_off_ <= off) {
                // Start at whichever of the two came first, so the
                // viewer sees PAT and PMT before the access point.
                anchor_ = last_pat_off_ < last_pmt_off_ ? last_pat_off_
                                                        : last_pmt_off_;
                have_anchor_ = true;
            }
        }
    }
}

void TSScanner::feed(const uint8_t *buf, size_t n, uint64_t base)
{
    stats_.bytes += n;
    size_t i = 0;

    // finish a packet split across feed() calls
    if (partial_len_ > 0) {
        const size_t need = TS_PACKET_SIZE - partial_len_;
        const size_t take = n < need ? n : need;
        memcpy(partial_ + partial_len_, buf, take);
        partial_len_ += take;
        i += take;
        if (partial_len_ < TS_PACKET_SIZE) {
            return;
        }
        packet(partial_, partial_off_);
        partial_len_ = 0;
    }

    while (i < n) {
        if (!synced_) {
            // Hunt for a sync byte that is followed by another one a
            // packet later, so a 0x47 inside a payload doesn't fool us.
            size_t j = i;
            bool found = false;
            while (j < n) {
                if (buf[j] == TS_SYNC_BYTE) {
                    const size_t next = j + TS_PACKET_SIZE;
                    if (next >= n || buf[next] == TS_SYNC_BYTE) {
                        found = true;
                        break;
                    }
                }
                j++;
            }
            if (!found) {
                return;   // no plausible start in this chunk
            }
            if (j != i) {
                stats_.resyncs++;
            }
            i = j;
            synced_ = true;
        }
        const size_t avail = n - i;
        if (avail < TS_PACKET_SIZE) {
            memcpy(partial_, buf + i, avail);
            partial_len_ = avail;
            partial_off_ = base + i;
            return;
        }
        packet(buf + i, base + i);
        i += TS_PACKET_SIZE;
    }
}

bool TSScanner::join_offset(uint64_t &out) const
{
    if (!have_anchor_ || !have_pmt_) {
        return false;
    }
    out = anchor_;
    return true;
}

// ----------------------------------------------------------- selftest

#include <stdio.h>

namespace {

struct TSBuilder {
    uint8_t cc[8192] {};

    // Append one 188-byte packet.
    void pkt(uint8_t *out, uint16_t pid, bool pusi, const uint8_t *payload,
             size_t plen, bool rai)
    {
        memset(out, 0xFF, TS_PACKET_SIZE);
        out[0] = TS_SYNC_BYTE;
        out[1] = uint8_t((pusi ? 0x40 : 0) | ((pid >> 8) & 0x1F));
        out[2] = uint8_t(pid & 0xFF);
        size_t body = 4;
        if (rai) {
            out[3] = uint8_t(0x30 | (cc[pid] & 0x0F));   // AF + payload
            const size_t af_len = TS_PACKET_SIZE - 5 - plen;
            out[4] = uint8_t(af_len);
            out[5] = 0x40;                               // RAI
            for (size_t i = 6; i < 5 + af_len; i++) {
                out[i] = 0xFF;
            }
            body = 5 + af_len;
        } else {
            out[3] = uint8_t(0x10 | (cc[pid] & 0x0F));   // payload only
        }
        cc[pid] = uint8_t((cc[pid] + 1) & 0x0F);
        if (payload != nullptr && plen > 0) {
            memcpy(out + body, payload, plen);
        }
    }

    static void finish_section(uint8_t *sec, size_t body_len)
    {
        // body_len counts from table_id through the last byte before CRC
        const uint32_t crc = ts_crc32(sec, body_len);
        sec[body_len + 0] = uint8_t(crc >> 24);
        sec[body_len + 1] = uint8_t(crc >> 16);
        sec[body_len + 2] = uint8_t(crc >> 8);
        sec[body_len + 3] = uint8_t(crc);
    }

    void pat(uint8_t *out, uint16_t pmt_pid, uint8_t version)
    {
        uint8_t sec[64] {};
        sec[0] = 0x00;                       // table_id
        const size_t body = 12;              // through the program entry
        sec[1] = uint8_t(0xB0 | (((body + 4 - 3) >> 8) & 0x0F));
        sec[2] = uint8_t((body + 4 - 3) & 0xFF);
        sec[3] = 0x00; sec[4] = 0x01;        // transport_stream_id
        sec[5] = uint8_t(0xC1 | (version << 1));
        sec[6] = 0x00; sec[7] = 0x00;
        sec[8] = 0x00; sec[9] = 0x01;        // program_number 1
        sec[10] = uint8_t(0xE0 | ((pmt_pid >> 8) & 0x1F));
        sec[11] = uint8_t(pmt_pid & 0xFF);
        finish_section(sec, body);
        uint8_t payload[TS_PACKET_SIZE] {};
        payload[0] = 0x00;                   // pointer_field
        memcpy(payload + 1, sec, body + 4);
        pkt(out, 0, true, payload, body + 4 + 1, false);
    }

    void pmt(uint8_t *out, uint16_t pmt_pid, uint16_t vpid, uint8_t stype,
             uint8_t version)
    {
        uint8_t sec[64] {};
        sec[0] = 0x02;
        const size_t body = 17;              // through the one ES entry
        sec[1] = uint8_t(0xB0 | (((body + 4 - 3) >> 8) & 0x0F));
        sec[2] = uint8_t((body + 4 - 3) & 0xFF);
        sec[3] = 0x00; sec[4] = 0x01;
        sec[5] = uint8_t(0xC1 | (version << 1));
        sec[6] = 0x00; sec[7] = 0x00;
        sec[8] = uint8_t(0xE0 | ((vpid >> 8) & 0x1F));
        sec[9] = uint8_t(vpid & 0xFF);       // PCR PID
        sec[10] = 0xF0; sec[11] = 0x00;      // program_info_length 0
        sec[12] = stype;
        sec[13] = uint8_t(0xE0 | ((vpid >> 8) & 0x1F));
        sec[14] = uint8_t(vpid & 0xFF);
        sec[15] = 0xF0; sec[16] = 0x00;      // ES_info_length 0
        finish_section(sec, body);
        uint8_t payload[TS_PACKET_SIZE] {};
        payload[0] = 0x00;
        memcpy(payload + 1, sec, body + 4);
        pkt(out, pmt_pid, true, payload, body + 4 + 1, false);
    }

    // `key` picks the payload (keyframe NAL vs a plain slice); `rai`
    // controls the adaptation field's random_access_indicator. They are
    // separate so a stream that lies -- RAI set on a non-keyframe --
    // can be built.
    /*
      A PMT with `n_es` elementary streams, split across as many packets
      as it needs: one PUSI packet then continuation packets. Without
      this, every section fits in one packet and the multi-packet
      reassembly path is never exercised at all.

      Returns how many packets were written.
     */
    size_t pmt_split(uint8_t *out, uint16_t pmt_pid, uint16_t vpid,
                     uint8_t stype, uint8_t version, size_t n_es,
                     size_t max_packets)
    {
        if (max_packets == 0) {
            return 0;
        }
        uint8_t sec[TS_MAX_SECTION] {};
        size_t k = 0;
        sec[k++] = 0x02;
        k += 2;                                   // length, patched below
        sec[k++] = 0x00; sec[k++] = 0x01;
        sec[k++] = uint8_t(0xC1 | (version << 1));
        sec[k++] = 0x00; sec[k++] = 0x00;
        sec[k++] = uint8_t(0xE0 | ((vpid >> 8) & 0x1F));
        sec[k++] = uint8_t(vpid & 0xFF);
        sec[k++] = 0xF0; sec[k++] = 0x00;
        // first ES entry is the video one
        sec[k++] = stype;
        sec[k++] = uint8_t(0xE0 | ((vpid >> 8) & 0x1F));
        sec[k++] = uint8_t(vpid & 0xFF);
        sec[k++] = 0xF0; sec[k++] = 0x00;
        for (size_t e = 1; e < n_es && k + 5 + 4 < sizeof(sec); e++) {
            const uint16_t pid = uint16_t(0x200 + e);
            sec[k++] = TS_STREAM_PRIVATE;
            sec[k++] = uint8_t(0xE0 | ((pid >> 8) & 0x1F));
            sec[k++] = uint8_t(pid & 0xFF);
            sec[k++] = 0xF0; sec[k++] = 0x00;
        }
        const size_t body = k;
        const size_t section_length = body + 4 - 3;
        sec[1] = uint8_t(0xB0 | ((section_length >> 8) & 0x0F));
        sec[2] = uint8_t(section_length & 0xFF);
        finish_section(sec, body);
        const size_t total = body + 4;

        // first packet carries the pointer_field, the rest are
        // continuations with no pointer field and PUSI clear
        size_t written = 0;
        size_t off = 0;
        bool first = true;
        while (off < total && written < max_packets) {
            uint8_t payload[TS_PACKET_SIZE] {};
            size_t plen = 0;
            if (first) {
                payload[plen++] = 0x00;           // pointer_field
            }
            const size_t room = (TS_PACKET_SIZE - 4) - plen;
            const size_t take = (total - off) < room ? (total - off) : room;
            memcpy(payload + plen, sec + off, take);
            plen += take;
            off += take;
            pkt(out + written * TS_PACKET_SIZE, pmt_pid, first,
                payload, plen, false);
            written++;
            first = false;
        }
        return written;
    }

    void video(uint8_t *out, uint16_t vpid, bool key,
               uint8_t stype = TS_STREAM_H264, int rai = -1)
    {
        // A PES header followed by an access-unit delimiter, so the
        // RAI confirmation has something real to find.
        uint8_t payload[32] {};
        size_t n = 0;
        payload[n++] = 0x00; payload[n++] = 0x00; payload[n++] = 0x01;
        payload[n++] = 0xE0;                         // PES video stream id
        payload[n++] = 0x00; payload[n++] = 0x00;    // PES length (unbounded)
        payload[n++] = 0x80; payload[n++] = 0x00; payload[n++] = 0x00;
        payload[n++] = 0x00; payload[n++] = 0x00; payload[n++] = 0x01;
        if (stype == TS_STREAM_HEVC) {
            // HEVC NAL header is two bytes and the type is bits 6..1:
            // 35 = AUD, 1 = TRAIL_R. An H.264 AUD byte here would
            // decode as type 4 and be rejected, which is the point of
            // confirming the RAI bit against the payload at all.
            payload[n++] = key ? uint8_t(35 << 1) : uint8_t(1 << 1);
            payload[n++] = 0x01;
        } else {
            payload[n++] = key ? 0x09 : 0x41;        // AUD / non-IDR slice
        }
        payload[n++] = 0x10;
        pkt(out, vpid, true, payload, n, rai < 0 ? key : rai != 0);
    }
};

#define CHECK(cond, msg) do {                                   \
        if (!(cond)) {                                          \
            printf("videots selftest FAIL: %s\n", msg);         \
            return 1;                                           \
        }                                                       \
    } while (0)

}  // namespace

int videots_selftest(void)
{
    // CRC over a known-good section must come out zero when the CRC
    // itself is included -- that is how a receiver validates it.
    {
        uint8_t sec[16] {};
        sec[0] = 0x00; sec[1] = 0xB0; sec[2] = 0x0D;
        TSBuilder::finish_section(sec, 12);
        CHECK(ts_crc32(sec, 16) == 0, "CRC self-check");
    }

    // A stream of PAT, PMT, non-key, key must yield an anchor at the PAT.
    {
        TSBuilder b;
        uint8_t s[TS_PACKET_SIZE * 4] {};
        b.pat(s + 0 * TS_PACKET_SIZE, 0x100, 0);
        b.pmt(s + 1 * TS_PACKET_SIZE, 0x100, 0x101, TS_STREAM_H264, 0);
        b.video(s + 2 * TS_PACKET_SIZE, 0x101, false);
        b.video(s + 3 * TS_PACKET_SIZE, 0x101, true);

        TSScanner sc;
        sc.feed(s, sizeof(s), 0);
        CHECK(sc.have_program(), "PAT+PMT parsed");
        CHECK(sc.video_pid() == 0x101, "video PID");
        CHECK(sc.video_stream_type() == TS_STREAM_H264, "stream type");
        CHECK(sc.stats().pat_seen == 1, "one PAT");
        CHECK(sc.stats().pmt_seen == 1, "one PMT");
        CHECK(sc.stats().rai_seen == 1, "one RAI");
        CHECK(sc.stats().cc_errors == 0, "no CC errors");
        CHECK(sc.stats().crc_errors == 0, "no CRC errors");
        uint64_t off = 1;
        CHECK(sc.join_offset(off), "anchor found");
        CHECK(off == 0, "anchor is the PAT offset");
    }

    // A keyframe before any PSI must NOT produce an anchor: the viewer
    // would have no PMT and so no idea which PID carries video.
    {
        TSBuilder b;
        uint8_t s[TS_PACKET_SIZE * 2] {};
        b.video(s + 0, 0x101, true);
        b.video(s + TS_PACKET_SIZE, 0x101, true);
        TSScanner sc;
        sc.feed(s, sizeof(s), 0);
        uint64_t off = 0;
        CHECK(!sc.join_offset(off), "no anchor without PSI");
    }

    // Feeding one byte at a time must give the same result as one go:
    // packets split across reads are the normal case on TCP.
    {
        TSBuilder b;
        uint8_t s[TS_PACKET_SIZE * 4] {};
        b.pat(s + 0 * TS_PACKET_SIZE, 0x100, 0);
        b.pmt(s + 1 * TS_PACKET_SIZE, 0x100, 0x101, TS_STREAM_H264, 0);
        b.video(s + 2 * TS_PACKET_SIZE, 0x101, false);
        b.video(s + 3 * TS_PACKET_SIZE, 0x101, true);
        TSScanner sc;
        for (size_t i = 0; i < sizeof(s); i++) {
            sc.feed(s + i, 1, i);
        }
        CHECK(sc.have_program(), "byte-at-a-time PSI");
        CHECK(sc.stats().rai_seen == 1, "byte-at-a-time RAI");
        uint64_t off = 1;
        CHECK(sc.join_offset(off) && off == 0, "byte-at-a-time anchor");
    }

    // A corrupt PMT must be rejected rather than believed.
    {
        TSBuilder b;
        uint8_t s[TS_PACKET_SIZE * 2] {};
        b.pat(s, 0x100, 0);
        b.pmt(s + TS_PACKET_SIZE, 0x100, 0x101, TS_STREAM_H264, 0);
        s[TS_PACKET_SIZE + 20] ^= 0xFF;          // flip a payload byte
        TSScanner sc;
        sc.feed(s, sizeof(s), 0);
        CHECK(!sc.have_program(), "corrupt PMT rejected");
        CHECK(sc.stats().crc_errors == 1, "CRC error counted");
    }

    // Garbage before the stream must be resynced past, not misparsed.
    {
        TSBuilder b;
        uint8_t s[64 + TS_PACKET_SIZE * 4] {};
        memset(s, 0x47, 64);                     // sync bytes that aren't
        b.pat(s + 64 + 0 * TS_PACKET_SIZE, 0x100, 0);
        b.pmt(s + 64 + 1 * TS_PACKET_SIZE, 0x100, 0x101, TS_STREAM_H264, 0);
        b.video(s + 64 + 2 * TS_PACKET_SIZE, 0x101, false);
        b.video(s + 64 + 3 * TS_PACKET_SIZE, 0x101, true);
        TSScanner sc;
        sc.feed(s, sizeof(s), 0);
        CHECK(sc.have_program(), "resync found the program");
        uint64_t off = 0;
        CHECK(sc.join_offset(off) && off == 64, "anchor after resync");
    }

    // A PMT version change that moves the video PID must be followed.
    {
        TSBuilder b;
        uint8_t s[TS_PACKET_SIZE * 4] {};
        b.pat(s + 0, 0x100, 0);
        b.pmt(s + TS_PACKET_SIZE, 0x100, 0x101, TS_STREAM_H264, 0);
        b.pmt(s + 2 * TS_PACKET_SIZE, 0x100, 0x102, TS_STREAM_HEVC, 1);
        b.video(s + 3 * TS_PACKET_SIZE, 0x102, true, TS_STREAM_HEVC);
        TSScanner sc;
        sc.feed(s, sizeof(s), 0);
        CHECK(sc.video_pid() == 0x102, "PMT version change followed");
        CHECK(sc.video_stream_type() == TS_STREAM_HEVC, "new stream type");
        CHECK(sc.stats().rai_seen == 1, "RAI on the new PID");
    }

    // A muxer that sets RAI on a non-keyframe must not fool us: the
    // bit is a hint, and serving a viewer from a point the decoder
    // cannot start at is indistinguishable from a broken stream.
    {
        TSBuilder b;
        uint8_t s[TS_PACKET_SIZE * 3] {};
        b.pat(s + 0, 0x100, 0);
        b.pmt(s + TS_PACKET_SIZE, 0x100, 0x101, TS_STREAM_H264, 0);
        // non-keyframe payload, but the RAI bit set: a well-formed
        // packet that lies about being a random access point.
        b.video(s + 2 * TS_PACKET_SIZE, 0x101, false, TS_STREAM_H264, 1);
        TSScanner sc;
        sc.feed(s, sizeof(s), 0);
        CHECK(sc.have_program(), "false-RAI case parsed PSI");
        uint64_t off = 0;
        CHECK(!sc.join_offset(off), "false RAI must not produce an anchor");
    }

    printf("videots selftest: OK\n");
    return 0;
}

// --------------------------------------------------------------- fuzz

namespace {

// xorshift32: tiny, deterministic, and no dependency on the platform's
// rand() so a failing seed reproduces anywhere.
struct Rng {
    uint32_t s;
    explicit Rng(uint32_t seed) : s(seed ? seed : 1) {}
    uint32_t next(void)
    {
        s ^= s << 13;
        s ^= s >> 17;
        s ^= s << 5;
        return s;
    }
    uint32_t below(uint32_t n) { return n ? next() % n : 0; }
};

}  // namespace

int videots_fuzz(unsigned iterations, uint32_t seed)
{
    for (unsigned it = 0; it < iterations; it++) {
        Rng rng(seed + it);

        // Build a valid stream, then corrupt it.
        TSBuilder b;
        const size_t npkt = 8 + rng.below(24);
        std::vector<uint8_t> s(npkt * TS_PACKET_SIZE);
        for (size_t i = 0; i < npkt; i++) {
            uint8_t *p = &s[i * TS_PACKET_SIZE];
            switch (i % 4) {
            case 0: b.pat(p, 0x100, uint8_t(rng.below(32))); break;
            case 1:
                if (rng.below(2) == 0) {
                    // a PMT big enough to span several packets, so the
                    // reassembly path is fuzzed too
                    const size_t used = b.pmt_split(
                        p, 0x100, 0x101, TS_STREAM_H264,
                        uint8_t(rng.below(32)), 4 + rng.below(240),
                        npkt - i);
                    i += used > 0 ? used - 1 : 0;
                } else {
                    b.pmt(p, 0x100, 0x101, TS_STREAM_H264,
                          uint8_t(rng.below(32)));
                }
                break;
            default: b.video(p, 0x101, (i % 8) == 3); break;
            }
        }

        const unsigned mutations = rng.below(24);
        for (unsigned m = 0; m < mutations; m++) {
            const size_t off = rng.below(uint32_t(s.size()));
            switch (rng.below(4)) {
            case 0: s[off] ^= uint8_t(1u << rng.below(8)); break;  // bit flip
            case 1: s[off] = uint8_t(rng.next()); break;           // byte set
            case 2: s[off] = TS_SYNC_BYTE; break;   // spurious sync byte
            case 3: s[off] = 0xFF; break;           // saturate a length field
            }
        }
        if (rng.below(4) == 0) {
            s.resize(1 + rng.below(uint32_t(s.size())));   // truncate
        }

        // Feed in irregular chunks: a packet split across reads is the
        // normal case, and it is where an assembler most easily breaks.
        TSScanner sc;
        size_t i = 0;
        while (i < s.size()) {
            size_t chunk = 1 + rng.below(400);
            if (i + chunk > s.size()) {
                chunk = s.size() - i;
            }
            sc.feed(&s[i], chunk, i);
            i += chunk;
        }

        // Invariants that must hold whatever the input was.
        uint64_t off = 0;
        if (sc.join_offset(off)) {
            if (!sc.have_program()) {
                printf("videots fuzz FAIL (seed %u, iter %u): anchor without "
                       "a program\n", seed, it);
                return 1;
            }
            if (off >= s.size()) {
                printf("videots fuzz FAIL (seed %u, iter %u): anchor %llu "
                       "past end %zu\n", seed, it,
                       (unsigned long long)off, s.size());
                return 1;
            }
        }
        if (sc.have_program() && sc.video_pid() == 0) {
            printf("videots fuzz FAIL (seed %u, iter %u): program with no "
                   "video PID\n", seed, it);
            return 1;
        }
        const TSStats &st = sc.stats();
        if (st.packets * TS_PACKET_SIZE > st.bytes + TS_PACKET_SIZE) {
            printf("videots fuzz FAIL (seed %u, iter %u): counted more "
                   "packets than bytes fed\n", seed, it);
            return 1;
        }
    }
    printf("videots fuzz: OK (%u iterations from seed %u)\n",
           iterations, seed);
    return 0;
}
