/*
  Per-slot stream buffering. See videostream.h.
 */
#include "videostream.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

size_t video_ring_bytes(void)
{
    static size_t cached = 0;
    if (cached == 0) {
        cached = VIDEO_RING_DEFAULT;
        const char *env = getenv("SUPPORTPROXY_VIDEO_RING_BYTES");
        if (env != nullptr && *env != '\0') {
            char *endp = nullptr;
            errno = 0;
            long long v = strtoll(env, &endp, 10);
            if (errno == 0 && endp != env && *endp == '\0' && v > 0) {
                cached = size_t(v);
            }
        }
    }
    return cached;
}

bool VideoRing::init(size_t bytes)
{
    if (bytes < 4096) {
        bytes = 4096;
    }
    buf_.assign(bytes, 0);
    write_pos_ = 0;
    return true;
}

void VideoRing::write(const uint8_t *buf, size_t n)
{
    const size_t cap = buf_.size();
    if (cap == 0 || n == 0) {
        return;
    }
    if (n >= cap) {
        // Only the tail can survive; skip the part that would be
        // overwritten before this call even returned.
        buf += n - cap;
        write_pos_ += n - cap;
        n = cap;
    }
    const size_t start = size_t(write_pos_ % cap);
    const size_t first = (cap - start) < n ? (cap - start) : n;
    memcpy(&buf_[start], buf, first);
    if (n > first) {
        memcpy(&buf_[0], buf + first, n - first);
    }
    write_pos_ += n;
}

uint64_t VideoRing::oldest(void) const
{
    const size_t cap = buf_.size();
    return write_pos_ > cap ? write_pos_ - cap : 0;
}

bool VideoRing::resident(uint64_t pos) const
{
    return pos >= oldest() && pos <= write_pos_;
}

size_t VideoRing::read_at(uint64_t pos, uint8_t *out, size_t n) const
{
    const size_t cap = buf_.size();
    if (cap == 0 || !resident(pos)) {
        return 0;
    }
    const uint64_t avail64 = write_pos_ - pos;
    const size_t avail = avail64 > n ? n : size_t(avail64);
    if (avail == 0) {
        return 0;
    }
    const size_t start = size_t(pos % cap);
    const size_t first = (cap - start) < avail ? (cap - start) : avail;
    memcpy(out, &buf_[start], first);
    if (avail > first) {
        memcpy(out + first, &buf_[0], avail - first);
    }
    return avail;
}

// ----------------------------------------------------------- selftest

#define RCHECK(cond, msg) do {                                  \
        if (!(cond)) {                                          \
            printf("videostream selftest FAIL: %s\n", msg);     \
            return 1;                                           \
        }                                                       \
    } while (0)

int videostream_selftest(void)
{
    // basic append and read-back
    {
        VideoRing r;
        r.init(4096);
        uint8_t in[300];
        for (size_t i = 0; i < sizeof(in); i++) {
            in[i] = uint8_t(i);
        }
        r.write(in, sizeof(in));
        RCHECK(r.write_pos() == 300, "write_pos advanced");
        RCHECK(r.oldest() == 0, "nothing evicted yet");
        uint8_t out[300] {};
        RCHECK(r.read_at(0, out, sizeof(out)) == 300, "read back all");
        RCHECK(memcmp(in, out, sizeof(in)) == 0, "bytes match");
        // a partial read from the middle
        RCHECK(r.read_at(100, out, 50) == 50, "partial read");
        RCHECK(memcmp(out, in + 100, 50) == 0, "partial bytes match");
    }

    // wrap: the ring must stay byte-exact across the seam
    {
        VideoRing r;
        r.init(4096);
        uint8_t chunk[1000];
        for (int pass = 0; pass < 10; pass++) {
            for (size_t i = 0; i < sizeof(chunk); i++) {
                chunk[i] = uint8_t(pass * 31 + i);
            }
            r.write(chunk, sizeof(chunk));
        }
        RCHECK(r.write_pos() == 10000, "wrapped write_pos");
        RCHECK(r.oldest() == 10000 - 4096, "oldest tracks eviction");
        RCHECK(!r.resident(0), "evicted offset is not resident");
        RCHECK(r.resident(r.oldest()), "oldest is resident");

        // the last chunk must read back exactly, spanning the seam
        uint8_t out[1000] {};
        RCHECK(r.read_at(9000, out, 1000) == 1000, "read last chunk");
        for (size_t i = 0; i < sizeof(out); i++) {
            RCHECK(out[i] == uint8_t(9 * 31 + i), "wrapped bytes match");
        }
    }

    // a write larger than the ring keeps the tail, not the head
    {
        VideoRing r;
        r.init(4096);
        std::vector<uint8_t> big(10000);
        for (size_t i = 0; i < big.size(); i++) {
            big[i] = uint8_t(i);
        }
        r.write(big.data(), big.size());
        RCHECK(r.write_pos() == 10000, "oversized write advances fully");
        RCHECK(r.oldest() == 10000 - 4096, "oversized write evicts");
        uint8_t out[16] {};
        RCHECK(r.read_at(10000 - 16, out, 16) == 16, "tail readable");
        for (size_t i = 0; i < 16; i++) {
            RCHECK(out[i] == uint8_t(10000 - 16 + i), "tail bytes are the tail");
        }
    }

    // reading an evicted position must fail rather than return garbage
    {
        VideoRing r;
        r.init(4096);
        uint8_t chunk[5000] {};
        r.write(chunk, sizeof(chunk));
        uint8_t out[16] {};
        RCHECK(r.read_at(0, out, sizeof(out)) == 0, "evicted read returns 0");
        RCHECK(r.read_at(r.write_pos() + 1, out, sizeof(out)) == 0,
               "future read returns 0");
    }

    printf("videostream selftest: OK\n");
    return 0;
}
