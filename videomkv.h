#pragma once
#include "videots.h"
#include <functional>
#include <string>
#include <vector>

// The APCG live profile has an unknown-size Segment and finite, independent
// FFV1 Clusters. Preserve bytes, including BlockAdditional telemetry. Bounds
// are independent of advertised EBML sizes and HTTP chunk boundaries.
class VideoScanner : public TSScanner {
public:
    bool matroska = false;
    bool failed = false;
    std::string prefix;
    std::function<void(const uint8_t *, size_t)> cluster;
    void reset() { *this = VideoScanner(); }
    bool join_offset(uint64_t &out) const {
        if (!matroska) return TSScanner::join_offset(out);
        out = anchor;
        return have_anchor && !failed;
    }
    void feed(const uint8_t *buf, size_t n, uint64_t base) {
        if (!matroska) { TSScanner::feed(buf, n, base); return; }
        if (failed) return;
        if (pending.empty()) offset = base;
        pending.insert(pending.end(), buf, buf+n);
        while (!pending.empty()) {
            uint64_t id, size; size_t a, b;
            int r = vint(pending.data(), pending.size(), id, a, true);
            if (r < 0) { failed = true; return; }
            if (!r) return;
            r = vint(pending.data()+a, pending.size()-a, size, b, false);
            if (r < 0) { failed = true; return; }
            if (!r) return;
            const bool unknown = size == ((uint64_t(1) << (7*b))-1);
            if (stage == 1) {
                if (id != 0x18538067 || !unknown) { failed = true; return; }
                size = 0; // descend into the live Segment
            } else if (unknown || size > 4*1024*1024 || (stage < 4 && size > 65536)) {
                failed = true; return;
            }
            const size_t total = a+b+size;
            if (pending.size() < total) return;
            const uint64_t expected[] = {0x1a45dfa3, 0x18538067, 0x1549a966, 0x1654ae6b};
            if (stage < 4) {
                if (id != expected[stage] || prefix.size()+total > 131072) { failed = true; return; }
                prefix.append(reinterpret_cast<const char *>(pending.data()), total);
                stage++;
            } else {
                if (id != 0x1f43b675) { failed = true; return; }
                anchor = offset;
                have_anchor = true;
                if (cluster) cluster(pending.data(), total);
            }
            pending.erase(pending.begin(), pending.begin()+total);
            offset += total;
        }
    }
private:
    unsigned stage = 0;
    uint64_t offset = 0, anchor = 0;
    bool have_anchor = false;
    std::vector<uint8_t> pending;
    static int vint(const uint8_t *p, size_t n, uint64_t &value, size_t &len, bool id) {
        if (!n) return 0;
        if (!p[0]) return -1;
        len = 1; uint8_t mask = 0x80;
        while (!(p[0]&mask)) { len++; mask >>= 1; }
        if (len > (id ? 4U : 8U)) return -1;
        if (n < len) return 0;
        value = id ? p[0] : (p[0]&~mask);
        for (size_t i=1; i<len; i++) value = (value<<8)|p[i];
        return 1;
    }
};

// Strict streaming HTTP chunk decoder. No extensions or trailers are needed
// by the camera publisher. A bounded line and chunk size prevent allocations
// controlled by an unauthenticated or malformed advertised length.
class VideoChunks {
public:
    bool feed(const uint8_t *p, size_t n, const std::function<void(const uint8_t *, size_t)> &emit) {
        while (n) {
            if (remaining) {
                const size_t take = n < remaining ? n : remaining;
                emit(p, take); p += take; n -= take; remaining -= take;
                if (!remaining) ending = 2;
            } else if (ending) {
                if (*p++ != (ending == 2 ? '\r' : '\n')) return false;
                n--; ending--;
            } else {
                char c = *p++; n--;
                if (c == '\n') {
                    if (line.size() < 2 || line.back() != '\r') return false;
                    size_t length = 0;
                    for (size_t i=0; i+1<line.size(); i++) {
                        char h=line[i];
                        unsigned digit = h >= '0' && h <= '9' ? h-'0' :
                            h >= 'a' && h <= 'f' ? h-'a'+10 : h >= 'A' && h <= 'F' ? h-'A'+10 : 16;
                        if (digit > 15 || length > 4*1024*1024/16) return false;
                        length = length*16+digit;
                    }
                    if (!length || length > 4*1024*1024) return false; // zero chunk ends publication
                    remaining = length; line.clear();
                } else {
                    line += c;
                    if (line.size() > 10) return false;
                }
            }
        }
        return true;
    }
private:
    std::string line;
    size_t remaining = 0;
    unsigned ending = 0;
};
