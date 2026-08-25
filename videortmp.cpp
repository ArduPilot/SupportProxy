/*
  Native RTMP publish ingest. See videortmp.h.
 */
#include "videortmp.h"

#include <stdio.h>
#include <string.h>

#include "httpreq.h"

namespace {

// ---------------------------------------------------------------- AMF0

enum {
    AMF_NUMBER = 0x00,
    AMF_BOOLEAN = 0x01,
    AMF_STRING = 0x02,
    AMF_OBJECT = 0x03,
    AMF_NULL = 0x05,
    AMF_UNDEFINED = 0x06,
    AMF_REFERENCE = 0x07,
    AMF_ECMA_ARRAY = 0x08,
    AMF_OBJECT_END = 0x09,
    AMF_STRICT_ARRAY = 0x0a,
    AMF_DATE = 0x0b,
    AMF_LONG_STRING = 0x0c,
};

double be_double(const uint8_t *p)
{
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) {
        v = (v << 8) | p[i];
    }
    double d;
    memcpy(&d, &v, sizeof(d));
    return d;
}

void put_be_double(std::vector<uint8_t> &b, double d)
{
    uint64_t v;
    memcpy(&v, &d, sizeof(v));
    for (int i = 7; i >= 0; i--) {
        b.push_back(uint8_t((v >> (i * 8)) & 0xff));
    }
}

void amf_num(std::vector<uint8_t> &b, double d)
{
    b.push_back(AMF_NUMBER);
    put_be_double(b, d);
}

void amf_str(std::vector<uint8_t> &b, const char *s)
{
    const size_t n = strlen(s);
    b.push_back(AMF_STRING);
    b.push_back(uint8_t((n >> 8) & 0xff));
    b.push_back(uint8_t(n & 0xff));
    b.insert(b.end(), s, s + n);
}

void amf_key(std::vector<uint8_t> &b, const char *s)
{
    const size_t n = strlen(s);
    b.push_back(uint8_t((n >> 8) & 0xff));
    b.push_back(uint8_t(n & 0xff));
    b.insert(b.end(), s, s + n);
}

void amf_null(std::vector<uint8_t> &b) { b.push_back(AMF_NULL); }

void amf_obj_end(std::vector<uint8_t> &b)
{
    b.push_back(0);
    b.push_back(0);
    b.push_back(AMF_OBJECT_END);
}

/*
  Skip one AMF0 value. Returns false on anything malformed or truncated,
  which is what stops a hostile peer steering us past the buffer.
 */
bool amf_skip(const uint8_t *p, size_t n, size_t &i, int depth = 0);

bool amf_skip_object_body(const uint8_t *p, size_t n, size_t &i, int depth)
{
    while (true) {
        if (i + 2 > n) {
            return false;
        }
        const size_t klen = (size_t(p[i]) << 8) | p[i + 1];
        i += 2;
        if (klen == 0) {
            if (i >= n || p[i] != AMF_OBJECT_END) {
                return false;
            }
            i++;
            return true;
        }
        if (i + klen > n) {
            return false;
        }
        i += klen;
        if (!amf_skip(p, n, i, depth + 1)) {
            return false;
        }
    }
}

bool amf_skip(const uint8_t *p, size_t n, size_t &i, int depth)
{
    if (depth > 8 || i >= n) {
        return false;
    }
    const uint8_t m = p[i++];
    switch (m) {
    case AMF_NUMBER:
        i += 8;
        return i <= n;
    case AMF_BOOLEAN:
        i += 1;
        return i <= n;
    case AMF_STRING: {
        if (i + 2 > n) {
            return false;
        }
        const size_t len = (size_t(p[i]) << 8) | p[i + 1];
        i += 2 + len;
        return i <= n;
    }
    case AMF_LONG_STRING: {
        if (i + 4 > n) {
            return false;
        }
        size_t len = 0;
        for (int k = 0; k < 4; k++) {
            len = (len << 8) | p[i + k];
        }
        i += 4 + len;
        return i <= n;
    }
    case AMF_NULL:
    case AMF_UNDEFINED:
        return true;
    case AMF_REFERENCE:
        i += 2;
        return i <= n;
    case AMF_DATE:
        i += 10;
        return i <= n;
    case AMF_OBJECT:
        return amf_skip_object_body(p, n, i, depth);
    case AMF_ECMA_ARRAY:
        i += 4;
        if (i > n) {
            return false;
        }
        return amf_skip_object_body(p, n, i, depth);
    case AMF_STRICT_ARRAY: {
        if (i + 4 > n) {
            return false;
        }
        size_t cnt = 0;
        for (int k = 0; k < 4; k++) {
            cnt = (cnt << 8) | p[i + k];
        }
        i += 4;
        if (cnt > n) {
            return false;       // more elements than bytes left
        }
        for (size_t k = 0; k < cnt; k++) {
            if (!amf_skip(p, n, i, depth + 1)) {
                return false;
            }
        }
        return true;
    }
    case AMF_OBJECT_END:
        return true;
    default:
        return false;
    }
}

bool amf_read_string(const uint8_t *p, size_t n, size_t &i, std::string &out)
{
    if (i >= n || p[i] != AMF_STRING) {
        return false;
    }
    i++;
    if (i + 2 > n) {
        return false;
    }
    const size_t len = (size_t(p[i]) << 8) | p[i + 1];
    i += 2;
    if (i + len > n) {
        return false;
    }
    out.assign(reinterpret_cast<const char *>(p + i), len);
    i += len;
    return true;
}

bool amf_read_number(const uint8_t *p, size_t n, size_t &i, double &out)
{
    if (i >= n || p[i] != AMF_NUMBER) {
        return false;
    }
    if (i + 9 > n) {
        return false;
    }
    out = be_double(p + i + 1);
    i += 9;
    return true;
}

/*
  Pull named string members out of an AMF0 object or ECMA array. Only
  string values are of interest (app, tcUrl); everything else is skipped.
 */
bool amf_object_strings(const uint8_t *p, size_t n, size_t &i,
                        const char *k1, std::string &v1,
                        const char *k2, std::string &v2)
{
    if (i >= n) {
        return false;
    }
    const uint8_t m = p[i++];
    if (m == AMF_ECMA_ARRAY) {
        i += 4;
    } else if (m != AMF_OBJECT) {
        i--;
        return amf_skip(p, n, i);
    }
    while (true) {
        if (i + 2 > n) {
            return false;
        }
        const size_t klen = (size_t(p[i]) << 8) | p[i + 1];
        i += 2;
        if (klen == 0) {
            if (i >= n || p[i] != AMF_OBJECT_END) {
                return false;
            }
            i++;
            return true;
        }
        if (i + klen > n) {
            return false;
        }
        const std::string key(reinterpret_cast<const char *>(p + i), klen);
        i += klen;
        std::string sv;
        const size_t save = i;
        if (i < n && p[i] == AMF_STRING && amf_read_string(p, n, i, sv)) {
            if (key == k1) {
                v1 = sv;
            } else if (key == k2) {
                v2 = sv;
            }
            continue;
        }
        i = save;
        if (!amf_skip(p, n, i)) {
            return false;
        }
    }
}

/*
  Split "name?pw=secret" (or "&password=") into the bare name and the
  credential. Cameras put the stream key in a single field, so a query on
  the stream name is the only place RTMP has to carry one.
 */
bool split_credential(std::string &name, std::string &pw)
{
    const size_t q = name.find_first_of("?&");
    if (q == std::string::npos) {
        return false;
    }
    const std::string query = name.substr(q + 1);
    name.resize(q);
    size_t at = 0;
    while (at < query.size()) {
        size_t end = query.find('&', at);
        if (end == std::string::npos) {
            end = query.size();
        }
        const std::string kv = query.substr(at, end - at);
        const size_t eq = kv.find('=');
        if (eq != std::string::npos) {
            const std::string k = kv.substr(0, eq);
            if (k == "pw" || k == "password" || k == "key") {
                pw = http_url_decode(kv.substr(eq + 1));
                return true;    // first credential wins; a duplicate cannot erase it
            }
        }
        at = end + 1;
    }
    return false;
}

}  // namespace

// ------------------------------------------------------------- session

bool RtmpSession::fail(const char *why)
{
    error_ = why;
    state_ = RTMP_DEAD;
    return false;
}

void RtmpSession::compact(void)
{
    if (in_pos_ == in_.size()) {
        in_.clear();
        in_pos_ = 0;
    } else if (in_pos_ > 65536) {
        in_.erase(in_.begin(), in_.begin() + long(in_pos_));
        in_pos_ = 0;
    }
}

std::string RtmpSession::path(void) const
{
    if (app_.empty()) {
        return stream_;
    }
    if (stream_.empty()) {
        return app_;
    }
    return app_ + "/" + stream_;
}

bool RtmpSession::feed(const uint8_t *buf, size_t n, time_t now)
{
    if (state_ == RTMP_DEAD) {
        return false;
    }
    if (started_ == 0) {
        started_ = now;
    }
    now_ = now;
    total_in_ += n;
    if (!publishing_
        && (total_in_ > RTMP_PREPUBLISH_MAX_BYTES
            || now - started_ > RTMP_PREPUBLISH_MAX_S)) {
        return fail("did not publish in time");
    }
    if (n > 0) {
        in_.insert(in_.end(), buf, buf + n);
    }
    return run_parser();
}

/*
  Continue on bytes already buffered. Needed because parsing stops at
  publish so the caller can authorise in order: whatever the publisher
  pipelined behind it is still sitting in the input buffer, and without
  this it would wait for a read that may never come.
 */
bool RtmpSession::resume(void)
{
    if (state_ == RTMP_DEAD) {
        return false;
    }
    return run_parser();
}

bool RtmpSession::run_parser(void)
{
    while (true) {
        const size_t before = in_pos_;
        if (state_ == RTMP_WANT_C0C1 || state_ == RTMP_WANT_C2) {
            if (!do_handshake()) {
                return state_ != RTMP_DEAD;
            }
        } else if (state_ == RTMP_CHUNKS) {
            if (!parse_chunks()) {
                return state_ != RTMP_DEAD;
            }
        } else {
            return false;
        }
        /*
          Stop on publish. Media in the same read -- which a publisher
          that does not wait for onStatus sends -- would otherwise be
          parsed while publishing_ is still false and dropped by
          on_media(), losing the sequence header and its parameter sets.
         */
        if (publish_pending_) {
            break;
        }
        if (in_pos_ == before) {
            break;              // no progress: need more bytes
        }
    }
    compact();
    return true;
}

/*
  The simple handshake: S1 is a timestamp, a zero word and filler, and S2
  echoes C1. No digest, because nothing here plays back to Flash.
 */
bool RtmpSession::do_handshake(void)
{
    if (state_ == RTMP_WANT_C0C1) {
        if (avail() < 1537) {
            return false;
        }
        const uint8_t *p = cur();
        if (p[0] != 3) {
            return fail("unsupported RTMP version");
        }
        std::vector<uint8_t> s;
        s.reserve(1 + 1536 + 1536);
        s.push_back(3);
        // S1: zero time, zero, then filler. The peer only echoes it.
        s.insert(s.end(), 1536, 0);
        for (size_t i = 8; i < 1536; i++) {
            s[1 + i] = uint8_t(i & 0xff);
        }
        s.insert(s.end(), p + 1, p + 1537);      // S2 echoes C1
        to_peer_.insert(to_peer_.end(), s.begin(), s.end());
        in_pos_ += 1537;
        saw_c0c1_ = true;
        state_ = RTMP_WANT_C2;
        return true;
    }
    if (avail() < 1536) {
        return false;
    }
    in_pos_ += 1536;            // C2, not validated
    state_ = RTMP_CHUNKS;
    return true;
}

bool RtmpSession::parse_chunks(void)
{
    const size_t start = in_pos_;
    const uint8_t *p = in_.data();
    size_t i = in_pos_;
    const size_t end = in_.size();

    if (i >= end) {
        return false;
    }
    const uint8_t b0 = p[i];
    const uint8_t fmt = uint8_t(b0 >> 6);
    uint32_t csid = b0 & 0x3f;
    size_t hdr = 1;
    if (csid == 0) {
        if (i + 2 > end) {
            return false;
        }
        csid = 64 + p[i + 1];
        hdr = 2;
    } else if (csid == 1) {
        if (i + 3 > end) {
            return false;
        }
        csid = 64u + p[i + 1] + 256u * p[i + 2];
        hdr = 3;
    }
    if (csid > RTMP_MAX_CHUNK_STREAM) {
        return fail("chunk stream id out of range");
    }
    if (cs_.size() <= csid) {
        cs_.resize(csid + 1);
    }
    ChunkStream &c = cs_[csid];

    static const size_t mh[4] = { 11, 7, 3, 0 };
    if (i + hdr + mh[fmt] > end) {
        return false;
    }
    const uint8_t *h = p + i + hdr;

    /*
      Decode into locals and commit only once the whole chunk is here.

      Committing as we go looked harmless because an incomplete chunk
      leaves in_pos_ at the header and simply returns for more bytes --
      but that means the next feed() re-parses the same header and
      applies its timestamp delta a second time. Ordinary TCP
      segmentation is enough to trigger it, no malformed input needed.
     */
    uint32_t new_ts = c.ts;
    uint32_t new_delta = c.delta;
    uint32_t new_len = c.len;
    uint8_t new_type = c.type;
    uint32_t new_sid = c.sid;
    bool new_ext_ts = c.ext_ts;

    uint32_t ts_field = c.ts;
    if (fmt <= 2) {
        ts_field = (uint32_t(h[0]) << 16) | (uint32_t(h[1]) << 8) | h[2];
    }
    if (fmt == 0) {
        new_len = (uint32_t(h[3]) << 16) | (uint32_t(h[4]) << 8) | h[5];
        new_type = h[6];
        new_sid = uint32_t(h[7]) | (uint32_t(h[8]) << 8)
                | (uint32_t(h[9]) << 16) | (uint32_t(h[10]) << 24);
    } else if (fmt == 1) {
        new_len = (uint32_t(h[3]) << 16) | (uint32_t(h[4]) << 8) | h[5];
        new_type = h[6];
    }
    size_t pos = i + hdr + mh[fmt];

    /*
      An extended timestamp follows the header when the 24-bit field is
      saturated. fmt 3 has no field of its own, so it repeats the
      extension whenever the message it continues used one -- the usual
      interop trap, and the reason ext_ts is remembered per chunk stream.
     */
    const bool want_ext = (fmt <= 2 && ts_field == 0xffffff)
                       || (fmt == 3 && c.ext_ts);
    uint32_t ext = 0;
    if (want_ext) {
        if (pos + 4 > end) {
            return false;
        }
        ext = (uint32_t(p[pos]) << 24) | (uint32_t(p[pos + 1]) << 16)
            | (uint32_t(p[pos + 2]) << 8) | p[pos + 3];
        pos += 4;
    }
    if (fmt <= 2) {
        new_ext_ts = (ts_field == 0xffffff);
        const uint32_t t = new_ext_ts ? ext : ts_field;
        if (fmt == 0) {
            new_ts = t;
            new_delta = 0;
        } else {
            new_delta = t;
            new_ts = c.ts + t;
        }
    } else if (c.acc.empty()) {
        // A fresh message on a fmt-3 header repeats the last delta.
        new_ts = c.ts + c.delta;
    }

    if (new_len > RTMP_MAX_MESSAGE_BYTES) {
        return fail("message too large");
    }
    /*
      Only fmt 3 may continue a message. Anything else while this chunk
      stream still owes bytes is a protocol violation -- and accepting
      it silently spliced two wire messages into one, because the
      length and type were replaced while the old payload stayed in the
      accumulator. Abort Message is how a peer legitimately discards a
      partial message; it is handled in on_message().
     */
    if (fmt != 3 && !c.acc.empty()) {
        return fail("header restarts a message already in progress");
    }
    const size_t remaining = new_len - c.acc.size();
    const size_t take = remaining < in_chunk_ ? remaining : in_chunk_;
    if (pos + take > end) {
        return false;           // wait for the rest of this chunk
    }

    if (assembly_bytes_ + take > RTMP_MAX_ASSEMBLY_BYTES) {
        return fail("too many partial messages");
    }

    /*
      Acknowledge once per window. A publisher that asked for a window
      and never sees one is entitled to stop sending -- which presents
      as a stream that runs for a while and then stalls, with nothing in
      the log to say why.
     */
    bytes_in_ += (pos - i) + take;
    if (ack_window_ != 0 && bytes_in_ - acked_ >= ack_window_) {
        acked_ = bytes_in_;
        const uint32_t seq = uint32_t(acked_ & 0xffffffffu);
        const uint8_t ack[4] = {
            uint8_t((seq >> 24) & 0xff), uint8_t((seq >> 16) & 0xff),
            uint8_t((seq >> 8) & 0xff), uint8_t(seq & 0xff),
        };
        send_msg(2, 3, 0, ack, sizeof(ack));
    }

    // Whole chunk is buffered: now it is safe to advance the state.
    c.ts = new_ts;
    c.delta = new_delta;
    c.len = new_len;
    c.type = new_type;
    c.sid = new_sid;
    c.ext_ts = new_ext_ts;
    c.acc.insert(c.acc.end(), p + pos, p + pos + take);
    assembly_bytes_ += take;
    pos += take;
    in_pos_ = pos;

    if (c.acc.size() >= c.len) {
        std::vector<uint8_t> msg;
        msg.swap(c.acc);
        assembly_bytes_ -= msg.size();
        if (!on_message(c, msg.data(), msg.size())) {
            return false;
        }
    }
    if (to_peer_.size() > RTMP_MAX_OUT_BYTES) {
        return fail("peer is not reading its responses");
    }
    return in_pos_ > start;
}

bool RtmpSession::on_message(ChunkStream &c, const uint8_t *p, size_t n)
{
    switch (c.type) {
    case 1:                     // Set Chunk Size
        if (n < 4) {
            return fail("short SetChunkSize");
        }
        {
            const uint32_t v = ((uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16)
                                | (uint32_t(p[2]) << 8) | p[3]) & 0x7fffffff;
            if (v == 0 || v > RTMP_MAX_CHUNK_SIZE) {
                return fail("bad chunk size");
            }
            in_chunk_ = v;
        }
        return true;
    case 2:                     // Abort Message
        /*
          The peer discarding a partial message on a chunk stream. The
          spec's way out of the state the check in parse_chunks()
          otherwise treats as fatal.
         */
        if (n >= 4) {
            const uint32_t id = (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16)
                              | (uint32_t(p[2]) << 8) | p[3];
            if (id < cs_.size()) {
                assembly_bytes_ -= cs_[id].acc.size();
                cs_[id].acc.clear();
            }
        }
        return true;
    case 3:                     // Acknowledgement from the peer
        return true;
    case 5:                     // Window Acknowledgement Size
        if (n >= 4) {
            ack_window_ = (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16)
                        | (uint32_t(p[2]) << 8) | p[3];
        }
        return true;
    case 6:                     // Set Peer Bandwidth
        // Carries a window plus a limit type; the window is what we owe
        // acknowledgements against.
        if (n >= 4) {
            ack_window_ = (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16)
                        | (uint32_t(p[2]) << 8) | p[3];
        }
        return true;
    case 4:                     // User Control
        if (n >= 2) {
            const uint32_t ev = (uint32_t(p[0]) << 8) | p[1];
            if (ev == 6 && n >= 6) {        // PingRequest
                uint8_t pong[6] = { 0, 7, p[2], p[3], p[4], p[5] };
                send_msg(2, 4, 0, pong, sizeof(pong));
            }
        }
        return true;
    case 8:                     // audio
    case 9:                     // video
    case 18:                    // AMF0 data (metadata)
        on_media(c.type, c.ts, p, n);
        return true;
    case 20:                    // AMF0 command
        return on_command(c, p, n);
    case 17:                    // AMF3 command
        return true;            // ignored; publishers use AMF0
    default:
        return true;
    }
}

void RtmpSession::send_msg(uint8_t csid, uint8_t type, uint32_t sid,
                           const uint8_t *p, size_t n, uint32_t ts)
{
    std::vector<uint8_t> &o = to_peer_;
    o.push_back(csid);                     // fmt 0
    o.push_back(uint8_t((ts >> 16) & 0xff));
    o.push_back(uint8_t((ts >> 8) & 0xff));
    o.push_back(uint8_t(ts & 0xff));
    o.push_back(uint8_t((n >> 16) & 0xff));
    o.push_back(uint8_t((n >> 8) & 0xff));
    o.push_back(uint8_t(n & 0xff));
    o.push_back(type);
    o.push_back(uint8_t(sid & 0xff));
    o.push_back(uint8_t((sid >> 8) & 0xff));
    o.push_back(uint8_t((sid >> 16) & 0xff));
    o.push_back(uint8_t((sid >> 24) & 0xff));
    size_t at = 0;
    while (at < n) {
        if (at != 0) {
            o.push_back(uint8_t(0xc0 | csid));
        }
        const size_t take = (n - at) < RTMP_OUT_CHUNK_SIZE
            ? (n - at) : RTMP_OUT_CHUNK_SIZE;
        o.insert(o.end(), p + at, p + at + take);
        at += take;
    }
}

void RtmpSession::send_amf(uint8_t csid, uint32_t sid,
                           const std::vector<uint8_t> &b)
{
    send_msg(csid, 20, sid, b.data(), b.size());
}

bool RtmpSession::on_command(ChunkStream &c, const uint8_t *p, size_t n)
{
    size_t i = 0;
    std::string cmd;
    if (!amf_read_string(p, n, i, cmd)) {
        return fail("unparseable command");
    }
    double txn = 0;
    amf_read_number(p, n, i, txn);

    if (cmd == "connect") {
        /*
          Once only. Repeating it is not a legal phase transition and
          each one costs several responses, which is free amplification
          for a peer that never reads them.
         */
        if (connected_) {
            return fail("repeated connect");
        }
        connected_ = true;
        std::string tc_url;
        amf_object_strings(p, n, i, "app", app_, "tcUrl", tc_url);
        password_present_ = split_credential(app_, password_);
        if (!password_present_ && !tc_url.empty()) {
            std::string ignored = tc_url;
            std::string pw;
            if (split_credential(ignored, pw)) {
                password_ = pw;
                password_present_ = true;
            }
        }
        // Window Ack Size, Set Peer Bandwidth, Stream Begin, chunk size.
        const uint8_t win[4] = { 0x00, 0x26, 0x25, 0xa0 };
        send_msg(2, 5, 0, win, sizeof(win));
        const uint8_t bw[5] = { 0x00, 0x26, 0x25, 0xa0, 0x02 };
        send_msg(2, 6, 0, bw, sizeof(bw));
        const uint8_t begin[6] = { 0, 0, 0, 0, 0, 0 };
        send_msg(2, 4, 0, begin, sizeof(begin));
        const uint8_t cs[4] = {
            uint8_t((RTMP_OUT_CHUNK_SIZE >> 24) & 0xff),
            uint8_t((RTMP_OUT_CHUNK_SIZE >> 16) & 0xff),
            uint8_t((RTMP_OUT_CHUNK_SIZE >> 8) & 0xff),
            uint8_t(RTMP_OUT_CHUNK_SIZE & 0xff),
        };
        send_msg(2, 1, 0, cs, sizeof(cs));

        std::vector<uint8_t> b;
        amf_str(b, "_result");
        amf_num(b, txn);
        b.push_back(AMF_OBJECT);
        amf_key(b, "fmsVer");
        amf_str(b, "FMS/3,0,1,123");
        amf_key(b, "capabilities");
        amf_num(b, 31);
        amf_obj_end(b);
        b.push_back(AMF_OBJECT);
        amf_key(b, "level");
        amf_str(b, "status");
        amf_key(b, "code");
        amf_str(b, "NetConnection.Connect.Success");
        amf_key(b, "description");
        amf_str(b, "Connection succeeded.");
        amf_key(b, "objectEncoding");
        amf_num(b, 0);
        amf_obj_end(b);
        send_amf(3, 0, b);

        std::vector<uint8_t> d;
        amf_str(d, "onBWDone");
        amf_num(d, 0);
        amf_null(d);
        amf_num(d, 8192);
        send_amf(3, 0, d);
        return true;
    }

    if (cmd == "releaseStream" || cmd == "FCUnpublish"
        || cmd == "deleteStream" || cmd == "closeStream") {
        if (cmd == "releaseStream") {
            std::vector<uint8_t> b;
            amf_str(b, "_result");
            amf_num(b, txn);
            amf_null(b);
            send_amf(3, 0, b);
            return true;
        }
        // A publisher tearing down: let the caller notice the close.
        if (publishing_ && (cmd == "deleteStream" || cmd == "FCUnpublish")) {
            return fail("publisher unpublished");
        }
        return true;
    }

    if (cmd == "FCPublish") {
        std::string name;
        size_t j = i;
        amf_skip(p, n, j);              // command object, usually null
        amf_read_string(p, n, j, name);
        /*
          The response ffmpeg gets wrong: it writes the command name and
          stops. A camera that waits for the status object here simply
          never publishes, which is the whole reason this file exists.
         */
        std::vector<uint8_t> b;
        amf_str(b, "onFCPublish");
        amf_num(b, 0);
        amf_null(b);
        b.push_back(AMF_OBJECT);
        amf_key(b, "level");
        amf_str(b, "status");
        amf_key(b, "code");
        amf_str(b, "NetStream.Publish.Start");
        amf_key(b, "description");
        amf_str(b, name.empty() ? "Publishing." : name.c_str());
        amf_obj_end(b);
        send_amf(3, 0, b);
        return true;
    }

    if (cmd == "createStream") {
        std::vector<uint8_t> b;
        amf_str(b, "_result");
        amf_num(b, txn);
        amf_null(b);
        amf_num(b, publish_sid_);
        send_amf(3, 0, b);
        return true;
    }

    if (cmd == "publish") {
        if (publishing_ || publish_pending_) {
            return fail("second publish on one connection");
        }
        if (!connected_) {
            return fail("publish before connect");
        }
        std::string name;
        size_t j = i;
        amf_skip(p, n, j);              // command object
        if (!amf_read_string(p, n, j, name)) {
            return fail("publish without a stream name");
        }
        stream_ = name;
        std::string pw;
        if (split_credential(stream_, pw)) {
            password_ = pw;
            password_present_ = true;
        }
        publish_txn_ = txn;
        publish_sid_ = c.sid != 0 ? c.sid : 1;
        publish_pending_ = true;
        return true;            // the caller authorises, then answers
    }

    if (cmd == "play" || cmd == "play2") {
        return fail("this port accepts publishers only");
    }
    return true;                // unknown commands are ignored
}

void RtmpSession::accept_publish(void)
{
    if (!publish_pending_) {
        return;
    }
    publish_pending_ = false;
    publishing_ = true;
    publishing_since_ = now_ != 0 ? now_ : started_;

    // Stream Begin for the publishing stream, then the status the
    // client is waiting on.
    uint8_t begin[6] = { 0, 0, 0, 0, 0, 0 };
    begin[2] = uint8_t((publish_sid_ >> 24) & 0xff);
    begin[3] = uint8_t((publish_sid_ >> 16) & 0xff);
    begin[4] = uint8_t((publish_sid_ >> 8) & 0xff);
    begin[5] = uint8_t(publish_sid_ & 0xff);
    send_msg(2, 4, 0, begin, sizeof(begin));

    std::vector<uint8_t> b;
    amf_str(b, "onStatus");
    amf_num(b, 0);
    amf_null(b);
    b.push_back(AMF_OBJECT);
    amf_key(b, "level");
    amf_str(b, "status");
    amf_key(b, "code");
    amf_str(b, "NetStream.Publish.Start");
    amf_key(b, "description");
    amf_str(b, stream_.empty() ? "Publishing."
                               : (stream_ + " is now published.").c_str());
    amf_key(b, "clientid");
    amf_num(b, 1);
    amf_obj_end(b);
    send_msg(5, 20, publish_sid_, b.data(), b.size());

    write_flv_header();
}

void RtmpSession::reject_publish(const char *code, const char *description)
{
    publish_pending_ = false;
    std::vector<uint8_t> b;
    amf_str(b, "onStatus");
    amf_num(b, publish_txn_);
    amf_null(b);
    b.push_back(AMF_OBJECT);
    amf_key(b, "level");
    amf_str(b, "error");
    amf_key(b, "code");
    amf_str(b, code);
    amf_key(b, "description");
    amf_str(b, description);
    amf_obj_end(b);
    send_msg(5, 20, publish_sid_, b.data(), b.size());
    error_ = description;
    state_ = RTMP_DEAD;
}

// ----------------------------------------------------------------- FLV

void RtmpSession::write_flv_header(void)
{
    if (flv_header_written_) {
        return;
    }
    flv_header_written_ = true;
    // "FLV", version 1, audio+video present, 9-byte header, then the
    // zero PreviousTagSize the first tag follows.
    static const uint8_t h[13] = {
        'F', 'L', 'V', 0x01, 0x05, 0x00, 0x00, 0x00, 0x09,
        0x00, 0x00, 0x00, 0x00,
    };
    to_flv_.insert(to_flv_.end(), h, h + sizeof(h));
}

void RtmpSession::write_flv_tag(uint8_t type, uint32_t ts,
                                const uint8_t *p, size_t n)
{
    const size_t at = to_flv_.size();
    to_flv_.push_back(type);
    to_flv_.push_back(uint8_t((n >> 16) & 0xff));
    to_flv_.push_back(uint8_t((n >> 8) & 0xff));
    to_flv_.push_back(uint8_t(n & 0xff));
    to_flv_.push_back(uint8_t((ts >> 16) & 0xff));
    to_flv_.push_back(uint8_t((ts >> 8) & 0xff));
    to_flv_.push_back(uint8_t(ts & 0xff));
    to_flv_.push_back(uint8_t((ts >> 24) & 0xff));   // extended byte
    to_flv_.push_back(0);
    to_flv_.push_back(0);
    to_flv_.push_back(0);
    to_flv_.insert(to_flv_.end(), p, p + n);
    const uint32_t tagsz = uint32_t(to_flv_.size() - at);
    to_flv_.push_back(uint8_t((tagsz >> 24) & 0xff));
    to_flv_.push_back(uint8_t((tagsz >> 16) & 0xff));
    to_flv_.push_back(uint8_t((tagsz >> 8) & 0xff));
    to_flv_.push_back(uint8_t(tagsz & 0xff));
}

void RtmpSession::on_media(uint8_t type, uint32_t ts,
                           const uint8_t *p, size_t n)
{
    if (!publishing_ || n == 0) {
        return;                 // pre-publish media is not ours to keep
    }
    if (type == 9 && vcodec_ == RTMP_VCODEC_NONE) {
        /*
          Legacy tag header: codec id in the low nibble, 7 being AVC.
          Enhanced RTMP sets the high bit and carries a FourCC instead,
          which is how HEVC arrives.
         */
        if ((p[0] & 0x80) == 0) {
            vcodec_ = (p[0] & 0x0f) == 7 ? RTMP_VCODEC_H264
                                         : RTMP_VCODEC_OTHER;
        } else if (n >= 5) {
            vcodec_ = memcmp(p + 1, "avc1", 4) == 0 ? RTMP_VCODEC_H264
                                                    : RTMP_VCODEC_OTHER;
        }
    }
    if (type == 18) {
        /*
          RTMP sends metadata as @setDataFrame("onMetaData", {...}); FLV
          wants the onMetaData call on its own, so drop the wrapper.
         */
        static const char tag[] = "@setDataFrame";
        const size_t skip = 3 + sizeof(tag) - 1;
        if (n > skip && p[0] == AMF_STRING
            && p[1] == 0 && p[2] == uint8_t(sizeof(tag) - 1)
            && memcmp(p + 3, tag, sizeof(tag) - 1) == 0) {
            p += skip;
            n -= skip;
        }
    }
    media_bytes_ += n;
    write_flv_tag(type, ts, p, n);
}
