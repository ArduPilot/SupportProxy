#include "videortspview.h"
#include "videoview.h"
#include "videoauth.h"
#include "httpreq.h"

#include <algorithm>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <openssl/rand.h>

namespace {
constexpr size_t REQUEST_LIMIT = 16384;
constexpr size_t RTP_PAYLOAD = 7 * TS_PACKET_SIZE;

std::string path(const std::string &target)
{
    size_t start = 0;
    if (target.compare(0, 7, "rtsp://") == 0) {
        start = target.find('/', 7);
        if (start == std::string::npos) return "/";
    }
    return target.substr(start, target.find('?', start) - start);
}

bool decimal(const std::string &s, unsigned &value, unsigned max)
{
    if (s.empty()) return false;
    value = 0;
    for (unsigned char c : s) {
        if (c < '0' || c > '9' || value > max / 10) return false;
        value = value * 10 + c - '0';
        if (value > max) return false;
    }
    return true;
}

void put32(std::string &s, uint32_t v)
{
    for (int shift = 24; shift >= 0; shift -= 8) s += char(v >> shift);
}

uint32_t timestamp()
{
    struct timespec t {};
    clock_gettime(CLOCK_MONOTONIC, &t);
    return uint32_t(uint64_t(t.tv_sec) * 90000 + t.tv_nsec * 9 / 100000);
}

std::string trim(const std::string &s)
{
    const size_t first = s.find_first_not_of(" \t");
    if (first == std::string::npos) return "";
    return s.substr(first, s.find_last_not_of(" \t") - first + 1);
}

bool tcp_transport(const std::string &header, unsigned &channel)
{
    size_t offset = 0;
    while (offset < header.size()) {
        const size_t comma = header.find(',', offset);
        const std::string entry = trim(header.substr(offset, comma-offset));
        const size_t semicolon = entry.find(';');
        bool valid = trim(entry.substr(0, semicolon)) == "RTP/AVP/TCP";
        bool have_channels = false;
        unsigned first = 0, second;
        size_t param = semicolon;
        while (param != std::string::npos) {
            const size_t next = entry.find(';', param + 1);
            const std::string value = trim(entry.substr(param + 1, next-param-1));
            if (value == "multicast") valid = false;
            if (value.compare(0, 12, "interleaved=") == 0) {
                const std::string channels = value.substr(12);
                const size_t dash = channels.find('-');
                valid = valid && !have_channels && dash != std::string::npos &&
                    decimal(channels.substr(0, dash), first, 254) &&
                    decimal(channels.substr(dash + 1), second, 255) && second == first + 1;
                have_channels = true;
            }
            param = next;
        }
        if (valid) {
            channel = first;
            return true;
        }
        if (comma == std::string::npos) break;
        offset = comma + 1;
    }
    return false;
}

bool normal_scale(const std::string &scale)
{
    if (scale.empty()) return true;
    char *end = nullptr;
    errno = 0;
    const double value = strtod(scale.c_str(), &end);
    return errno == 0 && end != scale.c_str() && *end == '\0' && value == 1.0;
}

bool valid_rtcp(const uint8_t *data, size_t size)
{
    if (size < 4) return false;
    size_t offset = 0;
    while (offset < size) {
        const uint8_t *p = data + offset;
        if (size-offset < 4 || (p[0] >> 6) != 2 || p[1] < 192 || p[1] > 223)
            return false;
        const size_t length = ((size_t(p[2]) << 8) | p[3]) * 4 + 4;
        if (length > size-offset) return false;
        if (p[1] == 201 && length < 8 + 24 * size_t(p[0] & 31)) return false;
        if ((p[0] & 0x20) && (offset+length != size || p[length-1] == 0 || p[length-1] > length-4))
            return false;
        offset += length;
    }
    return true;
}
}

RtspViewer::RtspViewer(int fd, int port2, time_t now)
    : fd_(fd), port2_(port2), connected_(now), progress_(now), control_(now)
{
    uint8_t random[14];
    if (RAND_bytes(random, sizeof(random)) != 1) {
        closing_ = true;
        reason_ = "RTSP random generation failed";
        return;
    }
    char id[17];
    for (size_t i = 0; i < 8; i++) snprintf(id + 2*i, 3, "%02x", random[i]);
    session_ = id;
    memcpy(&ssrc_, random + 8, sizeof(ssrc_));
    memcpy(&seq_, random + 12, sizeof(seq_));
}

bool RtspViewer::playback_target(const std::string &target)
{
    return path(target).compare(0, 6, "/view/") == 0;
}

void RtspViewer::reply(const std::string &cseq, int code, const char *reason,
                       const std::string &headers, const std::string &body)
{
    out_ += "RTSP/1.0 " + std::to_string(code) + " " + reason + "\r\n"
            "CSeq: " + cseq + "\r\n" + headers +
            "Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
}

bool RtspViewer::request(const std::string &head, const KeyEntry &ke, int slot,
                         const VideoRing &ring, const VideoScanner &scanner,
                         time_t now)
{
    HttpRequest req;
    if (req.feed(reinterpret_cast<const uint8_t *>(head.data()), head.size()) != 1)
        return false;
    const size_t eol = head.find("\r\n");
    if (eol == std::string::npos || eol < 9 || head.substr(eol-9, 9) != " RTSP/1.0")
        return false;
    const std::string cseq = req.header("CSeq");
    for (unsigned char c : req.target()) {
        if (c <= 0x20 || c == 0x7f) return false;
    }
    unsigned number;
    if (req.header_count("CSeq") != 1 || !decimal(cseq, number, 2147483647))
        return false;
    control_ = now;
    const std::string &method = req.method();
    if (method == "OPTIONS") {
        reply(cseq, 200, "OK", "Public: OPTIONS, DESCRIBE, SETUP, PLAY, PAUSE, TEARDOWN, GET_PARAMETER\r\n");
        return true;
    }
    const std::string base = "/view/v" + std::to_string(slot + 1);
    const std::string target_path = path(req.target());
    if (target_path != base && target_path != base + "/" && target_path != base + "/trackID=0") {
        reply(cseq, 404, "Not Found");
        return true;
    }

    std::string pw, token;
    const bool has_pw = http_query_value(req.target(), "pw", pw);
    const bool has_token = http_query_value(req.target(), "t", token);
    const bool has_basic = req.header_count("Authorization") != 0;
    bool permitted = authorised_;
    if (!authorised_ || has_pw || has_token || has_basic) {
        permitted = (has_token && video_token_valid(ke, port2_, slot, token.c_str(), now));
        if (!permitted) {
            if (!has_pw) pw = http_basic_password(req.header("Authorization"));
            permitted = video_viewer_authorised(ke, pw);
        }
    }
    if (!permitted) {
        reply(cseq, 401, "Unauthorized", "WWW-Authenticate: Basic realm=\"SupportProxy video\"\r\n");
        if (++auth_failures_ >= 3) closing_ = true;
        return true;
    }
    authorised_ = true;
    if (scanner.matroska) {
        reply(cseq, 415, "Unsupported Media Type");
        return true;
    }
    if (method == "DESCRIBE") {
        uint64_t anchor;
        if (!scanner.join_offset(anchor) || !ring.resident(anchor)) {
            reply(cseq, 503, "Service Unavailable");
            return true;
        }
        // A relative track URL deliberately carries no password or token.
        // Admission belongs to this TCP connection, including subsequent SETUP.
        std::string location = req.target().substr(0, req.target().find('?'));
        if (location.back() != '/') location += '/';
        const std::string sdp =
            "v=0\r\no=- " + std::to_string(ssrc_) + " 1 IN IP4 0.0.0.0\r\n"
            "s=SupportProxy video\r\nc=IN IP4 0.0.0.0\r\nt=0 0\r\n"
            "a=control:*\r\nm=video 0 RTP/AVP 33\r\n"
            "a=rtpmap:33 MP2T/90000\r\na=control:trackID=0\r\n";
        reply(cseq, 200, "OK", "Content-Type: application/sdp\r\nContent-Base: " + location + "\r\n", sdp);
    } else if (method == "SETUP") {
        if (playing_) {
            reply(cseq, 455, "Method Not Valid in This State");
            return true;
        }
        // Only interleaved unicast TCP. Never connect or send UDP to a
        // client-supplied destination (including Transport destination=).
        unsigned first;
        if (!tcp_transport(req.header("Transport"), first)) {
            reply(cseq, 461, "Unsupported Transport");
            return true;
        }
        const std::string requested_session = req.header("Session");
        if (!requested_session.empty() && requested_session != session_) {
            reply(cseq, 454, "Session Not Found");
            return true;
        }
        setup_ = true;
        channel_ = uint8_t(first);
        reply(cseq, 200, "OK", "Session: " + session_ + ";timeout=" +
              std::to_string(VIDEO_RTSP_SESSION_TIMEOUT_S) + "\r\n"
              "Transport: RTP/AVP/TCP;unicast;interleaved=" + std::to_string(first) + "-" +
              std::to_string(first + 1) + "\r\n");
    } else if (method == "PLAY" || method == "PAUSE" || method == "TEARDOWN" || method == "GET_PARAMETER") {
        if (!setup_ || req.header("Session") != session_) {
            reply(cseq, 454, "Session Not Found");
            return true;
        }
        if (method == "PLAY") {
            // Live-only. Seeking and Scale would need different ring policy.
            const std::string range = req.header("Range");
            if ((!range.empty() && range != "npt=0.000-" && range != "npt=0-" && range != "npt=now-") ||
                !normal_scale(req.header("Scale"))) {
                reply(cseq, 457, "Invalid Range");
                return true;
            }
            // A short pause must not rewind within the existing RTP
            // session. Only the first PLAY or an overwritten cursor
            // needs a new keyframe anchor.
            if (!playing_ && (!played_ || !ring.resident(read_pos_)) &&
                (!scanner.join_offset(read_pos_) || !ring.resident(read_pos_))) {
                reply(cseq, 503, "Service Unavailable");
                return true;
            }
            playing_ = true;
            played_ = true;
            progress_ = now;
        } else if (method == "PAUSE") {
            playing_ = false;
        } else if (method == "TEARDOWN") {
            playing_ = false;
            closing_ = true;
        }
        reply(cseq, 200, "OK", "Session: " + session_ + "\r\n");
    } else {
        reply(cseq, 405, "Method Not Allowed");
    }
    return true;
}

bool RtspViewer::on_readable(const KeyEntry &ke, int slot, const VideoRing &ring,
                             const VideoScanner &scanner, time_t now)
{
    if (closing_ && sent_ == out_.size()) return false;
    if (!authorised_ && now-connected_ > VIDEO_RTSP_AUTH_TIMEOUT_S) {
        reason_ = "RTSP authentication timeout";
        return false;
    }
    uint8_t buf[4096];
    const ssize_t n = recv(fd_, buf, sizeof(buf), 0);
    if (n == 0) return false;
    if (n < 0) return errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR;
    // EPOLLIN remains level-triggered while queued output is flushed.
    // Consume and discard further input so a blocked TEARDOWN reply
    // cannot spin the shared video child on unread data or EOF.
    if (closing_) return true;
    input_.append(reinterpret_cast<const char *>(buf), size_t(n));
    if (input_.size() > REQUEST_LIMIT) return false;
    while (!input_.empty()) {
        if (input_[0] == '$') {
            if (input_.size() < 4) break;
            const size_t len = (uint8_t(input_[2]) << 8) | uint8_t(input_[3]);
            if (!setup_ || uint8_t(input_[1]) != channel_ + 1 || len > REQUEST_LIMIT - 4)
                return false;
            if (input_.size() < len + 4) break;
            if (!valid_rtcp(reinterpret_cast<const uint8_t *>(input_.data()+4), len))
                return false;
            control_ = now;
            input_.erase(0, len + 4); // bounded RTCP receiver reports
            continue;
        }
        const size_t end = input_.find("\r\n\r\n");
        if (end == std::string::npos) break;
        const size_t header_size = end + 4;
        HttpRequest req;
        if (req.feed(reinterpret_cast<const uint8_t *>(input_.data()), header_size) != 1)
            return false;
        unsigned body_size = 0;
        if (req.header_count("Content-Length") > 1 || req.header_count("Transfer-Encoding") ||
            (req.header_count("Content-Length") &&
             !decimal(req.header("Content-Length"), body_size, REQUEST_LIMIT))) return false;
        if (header_size + body_size > REQUEST_LIMIT) return false;
        if (input_.size() < header_size + body_size) break;
        if (!request(input_.substr(0, header_size), ke, slot, ring, scanner, now)) return false;
        input_.erase(0, header_size + body_size);
        if (out_.size() > REQUEST_LIMIT) return false;
        if (closing_) break;
    }
    return true;
}

bool RtspViewer::flush(time_t now)
{
    while (sent_ < out_.size()) {
        const ssize_t n = send(fd_, out_.data() + sent_, out_.size() - sent_, MSG_NOSIGNAL);
        if (n < 0 && errno == EINTR) continue;
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            blocked_ = true;
            if (now - progress_ > VIDEO_VIEWER_STUCK_S) {
                reason_ = "stalled";
                return false;
            }
            return true;
        }
        if (n <= 0) return false;
        sent_ += size_t(n);
        progress_ = now;
    }
    out_.clear(); sent_ = 0; blocked_ = false;
    return true;
}

void RtspViewer::sender_report(uint32_t rtp_time)
{
    // RFC 3550 compound SR + SDES, on the negotiated RTCP channel.
    std::string report;
    report += char(0x80); report += char(200); report += char(0); report += char(6);
    put32(report, ssrc_);
    struct timespec t {};
    clock_gettime(CLOCK_REALTIME, &t);
    put32(report, uint32_t(t.tv_sec + 2208988800ULL));
    put32(report, uint32_t((uint64_t(t.tv_nsec) << 32) / 1000000000));
    put32(report, rtp_time); put32(report, packets_); put32(report, octets_);
    const std::string cname = "SupportProxy-" + session_;
    std::string sdes;
    put32(sdes, ssrc_); sdes += char(1); sdes += char(cname.size()); sdes += cname;
    sdes += char(0);
    while (sdes.size() % 4) sdes += char(0);
    report += char(0x81); report += char(202);
    report += char((sdes.size()/4) >> 8); report += char(sdes.size()/4);
    report += sdes;
    out_ += '$'; out_ += char(channel_ + 1);
    out_ += char(report.size() >> 8); out_ += char(report.size()); out_ += report;
}

bool RtspViewer::on_writable(const VideoRing &ring, time_t now)
{
    if (!authorised_ && now-connected_ > VIDEO_RTSP_AUTH_TIMEOUT_S) {
        reason_ = "RTSP authentication timeout";
        return false;
    }
    // Check even while a partial TCP frame is blocked. Waiting to flush
    // it first would postpone the ring's drop policy until the socket
    // becomes writable, which a wedged viewer might never do.
    if (playing_ && !ring.resident(read_pos_)) {
        reason_ = "fell too far behind (lapped)";
        return false;
    }
    if (!flush(now)) return false;
    if (!out_.empty()) return true;
    if (closing_) return false;
    if (now - control_ > VIDEO_RTSP_SESSION_TIMEOUT_S + VIDEO_RTSP_TIMEOUT_GRACE_S) {
        reason_ = "RTSP control timeout";
        return false;
    }
    if (!playing_) return true;
    size_t budget = VIDEO_VIEWER_WRITE_CHUNK;
    while (budget >= TS_PACKET_SIZE) {
        uint8_t payload[RTP_PAYLOAD];
        const size_t want = std::min(budget, sizeof(payload)) / TS_PACKET_SIZE * TS_PACKET_SIZE;
        const size_t got = ring.read_at(read_pos_, payload, want) / TS_PACKET_SIZE * TS_PACKET_SIZE;
        if (!got) break;
        const uint32_t rtp_time = timestamp();
        if (!report_ || now - report_ >= 5) {
            sender_report(rtp_time);
            report_ = now;
        }
        const size_t length = got + 12;
        out_ += '$'; out_ += char(channel_);
        out_ += char(length >> 8); out_ += char(length);
        out_ += char(0x80); out_ += char(33);
        out_ += char(seq_ >> 8); out_ += char(seq_); seq_++;
        put32(out_, rtp_time); put32(out_, ssrc_);
        out_.append(reinterpret_cast<const char *>(payload), got);
        read_pos_ += got; bytes_sent_ += got;
        packets_++; octets_ += uint32_t(got);
        budget -= got;
        if (!flush(now)) return false;
        if (!out_.empty()) break;
    }
    return true;
}
