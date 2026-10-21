/* RTSP playback of the existing MPEG-TS ring, over interleaved TCP.
 * The socket remains owned by VideoViewer. No child or extra ports are needed.
 */
#pragma once

#include <stdint.h>
#include <time.h>
#include <string>

#include "keydb.h"
#include "videomkv.h"
#include "videostream.h"

#define VIDEO_RTSP_AUTH_TIMEOUT_S 15
#define VIDEO_RTSP_SESSION_TIMEOUT_S 60
#define VIDEO_RTSP_TIMEOUT_GRACE_S 5

class RtspViewer {
public:
    RtspViewer(int fd, int port2, time_t now);
    bool on_readable(const KeyEntry &ke, int slot, const VideoRing &ring,
                     const VideoScanner &scanner, time_t now);
    bool on_writable(const VideoRing &ring, time_t now);
    bool wants_write() const { return blocked_ || sent_ < out_.size(); }
    uint64_t bytes_sent() const { return bytes_sent_; }
    const char *drop_reason() const { return reason_; }
    static bool playback_target(const std::string &target);

private:
    int fd_, port2_;
    std::string input_, out_, session_;
    size_t sent_ = 0;
    bool authorised_ = false, setup_ = false, playing_ = false;
    bool played_ = false;
    bool closing_ = false, blocked_ = false;
    uint8_t channel_ = 0;
    uint16_t seq_ = 0;
    uint32_t ssrc_ = 0;
    uint64_t read_pos_ = 0, bytes_sent_ = 0;
    uint32_t packets_ = 0, octets_ = 0;
    time_t connected_, progress_, control_, report_ = 0;
    unsigned auth_failures_ = 0;
    const char *reason_ = "RTSP connection closed";

    bool request(const std::string &head, const KeyEntry &ke, int slot,
                 const VideoRing &ring, const VideoScanner &scanner, time_t now);
    void reply(const std::string &cseq, int code, const char *reason,
               const std::string &headers = "", const std::string &body = "");
    bool flush(time_t now);
    void sender_report(uint32_t timestamp);
};
