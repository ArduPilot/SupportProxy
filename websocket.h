/*
  handle websocket connections
 */

#pragma once

#include <stdint.h>
#include <unistd.h>
#include <string>
#include <openssl/ssl.h>

// Result of peeking at a new TCP stream's first bytes.
//   WS_NO   - definitely not a WebSocket/TLS handshake (raw MAVLink)
//   WS_YES  - a WebSocket (HTTP upgrade) or TLS ClientHello
//   WS_MORE - the bytes so far are a prefix of a handshake but there
//             aren't enough yet to decide; the caller must wait for
//             more rather than committing to raw (committing early
//             misclassifies a fragmented handshake as raw MAVLink)
enum ws_detect_t { WS_NO, WS_YES, WS_MORE };

class WebSocket {
public:
    WebSocket(int fd);
    ~WebSocket();

    static ws_detect_t detect(int fd);
    ssize_t send(const void *buf, size_t n);
    ssize_t recv(void *buf, size_t n);
    bool is_SSL(void) const {
	return _is_SSL;
    }

private:
    int fd = -1;
    bool _is_SSL = false;
    bool SSL_handshake_complete = false;
    uint8_t pending[1024] {};
    uint32_t npending = 0;
    SSL *ssl = nullptr;
    SSL_CTX *ctx = nullptr;
    bool done_headers = false;

    char handshake_buf[512] {};
    size_t handshake_len = 0;
    size_t handshake_sent = 0;

    
    void fill_pending(void);
    bool send_handshake(const std::string &key);
    void check_headers(void);
    ssize_t decode(uint8_t *buf, size_t n, size_t &used);
};
