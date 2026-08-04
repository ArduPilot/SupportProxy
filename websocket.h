/*
  handle websocket connections
 */

#pragma once

#include <stdint.h>
#include <unistd.h>
#include <string>
#include <vector>
#include <openssl/ssl.h>

// Result of peeking at a new TCP stream's first bytes.
//   WS_NO   - definitely not a WebSocket/TLS handshake (raw MAVLink)
//   WS_YES  - a WebSocket (HTTP upgrade) or TLS ClientHello
//   WS_MORE - the bytes so far are a prefix of a handshake but there
//             aren't enough yet to decide; the caller must wait for
//             more rather than committing to raw (committing early
//             misclassifies a fragmented handshake as raw MAVLink)
enum ws_detect_t { WS_NO, WS_YES, WS_MORE };

// Largest single WebSocket message we will reassemble. MAVLink frames are
// <300 bytes; video sends 8-64 KiB. A message larger than this fails the
// connection rather than being buffered without bound.
#define WS_DEFAULT_MAX_MESSAGE (256*1024)

// Cap on framed-but-unwritten output. A peer that stops reading must not
// make us buffer without bound; past this we fail the connection.
#define WS_MAX_TX_QUEUE (1024*1024)

class WebSocket {
public:
    explicit WebSocket(int fd, size_t max_message = WS_DEFAULT_MAX_MESSAGE);
    ~WebSocket();

    static ws_detect_t detect(int fd);
    ssize_t send(const void *buf, size_t n);
    ssize_t recv(void *buf, size_t n);
    bool is_SSL(void) const {
	return _is_SSL;
    }

    // Request target from the HTTP upgrade line ("/", "/v1?token=..."),
    // empty until the handshake completes. Lets a caller route on path.
    const std::string &request_target(void) const {
        return req_target;
    }

    // Push queued output. Callers driving a write-ready event loop use
    // this; send() also flushes opportunistically. False = link is dead.
    bool flush(void);
    bool has_pending_output(void) const {
        return tx_sent < tx.size();
    }

private:
    int fd = -1;
    bool _is_SSL = false;
    bool SSL_handshake_complete = false;
    SSL *ssl = nullptr;
    SSL_CTX *ctx = nullptr;
    bool done_headers = false;
    bool sent_close = false;

    const size_t max_message;

    std::vector<uint8_t> rx;        // raw bytes read off the socket
    std::vector<uint8_t> msg;       // decoded payload not yet handed to caller
    size_t msg_taken = 0;           // how much of msg the caller has consumed
    bool in_fragment = false;       // mid multi-frame message

    std::vector<uint8_t> tx;        // framed output
    size_t tx_sent = 0;             // how much of tx has reached the socket

    std::string req_target;

    char handshake_buf[512] {};
    size_t handshake_len = 0;
    size_t handshake_sent = 0;

    void fill_pending(void);
    bool send_handshake(const std::string &key);
    void check_headers(void);
    // Pull complete frames out of rx into msg. Returns false if the
    // stream is unrecoverable and the connection must be failed.
    bool decode_frames(void);
    void queue_frame(uint8_t opcode, const void *data, size_t n);
};
