/*
  handle websocket connections
 */
#include "websocket.h"
#include <sys/socket.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <string>
#include <openssl/sha.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#ifndef SSL_CERT_DIR
#define SSL_CERT_DIR "./"
#endif

// Only the method token is matched, not a whole request line: the target
// may be any path/query ("/", "/v1?token=..."), and matching a literal
// "GET / HTTP/1.1" would reject those. "GET " is still unambiguous against
// the alternatives on this port -- a raw MAVLink2 frame starts 0xFD (v1
// 0xFE) and a TLS ClientHello 0x16.
static const char *ws_prefix = "GET ";
static uint8_t wss_prefix[] { 0x16, 0x03, 0x01 };

// WebSocket opcodes (RFC 6455 s5.2)
#define WS_OP_CONT  0x0
#define WS_OP_TEXT  0x1
#define WS_OP_BIN   0x2
#define WS_OP_CLOSE 0x8
#define WS_OP_PING  0x9
#define WS_OP_PONG  0xA

// Read chunk when pulling from the socket.
#define WS_READ_CHUNK 16384

/*
  see if this could be a WebSocket connection by looking at the first
  packet
 */
ws_detect_t WebSocket::detect(int fd)
{
    const size_t ws_len = strlen(ws_prefix);          // 4 ("GET ")
    const size_t wss_len = sizeof(wss_prefix);        // 3 (TLS ClientHello)
    uint8_t peekbuf[8] {};

    ssize_t peekn = ::recv(fd, peekbuf, sizeof(peekbuf), MSG_PEEK);
    if (peekn <= 0) {
	return WS_MORE;   // nothing readable yet; try again
    }
    const size_t n = size_t(peekn);

    // TLS ClientHello (wss). Compare only the bytes we have.
    const size_t wss_cmp = n < wss_len ? n : wss_len;
    if (memcmp(wss_prefix, peekbuf, wss_cmp) == 0) {
	if (n >= wss_len) {
	    return WS_YES;
	}
	return WS_MORE;   // matches so far, need more to be sure
    }

    // HTTP upgrade (ws). ws_prefix is a char*, so its length is strlen(),
    // not sizeof() -- the old sizeof() admitted an 8-byte prefix and then
    // compared against a half-filled buffer, misclassifying a fragmented
    // request as raw MAVLink.
    const size_t ws_cmp = n < ws_len ? n : ws_len;
    if (memcmp(ws_prefix, peekbuf, ws_cmp) == 0) {
	if (n >= ws_len) {
	    return WS_YES;
	}
	return WS_MORE;   // matches so far, need more to be sure
    }

    // Doesn't match either handshake prefix. A raw MAVLink2 frame
    // starts with 0xFD (v1: 0xFE), never 'G' or 0x16, so this is a
    // definite raw connection even from a single byte.
    return WS_NO;
}

/*
  constructor
 */
WebSocket::WebSocket(int _fd, size_t _max_message) :
    max_message(_max_message)
{
    fd = _fd;
    uint8_t peekbuf[8] {};

    const ssize_t peekn = ::recv(fd, peekbuf, sizeof(peekbuf), MSG_PEEK);
    if (peekn >= ssize_t(sizeof(wss_prefix)) && memcmp(wss_prefix, peekbuf, sizeof(wss_prefix)) == 0) {
	// SSL connection
	_is_SSL = true;
    }

    if (_is_SSL) {
	/*
	  setup SSL connection with OpenSSL
	 */
	const char *cert_file = SSL_CERT_DIR "fullchain.pem";
	const char *key_file  = SSL_CERT_DIR "privkey.pem";
	SSL_library_init();
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();
	ctx = SSL_CTX_new(TLS_server_method());
	if (!ctx) {
	    printf("SSL_CTX_new failed");
	    return;
	}
	if (SSL_CTX_use_certificate_chain_file(ctx, cert_file) <= 0) {
	    ERR_print_errors_fp(stdout);
	    return;
	}
	if (SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM) <= 0) {
	    ERR_print_errors_fp(stdout);
	    return;
	}
	ssl = SSL_new(ctx);
	SSL_set_fd(ssl, fd);
    }

    fill_pending();
    check_headers();
}

/*
  destructor: release the SSL objects. The socket fd is owned by the
  caller (Connection2 / listen_port) and is closed there, never here.
 */
WebSocket::~WebSocket()
{
    if (ssl) {
	SSL_free(ssl);
	ssl = nullptr;
    }
    if (ctx) {
	SSL_CTX_free(ctx);
	ctx = nullptr;
    }
}

void WebSocket::check_headers(void)
{
    // Headers end at the first blank line. Without waiting for the full
    // terminator a fragmented request could be parsed with a truncated
    // (or absent) key.
    static const char terminator[] = "\r\n\r\n";
    if (rx.size() < 4) {
        return;
    }
    const uint8_t *end = nullptr;
    for (size_t i = 0; i + 4 <= rx.size(); i++) {
        if (memcmp(&rx[i], terminator, 4) == 0) {
            end = &rx[i] + 4;
            break;
        }
    }
    if (end == nullptr) {
        return;
    }
    const size_t header_bytes = size_t(end - rx.data());
    std::string headers(reinterpret_cast<const char *>(rx.data()), header_bytes);

    // Request target from "GET <target> HTTP/1.1", for path routing.
    const size_t sp1 = headers.find(' ');
    if (sp1 != std::string::npos) {
        const size_t sp2 = headers.find(' ', sp1 + 1);
        if (sp2 != std::string::npos) {
            req_target = headers.substr(sp1 + 1, sp2 - sp1 - 1);
        }
    }

    std::string key_marker = "Sec-WebSocket-Key: ";
    size_t key_pos = headers.find(key_marker);
    if (key_pos != std::string::npos) {
        key_pos += key_marker.length();
        size_t hend = headers.find("\r\n", key_pos);
        if (hend != std::string::npos) {
            std::string sec_key = headers.substr(key_pos, hend - key_pos);
            if (send_handshake(sec_key)) {
                done_headers = true;
                // Drop only the header bytes: a client may pipeline its
                // first frame into the same segment, and discarding the
                // whole buffer would lose it.
                rx.erase(rx.begin(), rx.begin() + header_bytes);
                printf("WebSocket: done headers\n");
            }
        }
    }
}

/*
  try to receive more data
 */
void WebSocket::fill_pending(void)
{
    if (fd < 0) {
        return;
    }
    // Bound the raw buffer too: a peer that never completes a frame must
    // not be able to make us grow without limit.
    if (rx.size() > max_message + 64) {
        printf("WebSocket: receive buffer overflow\n");
        fd = -1;
        return;
    }
    const size_t off = rx.size();
    rx.resize(off + WS_READ_CHUNK);
    ssize_t n = 0;
    if (ssl) {
        if (!SSL_handshake_complete) {
            auto res = SSL_accept(ssl);
            if (res <= 0) {
                int err = SSL_get_error(ssl, res);
                rx.resize(off);
                if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                    // still pending
                    return;
                }
                ERR_print_errors_fp(stdout);
                fd = -1;  // owner closes the socket
                return;
            }
            printf("SSL handshake completed\n");
            SSL_handshake_complete = true;
        }
        n = SSL_read(ssl, &rx[off], WS_READ_CHUNK);
        if (n <= 0) {
            int err = SSL_get_error(ssl, n);
            rx.resize(off);
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                return;
            }
            if (err == SSL_ERROR_ZERO_RETURN) {
                // orderly shutdown
                fd = -1;  // owner closes the socket
                return;
            }
            ERR_print_errors_fp(stdout);
            fd = -1;  // owner closes the socket
            return;
        }
    } else {
        n = ::recv(fd, &rx[off], WS_READ_CHUNK, 0);
        if (n < 0) {
            rx.resize(off);
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return;
            }
            fd = -1;  // owner closes the socket
            return;
        }
        if (n == 0) {
            // EOF
            rx.resize(off);
            fd = -1;  // owner closes the socket
            return;
        }
    }
    rx.resize(off + size_t(n));
}

/*
  Decode complete frames out of rx, appending payload to msg.

  Handles fragmentation (continuation frames until FIN) and control
  frames (ping is answered, close ends the stream, pong ignored) rather
  than passing them to the caller as if they were data.

  Returns false if the stream is unrecoverable and the connection must
  be failed.
 */
bool WebSocket::decode_frames(void)
{
    size_t pos = 0;
    for (;;) {
        if (rx.size() - pos < 2) {
            break;
        }
        const uint8_t *f = &rx[pos];
        const bool fin = (f[0] & 0x80) != 0;
        const uint8_t opcode = f[0] & 0x0F;
        const bool masked = (f[1] & 0x80) != 0;
        uint64_t payload_len = f[1] & 0x7F;
        size_t hdr = 2;

        if (payload_len == 126) {
            if (rx.size() - pos < 4) break;
            // assemble by hand: casting the buffer to uint16_t* is
            // undefined for an unaligned address and trips -Wcast-align
            payload_len = (uint64_t(f[2]) << 8) | uint64_t(f[3]);
            hdr = 4;
        } else if (payload_len == 127) {
            if (rx.size() - pos < 10) break;
            payload_len = 0;
            for (int i = 0; i < 8; i++) {
                payload_len = (payload_len << 8) | uint64_t(f[2 + i]);
            }
            hdr = 10;
        }

        // Bound before any addition: an attacker-supplied length near
        // UINT64_MAX would otherwise wrap the completeness check below.
        if (payload_len > max_message) {
            printf("WebSocket: frame of %llu bytes exceeds limit\n",
                   (unsigned long long)payload_len);
            return false;
        }
        // RFC 6455 s5.1: client-to-server frames MUST be masked.
        if (!masked) {
            printf("WebSocket: unmasked client frame rejected\n");
            return false;
        }
        // Control frames must be short and unfragmented (s5.5).
        const bool is_control = (opcode & 0x8) != 0;
        if (is_control && (payload_len > 125 || !fin)) {
            printf("WebSocket: malformed control frame\n");
            return false;
        }

        const size_t need = hdr + 4 + size_t(payload_len);
        if (rx.size() - pos < need) {
            break;   // incomplete; wait for more
        }

        uint8_t mask[4];
        memcpy(mask, f + hdr, 4);
        uint8_t *payload = &rx[pos + hdr + 4];
        for (size_t i = 0; i < payload_len; i++) {
            payload[i] ^= mask[i % 4];
        }

        switch (opcode) {
        case WS_OP_CLOSE:
            // Echo the close and stop; the owner closes the socket.
            if (!sent_close) {
                queue_frame(WS_OP_CLOSE, payload, size_t(payload_len));
                sent_close = true;
                flush();
            }
            return false;
        case WS_OP_PING:
            queue_frame(WS_OP_PONG, payload, size_t(payload_len));
            flush();
            break;
        case WS_OP_PONG:
            break;   // unsolicited pongs are legal and ignored
        case WS_OP_CONT:
            if (!in_fragment) {
                printf("WebSocket: continuation with no message open\n");
                return false;
            }
            if (msg.size() + payload_len > max_message) {
                printf("WebSocket: fragmented message exceeds limit\n");
                return false;
            }
            msg.insert(msg.end(), payload, payload + payload_len);
            if (fin) {
                in_fragment = false;
            }
            break;
        case WS_OP_TEXT:
        case WS_OP_BIN:
            if (in_fragment) {
                printf("WebSocket: new message while one is open\n");
                return false;
            }
            if (msg.size() + payload_len > max_message) {
                printf("WebSocket: message exceeds limit\n");
                return false;
            }
            msg.insert(msg.end(), payload, payload + payload_len);
            if (!fin) {
                in_fragment = true;
            }
            break;
        default:
            printf("WebSocket: unknown opcode 0x%x\n", unsigned(opcode));
            return false;
        }

        pos += need;
    }

    if (pos > 0) {
        rx.erase(rx.begin(), rx.begin() + pos);
    }
    return true;
}

/*
  helper to base64 encode input
 */
static std::string base64_encode(const uint8_t* input, size_t len)
{
    BIO *bio, *b64;
    BUF_MEM *buffer_ptr;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(bio, input, len);
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &buffer_ptr);

    std::string result(buffer_ptr->data, buffer_ptr->length);
    BIO_free_all(bio);
    return result;
}

/*
  perform websocket handshake response
 */
bool WebSocket::send_handshake(const std::string &key)
{
    if (handshake_len == 0) {
        const char *guid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
        std::string accept_src = key + guid;

        uint8_t sha1_hash[SHA_DIGEST_LENGTH];
        SHA1((const unsigned char *)accept_src.c_str(), accept_src.length(), sha1_hash);

        std::string accept_val = base64_encode(sha1_hash, SHA_DIGEST_LENGTH);

        int n = snprintf(handshake_buf, sizeof(handshake_buf),
                         "HTTP/1.1 101 Switching Protocols\r\n"
                         "Upgrade: websocket\r\n"
                         "Connection: Upgrade\r\n"
                         "Sec-WebSocket-Accept: %s\r\n"
                         "\r\n",
                         accept_val.c_str());
        if (n < 0) {
            return false;
        }
        handshake_len = (size_t)n;
        handshake_sent = 0;
    }

    while (handshake_sent < handshake_len) {
        ssize_t wret;
        if (ssl) {
            wret = SSL_write(ssl, handshake_buf + handshake_sent, handshake_len - handshake_sent);
            if (wret <= 0) {
                int err = SSL_get_error(ssl, wret);
                if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ) {
                    return false; // try again later
                }
                ERR_print_errors_fp(stdout);
                fd = -1;  // owner closes the socket
                return false;
            }
        } else {
            wret = ::send(fd, handshake_buf + handshake_sent, handshake_len - handshake_sent, 0);
            if (wret < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    return false;
                }
                fd = -1;  // owner closes the socket
                return false;
            }
        }
        handshake_sent += (size_t)wret;
    }
    return handshake_sent == handshake_len;
}

/*
  append a framed message to the output queue
 */
void WebSocket::queue_frame(uint8_t opcode, const void *data, size_t n)
{
    uint8_t header[10];
    size_t header_len;
    header[0] = uint8_t(0x80 | opcode);   // FIN + opcode

    if (n <= 125) {
        header[1] = uint8_t(n);
        header_len = 2;
    } else if (n <= 65535) {
        header[1] = 126;
        header[2] = uint8_t((n >> 8) & 0xFF);
        header[3] = uint8_t(n & 0xFF);
        header_len = 4;
    } else {
        header[1] = 127;
        for (int i = 0; i < 8; i++) {
            header[2 + i] = uint8_t((uint64_t(n) >> (56 - 8*i)) & 0xFF);
        }
        header_len = 10;
    }

    // Drop the fully-flushed prefix first so tx doesn't grow forever on
    // a long-lived link.
    if (tx_sent > 0 && tx_sent == tx.size()) {
        tx.clear();
        tx_sent = 0;
    }
    tx.insert(tx.end(), header, header + header_len);
    const uint8_t *p = static_cast<const uint8_t *>(data);
    tx.insert(tx.end(), p, p + n);
}

/*
  push queued output to the socket
 */
bool WebSocket::flush(void)
{
    while (tx_sent < tx.size()) {
        const size_t remain = tx.size() - tx_sent;
        ssize_t wret;
        if (_is_SSL && ssl) {
            wret = SSL_write(ssl, &tx[tx_sent], int(remain));
            if (wret <= 0) {
                int err = SSL_get_error(ssl, wret);
                if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ) {
                    return true;   // stays queued
                }
                ERR_print_errors_fp(stdout);
                fd = -1;
                return false;
            }
        } else {
            wret = ::send(fd, &tx[tx_sent], remain, 0);
            if (wret < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    return true;   // stays queued
                }
                fd = -1;
                return false;
            }
        }
        tx_sent += size_t(wret);
    }
    tx.clear();
    tx_sent = 0;
    return true;
}

/*
  encode a packet onto a connected WebSocket
 */
ssize_t WebSocket::send(const void *buf, size_t n)
{
    if (!done_headers) {
	// The HTTP upgrade response hasn't been sent yet. Writing a
	// MAVLink frame onto the socket now would land *before* the
	// "HTTP/1.1 101" line and corrupt the handshake (the peer's WS
	// parser sees binary garbage as the status line). Drop the
	// frame but report it as sent so the caller doesn't treat it as
	// a dead link and tear the session down; the handshake
	// completes on the next read and forwarding resumes.
	return n;
    }
    if (fd < 0) {
        return -1;
    }
    // Queue-then-flush rather than write-and-hope. Previously a short
    // write returned 0, which send_message() reports as failure and the
    // caller turns into a connection teardown -- so a momentarily full
    // socket killed the session. Framing once into tx and tracking
    // tx_sent means a partial write simply resumes where it left off.
    if (tx.size() - tx_sent > WS_MAX_TX_QUEUE) {
        printf("WebSocket: output queue full, dropping connection\n");
        fd = -1;
        return -1;
    }
    queue_frame(WS_OP_BIN, buf, n);
    if (!flush()) {
        return -1;
    }
    return n;
}

/*
  receive some data
 */
ssize_t WebSocket::recv(void *buf, size_t n)
{
    // Hand back anything already decoded before reading more, so a
    // caller with a small buffer drains a large message across calls
    // instead of losing the remainder.
    if (msg_taken < msg.size()) {
        const size_t avail = msg.size() - msg_taken;
        const size_t take = n < avail ? n : avail;
        memcpy(buf, &msg[msg_taken], take);
        msg_taken += take;
        if (msg_taken == msg.size()) {
            msg.clear();
            msg_taken = 0;
        }
        return ssize_t(take);
    }

    fill_pending();
    if (fd < 0) {
	return -1;
    }
    if (!done_headers) {
	check_headers();
	if (!done_headers) {
	    // don't decode partial HTTP upgrade headers as a frame:
	    // that consumed header bytes and broke the handshake when
	    // the request arrived fragmented
	    return 0;
	}
    }
    if (!decode_frames()) {
        fd = -1;  // owner closes the socket
        return -1;
    }
    // A message still being assembled from fragments isn't deliverable yet.
    if (in_fragment || msg.empty()) {
        return 0;
    }
    const size_t take = n < msg.size() ? n : msg.size();
    memcpy(buf, msg.data(), take);
    msg_taken = take;
    if (msg_taken == msg.size()) {
        msg.clear();
        msg_taken = 0;
    }
    return ssize_t(take);
}
