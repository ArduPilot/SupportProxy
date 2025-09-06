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

static const char *ws_prefix = "GET / HTTP/1.1";
static uint8_t wss_prefix[] { 0x16, 0x03, 0x01 };

/*
  see if this could be a WebSocket connection by looking at the first
  packet
 */
bool WebSocket::detect(int fd)
{
    uint8_t peekbuf[14] {};

    const ssize_t peekn = ::recv(fd, peekbuf, sizeof(peekbuf), MSG_PEEK);
    if (peekn >= ssize_t(sizeof(wss_prefix)) && memcmp(wss_prefix, peekbuf, sizeof(wss_prefix)) == 0) {
	// SSL connection
	return true;
    }
    if (peekn >= ssize_t(sizeof(ws_prefix)) &&
	strncmp(ws_prefix, (const char *)peekbuf, strlen(ws_prefix)) == 0) {
	return true;
    }
    return false;
}

/*
  constructor
 */
WebSocket::WebSocket(int _fd)
{
    fd = _fd;
    uint8_t peekbuf[14] {};

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

void WebSocket::check_headers(void)
{
    auto len = strnlen((const char *)pending, npending);

    // parse Sec-WebSocket-Key from HTTP headers
    std::string headers(reinterpret_cast<const char *>(pending), len);
    std::string key_marker = "Sec-WebSocket-Key: ";
    size_t key_pos = headers.find(key_marker);
    if (key_pos != std::string::npos) {
        key_pos += key_marker.length();
        size_t end = headers.find("\r\n", key_pos);
        if (end != std::string::npos) {
            std::string sec_key = headers.substr(key_pos, end - key_pos);
            if (send_handshake(sec_key)) {
                done_headers = true;
                npending = 0;
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
    // ensure always null terminated
    auto space = (sizeof(pending)-1) - npending;
    if (fd >= 0 && space > 0) {
        ssize_t n = 0;
        if (ssl) {
            if (!SSL_handshake_complete) {
                auto res = SSL_accept(ssl);
                if (res <= 0) {
                    int err = SSL_get_error(ssl, res);
                    if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                        // still pending
                        return;
                    }
                    ERR_print_errors_fp(stdout);
                    close(fd);
                    fd = -1;
                    return;
                }
                printf("SSL handshake completed\n");
                SSL_handshake_complete = true;
            }
            n = SSL_read(ssl, &pending[npending], space);
            if (n <= 0) {
                int err = SSL_get_error(ssl, n);
                if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                    return;
                }
                if (err == SSL_ERROR_ZERO_RETURN) {
                    // orderly shutdown
                    close(fd);
                    fd = -1;
                    return;
                }
                ERR_print_errors_fp(stdout);
                close(fd);
                fd = -1;
                return;
            }
        } else {
            n = ::recv(fd, &pending[npending], space, 0);
            if (n < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    return;
                }
                close(fd);
                fd = -1;
                return;
            }
            if (n == 0) {
                // EOF
                close(fd);
                fd = -1;
                return;
            }
        }
        npending += n;
    }
}

/*
  decode an incoming WebSocket packet and overwrite buf with the decoded data
  return the number of decoded payload bytes, or -1 on error
 */
ssize_t WebSocket::decode(uint8_t *buf, size_t n, size_t &used)
{
    if (n < 2) return -1;

    // NOTE: opcode currently unused, reserved for future handling of ping/close/etc.
    [[maybe_unused]] uint8_t opcode = buf[0] & 0x0F;
    bool masked = buf[1] & 0x80;
    uint64_t payload_len = buf[1] & 0x7F;
    size_t pos = 2;

    if (payload_len == 126) {
        if (n < 4) return -1;
        payload_len = ntohs(*(uint16_t *)(buf + pos));
        pos += 2;
    } else if (payload_len == 127) {
        if (n < 10) return -1;
        payload_len = be64toh(*(uint64_t *)(buf + pos));
        pos += 8;
    }

    if (masked) {
	if (n < pos + 4 + payload_len) {
	    return -1;
	}
	uint8_t mask[4];
	memcpy(mask, buf + pos, 4);
	pos += 4;
	for (size_t i = 0; i < payload_len; i++) {
	    buf[i] = buf[pos + i] ^ mask[i % 4];
	}
    } else {
	if (n < pos + payload_len) {
	    return -1;
	}
        memmove(buf, buf + pos, payload_len);
    }

    used = pos + payload_len;

    return payload_len;
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
                close(fd); fd = -1;
                return false;
            }
        } else {
            wret = ::send(fd, handshake_buf + handshake_sent, handshake_len - handshake_sent, 0);
            if (wret < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    return false;
                }
                close(fd); fd = -1;
                return false;
            }
        }
        handshake_sent += (size_t)wret;
    }
    return handshake_sent == handshake_len;
}

/*
  encode a packet onto a connected WebSocket
 */
ssize_t WebSocket::send(const void *buf, size_t n)
{
    uint8_t header[10];
    size_t header_len = 0;
    header[0] = 0x82; // FIN + binary opcode

    if (n <= 125) {
        header[1] = n;
        header_len = 2;
    } else if (n <= 65535) {
        header[1] = 126;
        *(uint16_t *)(header + 2) = htons(n);
        header_len = 4;
    } else {
        header[1] = 127;
        *(uint64_t *)(header + 2) = htobe64(n);
        header_len = 10;
    }

    uint8_t pkt[header_len + n];
    memcpy(pkt, header, header_len);
    memcpy(&pkt[header_len], buf, n);

    ssize_t sent;
    if (_is_SSL && ssl) {
        sent = SSL_write(ssl, pkt, sizeof(pkt));
        if (sent <= 0) {
            int err = SSL_get_error(ssl, sent);
            if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ) {
                return 0; // try again later
            }
            ERR_print_errors_fp(stdout);
            close(fd); fd = -1;
            return -1;
        }
    } else {
        sent = ::send(fd, pkt, sizeof(pkt), 0);
        if (sent < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return 0;
            }
            close(fd); fd = -1;
            return -1;
        }
    }
    if (sent < ssize_t(sizeof(pkt))) {
        return 0; // partial; retry later
    }
    return sizeof(pkt) - header_len;
}

/*
  receive some data
 */
ssize_t WebSocket::recv(void *buf, size_t n)
{
    fill_pending();
    if (fd < 0) {
	return -1;
    }
    if (!done_headers) {
	check_headers();
    }
    size_t used;
    auto decode_len = decode(pending, npending, used);
    if (decode_len == -1) {
	return 0;
    }
    if (ssize_t(n) > decode_len) {
	n = decode_len;
    }

    memcpy(buf, pending, n);
    memmove(pending, &pending[used], npending-used);
    npending -= used;
    return n;
}
