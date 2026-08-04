/*
  Minimal HTTP request parsing for the video port. See httpreq.h.
 */
#include "httpreq.h"

#include <ctype.h>
#include <stdio.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>

int HttpRequest::feed(const uint8_t *buf, size_t n)
{
    if (buf_.size() + n > HTTP_MAX_REQUEST) {
        return -1;
    }
    buf_.append(reinterpret_cast<const char *>(buf), n);
    const size_t end = buf_.find("\r\n\r\n");
    if (end == std::string::npos) {
        // Tolerate bare-LF headers from hand-rolled clients.
        const size_t end2 = buf_.find("\n\n");
        if (end2 == std::string::npos) {
            return 0;
        }
    }
    return parse() ? 1 : -1;
}

bool HttpRequest::parse(void)
{
    size_t hdr_end = buf_.find("\r\n\r\n");
    size_t sep = 4;
    if (hdr_end == std::string::npos) {
        hdr_end = buf_.find("\n\n");
        sep = 2;
        if (hdr_end == std::string::npos) {
            return false;
        }
    }
    leftover_ = buf_.substr(hdr_end + sep);
    const std::string head = buf_.substr(0, hdr_end);

    size_t line_end = head.find('\n');
    if (line_end == std::string::npos) {
        return false;
    }
    std::string line = head.substr(0, line_end);
    if (!line.empty() && line.back() == '\r') {
        line.pop_back();
    }
    headers_ = head.substr(line_end + 1);

    const size_t sp1 = line.find(' ');
    if (sp1 == std::string::npos) {
        return false;
    }
    const size_t sp2 = line.find(' ', sp1 + 1);
    if (sp2 == std::string::npos) {
        return false;
    }
    method_ = line.substr(0, sp1);
    target_ = line.substr(sp1 + 1, sp2 - sp1 - 1);

    const size_t q = target_.find('?');
    if (q == std::string::npos) {
        path_ = target_;
        query_.clear();
    } else {
        path_ = target_.substr(0, q);
        query_ = target_.substr(q + 1);
    }
    return !method_.empty() && !path_.empty();
}

static std::string lower(const std::string &s)
{
    std::string o = s;
    for (auto &c : o) {
        c = char(tolower(static_cast<unsigned char>(c)));
    }
    return o;
}

std::string HttpRequest::header(const char *name) const
{
    const std::string want = lower(name) + ":";
    size_t pos = 0;
    while (pos < headers_.size()) {
        size_t eol = headers_.find('\n', pos);
        if (eol == std::string::npos) {
            eol = headers_.size();
        }
        std::string line = headers_.substr(pos, eol - pos);
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }
        if (lower(line).compare(0, want.size(), want) == 0) {
            std::string v = line.substr(want.size());
            size_t b = v.find_first_not_of(" \t");
            if (b == std::string::npos) {
                return "";
            }
            size_t e = v.find_last_not_of(" \t");
            return v.substr(b, e - b + 1);
        }
        pos = eol + 1;
    }
    return "";
}

std::string HttpRequest::query(const char *name) const
{
    const std::string want = name;
    size_t pos = 0;
    while (pos <= query_.size()) {
        size_t amp = query_.find('&', pos);
        if (amp == std::string::npos) {
            amp = query_.size();
        }
        const std::string kv = query_.substr(pos, amp - pos);
        const size_t eq = kv.find('=');
        if (eq != std::string::npos && kv.compare(0, eq, want) == 0) {
            return http_url_decode(kv.substr(eq + 1));
        }
        if (amp == query_.size()) {
            break;
        }
        pos = amp + 1;
    }
    return "";
}

std::string http_url_decode(const std::string &s)
{
    std::string o;
    o.reserve(s.size());
    for (size_t i = 0; i < s.size(); i++) {
        if (s[i] == '+') {
            o += ' ';
        } else if (s[i] == '%' && i + 2 < s.size()
                   && isxdigit(static_cast<unsigned char>(s[i + 1]))
                   && isxdigit(static_cast<unsigned char>(s[i + 2]))) {
            const std::string hex = s.substr(i + 1, 2);
            o += char(strtol(hex.c_str(), nullptr, 16));
            i += 2;
        } else {
            o += s[i];
        }
    }
    return o;
}

std::string http_basic_password(const std::string &authorization)
{
    const std::string prefix = "Basic ";
    if (authorization.size() <= prefix.size()
        || lower(authorization).compare(0, prefix.size(),
                                        lower(prefix)) != 0) {
        return "";
    }
    const std::string b64 = authorization.substr(prefix.size());

    // base64-decode; the result is "user:password" and we want the pass
    std::string out(b64.size(), '\0');
    BIO *b = BIO_new_mem_buf(b64.data(), int(b64.size()));
    BIO *d = BIO_new(BIO_f_base64());
    BIO_set_flags(d, BIO_FLAGS_BASE64_NO_NL);
    b = BIO_push(d, b);
    const int n = BIO_read(b, &out[0], int(out.size()));
    BIO_free_all(b);
    if (n <= 0) {
        return "";
    }
    out.resize(size_t(n));
    const size_t colon = out.find(':');
    if (colon == std::string::npos) {
        return "";
    }
    return out.substr(colon + 1);
}

std::string http_simple_response(int code, const char *reason,
                                 const char *content_type,
                                 const std::string &text)
{
    char head[512];
    snprintf(head, sizeof(head),
             "HTTP/1.1 %d %s\r\n"
             "Content-Type: %s\r\n"
             "Content-Length: %zu\r\n"
             "Cache-Control: no-store\r\n"
             "Connection: close\r\n"
             "\r\n",
             code, reason, content_type, text.size());
    return std::string(head) + text;
}


std::string http_redact_target(const std::string &target)
{
    static const char *secret_keys[] = { "pw", "password", "t", "key" };
    const size_t q = target.find('?');
    if (q == std::string::npos) {
        return target;
    }
    std::string out = target.substr(0, q + 1);
    size_t at = q + 1;
    bool first = true;
    while (at <= target.size()) {
        size_t end = target.find('&', at);
        if (end == std::string::npos) {
            end = target.size();
        }
        const std::string kv = target.substr(at, end - at);
        const size_t eq = kv.find('=');
        if (!first) {
            out += '&';
        }
        first = false;
        if (eq == std::string::npos) {
            out += kv;
        } else {
            const std::string k = kv.substr(0, eq);
            bool secret = false;
            for (const char *s : secret_keys) {
                if (k == s) {
                    secret = true;
                    break;
                }
            }
            out += k;
            out += '=';
            out += secret ? "<redacted>" : kv.substr(eq + 1);
        }
        if (end == target.size()) {
            break;
        }
        at = end + 1;
    }
    return out;
}
