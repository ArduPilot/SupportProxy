/*
  Minimal HTTP request parsing for the video port.

  Only what a viewer connection needs: the request line, a handful of
  headers, and a query string. Deliberately not a general HTTP server --
  the video port serves one thing.
 */
#pragma once

#include <stddef.h>
#include <stdint.h>

#include <string>

// Longest request we will buffer before giving up on a peer. A viewer
// request is a few hundred bytes; anything much larger is a client
// doing something we do not serve.
#define HTTP_MAX_REQUEST 8192

class HttpRequest {
public:
    // Feed bytes as they arrive. Returns:
    //   1  complete request parsed
    //   0  incomplete, feed more
    //  -1  malformed or too large
    int feed(const uint8_t *buf, size_t n);

    const std::string &method(void) const { return method_; }
    const std::string &target(void) const { return target_; }
    const std::string &path(void) const { return path_; }

    // Header lookup, case-insensitive. Empty string when absent.
    std::string header(const char *name) const;

    // Query parameter from the request target. Empty when absent.
    std::string query(const char *name) const;

    // Bytes left over after the request (a pipelined body, normally
    // none). The caller owns what it does with them.
    const std::string &leftover(void) const { return leftover_; }

private:
    std::string buf_;
    std::string method_;
    std::string target_;
    std::string path_;
    std::string query_;
    std::string headers_;      // raw block, searched case-insensitively
    std::string leftover_;

    bool parse(void);
};

// Percent-decode, in place semantics (returns a new string). Invalid
// escapes are left as-is rather than silently dropped.
std::string http_url_decode(const std::string &s);

/*
  Fetch the first named query parameter from a request target. The boolean
  distinguishes an absent parameter from one explicitly supplied with an
  empty value; callers making access-control decisions must not collapse the
  two. `value` is percent-decoded when present.
 */
bool http_query_value(const std::string &target, const char *name,
                      std::string &value);

/*
  A request target with credential query values replaced.

  Anything logged has to go through this. A viewer may authenticate with
  ?pw=, and unlike the 60-second view token that is a long-lived
  credential -- writing it to proxy.log puts it on disk for the life of
  the file and into every operator's browser through the server page.
  Redacting at the point of display is too late for the copy on disk.
 */
std::string http_redact_target(const std::string &target);

// Decode a "Basic base64(user:pass)" credential. Returns the password
// part, or an empty string if the header is not Basic or is malformed.
std::string http_basic_password(const std::string &authorization);

// Build a simple response with no body beyond `text`.
std::string http_simple_response(int code, const char *reason,
                                 const char *content_type,
                                 const std::string &text);
