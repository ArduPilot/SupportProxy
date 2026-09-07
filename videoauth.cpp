/*
  Video publisher admission. See videoauth.h for the model.
 */
#include "videoauth.h"

#include <string.h>
#include <stdio.h>
#include <openssl/sha.h>
#include <errno.h>
#include <openssl/crypto.h>
#include <openssl/hmac.h>
#include <stdlib.h>

#include "conntdb.h"

// How long a cached connections.tdb read stays usable. Short enough that
// a session appearing or moving is noticed promptly, long enough that a
// datagram burst doesn't turn into a burst of tdb opens.
#define VIDEO_AUTH_CACHE_S 2

const char *video_admit_str(video_admit_t r)
{
    switch (r) {
    case VIDEO_ADMIT_OK:            return "ok";
    case VIDEO_ADMIT_NO_SESSION:    return "no MAVLink session";
    case VIDEO_ADMIT_STALE_SESSION: return "MAVLink session too old";
    case VIDEO_ADMIT_WRONG_IP:      return "address does not match the MAVLink session";
    case VIDEO_ADMIT_UNAUTH:        return "MAVLink session not signature-validated";
    case VIDEO_ADMIT_BAD_PASSWORD:  return "wrong publish password";
    case VIDEO_ADMIT_SLOT_BUSY:     return "another publisher holds this slot";
    case VIDEO_ADMIT_NO_CREDENTIAL:
        return "a publish password is set, and plain MPEG-TS/UDP cannot carry "
               "one -- publish over RTSP, or clear the password";
    case VIDEO_ADMIT_MISSING_PASSWORD:
        return "a publish password is set but none was supplied -- add "
               "?pw=... to the RTSP URL";
    }
    return "unknown";
}

bool video_password_matches(const uint8_t stored[32],
                            const std::string &candidate)
{
    // An all-zero key is the "unset" sentinel, never a hash to match.
    bool any = false;
    for (int i = 0; i < 32; i++) {
        any |= stored[i] != 0;
    }
    if (!any || candidate.empty()
        || candidate.find('\0') != std::string::npos) {
        return false;
    }
    uint8_t want[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char *>(candidate.data()),
           candidate.size(), want);
    return CRYPTO_memcmp(want, stored, sizeof(want)) == 0;
}

bool VideoAuth::refresh(time_t now)
{
    auto *db = conn_db_open();
    if (db == nullptr) {
        // Can't read: leave whatever we had and let the caller decide.
        // Failing closed here would drop a live publisher every time the
        // file is briefly locked.
        fetched_at_ = now;
        return false;
    }
    struct ConnEntry e {};
    if (conn_get_user(db, port2_, e)) {
        have_ = true;
        peer_ip_be_ = e.peer_ip_be;
        authenticated_ = e.authenticated != 0;
        seen_at_ = now;
    }
    // No row: do NOT forget what we last saw. The row disappears when
    // the session child exits, which is exactly when the grace window
    // is supposed to keep video alive. check_session() ages seen_at_
    // out instead.
    conn_db_close(db);
    fetched_at_ = now;
    return true;
}

video_admit_t VideoAuth::check_session(const struct KeyEntry &ke,
                                       uint32_t peer_ip_be, time_t now) const
{
    if (!have_) {
        return VIDEO_ADMIT_NO_SESSION;
    }
    if (peer_ip_be_ != peer_ip_be) {
        return VIDEO_ADMIT_WRONG_IP;
    }
    const uint32_t grace = ke.video_mav_grace_s ? ke.video_mav_grace_s
                                                : VIDEO_MAV_GRACE_DEFAULT_S;
    // Measured from when we last saw the session live, not from a field
    // in a record that no longer exists. This is what lets a publisher
    // start (or restart) during a telemetry outage.
    if (now > seen_at_ + time_t(grace)) {
        return VIDEO_ADMIT_STALE_SESSION;
    }
    if ((ke.flags & KEY_FLAG_BIDI_SIGN) != 0 && !authenticated_) {
        return VIDEO_ADMIT_UNAUTH;
    }
    return VIDEO_ADMIT_OK;
}

video_admit_t VideoAuth::admit(const struct KeyEntry &ke, uint32_t peer_ip_be,
                               const std::string *password,
                               bool credential_capable, bool session_ok,
                               bool open_publish, time_t now)
{
    // Path A: a publish password, when set, is sufficient on its own.
    bool have_pw = false;
    for (int i = 0; i < 32; i++) {
        have_pw |= ke.video_publish_key[i] != 0;
    }
    if (have_pw) {
        /*
          A credential that was offered is judged on its own merits, and
          a wrong one is fatal even on a session_ok slot: falling back
          on a typo would turn a clear rejection into a silent downgrade
          to address matching.
         */
        if (password != nullptr) {
            return video_password_matches(ke.video_publish_key, *password)
                ? VIDEO_ADMIT_OK : VIDEO_ADMIT_BAD_PASSWORD;
        }
        /*
          None offered. By default the password replaces the
          MAVLink-session check rather than adding to it: an operator
          sets one precisely because they do not want address matching
          to be the gate. VIDEO_SLOT_SESSION_OK opts one slot back out,
          for a publisher with nowhere to put a credential.

          Distinguish the two cases when refusing -- "wrong publish
          password" is true but useless to someone whose udpsink never
          sent one.
         */
        if (!session_ok && !open_publish) {
            return credential_capable ? VIDEO_ADMIT_MISSING_PASSWORD
                                      : VIDEO_ADMIT_NO_CREDENTIAL;
        }
    }

    // No credential offered and the slot is open: nothing else to check.
    if (open_publish) {
        return VIDEO_ADMIT_OK;
    }

    // Path B: match a recent MAVLink session.
    if (fetched_at_ == 0 || now - fetched_at_ >= VIDEO_AUTH_CACHE_S) {
        refresh(now);
    }
    video_admit_t r = check_session(ke, peer_ip_be, now);
    if (r != VIDEO_ADMIT_OK) {
        // The cache may simply predate a session that just came up.
        // Re-read once before rejecting, but only if the cached copy
        // isn't already fresh -- otherwise a stream of unauthorised
        // packets would drive one tdb open each.
        if (now - fetched_at_ > 0 && refresh(now)) {
            r = check_session(ke, peer_ip_be, now);
        }
    }
    return r;
}

bool video_token_valid(const struct KeyEntry &ke, int port2, int slot,
                       const char *token, time_t now)
{
    if (token == nullptr || *token == '\0') {
        return false;
    }
    const char *dot = strchr(token, '.');
    if (dot == nullptr) {
        return false;
    }
    char *endp = nullptr;
    errno = 0;
    const long long expiry = strtoll(token, &endp, 10);
    if (errno != 0 || endp != dot || expiry <= 0) {
        return false;
    }
    if (now > time_t(expiry)) {
        return false;
    }
    const char *mac_hex = dot + 1;
    if (strlen(mac_hex) != 64) {
        return false;
    }

    char msg[128];
    const int mlen = snprintf(msg, sizeof(msg), "video-view|%d|%d|%lld",
                              port2, slot, expiry);
    if (mlen <= 0 || size_t(mlen) >= sizeof(msg)) {
        return false;
    }

    uint8_t want[32];
    unsigned int want_len = 0;
    if (HMAC(EVP_sha256(), ke.secret_key, int(sizeof(ke.secret_key)),
             reinterpret_cast<const unsigned char *>(msg), size_t(mlen),
             want, &want_len) == nullptr || want_len != sizeof(want)) {
        return false;
    }

    uint8_t got[32];
    for (int i = 0; i < 32; i++) {
        char pair[3] = { mac_hex[i * 2], mac_hex[i * 2 + 1], 0 };
        char *e2 = nullptr;
        const long v = strtol(pair, &e2, 16);
        if (e2 != pair + 2) {
            return false;
        }
        got[i] = uint8_t(v);
    }
    return CRYPTO_memcmp(want, got, sizeof(want)) == 0;
}
