/*
  Video publisher admission.

  Two independent paths, neither tied to the MAVLink process tree:

    A. publish password  -- accepted standalone, no MAVLink needed. For
       CGNAT, split-egress (video on a second link) and video-only use.

    B. MAVLink session    -- with no publish password set (or on a slot
       flagged VIDEO_SLOT_SESSION_OK, where one is set but the publisher
       offered none), a publisher is accepted when a MAVLink session for
       this entry was seen from the same IPv4 address within the entry's
       grace window. The grace is
       what lets video ride through a telemetry dropout instead of being
       revoked by a link flap. On a bidi entry the session must also have
       been signature-validated.

    C. open slot          -- VIDEO_SLOT_OPEN_PUB admits a publisher that
       offered no credential with no check at all. Off by default.

  Path B reads connections.tdb, which makes that file an authorisation
  input. It sits alongside keys.tdb in the proxy's working directory and
  both are 0600, so anyone who can forge one can forge the other; but
  peer_ip_be / authenticated must only ever be written by the session
  child.
 */
#pragma once

#include <stdint.h>
#include <time.h>

#include <string>

#include "keydb.h"

enum video_admit_t {
    VIDEO_ADMIT_OK = 0,
    VIDEO_ADMIT_NO_SESSION,     // no MAVLink session record at all
    VIDEO_ADMIT_STALE_SESSION,  // last seen longer ago than the grace window
    VIDEO_ADMIT_WRONG_IP,       // session exists, but from another address
    VIDEO_ADMIT_UNAUTH,         // bidi entry whose session never authenticated
    VIDEO_ADMIT_BAD_PASSWORD,   // publish password set and wrong/absent
    VIDEO_ADMIT_SLOT_BUSY,      // another publisher already holds the slot
    VIDEO_ADMIT_NO_CREDENTIAL,  // a publish password is set, but this
                                // transport cannot carry one at all
    VIDEO_ADMIT_MISSING_PASSWORD,  // transport could carry one; none given
};

const char *video_admit_str(video_admit_t r);

/*
  Cached view of the entry's MAVLink session.

  Re-reading connections.tdb per packet is not an option: a per-packet
  tdb open under load is what caused the lock-contention stall that
  commit 6fea59a fixed on the MAVLink side. So the state is cached and
  refreshed on a timer, with one forced refresh allowed when a decision
  would otherwise be a rejection -- so a publisher that starts moments
  after its MAVLink session does not have to wait out the timer.
 */
class VideoAuth {
public:
    explicit VideoAuth(int port2) : port2_(port2) {}

    /*
      Decide whether `peer_ip_be` may publish.

      `password` is non-null only when a credential was explicitly supplied.
      It is length-aware, so an empty or embedded-NUL value is still an
      offered (wrong) credential rather than silently becoming absent.
      `credential_capable` distinguishes a transport that supplied none
      (RTSP/RTMP) from one that cannot carry one at all (UDP), which is what
      the operator sees in the rejection log.

      `session_ok` is the slot's VIDEO_SLOT_SESSION_OK bit: when set, a
      publisher that offered no credential falls back to path B even
      though the entry has a publish password. A credential that was
      offered and is wrong is still refused.

      `open_publish` is the slot's VIDEO_SLOT_OPEN_PUB bit: a publisher
      that offered no credential is admitted with no check at all. A
      credential that was offered is still judged.
     */
    video_admit_t admit(const struct KeyEntry &ke, uint32_t peer_ip_be,
                        const std::string *password, bool credential_capable,
                        bool session_ok, bool open_publish, time_t now);

    // Force the next lookup to re-read, e.g. after a config change.
    void invalidate(void) { fetched_at_ = 0; }

    // Sample the MAVLink session state even when no video traffic is
    // flowing. Without this the child only ever looks on a packet, so a
    // session that comes and goes between publishes is never observed
    // and the grace window has nothing to work from.
    void observe(time_t now) { refresh(now); }

private:
    int port2_;
    /*
      Last-known-good session, which deliberately OUTLIVES the record.

      connections.tdb only holds a row while the session child is alive;
      when it idles out the row is deleted. If the absence of a row meant
      "no session", the grace window could never apply -- the case it
      exists for is precisely a MAVLink session that has gone away. So we
      remember what we last saw and age it out ourselves.
     */
    bool have_ = false;         // have we ever seen a session?
    uint32_t peer_ip_be_ = 0;
    bool authenticated_ = false;
    time_t seen_at_ = 0;        // when the session was last observed live
    time_t fetched_at_ = 0;     // when connections.tdb was last read

    bool refresh(time_t now);
    video_admit_t check_session(const struct KeyEntry &ke,
                                uint32_t peer_ip_be, time_t now) const;
};

// Constant-time compare of a candidate password against a stored
// sha256. Returns false when the stored key is all-zero (unset).
bool video_password_matches(const uint8_t stored[32],
                            const std::string &candidate);

/*
  Verify a short-lived viewer token minted by the web admin.

  Format: "<expiry>.<hex hmac-sha256>", the MAC taken over
  "video-view|<port2>|<slot>|<expiry>" with the entry's MAVLink secret
  key. That key is already shared between the web admin and this
  process, so browser playback needs no new secret, no new state and
  no new file -- and the browser never sees the key itself.

  The token exists because the alternative is putting the viewer
  password in a browser URL, where it lands in history, logs and
  Referer headers.
 */
bool video_token_valid(const struct KeyEntry &ke, int port2, int slot,
                       const char *token, time_t now);
