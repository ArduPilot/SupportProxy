"""Short-lived viewer tokens for browser playback.

The browser needs a credential to open a WebSocket to the video port,
and the obvious candidate -- the viewer password -- must not go in a
URL: it would land in browser history, proxy logs and Referer headers.

Instead the admin page, which has already authenticated the operator
and can read the entry, mints a token signed with the entry's existing
MAVLink secret key. The video child already loads that key, so this
needs no new shared secret, no new state and no new file, and the
browser never sees the key itself.

Keep in sync with video_token_valid() in videoauth.cpp.
"""
import hashlib
import hmac
import time

# Short by design: the token only has to survive the moment between
# rendering the page and the player opening its socket.
TOKEN_TTL_S = 60


def mint(secret_key, port2, slot, ttl_s=TOKEN_TTL_S, now=None):
    """Return "<expiry>.<hex hmac>" for this entry and slot."""
    if now is None:
        now = time.time()
    expiry = int(now) + int(ttl_s)
    msg = 'video-view|%d|%d|%d' % (int(port2), int(slot), expiry)
    mac = hmac.new(bytes(secret_key), msg.encode('ascii'),
                   hashlib.sha256).hexdigest()
    return '%d.%s' % (expiry, mac)


def verify(secret_key, port2, slot, token, now=None):
    """Mirror of the C++ check, for tests."""
    if now is None:
        now = time.time()
    if not token or '.' not in token:
        return False
    exp_s, _, mac = token.partition('.')
    try:
        expiry = int(exp_s)
    except ValueError:
        return False
    if expiry <= 0 or now > expiry:
        return False
    msg = 'video-view|%d|%d|%d' % (int(port2), int(slot), expiry)
    want = hmac.new(bytes(secret_key), msg.encode('ascii'),
                    hashlib.sha256).hexdigest()
    return hmac.compare_digest(want, mac)
