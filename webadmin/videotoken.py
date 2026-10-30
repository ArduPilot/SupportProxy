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


def mint(secret_key, port2, slot, ttl_s=TOKEN_TTL_S, now=None, until=None):
    """Return "<expiry>.<hex hmac>" for this entry and slot.

    With `until` (a share link's expiry) the token is
    "<expiry>.<until>.<hex hmac>": the video child stops serving a viewer
    admitted with it once `until` passes, or the entry's key changes.
    """
    if now is None:
        now = time.time()
    expiry = int(now) + int(ttl_s)
    if until is None:
        msg = 'video-view|%d|%d|%d' % (int(port2), int(slot), expiry)
        prefix = '%d' % expiry
    else:
        msg = 'video-view|%d|%d|%d|%d' % (int(port2), int(slot), expiry,
                                          int(until))
        prefix = '%d.%d' % (expiry, int(until))
    mac = hmac.new(bytes(secret_key), msg.encode('ascii'),
                   hashlib.sha256).hexdigest()
    return '%s.%s' % (prefix, mac)


def verify(secret_key, port2, slot, token, now=None):
    """Mirror of the C++ check, for tests."""
    if now is None:
        now = time.time()
    if not token or '.' not in token:
        return False
    parts = token.split('.')
    if len(parts) not in (2, 3):
        return False
    mac = parts[-1]
    try:
        expiry = int(parts[0])
        until = int(parts[1]) if len(parts) == 3 else None
    except ValueError:
        return False
    if expiry <= 0 or now > expiry:
        return False
    if until is None:
        msg = 'video-view|%d|%d|%d' % (int(port2), int(slot), expiry)
    else:
        if until <= 0 or now > until:
            return False
        msg = 'video-view|%d|%d|%d|%d' % (int(port2), int(slot), expiry,
                                          until)
    want = hmac.new(bytes(secret_key), msg.encode('ascii'),
                    hashlib.sha256).hexdigest()
    return hmac.compare_digest(want, mac)


# Share links are for bystanders with no account, so unlike the viewer
# token they have to live for hours. They are verified here only, never
# by the video child: a visitor trades one for a 60 s viewer token.
# A different MAC domain keeps one from being passed off as the other.
SHARE_TTL_CHOICES_H = (1, 6, 24, 168)


# Truncated HMAC-SHA256: 16 hex digits is 64 bits. Only this server can
# check a link, so a guesser has to make an online request per try, which
# makes 64 bits far more than enough, and keeps the
# URL short enough to paste into a chat message.
SHARE_MAC_HEX = 16


def _share_mac(secret_key, port2, slot, expiry):
    msg = 'video-share|%d|%d|%d' % (int(port2), int(slot), int(expiry))
    return hmac.new(bytes(secret_key), msg.encode('ascii'),
                    hashlib.sha256).hexdigest()[:SHARE_MAC_HEX]


def mint_share(secret_key, port2, slot, ttl_s, now=None):
    """Return "<expiry>.<16 hex digits of hmac>" for a public share link.

    Stateless, so it cannot be revoked individually; rotating the
    entry's secret key invalidates every link at once.
    """
    if now is None:
        now = time.time()
    expiry = int(now) + int(ttl_s)
    return '%d.%s' % (expiry, _share_mac(secret_key, port2, slot, expiry))


def share_expiry(token):
    """The expiry inside a share token that check_share() accepted."""
    return int(token.partition('.')[0])


def check_share(secret_key, port2, slot, token, now=None):
    """Return 'ok', 'expired' or 'invalid'."""
    if now is None:
        now = time.time()
    if not token or '.' not in token:
        return 'invalid'
    exp_s, _, mac = token.partition('.')
    # One spelling per link: int() alone would also take '+123', ' 123'
    # and '1_23', each a different URL for the same signed value.
    if not (exp_s.isascii() and exp_s.isdigit()) or exp_s.startswith('0'):
        return 'invalid'
    expiry = int(exp_s)
    want = _share_mac(secret_key, port2, slot, expiry)
    if not hmac.compare_digest(want.encode('ascii'), mac.encode('utf-8')):
        return 'invalid'
    return 'expired' if now > expiry else 'ok'
