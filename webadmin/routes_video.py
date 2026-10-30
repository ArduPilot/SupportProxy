"""Browser playback page.

Serves a player per configured video slot, with a short-lived token so
the viewer password never appears in a URL. The page is honest about
what a browser can actually decode: of the streams this proxy carries,
H.264 plays and HEVC generally does not, so an unplayable stream gets
an explanation and a copyable ffplay/VLC command rather than a broken
<video> element.
"""
from flask import (Blueprint, Response, abort, current_app, jsonify,
                   make_response, render_template, request, url_for)

import functools
import http.client
import re

import keydb_lib

from .auth import current_owner, is_admin, require_login
from .db import tdb_readonly
from . import anon_limit, videotoken, connections
import conntdb_lib

bp = Blueprint('video', __name__, url_prefix='/video')

# stream_type values, as they appear in a PMT. Keep in sync with
# videots.h -- these decide what the page offers.
STREAM_NAMES = {
    0x02: 'MPEG-2',
    0x1B: 'H.264',
    0x24: 'HEVC',
}

# What a browser's Media Source Extensions can actually play. HEVC is
# excluded deliberately: mpegts.js can demux it, but MSE support is
# absent on most desktops, so offering a player would just show a black
# rectangle.
BROWSER_PLAYABLE = (0x1B,)


def _viewer_host():
    """Host the browser should open the video socket on.

    The video port is served by the proxy itself, not through this app,
    so the player connects directly to the same host on that port.
    """
    return request.host.split(':')[0]


def _resolve_port2():
    """Which entry this request is about. An admin may name any entry
    with ?port2=; an owner only ever gets their own."""
    port2 = current_owner()
    want = request.args.get('port2', type=int)
    if want is not None and want != port2:
        if not is_admin():
            abort(403)
        port2 = want
    return port2


@bp.route('/token', methods=['GET'])
@require_login
def token():
    """Mint a fresh viewer token.

    Tokens last a minute by design, but a player reconnects for as long
    as the page is open -- after a publisher restart, a network blip, or
    a laptop waking up. A page that minted one token at render would
    stop being able to reconnect after that minute, which presents as
    "it only works if I reload".
    """
    port2 = _resolve_port2()
    slot = request.args.get('slot', type=int)
    if slot is None or slot < 0 or slot >= keydb_lib.MAX_VIDEO_PORTS:
        abort(400)

    with tdb_readonly() as db:
        ke = keydb_lib.KeyEntry(port2)
        if not ke.fetch(db):
            abort(404)
        if not ke.video_enabled() or not ke.video_ports[slot]:
            abort(404)
        return jsonify({'token': videotoken.mint(ke.secret_key, port2, slot)})


@bp.route('/share', methods=['POST'])
@require_login
def share():
    """Create a public viewer link for one slot.

    The link is a signed, expiring URL: it needs no account and no
    stored state, so there is nothing to revoke -- it simply stops
    working. Rotating the entry's secret key ends every link at once.
    """
    port2 = _resolve_port2()
    slot = request.form.get('slot', type=int)
    hours = request.form.get('hours', type=int)
    if slot is None or slot < 0 or slot >= keydb_lib.MAX_VIDEO_PORTS:
        abort(400)
    if hours not in videotoken.SHARE_TTL_CHOICES_H:
        abort(400)

    with tdb_readonly() as db:
        ke = keydb_lib.KeyEntry(port2)
        if not ke.fetch(db):
            abort(404)
        if not ke.video_enabled() or not ke.video_ports[slot]:
            abort(404)
        token = videotoken.mint_share(ke.secret_key, port2, slot,
                                      hours * 3600)
    return jsonify({
        'url': url_for('watch.page', port2=port2, slot=slot, token=token,
                       _external=True),
        'hours': hours,
    })


@bp.route('/', methods=['GET'])
@require_login
def index():
    port2 = _resolve_port2()

    with tdb_readonly() as db:
        ke = keydb_lib.KeyEntry(port2)
        if not ke.fetch(db):
            abort(404)

        raw_slots = {c.stream_idx for c in connections.list_for_port2(port2)
                     if c.role == conntdb_lib.CONN_ROLE_VIDEO_PUB and
                     c.app_proto == conntdb_lib.CONN_APP_MATROSKA}
        slots = []
        for slot, port in ke.active_video_ports():
            slots.append({
                'slot': slot,
                'raw_thermal': slot in raw_slots,
                'number': slot + 1,
                'port': port,
                'opts': ke.slot_opt_names(slot),
                'token': videotoken.mint(ke.secret_key, port2, slot),
                'needs_password': ke.video_viewer_pass_set(),
            })

    return render_template(
        'video.html',
        entry=ke,
        port2=port2,
        slots=slots,
        host=_viewer_host(),
        enabled=ke.video_enabled(),
        browser_playable=BROWSER_PLAYABLE,
        stream_names=STREAM_NAMES,
        # Carries ?port2= so an admin watching someone else's stream
        # keeps refreshing tokens for *that* entry, not their own.
        token_url=url_for('video.token', port2=port2),
        share_url=url_for('video.share', port2=port2),
        share_hours=videotoken.SHARE_TTL_CHOICES_H,
    )


# ---------------------------------------------------------------------
# Public viewing. No login: the signed share token in the URL is the
# credential, and it is only ever good for watching one slot.

watch_bp = Blueprint('watch', __name__, url_prefix='/watch')

# The proxy's video child is on this host; the port comes from the
# entry, never from the request.
HLS_UPSTREAM_HOST = '127.0.0.1'
HLS_UPSTREAM_TIMEOUT_S = 5
HLS_MAX_BODY = 32 * 1024 * 1024
MAX_PORT2 = 2 ** 31 - 1

# The video child appends the viewer token to segment URIs for clients
# that talk to it directly. Here every request carries its own, minted
# fresh, so leaving it in would give each playlist its own segment URLs
# and defeat caching.
_SEGMENT_TOKEN = re.compile(rb'(\.ts)\?t=[0-9.a-f]+')


@watch_bp.after_request
def _watch_headers(resp):
    # The token is in the URL, so keep it out of Referer and caches.
    resp.headers.setdefault('Cache-Control', 'no-store')
    resp.headers['Referrer-Policy'] = 'no-referrer'
    resp.headers['X-Robots-Tag'] = 'noindex'
    return resp


def _shared_entry(port2, slot, token):
    """The entry a share link points at, or an abort.

    Every failure other than expiry is the same 404, so a visitor cannot
    tell which part of a guessed link was wrong.
    """
    # port2 is a signed 32-bit key in the keydb; anything beyond that
    # cannot be an entry, and would make fetch() raise.
    if slot < 0 or slot >= keydb_lib.MAX_VIDEO_PORTS \
            or port2 > MAX_PORT2:
        abort(404)
    with tdb_readonly() as db:
        ke = keydb_lib.KeyEntry(port2)
        found = ke.fetch(db)
    if not found or not ke.video_enabled() or not ke.video_ports[slot]:
        abort(404)
    state = videotoken.check_share(ke.secret_key, port2, slot, token)
    if state == 'expired':
        abort(make_response(render_template('watch_expired.html'), 410))
    if state != 'ok':
        abort(404)
    return ke


@watch_bp.route('/<int:port2>/<int:slot>/<token>/')
def page(port2, slot, token):
    ke = _shared_entry(port2, slot, token)
    raw_thermal = any(
        c.stream_idx == slot and c.role == conntdb_lib.CONN_ROLE_VIDEO_PUB
        and c.app_proto == conntdb_lib.CONN_APP_MATROSKA
        for c in connections.list_for_port2(port2))
    base = url_for('watch.page', port2=port2, slot=slot, token=token)
    return render_template(
        'watch.html',
        entry=ke,
        number=slot + 1,
        port=ke.video_ports[slot],
        host=_viewer_host(),
        raw_thermal=raw_thermal,
        hls_url=base + 'index.m3u8',
        token_url=base + 'ws-token',
    )


@watch_bp.route('/<int:port2>/<int:slot>/<token>/ws-token')
def ws_token(port2, slot, token):
    """A 60 s viewer token for the player's WebSocket, minted from the
    share link for as long as the link is good."""
    ke = _shared_entry(port2, slot, token)
    # Carry the link's expiry into the token, so the viewer it admits is
    # dropped when the link lapses rather than watching on for as long
    # as the publisher streams.
    until = videotoken.share_expiry(token)
    return jsonify({'token': videotoken.mint(ke.secret_key, port2, slot,
                                             until=until)})


def _upstream(ke, port2, slot, path):
    """GET `path` from the video child. Returns (status, body)."""
    tok = videotoken.mint(ke.secret_key, port2, slot)
    conn = http.client.HTTPConnection(
        HLS_UPSTREAM_HOST, ke.video_ports[slot],
        timeout=HLS_UPSTREAM_TIMEOUT_S)
    try:
        conn.request('GET', '%s?t=%s' % (path, tok))
        resp = conn.getresponse()
        body = resp.read(HLS_MAX_BODY + 1)
        status = resp.status
        # read(n) returns what arrived if the child closes mid-response;
        # resp.length is the Content-Length not yet received. A cut
        # segment must not be served as a good, cacheable one.
        short = bool(resp.length)
    except (OSError, http.client.HTTPException):
        return 503, b''
    finally:
        conn.close()
    if len(body) > HLS_MAX_BODY:
        return 502, b''
    if short:
        return 503, b''
    return status, body


# Bystanders need no login, and each HLS request holds a web worker
# thread while it is fetched and then sent to a possibly slow client.
# They share the anonymous budget (see anon_limit) with public log
# playback, so a crowd cannot starve the login page and the admin UI.
HLS_MAX_CONCURRENT = anon_limit.MAX
_hls_slots = anon_limit.slots


def _hls_busy():
    resp = Response('Too many viewers right now; retrying shortly.\n',
                    status=503, mimetype='text/plain')
    resp.headers['Retry-After'] = '2'
    return resp


def _hls_limited(fn):
    """Run an HLS route under the concurrency cap. The slot is held until
    the response has been sent, not just until it is built."""
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        if not _hls_slots.acquire(blocking=False):
            return _hls_busy()
        try:
            resp = fn(*args, **kwargs)
        except BaseException:
            _hls_slots.release()
            raise
        resp.call_on_close(_hls_slots.release)
        return resp
    return wrapper


def _hls_response(status, body, content_type, cache):
    if status == 200:
        return Response(body, mimetype=content_type,
                        headers={'Cache-Control': cache})
    # Normalise: a player only needs to know whether to retry.
    code = 404 if status == 404 else 503
    return Response('Stream not available\n', status=code,
                    mimetype='text/plain')


# HLS is fetched through this app rather than straight from the video
# port: the video port speaks TLS only for WebSocket, so an https page
# could not load it, and a share link should be one origin.
@watch_bp.route('/<int:port2>/<int:slot>/<token>/index.m3u8')
@_hls_limited
def hls_playlist(port2, slot, token):
    ke = _shared_entry(port2, slot, token)
    status, body = _upstream(ke, port2, slot, '/v%d.m3u8' % (slot + 1))
    body = _SEGMENT_TOKEN.sub(rb'\1', body)
    return _hls_response(status, body, 'application/vnd.apple.mpegurl',
                         'no-cache')


@watch_bp.route('/<int:port2>/<int:slot>/<token>/'
                'v<int:number>-<int:inc>-<int:seq>.ts')
@_hls_limited
def hls_segment(port2, slot, token, number, inc, seq):
    ke = _shared_entry(port2, slot, token)
    if number != slot + 1:
        abort(404)
    status, body = _upstream(ke, port2, slot,
                             '/v%d-%d-%d.ts' % (number, inc, seq))
    return _hls_response(status, body, 'video/mp2t', 'public, max-age=60')
