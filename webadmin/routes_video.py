"""Browser playback page.

Serves a player per configured video slot, with a short-lived token so
the viewer password never appears in a URL. The page is honest about
what a browser can actually decode: of the streams this proxy carries,
H.264 plays and HEVC generally does not, so an unplayable stream gets
an explanation and a copyable ffplay/VLC command rather than a broken
<video> element.
"""
from flask import (Blueprint, abort, current_app, jsonify,
                   render_template, request, url_for)

import keydb_lib

from .auth import current_owner, is_admin, require_login
from .db import tdb_readonly
from . import videotoken

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


@bp.route('/', methods=['GET'])
@require_login
def index():
    port2 = _resolve_port2()

    with tdb_readonly() as db:
        ke = keydb_lib.KeyEntry(port2)
        if not ke.fetch(db):
            abort(404)

        slots = []
        for slot, port in ke.active_video_ports():
            slots.append({
                'slot': slot,
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
    )
