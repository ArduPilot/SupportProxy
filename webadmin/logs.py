"""Routes for browsing and downloading per-entry session logs.

Covers both file types written under logs/<port2>/<YYYY-MM-DD>/:

  * sessionN.tlog — raw MAVLink frame captures (KEY_FLAG_TLOG)
  * sessionN.bin  — ArduPilot dataflash logs over MAVLink (KEY_FLAG_BINLOG)

Two parallel views, sharing the listing/download helpers below:

  * admin: /admin/logs/<port2>/[<date>] — admin can browse any entry
  * owner: /me/logs/[<date>]            — owner can browse only their own

The blueprints differ only in which port2 they resolve and which auth
decorator they use.
"""
import os
import re
import time

from flask import (Blueprint, abort, current_app, render_template,
                   send_from_directory)

import keydb_lib

from .auth import current_owner, require_admin, require_login
from .db import tdb_readonly

DATE_RE = re.compile(r'^\d{4}-\d{2}-\d{2}$')
# Cover both .tlog (raw MAVLink frames) and .bin (ArduPilot dataflash
# logs over MAVLink). Listing + download flow through this regex, so
# broadening it surfaces .bin files alongside .tlog without further
# changes.
SESSION_RE = re.compile(r'^session\d+\.(tlog|bin)$')

# Natural-sort key: treat embedded digit runs as numbers so that
# session10.tlog sorts AFTER session2.tlog (not between session1 and
# session2 as plain lexical sort would). The non-digit chunks are
# lower-cased so a future mixed-case fixture doesn't fight the
# digit chunks.
_NATKEY_RE = re.compile(r'(\d+)')


def _natural_key(name):
    return [int(tok) if tok.isdigit() else tok.lower()
            for tok in _NATKEY_RE.split(name)]


def _logs_root():
    """Absolute path to the session-logs tree root."""
    return os.path.abspath(current_app.config['LOGS_DIR'])


def _safe_date(date):
    if not DATE_RE.match(date or ''):
        abort(404)


def _safe_session(session_name):
    if not SESSION_RE.match(session_name or ''):
        abort(404)


def _entry_label(port2):
    """Read the entry's name (best-effort) for display in templates."""
    with tdb_readonly() as db:
        ke = keydb_lib.KeyEntry(port2)
        if not ke.fetch(db):
            return None
        return ke


def _list_dates(port2):
    """All date subdirs under logs/<port2>/, newest first.

    Skip anything that doesn't match YYYY-MM-DD or is not a directory."""
    root = os.path.join(_logs_root(), str(port2))
    if not os.path.isdir(root):
        return []
    out = []
    for name in os.listdir(root):
        if not DATE_RE.match(name):
            continue
        if os.path.isdir(os.path.join(root, name)):
            out.append(name)
    # Newest first. YYYY-MM-DD sorts correctly under either lexical
    # or natural order; using the natural key keeps the helper
    # consistent across both list functions.
    out.sort(key=_natural_key, reverse=True)
    return out


def _list_sessions(port2, date):
    """All sessionN.{tlog,bin} files under logs/<port2>/<date>/."""
    _safe_date(date)
    root = os.path.join(_logs_root(), str(port2), date)
    if not os.path.isdir(root):
        return []
    files = []
    for name in os.listdir(root):
        if not SESSION_RE.match(name):
            continue
        path = os.path.join(root, name)
        try:
            st = os.stat(path)
        except OSError:
            continue
        files.append({
            'name': name,
            'size': st.st_size,
            'mtime': st.st_mtime,
            # ISO 8601 UTC for the <time datetime="..."> attr; the
            # client-side localtime.js rewrites the visible text in
            # the viewer's timezone. The fallback ('mtime_utc') is
            # rendered without a TZ suffix so that JS-on / JS-off
            # produce identical-width output (no column reflow on
            # the 5 s auto-refresh).
            'mtime_iso': time.strftime('%Y-%m-%dT%H:%M:%SZ',
                                       time.gmtime(st.st_mtime)),
            'mtime_utc': time.strftime('%Y-%m-%d %H:%M:%S',
                                       time.gmtime(st.st_mtime)),
        })
    # Natural sort so session10 lands after session9, not between
    # session1 and session2.
    files.sort(key=lambda f: _natural_key(f['name']))
    return files


def _send_session_file(port2, date, session_name):
    """send_from_directory takes care of path-traversal safety; we still
    pre-validate the date and filename so a malformed URL bounces with a
    404 before touching the filesystem.

    Session logs (.tlog or .bin) contain raw vehicle telemetry: do NOT
    let intermediaries (or a shared-device browser) cache them.
    Override the app's default SEND_FILE_MAX_AGE_DEFAULT (set for the
    logo etc.) with max_age=0 and explicit Cache-Control: private,
    no-store.
    """
    _safe_date(date)
    _safe_session(session_name)
    directory = os.path.join(_logs_root(), str(port2), date)
    if not os.path.isdir(directory):
        abort(404)
    resp = send_from_directory(directory, session_name,
                               as_attachment=True, max_age=0)
    resp.headers['Cache-Control'] = 'private, no-store'
    resp.headers['Pragma'] = 'no-cache'
    return resp


# ---------------------------------------------------------------------------
# admin views: any port2
# ---------------------------------------------------------------------------

admin_bp = Blueprint('admin_logs', __name__, url_prefix='/admin/logs')


@admin_bp.route('/<int:port2>/', methods=['GET'])
@require_admin
def admin_dates(port2):
    entry = _entry_label(port2)
    if entry is None:
        abort(404)
    return render_template('admin_logs.html',
                           entry=entry, dates=_list_dates(port2),
                           date=None, sessions=None)


@admin_bp.route('/<int:port2>/<date>/', methods=['GET'])
@require_admin
def admin_sessions(port2, date):
    _safe_date(date)
    entry = _entry_label(port2)
    if entry is None:
        abort(404)
    return render_template('admin_logs.html',
                           entry=entry, dates=_list_dates(port2),
                           date=date, sessions=_list_sessions(port2, date))


@admin_bp.route('/<int:port2>/<date>/<session_name>', methods=['GET'])
@require_admin
def admin_download(port2, date, session_name):
    return _send_session_file(port2, date, session_name)


# ---------------------------------------------------------------------------
# owner views: only their own port2
# ---------------------------------------------------------------------------

owner_bp = Blueprint('owner_logs', __name__, url_prefix='/me/logs')


@owner_bp.route('/', methods=['GET'])
@require_login
def owner_dates():
    port2 = current_owner()
    entry = _entry_label(port2)
    if entry is None:
        abort(404)
    return render_template('owner_logs.html',
                           entry=entry, dates=_list_dates(port2),
                           date=None, sessions=None)


@owner_bp.route('/<date>/', methods=['GET'])
@require_login
def owner_sessions(date):
    port2 = current_owner()
    _safe_date(date)
    entry = _entry_label(port2)
    if entry is None:
        abort(404)
    return render_template('owner_logs.html',
                           entry=entry, dates=_list_dates(port2),
                           date=date, sessions=_list_sessions(port2, date))


@owner_bp.route('/<date>/<session_name>', methods=['GET'])
@require_login
def owner_download(date, session_name):
    port2 = current_owner()
    return _send_session_file(port2, date, session_name)
