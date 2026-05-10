"""Routes for browsing and downloading per-entry tlogs.

Two parallel views:
  * admin: /admin/tlogs/<port2>/[<date>] — admin can browse any entry
  * owner: /me/tlogs/[<date>]            — owner can browse only their own

Both share the same listing/download helpers below; the blueprints
differ only in which port2 they resolve and which auth decorator they
use.
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
SESSION_RE = re.compile(r'^session\d+\.tlog$')


def _logs_root():
    """Absolute path to the tlog tree root."""
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
    out.sort(reverse=True)
    return out


def _list_sessions(port2, date):
    """All sessionN.tlog files under logs/<port2>/<date>/, sorted by name."""
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
    files.sort(key=lambda f: f['name'])
    return files


def _send_tlog(port2, date, session_name):
    """send_from_directory takes care of path-traversal safety; we still
    pre-validate the date and filename so a malformed URL bounces with a
    404 before touching the filesystem."""
    _safe_date(date)
    _safe_session(session_name)
    directory = os.path.join(_logs_root(), str(port2), date)
    if not os.path.isdir(directory):
        abort(404)
    return send_from_directory(directory, session_name, as_attachment=True)


# ---------------------------------------------------------------------------
# admin views: any port2
# ---------------------------------------------------------------------------

admin_bp = Blueprint('admin_tlogs', __name__, url_prefix='/admin/tlogs')


@admin_bp.route('/<int:port2>/', methods=['GET'])
@require_admin
def admin_dates(port2):
    entry = _entry_label(port2)
    if entry is None:
        abort(404)
    return render_template('admin_tlogs.html',
                           entry=entry, dates=_list_dates(port2),
                           date=None, sessions=None)


@admin_bp.route('/<int:port2>/<date>/', methods=['GET'])
@require_admin
def admin_sessions(port2, date):
    _safe_date(date)
    entry = _entry_label(port2)
    if entry is None:
        abort(404)
    return render_template('admin_tlogs.html',
                           entry=entry, dates=_list_dates(port2),
                           date=date, sessions=_list_sessions(port2, date))


@admin_bp.route('/<int:port2>/<date>/<session_name>', methods=['GET'])
@require_admin
def admin_download(port2, date, session_name):
    return _send_tlog(port2, date, session_name)


# ---------------------------------------------------------------------------
# owner views: only their own port2
# ---------------------------------------------------------------------------

owner_bp = Blueprint('owner_tlogs', __name__, url_prefix='/me/tlogs')


@owner_bp.route('/', methods=['GET'])
@require_login
def owner_dates():
    port2 = current_owner()
    entry = _entry_label(port2)
    if entry is None:
        abort(404)
    return render_template('owner_tlogs.html',
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
    return render_template('owner_tlogs.html',
                           entry=entry, dates=_list_dates(port2),
                           date=date, sessions=_list_sessions(port2, date))


@owner_bp.route('/<date>/<session_name>', methods=['GET'])
@require_login
def owner_download(date, session_name):
    port2 = current_owner()
    return _send_tlog(port2, date, session_name)
