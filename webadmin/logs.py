"""Routes for browsing and downloading per-entry session logs.

Covers both file types written under logs/<port2>/<YYYY-MM-DD>/:

  * <ts>.tlog — raw MAVLink frame captures (KEY_FLAG_TLOG)
  * <ts>.bin  — ArduPilot dataflash logs over MAVLink (KEY_FLAG_BINLOG)

where <ts> is a YYYY_MM_DD_HH:MM:SS session-start timestamp (with an
optional "-N" collision suffix). Legacy sessionN.* names are still
accepted so older logs remain browsable.

Two parallel views, sharing the listing/download helpers below:

  * shared: /admin/logs/<port2>/[<date>] — admin access, plus the entry's
    configured Private / Login Required / Public read policy
  * owner: /me/logs/[<date>]            — owner can browse only their own

Only admins can mutate logs through the shared namespace; widened entry
access is always read-only.
"""
import functools
import os
import re
import shutil
import stat
import subprocess
import threading
import time

from flask import (Blueprint, Response, abort, current_app, flash, g, redirect,
                   render_template, request, send_from_directory, url_for)

import keydb_lib

from .auth import current_entry, current_owner, require_admin, require_login
from .forms import DeleteLogForm
from .db import tdb_readonly

DATE_RE = re.compile(r'^\d{4}-\d{2}-\d{2}$')
# Cover both .tlog (raw MAVLink frames) and .bin (ArduPilot dataflash
# logs over MAVLink). Listing + download flow through this regex, so
# broadening it surfaces .bin files alongside .tlog without further
# changes. Accept the current YYYY_MM_DD_HH:MM:SS[-N] timestamp names
# and the legacy sessionN names so old logs stay browsable.
SESSION_RE = re.compile(
    r'^(session\d+|\d{4}_\d{2}_\d{2}_\d{2}:\d{2}:\d{2}(-\d+)?)'
    r'\.(tlog|bin|v[1-5]\.ts)$')

# Natural-sort key: treat embedded digit runs as numbers so that
# session10.tlog sorts AFTER session2.tlog (not between session1 and
# session2 as plain lexical sort would). The non-digit chunks are
# lower-cased so a future mixed-case fixture doesn't fight the
# digit chunks.
_NATKEY_RE = re.compile(r'(\d+)')

# A timestamp session name, with an optional "-N" collision suffix. An
# unsuffixed file is the original for that second and must sort BEFORE
# its "-N" siblings — but lexically "-" < ".", so "<ts>-2.bin" would
# otherwise beat "<ts>.bin". Normalise the unsuffixed name to "-1" for
# the sort key so the numeric suffix orders it correctly.
# The extension group must allow a compound extension: a video segment
# is "<ts>[-N].v1.ts", and a single (\.\w+) would not match it, which
# would silently drop video files out of the -N ordering fix below.
_TS_NAME_RE = re.compile(
    r'^(\d{4}_\d{2}_\d{2}_\d{2}:\d{2}:\d{2})(-\d+)?((?:\.\w+)+)$')

# Which session files are video, and so can be played rather than only
# downloaded. Deliberately a separate pattern from SESSION_RE: that one
# decides what may be served at all, this one only what gets a "watch"
# link, and conflating them would let a widened SESSION_RE quietly make
# new file types streamable.
VIDEO_NAME_RE = re.compile(
    r'^(session\d+|\d{4}_\d{2}_\d{2}_\d{2}:\d{2}:\d{2}(-\d+)?)'
    r'\.v[1-5]\.ts$')


def _natural_key(name):
    m = _TS_NAME_RE.match(name)
    if m and not m.group(2):
        name = m.group(1) + '-1' + m.group(3)
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


def _open_by_a_daemon(path):
    """True if some process has this file open.

    Asked of the kernel rather than guessed from mtime. The webadmin
    runs as the same user as the daemon, so its /proc/<pid>/fd entries
    are readable; anything not readable is skipped, which only ever
    makes this less certain, never wrongly certain.
    """
    try:
        target = os.path.realpath(path)
    except OSError:
        return False
    for name in os.listdir('/proc'):
        if not name.isdigit():
            continue
        fddir = '/proc/%s/fd' % name
        try:
            entries = os.listdir(fddir)
        except OSError:
            continue            # not ours, or gone
        for fd in entries:
            try:
                if os.readlink(os.path.join(fddir, fd)) == target:
                    return True
            except OSError:
                continue
    return False


def _is_being_written(path):
    """True if this file should not be deleted yet.

    An mtime heuristic alone is not enough for an interactive delete.
    The cleanup pass can live with one -- it runs on a timer and a
    mistake only costs a retry -- but here a quiet session whose log has
    not been appended to for a while would look idle, and unlinking it
    does not stop the daemon writing: the inode stays alive, its space
    unreclaimed, and the operator sees the file disappear while data is
    still going into it.

    So ask the kernel who has it open, and keep the mtime window as a
    cheap first answer for the common case of a file written seconds
    ago.
    """
    try:
        st = os.stat(path)
    except OSError:
        return False
    grace = current_app.config.get('LOG_ACTIVE_GRACE_S', 60)
    if (time.time() - st.st_mtime) < grace:
        return True
    return _open_by_a_daemon(path)


def _date_dir_fd(port2, date):
    """An fd for logs/<port2>/<date>, refusing to follow symlinks.

    Opening each component with O_NOFOLLOW and then working relative to
    the descriptor means a symlink swapped in anywhere along the path --
    which needs local access, not anything this app exposes -- cannot
    redirect a delete outside the tree. The name checks alone only stop
    traversal spelled in the request.
    """
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    root = None
    entry = None
    try:
        root = os.open(_logs_root(), os.O_RDONLY | os.O_DIRECTORY)
        entry = os.open(str(port2), flags, dir_fd=root)
        return os.open(date, flags, dir_fd=entry)
    except OSError:
        return None
    finally:
        for fd in (entry, root):
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass


def _delete_session(port2, date, session_name):
    """Delete one recording. Returns an error string, or None."""
    _safe_date(date)
    _safe_session(session_name)
    dirfd = _date_dir_fd(port2, date)
    if dirfd is None:
        return 'no such log'
    try:
        path = os.path.join(_logs_root(), str(port2), date, session_name)
        try:
            st = os.stat(session_name, dir_fd=dirfd,
                         follow_symlinks=False)
        except OSError:
            return 'no such log'
        if not stat.S_ISREG(st.st_mode):
            return 'not a recording'
        if _is_being_written(path):
            return 'still being written -- it will be deletable once the ' \
                   'session ends'
        try:
            os.unlink(session_name, dir_fd=dirfd)
        except OSError as e:
            return str(e)
    finally:
        os.close(dirfd)
    return None


def _delete_date(port2, date):
    """Delete every recording for one date. Returns (deleted, skipped).

    Only names SESSION_RE accepts are touched, so nothing else that
    happens to be in the directory can be removed by this route.
    """
    _safe_date(date)
    root = os.path.join(_logs_root(), str(port2), date)
    dirfd = _date_dir_fd(port2, date)
    if dirfd is None:
        return (0, 0)
    deleted = skipped = 0
    try:
        names = os.listdir(dirfd)
    except OSError:
        os.close(dirfd)
        return (0, 0)
    for name in names:
        if not SESSION_RE.match(name):
            continue
        path = os.path.join(root, name)
        try:
            st = os.stat(name, dir_fd=dirfd, follow_symlinks=False)
        except OSError:
            continue
        if not stat.S_ISREG(st.st_mode):
            skipped += 1
            continue
        if _is_being_written(path):
            skipped += 1
            continue
        try:
            os.unlink(name, dir_fd=dirfd)
            deleted += 1
        except OSError:
            skipped += 1
    os.close(dirfd)
    # Tidy the date directory away only if we emptied it. rmdir refuses
    # a non-empty one, so anything we deliberately did not touch keeps
    # it -- which is the behaviour we want.
    try:
        os.rmdir(root)
    except OSError:
        pass
    return (deleted, skipped)


def _flash_day(date, deleted, skipped):
    """One message covering both what went and what stayed."""
    if deleted == 0 and skipped == 0:
        flash('Nothing to delete for %s.' % date, 'error')
        return
    msg = 'Deleted %d file%s from %s.' % (deleted,
                                          '' if deleted == 1 else 's', date)
    if skipped:
        msg += (' %d left in place: still being written, or not removable.'
                % skipped)
    flash(msg, 'success' if deleted else 'error')


def _entry_label(port2):
    """Read the entry's name (best-effort) for display in templates."""
    with tdb_readonly() as db:
        ke = keydb_lib.KeyEntry(port2)
        if not ke.fetch(db):
            return None
        return ke


def require_log_read(view):
    """Allow an admin, or a reader admitted by the entry's log policy.

    These are the existing /admin/logs/<port2>/ URLs so shared links remain
    stable. Only GET views use this decorator; deletion stays behind
    require_admin regardless of the configured read policy.
    """
    @functools.wraps(view)
    def wrapper(port2, *args, **kwargs):
        entry = _entry_label(port2)
        if entry is None:
            abort(404)

        viewer = current_entry()
        can_manage = viewer is not None and viewer.is_admin()
        access = entry.log_access()
        if access == keydb_lib.LOG_ACCESS_PRIVATE and not can_manage:
            abort(403)
        if (access == keydb_lib.LOG_ACCESS_LOGIN_REQUIRED
                and viewer is None):
            return redirect(url_for('auth.login', next=request.path))

        # Avoid a second database read in each listing/playback view and give
        # the template an explicit capability rather than trusting session
        # presentation state for security-sensitive controls.
        g.log_entry = entry
        g.can_manage_logs = can_manage
        return view(port2, *args, **kwargs)
    return wrapper


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
            'is_video': _is_video(name),
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


def _is_video(session_name):
    return VIDEO_NAME_RE.match(session_name or '') is not None


def _ffmpeg_bin():
    """ffmpeg, if this host has it. The video feature already needs it
    for RTSP ingest, so on a server carrying video it is present; the
    web UI must still work without it."""
    return shutil.which('ffmpeg')


# Concurrent remuxes allowed for readers who are not logged in. Each one
# holds a web worker thread and an ffmpeg for as long as the client
# reads, and the shipped gunicorn runs 4 threads: without a cap, a
# public-logs entry lets anonymous readers take all of them.
_REMUX_ANON_MAX = 2
_remux_anon_slots = threading.BoundedSemaphore(_REMUX_ANON_MAX)


def _remux_response(port2, date, session_name):
    """Serve a recording as fragmented MP4 for a plain <video> element.

    Browsers cannot demux MPEG-TS, so the recording is remuxed on the
    fly. It is a stream copy -- no decoding, no re-encoding -- which
    measured at 0.12s of CPU for an 8 MB segment, so it is affordable
    even on the single-core server.

    The response has no Content-Length and so is not seekable: ffmpeg is
    writing it as it goes. Scrubbing through a long segment means
    downloading it, which is what the download link is for.
    """
    _safe_date(date)
    _safe_session(session_name)
    if not _is_video(session_name):
        abort(404)
    ff = _ffmpeg_bin()
    if ff is None:
        abort(501)
    path = os.path.join(_logs_root(), str(port2), date, session_name)
    if not os.path.isfile(path):
        abort(404)

    slot = None
    if current_entry() is None:
        if not _remux_anon_slots.acquire(blocking=False):
            resp = Response('Too many concurrent playbacks; try again '
                            'shortly.\n', status=503, mimetype='text/plain')
            resp.headers['Retry-After'] = '5'
            return resp
        slot = _remux_anon_slots

    try:
        proc = subprocess.Popen(
            [ff, '-hide_banner', '-loglevel', 'error', '-nostdin',
             '-i', path, '-c', 'copy',
             '-movflags', 'frag_keyframe+empty_moov+default_base_moof',
             '-f', 'mp4', 'pipe:1'],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    except OSError:
        if slot is not None:
            slot.release()
        raise

    def generate():
        try:
            while True:
                chunk = proc.stdout.read(64 * 1024)
                if not chunk:
                    break
                yield chunk
        finally:
            # The client closing the tab must not leave an ffmpeg
            # behind: the generator is closed either way, so the kill
            # belongs here rather than after the loop.
            try:
                proc.stdout.close()
            except OSError:
                pass
            if proc.poll() is None:
                proc.kill()
            proc.wait()
            if slot is not None:
                slot.release()

    resp = Response(generate(), mimetype='video/mp4')
    resp.headers['Cache-Control'] = 'private, no-store'
    resp.headers['Content-Disposition'] = 'inline'
    return resp


def _send_session_inline(port2, date, session_name):
    """Serve a recorded video segment for playback rather than download.

    Same validation as the download path; the differences are that it is
    not an attachment, it carries the MPEG-TS content type so a player
    recognises it, and it accepts range requests so seeking works.
    Restricted to video: nothing else here is meaningful to stream, and
    serving a .tlog inline just invites a browser to try rendering it.
    """
    _safe_date(date)
    _safe_session(session_name)
    if not _is_video(session_name):
        abort(404)
    directory = os.path.join(_logs_root(), str(port2), date)
    if not os.path.isdir(directory):
        abort(404)
    resp = send_from_directory(directory, session_name,
                               as_attachment=False, max_age=0,
                               mimetype='video/mp2t',
                               conditional=True)
    resp.headers['Cache-Control'] = 'private, no-store'
    return resp


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
@require_log_read
def admin_dates(port2):
    return render_template('admin_logs.html',
                           entry=g.log_entry, dates=_list_dates(port2),
                           date=None, sessions=None,
                           can_manage=g.can_manage_logs,
                           del_form=(DeleteLogForm()
                                     if g.can_manage_logs else None))


@admin_bp.route('/<int:port2>/<date>/', methods=['GET'])
@require_log_read
def admin_sessions(port2, date):
    _safe_date(date)
    return render_template('admin_logs.html',
                           entry=g.log_entry, dates=_list_dates(port2),
                           date=date, sessions=_list_sessions(port2, date),
                           can_manage=g.can_manage_logs,
                           del_form=(DeleteLogForm()
                                     if g.can_manage_logs else None))


@admin_bp.route('/<int:port2>/<date>/<session_name>', methods=['GET'])
@require_log_read
def admin_download(port2, date, session_name):
    return _send_session_file(port2, date, session_name)


@admin_bp.route('/<int:port2>/<date>/<session_name>/watch', methods=['GET'])
@require_log_read
def admin_watch(port2, date, session_name):
    _safe_date(date)
    _safe_session(session_name)
    if not _is_video(session_name):
        abort(404)
    return render_template(
        'log_play.html', entry=g.log_entry, date=date, name=session_name,
        stream_url=url_for('admin_logs.admin_stream', port2=port2,
                           date=date, session_name=session_name),
        mp4_url=url_for('admin_logs.admin_play_mp4', port2=port2,
                        date=date, session_name=session_name),
        have_ffmpeg=_ffmpeg_bin() is not None,
        download_url=url_for('admin_logs.admin_download', port2=port2,
                             date=date, session_name=session_name),
        back_url=url_for('admin_logs.admin_sessions', port2=port2,
                         date=date))


@admin_bp.route('/<int:port2>/<date>/<session_name>/stream', methods=['GET'])
@require_log_read
def admin_stream(port2, date, session_name):
    return _send_session_inline(port2, date, session_name)


@admin_bp.route('/<int:port2>/<date>/<session_name>/play.mp4',
                methods=['GET'])
@require_log_read
def admin_play_mp4(port2, date, session_name):
    return _remux_response(port2, date, session_name)


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
                           date=None, sessions=None,
                           del_form=DeleteLogForm())


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
                           date=date, sessions=_list_sessions(port2, date),
                           del_form=DeleteLogForm())


@owner_bp.route('/<date>/<session_name>', methods=['GET'])
@require_login
def owner_download(date, session_name):
    port2 = current_owner()
    return _send_session_file(port2, date, session_name)


@owner_bp.route('/<date>/<session_name>/watch', methods=['GET'])
@require_login
def owner_watch(date, session_name):
    port2 = current_owner()
    _safe_date(date)
    _safe_session(session_name)
    if not _is_video(session_name):
        abort(404)
    entry = _entry_label(port2)
    if entry is None:
        abort(404)
    return render_template(
        'log_play.html', entry=entry, date=date, name=session_name,
        stream_url=url_for('owner_logs.owner_stream', date=date,
                           session_name=session_name),
        mp4_url=url_for('owner_logs.owner_play_mp4', date=date,
                        session_name=session_name),
        have_ffmpeg=_ffmpeg_bin() is not None,
        download_url=url_for('owner_logs.owner_download', date=date,
                             session_name=session_name),
        back_url=url_for('owner_logs.owner_sessions', date=date))


@owner_bp.route('/<date>/<session_name>/stream', methods=['GET'])
@require_login
def owner_stream(date, session_name):
    port2 = current_owner()
    return _send_session_inline(port2, date, session_name)


@owner_bp.route('/<date>/<session_name>/play.mp4', methods=['GET'])
@require_login
def owner_play_mp4(date, session_name):
    port2 = current_owner()
    return _remux_response(port2, date, session_name)


# ----------------------------------------------------------- deletion
#
# POST-only, CSRF-protected, and scoped by the same auth decorators as
# the listing: an owner reaches only their own entry because the route
# takes no port2 at all, and an admin any.


@admin_bp.route('/<int:port2>/<date>/<session_name>/delete', methods=['POST'])
@require_admin
def admin_delete_session(port2, date, session_name):
    if not DeleteLogForm().validate_on_submit():
        abort(400)
    err = _delete_session(port2, date, session_name)
    if err:
        flash('Could not delete %s: %s' % (session_name, err), 'error')
    else:
        flash('Deleted %s.' % session_name, 'success')
    return redirect(url_for('admin_logs.admin_sessions',
                            port2=port2, date=date))


@admin_bp.route('/<int:port2>/<date>/delete', methods=['POST'])
@require_admin
def admin_delete_date(port2, date):
    if not DeleteLogForm().validate_on_submit():
        abort(400)
    deleted, skipped = _delete_date(port2, date)
    _flash_day(date, deleted, skipped)
    return redirect(url_for('admin_logs.admin_dates', port2=port2))


@owner_bp.route('/<date>/<session_name>/delete', methods=['POST'])
@require_login
def owner_delete_session(date, session_name):
    if not DeleteLogForm().validate_on_submit():
        abort(400)
    err = _delete_session(current_owner(), date, session_name)
    if err:
        flash('Could not delete %s: %s' % (session_name, err), 'error')
    else:
        flash('Deleted %s.' % session_name, 'success')
    return redirect(url_for('owner_logs.owner_sessions', date=date))


@owner_bp.route('/<date>/delete', methods=['POST'])
@require_login
def owner_delete_date(date):
    if not DeleteLogForm().validate_on_submit():
        abort(400)
    deleted, skipped = _delete_date(current_owner(), date)
    _flash_day(date, deleted, skipped)
    return redirect(url_for('owner_logs.owner_dates'))
