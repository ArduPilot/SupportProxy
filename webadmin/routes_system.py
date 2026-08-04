"""Admin view of the daemon: its activity log, and restarting it.

Separate from routes_admin.py (entries) and logs.py (per-entry session
recordings) because this is about the server itself rather than any
one user's data.
"""
import os

from flask import (Blueprint, current_app, flash, jsonify, redirect,
                   render_template, request, url_for)

from . import proxylog
from .auth import require_admin
from .forms import RestartProxyForm

bp = Blueprint('system', __name__, url_prefix='/admin/system')


@bp.route('/', methods=['GET'])
@require_admin
def index():
    path = proxylog.log_path(current_app)
    return render_template(
        'admin_system.html', restart_form=RestartProxyForm(), log_path=path,
        daemon_pid=proxylog.find_daemon(os.path.dirname(path)))


@bp.route('/log', methods=['GET'])
@require_admin
def log_data():
    """Bytes appended since `offset`, for the live tail.

    Polled, not streamed: gunicorn here runs sync workers, so holding a
    response open for a tail would occupy a worker for as long as the
    page is left open.
    """
    try:
        offset = int(request.args.get('offset', -1))
    except ValueError:
        offset = -1
    text, next_offset, restarted, ident = proxylog.read_since(
        proxylog.log_path(current_app), None if offset < 0 else offset,
        request.args.get('ident') or None)
    return jsonify({'text': text, 'offset': next_offset,
                    'restarted': restarted, 'ident': ident})


@bp.route('/restart', methods=['POST'])
@require_admin
def restart():
    form = RestartProxyForm()
    if not form.validate_on_submit():
        flash('Restart not confirmed.', 'error')
        return redirect(url_for('system.index'))
    # Bound to this installation's working directory: the daemon
    # writes keys.tdb there, which is what distinguishes it from
    # another instance on the same host.
    pid, err = proxylog.restart_daemon(
        os.path.dirname(os.path.abspath(
            current_app.config['KEYDB_PATH'])))
    if err:
        flash('Could not restart the proxy: %s' % err, 'error')
    else:
        flash('Signalled the proxy (pid %d). Live sessions have been '
              'dropped; the supervisor restarts it within a few seconds.'
              % pid, 'success')
    return redirect(url_for('system.index'))
