"""Self-service routes for an owner editing their own entry."""
from flask import Blueprint, abort, flash, redirect, render_template, url_for

import keydb_lib

from . import connections as conn_db
from .auth import current_owner, require_login
from .db import tdb_readonly, tdb_transaction
from .forms import KillForm, OwnerEditForm

bp = Blueprint('owner', __name__, url_prefix='/me')


@bp.route('/kill/<int:conn_index>', methods=['POST'])
@require_login
def kill_connection(conn_index):
    """Drop a single connection on the owner's port2.

    conn_index 0 is the user side: dropping it ends the whole session
    (the proxy can't run without conn1). conn_index >= 1 is an engineer
    slot — the child closes just that slot and keeps everything else.
    """
    form = KillForm()
    if not form.validate_on_submit():
        abort(400)
    port2 = current_owner()
    if conn_db.request_drop(port2, conn_index):
        flash('Drop requested.', 'success')
    else:
        flash('Connection not found or already gone.', 'error')
    return redirect(url_for('owner.me'))


@bp.route('/', methods=['GET', 'POST'])
@require_login
def me():
    port2 = current_owner()
    form = OwnerEditForm()

    if form.validate_on_submit():
        # Defense-in-depth on the owner cap: WTForms enforces it at validate
        # time, but reject again here so any future bypass of the form (e.g.
        # tests, a tweaked validator) still can't push retention over 30.
        if (form.log_retention_days.data is not None and
                form.log_retention_days.data > 30.0):
            abort(403)
        with tdb_transaction() as db:
            ke = keydb_lib.KeyEntry(port2)
            if not ke.fetch(db):
                abort(404)
            if form.name.data is not None:
                ke.name = form.name.data
            if form.new_passphrase.data:
                ke.set_passphrase(form.new_passphrase.data)
            if form.bidi_sign.data:
                ke.flags |= keydb_lib.FLAG_BIDI_SIGN
            else:
                ke.flags &= ~keydb_lib.FLAG_BIDI_SIGN
            was_tlog   = bool(ke.flags & keydb_lib.FLAG_TLOG)
            was_binlog = bool(ke.flags & keydb_lib.FLAG_BINLOG)
            if form.tlog_enabled.data:
                ke.flags |= keydb_lib.FLAG_TLOG
            else:
                ke.flags &= ~keydb_lib.FLAG_TLOG
            if form.binlog_enabled.data:
                ke.flags |= keydb_lib.FLAG_BINLOG
            else:
                ke.flags &= ~keydb_lib.FLAG_BINLOG
            if form.log_retention_days.data is not None:
                ke.log_retention_days = float(form.log_retention_days.data)
            # First-enable default: when either recording flag flips
            # from off to on and retention is still "keep forever",
            # seed 7 days so freshly-toggled flags have a reasonable
            # upper bound. Mirrors keydb_lib.set_flag's auto-default.
            just_enabled = ((form.tlog_enabled.data and not was_tlog)
                            or (form.binlog_enabled.data and not was_binlog))
            if (just_enabled
                    and ke.log_retention_days == 0.0
                    and (form.log_retention_days.data is None
                         or form.log_retention_days.data == 0.0)):
                ke.log_retention_days = keydb_lib.DEFAULT_LOG_RETENTION_DAYS
            if form.fc_sysid.data is not None:
                ke.fc_sysid = int(form.fc_sysid.data)
            if form.reset_timestamp.data:
                ke.timestamp = 0
            ke.store(db)
        flash('Saved.', 'success')
        return redirect(url_for('owner.me'))

    with tdb_readonly() as db:
        ke = keydb_lib.KeyEntry(port2)
        if not ke.fetch(db):
            # session points at an entry that no longer exists; force re-login
            from flask import session
            session.clear()
            return redirect(url_for('auth.login'))
        # populate form defaults from current state
        form.name.data = ke.name
        form.bidi_sign.data = bool(ke.flags & keydb_lib.FLAG_BIDI_SIGN)
        form.tlog_enabled.data = bool(ke.flags & keydb_lib.FLAG_TLOG)
        form.binlog_enabled.data = bool(ke.flags & keydb_lib.FLAG_BINLOG)
        form.log_retention_days.data = ke.log_retention_days
        form.fc_sysid.data = ke.fc_sysid
    active = conn_db.list_for_port2(port2)
    return render_template('owner.html', form=form, entry=ke, active=active,
                           kill_form=KillForm())
