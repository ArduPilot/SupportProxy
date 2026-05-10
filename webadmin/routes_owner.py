"""Self-service routes for an owner editing their own entry."""
from flask import Blueprint, abort, flash, redirect, render_template, url_for

import keydb_lib

from . import connections as conn_db
from .auth import current_owner, require_login
from .db import tdb_readonly, tdb_transaction
from .forms import OwnerEditForm

bp = Blueprint('owner', __name__, url_prefix='/me')


@bp.route('/', methods=['GET', 'POST'])
@require_login
def me():
    port2 = current_owner()
    form = OwnerEditForm()

    if form.validate_on_submit():
        # Defense-in-depth on the owner cap: WTForms enforces it at validate
        # time, but reject again here so any future bypass of the form (e.g.
        # tests, a tweaked validator) still can't push retention over 30.
        if (form.tlog_retention_days.data is not None and
                form.tlog_retention_days.data > 30.0):
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
            was_tlog = bool(ke.flags & keydb_lib.FLAG_TLOG)
            if form.tlog_enabled.data:
                ke.flags |= keydb_lib.FLAG_TLOG
            else:
                ke.flags &= ~keydb_lib.FLAG_TLOG
            if form.tlog_retention_days.data is not None:
                ke.tlog_retention_days = float(form.tlog_retention_days.data)
            # First-enable default to mirror keydb_lib.set_flag's auto-default.
            if (form.tlog_enabled.data and not was_tlog
                    and ke.tlog_retention_days == 0.0
                    and (form.tlog_retention_days.data is None
                         or form.tlog_retention_days.data == 0.0)):
                ke.tlog_retention_days = keydb_lib.DEFAULT_TLOG_RETENTION_DAYS
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
        form.tlog_retention_days.data = ke.tlog_retention_days
    active = conn_db.list_for_port2(port2)
    return render_template('owner.html', form=form, entry=ke, active=active)
