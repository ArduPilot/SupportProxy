"""Self-service routes for an owner editing their own entry."""
from flask import Blueprint, abort, flash, redirect, render_template, url_for

import keydb_lib

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
    return render_template('owner.html', form=form, entry=ke)
