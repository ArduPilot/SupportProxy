"""Admin routes: list all entries, edit any, add, delete.

Last-admin guard: an admin cannot revoke the FLAG_ADMIN bit on the only
remaining admin entry, nor delete it. Both checks happen inside the same
TDB transaction as the mutation so a concurrent grant/revoke can't slip
through.
"""
from flask import (Blueprint, abort, flash, redirect, render_template, request,
                   session, url_for)

import keydb_lib

from . import connections as conn_db
from .auth import is_admin, require_admin
from .db import tdb_readonly, tdb_transaction
from .forms import AdminAddForm, AdminEditForm, DeleteForm

bp = Blueprint('admin', __name__, url_prefix='/admin')


@bp.route('/', methods=['GET'])
@require_admin
def list_entries():
    with tdb_readonly() as db:
        entries = keydb_lib.list_entries(db)
    add_form = AdminAddForm()
    return render_template('admin_list.html', entries=entries, add_form=add_form)


@bp.route('/connections', methods=['GET'])
@require_admin
def connections():
    """Live connections across all entries.

    Joins connections.tdb with keys.tdb so we can render the entry
    name alongside each connection. Auto-refreshes via meta http-equiv
    in the template — the proxy heartbeat is 10s.
    """
    active = conn_db.list_active()
    with tdb_readonly() as db:
        names = {e.port2: e.name for e in keydb_lib.list_entries(db)}
        port1s = {e.port2: e.port1 for e in keydb_lib.list_entries(db)}
    return render_template('admin_connections.html',
                           active=active, names=names, port1s=port1s)


@bp.route('/add', methods=['POST'])
@require_admin
def add_entry():
    form = AdminAddForm()
    if not form.validate_on_submit():
        flash('Add failed: ' + '; '.join(
            '%s: %s' % (k, ', '.join(v)) for k, v in form.errors.items()),
            'error')
        return redirect(url_for('admin.list_entries'))
    try:
        with tdb_transaction() as db:
            keydb_lib.add_entry(db, form.port1.data, form.port2.data,
                                form.name.data, form.passphrase.data)
    except keydb_lib.CLIError as e:
        flash('Add failed: ' + str(e), 'error')
        return redirect(url_for('admin.list_entries'))
    flash('Added entry %d/%d.' % (form.port1.data, form.port2.data), 'success')
    return redirect(url_for('admin.list_entries'))


@bp.route('/<int:port2>', methods=['GET', 'POST'])
@require_admin
def edit(port2):
    form = AdminEditForm()
    delete_form = DeleteForm()

    if request.method == 'POST' and form.validate_on_submit():
        with tdb_transaction() as db:
            ke = keydb_lib.KeyEntry(port2)
            if not ke.fetch(db):
                abort(404)

            # last-admin guard: if we're about to clear FLAG_ADMIN on the
            # only admin, refuse — count admins inside the same transaction
            currently_admin = ke.is_admin()
            making_non_admin = currently_admin and not form.is_admin.data
            if making_non_admin and keydb_lib.count_admins(db) <= 1:
                flash('Refusing to revoke admin from the last admin.', 'error')
                return redirect(url_for('admin.edit', port2=port2))

            ke.name = form.name.data or ''
            if form.port1.data != ke.port1:
                # check uniqueness of new port1 (must not collide with any
                # other port1 or port2)
                ports1, ports2 = keydb_lib.get_port_sets(db)
                ports1.discard(ke.port1)  # our own old value is OK
                if form.port1.data in ports1 or form.port1.data in ports2:
                    flash('port1 %d is already in use.' % form.port1.data,
                          'error')
                    return redirect(url_for('admin.edit', port2=port2))
                ke.port1 = form.port1.data
            if form.new_passphrase.data:
                ke.set_passphrase(form.new_passphrase.data)
            if form.is_admin.data:
                ke.flags |= keydb_lib.FLAG_ADMIN
            else:
                ke.flags &= ~keydb_lib.FLAG_ADMIN
            if form.bidi_sign.data:
                ke.flags |= keydb_lib.FLAG_BIDI_SIGN
            else:
                ke.flags &= ~keydb_lib.FLAG_BIDI_SIGN
            if form.reset_timestamp.data:
                ke.timestamp = 0
            ke.store(db)

            # if the admin just demoted themselves, drop their session role
            if making_non_admin and session.get('owner') == port2:
                session['is_admin'] = False
        flash('Saved.', 'success')
        return redirect(url_for('admin.edit', port2=port2))

    with tdb_readonly() as db:
        ke = keydb_lib.KeyEntry(port2)
        if not ke.fetch(db):
            abort(404)
        form.name.data = ke.name
        form.port1.data = ke.port1
        form.is_admin.data = ke.is_admin()
        form.bidi_sign.data = bool(ke.flags & keydb_lib.FLAG_BIDI_SIGN)
    return render_template('admin_edit.html', form=form, entry=ke,
                           delete_form=delete_form)


@bp.route('/<int:port2>/delete', methods=['POST'])
@require_admin
def delete(port2):
    form = DeleteForm()
    if not form.validate_on_submit():
        abort(400)
    with tdb_transaction() as db:
        ke = keydb_lib.KeyEntry(port2)
        if not ke.fetch(db):
            abort(404)
        if ke.is_admin() and keydb_lib.count_admins(db) <= 1:
            flash('Refusing to delete the last admin entry.', 'error')
            return redirect(url_for('admin.edit', port2=port2))
        ke.remove(db)
        # if the admin just deleted their own entry, clear their session
        if session.get('owner') == port2:
            session.clear()
    flash('Deleted entry %d.' % port2, 'success')
    if session.get('owner') is None:
        return redirect(url_for('auth.login'))
    return redirect(url_for('admin.list_entries'))
