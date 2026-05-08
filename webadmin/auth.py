"""Login / logout / session helpers and role guard decorators."""
import functools
from urllib.parse import urlparse

from flask import (Blueprint, abort, flash, redirect, render_template,
                   request, session, url_for)

import keydb_lib

from .db import tdb_readonly
from .forms import LoginForm

bp = Blueprint('auth', __name__)


def current_owner():
    """port2 of the logged-in user, or None."""
    return session.get('owner')


def _refresh_role():
    """Re-fetch the session's entry from keys.tdb, drop the session if
    it's gone, and sync session['is_admin'] with the entry's current
    FLAG_ADMIN bit. Returns the live KeyEntry (or None when the session
    pointed at an entry that no longer exists).

    Called from require_login / require_admin so that an admin demoted
    or deleted via the web UI / keydb.py CLI can't keep using a stale
    session cookie.
    """
    port2 = current_owner()
    if port2 is None:
        return None
    with tdb_readonly() as db:
        ke = keydb_lib.KeyEntry(port2)
        if not ke.fetch(db):
            session.clear()
            return None
        live_admin = ke.is_admin()
    if session.get('is_admin') != live_admin:
        session['is_admin'] = live_admin
    return ke


def is_admin():
    """For *display* only (templates). Authorisation paths must call
    require_admin so the role is re-validated from keys.tdb."""
    return bool(session.get('is_admin'))


def require_login(view):
    @functools.wraps(view)
    def wrapper(*args, **kwargs):
        if current_owner() is None:
            return redirect(url_for('auth.login', next=request.path))
        if _refresh_role() is None:
            # entry was deleted; session has been cleared
            return redirect(url_for('auth.login', next=request.path))
        return view(*args, **kwargs)
    return wrapper


def require_admin(view):
    @functools.wraps(view)
    def wrapper(*args, **kwargs):
        ke = _refresh_role()
        if ke is None or not ke.is_admin():
            abort(403)
        return view(*args, **kwargs)
    return wrapper


def _is_safe_local_redirect(target):
    """Accept only a same-origin path. Reject scheme-relative URLs like
    '//evil.example/path' (which Flask would 302 to as an external
    redirect) and any URL that names a host."""
    if not target or not target.startswith('/'):
        return False
    if target.startswith('//') or target.startswith('/\\'):
        return False
    parsed = urlparse(target)
    return parsed.scheme == '' and parsed.netloc == ''


@bp.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        port = form.port.data
        passphrase = form.passphrase.data
        with tdb_readonly() as db:
            ke = keydb_lib.find_by_port(db, port)
            ok = ke is not None and ke.passphrase_matches(passphrase)
            # capture role before leaving the transaction
            admin = ok and ke.is_admin()
            port2 = ke.port2 if ke else None
        if ok:
            session.clear()
            session['owner'] = port2
            session['is_admin'] = admin
            next_url = request.args.get('next')
            if _is_safe_local_redirect(next_url):
                return redirect(next_url)
            return redirect(url_for('index'))
        flash('Login failed: unknown port or wrong passphrase.', 'error')
    return render_template('login.html', form=form)


@bp.route('/logout', methods=['POST'])
def logout():
    session.clear()
    return redirect(url_for('auth.login'))
