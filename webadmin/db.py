"""TDB transaction helpers shared by the webadmin routes.

Per project policy every write to keys.tdb (and every multi-record
consistent read) is wrapped in a TDB transaction. The `tdb_transaction`
context manager opens the DB, starts a transaction, and commits on clean
exit / cancels on exception. Single-record fetches that don't need a
consistent multi-record view should use `tdb_readonly`.
"""
import contextlib

from flask import current_app

import keydb_lib


def _open():
    return keydb_lib.open_db(current_app.config['KEYDB_PATH'])


@contextlib.contextmanager
def tdb_transaction():
    """Open the DB, run the body inside a TDB transaction, commit on success."""
    db = _open()
    db.transaction_start()
    try:
        yield db
    except Exception:
        db.transaction_cancel()
        db.close()
        raise
    db.transaction_prepare_commit()
    db.transaction_commit()
    db.close()


@contextlib.contextmanager
def tdb_readonly():
    """Open the DB, run the body inside a transaction, always cancel.

    Use for multi-record reads (list view, login lookup) that need a
    consistent snapshot but make no changes.
    """
    db = _open()
    db.transaction_start()
    try:
        yield db
    finally:
        db.transaction_cancel()
        db.close()
