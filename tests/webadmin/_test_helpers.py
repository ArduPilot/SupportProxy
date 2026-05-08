"""Constants and helpers shared by the webadmin test modules.

This is a regular Python module (not conftest.py) so test files can import
it directly with `from _test_helpers import ...`. pytest puts the test
file's directory on sys.path, so the bare `_test_helpers` name resolves.
"""
import os
import sys

_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__),
                                          os.pardir, os.pardir))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

import keydb_lib  # noqa: E402


ALICE_PORT1 = 14552
ALICE_PORT2 = 14553
ALICE_PASS = 'alicepass'

BOB_PORT1 = 14554
BOB_PORT2 = 14555
BOB_PASS = 'bobpass'


def login_as(client, port, passphrase):
    return client.post('/login',
                       data={'port': port, 'passphrase': passphrase},
                       follow_redirects=False)


def fetch_entry(keydb_path, port2):
    db = keydb_lib.open_db(keydb_path)
    db.transaction_start()
    try:
        ke = keydb_lib.KeyEntry(port2)
        if ke.fetch(db):
            return ke
        return None
    finally:
        db.transaction_cancel()
        db.close()
