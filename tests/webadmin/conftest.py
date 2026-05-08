"""Fixtures for webadmin tests.

Each test gets a fresh keys.tdb in a per-test tmpdir, seeded with two
entries: a non-admin (alice) and an admin (bob_admin).
"""
import pytest

from _test_helpers import (ALICE_PASS, ALICE_PORT1, ALICE_PORT2,
                           BOB_PASS, BOB_PORT1, BOB_PORT2)
import keydb_lib

from webadmin import create_app


@pytest.fixture
def keydb_path(tmp_path):
    p = str(tmp_path / 'keys.tdb')
    db = keydb_lib.init_db(p)
    db.transaction_start()
    keydb_lib.add_entry(db, ALICE_PORT1, ALICE_PORT2, 'alice', ALICE_PASS)
    keydb_lib.add_entry(db, BOB_PORT1, BOB_PORT2, 'bob_admin', BOB_PASS)
    keydb_lib.set_flag(db, BOB_PORT2, 'admin')
    db.transaction_prepare_commit()
    db.transaction_commit()
    db.close()
    return p


@pytest.fixture
def app(keydb_path):
    return create_app({
        'TESTING': True,
        'WTF_CSRF_ENABLED': False,
        'SESSION_COOKIE_SECURE': False,
        'KEYDB_PATH': keydb_path,
        'SECRET_KEY': 'test',
    })


@pytest.fixture
def client(app):
    return app.test_client()
