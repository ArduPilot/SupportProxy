"""POSTs without a valid CSRF token must be rejected when CSRF is enabled.

Production runs with CSRF on; the other test files disable it for brevity.
This file uses an alternate app fixture with CSRF enabled and verifies the
guard fires.
"""
import pytest

import keydb_lib

from _test_helpers import (ALICE_PASS, ALICE_PORT1, ALICE_PORT2,
                           BOB_PASS, BOB_PORT1, BOB_PORT2)
from webadmin import create_app


@pytest.fixture
def csrf_app(keydb_path):
    return create_app({
        'TESTING': True,
        'WTF_CSRF_ENABLED': True,
        'SESSION_COOKIE_SECURE': False,
        'KEYDB_PATH': keydb_path,
        'SECRET_KEY': 'csrftest',
    })


@pytest.fixture
def csrf_client(csrf_app):
    return csrf_app.test_client()


class TestCSRF:
    def test_login_post_without_token_rejected(self, csrf_client):
        resp = csrf_client.post('/login',
                                data={'port': ALICE_PORT1,
                                      'passphrase': ALICE_PASS})
        assert resp.status_code == 400

    def test_owner_post_without_token_rejected(self, csrf_client, keydb_path):
        # Even with a valid session, a missing CSRF token must block writes.
        with csrf_client.session_transaction() as sess:
            sess['owner'] = ALICE_PORT2
            sess['is_admin'] = False
        resp = csrf_client.post('/me/', data={'name': 'attacker'})
        assert resp.status_code == 400
        # the keys.tdb entry must be unchanged
        db = keydb_lib.open_db(keydb_path)
        ke = keydb_lib.KeyEntry(ALICE_PORT2)
        ke.fetch(db)
        db.close()
        assert ke.name == 'alice'
