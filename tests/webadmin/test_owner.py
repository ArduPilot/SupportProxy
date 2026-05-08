"""Owner self-service flows."""
import keydb_lib

from _test_helpers import (ALICE_PASS, ALICE_PORT1, ALICE_PORT2, BOB_PORT2,
                           fetch_entry, login_as)


class TestOwner:
    def test_owner_can_change_passphrase(self, client, keydb_path):
        login_as(client, ALICE_PORT1, ALICE_PASS)
        resp = client.post('/me/', data={
            'name': 'alice',
            'new_passphrase': 'newpass1',
            'confirm_passphrase': 'newpass1',
            'submit': 'Save',
        })
        assert resp.status_code == 302

        ke = fetch_entry(keydb_path, ALICE_PORT2)
        assert ke is not None
        assert ke.passphrase_matches('newpass1')
        assert not ke.passphrase_matches(ALICE_PASS)

    def test_owner_passphrase_mismatch_rejected(self, client, keydb_path):
        login_as(client, ALICE_PORT1, ALICE_PASS)
        resp = client.post('/me/', data={
            'name': 'alice',
            'new_passphrase': 'newpass1',
            'confirm_passphrase': 'different',
            'submit': 'Save',
        })
        # form re-renders, no save
        assert resp.status_code == 200
        ke = fetch_entry(keydb_path, ALICE_PORT2)
        assert ke.passphrase_matches(ALICE_PASS)

    def test_owner_can_rename(self, client, keydb_path):
        login_as(client, ALICE_PORT1, ALICE_PASS)
        client.post('/me/', data={
            'name': 'alice renamed',
            'submit': 'Save',
        })
        ke = fetch_entry(keydb_path, ALICE_PORT2)
        assert ke.name == 'alice renamed'

    def test_owner_can_toggle_bidi_sign(self, client, keydb_path):
        login_as(client, ALICE_PORT1, ALICE_PASS)
        # turn it on
        client.post('/me/', data={
            'name': 'alice',
            'bidi_sign': 'y',
            'submit': 'Save',
        })
        ke = fetch_entry(keydb_path, ALICE_PORT2)
        assert ke.flags & keydb_lib.FLAG_BIDI_SIGN
        # turn it off (omit the checkbox -> falsy)
        client.post('/me/', data={
            'name': 'alice',
            'submit': 'Save',
        })
        ke = fetch_entry(keydb_path, ALICE_PORT2)
        assert not (ke.flags & keydb_lib.FLAG_BIDI_SIGN)

    def test_owner_can_reset_signing_timestamp(self, client, keydb_path):
        # seed a non-zero timestamp first
        db = keydb_lib.open_db(keydb_path)
        db.transaction_start()
        ke = keydb_lib.KeyEntry(ALICE_PORT2)
        ke.fetch(db)
        ke.timestamp = 999999
        ke.store(db)
        db.transaction_prepare_commit()
        db.transaction_commit()
        db.close()

        login_as(client, ALICE_PORT1, ALICE_PASS)
        client.post('/me/', data={
            'name': 'alice',
            'reset_timestamp': 'y',
            'submit': 'Save',
        })
        assert fetch_entry(keydb_path, ALICE_PORT2).timestamp == 0

    def test_owner_cannot_access_admin_routes(self, client):
        login_as(client, ALICE_PORT1, ALICE_PASS)
        assert client.get('/admin/').status_code == 403
        assert client.get('/admin/' + str(BOB_PORT2)).status_code == 403

    def test_anonymous_cannot_access_me(self, client):
        resp = client.get('/me/')
        assert resp.status_code == 302
        assert '/login' in resp.location
