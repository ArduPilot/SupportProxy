"""Admin route flows: list, edit, grant/revoke admin, last-admin guard, delete."""
import keydb_lib

from _test_helpers import (ALICE_PASS, ALICE_PORT1, ALICE_PORT2,
                           BOB_PASS, BOB_PORT1, BOB_PORT2,
                           fetch_entry, login_as)


class TestAdminList:
    def test_admin_can_list(self, client):
        login_as(client, BOB_PORT1, BOB_PASS)
        resp = client.get('/admin/')
        assert resp.status_code == 200
        assert b'alice' in resp.data
        assert b'bob_admin' in resp.data


class TestAdminEdit:
    def test_admin_can_grant_admin_to_other(self, client, keydb_path):
        login_as(client, BOB_PORT1, BOB_PASS)
        resp = client.post('/admin/' + str(ALICE_PORT2), data={
            'name': 'alice',
            'port1': ALICE_PORT1,
            'is_admin': 'y',
            'submit': 'Save',
        })
        assert resp.status_code == 302
        assert fetch_entry(keydb_path, ALICE_PORT2).is_admin()

    def test_admin_can_revoke_admin_when_others_remain(self, client, keydb_path):
        # promote alice first
        db = keydb_lib.open_db(keydb_path)
        db.transaction_start()
        keydb_lib.set_flag(db, ALICE_PORT2, 'admin')
        db.transaction_prepare_commit()
        db.transaction_commit()
        db.close()

        # bob revokes own admin (alice is still admin)
        login_as(client, BOB_PORT1, BOB_PASS)
        client.post('/admin/' + str(BOB_PORT2), data={
            'name': 'bob',
            'port1': BOB_PORT1,
            'submit': 'Save',
            # is_admin omitted -> False
        })
        assert not fetch_entry(keydb_path, BOB_PORT2).is_admin()

    def test_cannot_revoke_last_admin(self, client, keydb_path):
        # bob is the only admin in the seed db; revoking should be refused
        login_as(client, BOB_PORT1, BOB_PASS)
        resp = client.post('/admin/' + str(BOB_PORT2), data={
            'name': 'bob',
            'port1': BOB_PORT1,
            'submit': 'Save',
        }, follow_redirects=True)
        assert b'last admin' in resp.data.lower()
        assert fetch_entry(keydb_path, BOB_PORT2).is_admin()

    def test_admin_can_toggle_bidi_sign(self, client, keydb_path):
        login_as(client, BOB_PORT1, BOB_PASS)
        # set bidi_sign on alice
        client.post('/admin/' + str(ALICE_PORT2), data={
            'name': 'alice',
            'port1': ALICE_PORT1,
            'bidi_sign': 'y',
            'submit': 'Save',
        })
        ke = fetch_entry(keydb_path, ALICE_PORT2)
        assert ke.flags & keydb_lib.FLAG_BIDI_SIGN
        # clear it (omit the checkbox -> falsy)
        client.post('/admin/' + str(ALICE_PORT2), data={
            'name': 'alice',
            'port1': ALICE_PORT1,
            'submit': 'Save',
        })
        ke = fetch_entry(keydb_path, ALICE_PORT2)
        assert not (ke.flags & keydb_lib.FLAG_BIDI_SIGN)

    def test_admin_can_change_passphrase_of_other(self, client, keydb_path):
        login_as(client, BOB_PORT1, BOB_PASS)
        client.post('/admin/' + str(ALICE_PORT2), data={
            'name': 'alice',
            'port1': ALICE_PORT1,
            'new_passphrase': 'newalicepass',
            'confirm_passphrase': 'newalicepass',
            'submit': 'Save',
        })
        ke = fetch_entry(keydb_path, ALICE_PORT2)
        assert ke.passphrase_matches('newalicepass')

    def test_admin_can_change_port1(self, client, keydb_path):
        login_as(client, BOB_PORT1, BOB_PASS)
        client.post('/admin/' + str(ALICE_PORT2), data={
            'name': 'alice',
            'port1': 14600,
            'submit': 'Save',
        })
        assert fetch_entry(keydb_path, ALICE_PORT2).port1 == 14600

    def test_admin_cannot_change_port1_to_collision(self, client, keydb_path):
        login_as(client, BOB_PORT1, BOB_PASS)
        # try to set alice's port1 to bob's port1 (collision)
        resp = client.post('/admin/' + str(ALICE_PORT2), data={
            'name': 'alice',
            'port1': BOB_PORT1,
            'submit': 'Save',
        }, follow_redirects=True)
        assert b'already in use' in resp.data
        assert fetch_entry(keydb_path, ALICE_PORT2).port1 == ALICE_PORT1


class TestAdminAdd:
    def test_admin_can_add_entry(self, client, keydb_path):
        login_as(client, BOB_PORT1, BOB_PASS)
        client.post('/admin/add', data={
            'port1': 15000,
            'port2': 15001,
            'name': 'new entry',
            'passphrase': 'newpass',
            'submit': 'Add',
        })
        ke = fetch_entry(keydb_path, 15001)
        assert ke is not None
        assert ke.port1 == 15000
        assert ke.passphrase_matches('newpass')


class TestAdminDelete:
    def test_admin_can_delete_other(self, client, keydb_path):
        login_as(client, BOB_PORT1, BOB_PASS)
        client.post('/admin/' + str(ALICE_PORT2) + '/delete',
                    data={'submit': 'Delete'})
        assert fetch_entry(keydb_path, ALICE_PORT2) is None

    def test_cannot_delete_last_admin(self, client, keydb_path):
        login_as(client, BOB_PORT1, BOB_PASS)
        client.post('/admin/' + str(BOB_PORT2) + '/delete',
                    data={'submit': 'Delete'}, follow_redirects=True)
        assert fetch_entry(keydb_path, BOB_PORT2) is not None


class TestNonAdminBlocked:
    def test_non_admin_cannot_edit_other(self, client):
        login_as(client, ALICE_PORT1, ALICE_PASS)
        assert client.post('/admin/' + str(BOB_PORT2), data={
            'name': 'attacker',
            'port1': BOB_PORT1,
            'submit': 'Save',
        }).status_code == 403

    def test_non_admin_cannot_delete(self, client):
        login_as(client, ALICE_PORT1, ALICE_PASS)
        assert client.post('/admin/' + str(BOB_PORT2) + '/delete',
                           data={'submit': 'Delete'}).status_code == 403


class TestSessionRevalidation:
    """The session cookie carries is_admin, but the role guards must
    re-check the live FLAG_ADMIN bit on every request — otherwise an
    admin who's been demoted (or had their entry deleted) could keep
    using a stale session to act as admin."""

    def test_demoted_admin_loses_privilege_immediately(self, client, keydb_path):
        # promote alice so we have two admins (otherwise the last-admin
        # guard would block the demotion below)
        db = keydb_lib.open_db(keydb_path)
        db.transaction_start()
        keydb_lib.set_flag(db, ALICE_PORT2, 'admin')
        db.transaction_prepare_commit()
        db.transaction_commit()
        db.close()

        # alice logs in and confirms she has admin access
        login_as(client, ALICE_PORT1, ALICE_PASS)
        assert client.get('/admin/').status_code == 200

        # while alice's session is still alive, demote her in the DB
        # (simulating bob revoking alice's admin via a separate session)
        db = keydb_lib.open_db(keydb_path)
        db.transaction_start()
        keydb_lib.clear_flag(db, ALICE_PORT2, 'admin')
        db.transaction_prepare_commit()
        db.transaction_commit()
        db.close()

        # alice's next admin request must be blocked even though her
        # session still says is_admin=True
        assert client.get('/admin/').status_code == 403
        # /me/ still works for alice as a normal owner
        assert client.get('/me/').status_code == 200

    def test_deleted_user_session_redirected_to_login(self, client, keydb_path):
        login_as(client, ALICE_PORT1, ALICE_PASS)
        # alice's entry is deleted out from under her (e.g. an admin
        # using a different session removed it via /admin/<port2>/delete)
        db = keydb_lib.open_db(keydb_path)
        db.transaction_start()
        keydb_lib.remove_entry(db, ALICE_PORT2)
        db.transaction_prepare_commit()
        db.transaction_commit()
        db.close()

        resp = client.get('/me/')
        assert resp.status_code == 302
        assert '/login' in resp.location
        with client.session_transaction() as sess:
            assert 'owner' not in sess
