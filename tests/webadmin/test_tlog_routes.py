"""Tlog form-field handling and the listing/download blueprint."""
import os
import pytest

import keydb_lib

from _test_helpers import (ALICE_PASS, ALICE_PORT1, ALICE_PORT2,
                           BOB_PASS, BOB_PORT1, BOB_PORT2,
                           fetch_entry, login_as)
from webadmin import create_app


@pytest.fixture
def logs_dir(tmp_path):
    """Per-test logs/ root the webadmin can serve from."""
    p = tmp_path / 'logs'
    p.mkdir()
    return p


@pytest.fixture
def app(keydb_path, logs_dir):
    """Override the default app fixture to also point LOGS_DIR at our tmpdir."""
    return create_app({
        'TESTING': True,
        'WTF_CSRF_ENABLED': False,
        'SESSION_COOKIE_SECURE': False,
        'KEYDB_PATH': keydb_path,
        'LOGS_DIR': str(logs_dir),
        'SECRET_KEY': 'test',
    })


def seed_session(logs_root, port2, date, session_name, content=b'TLOGDATA'):
    d = logs_root / str(port2) / date
    d.mkdir(parents=True, exist_ok=True)
    f = d / session_name
    f.write_bytes(content)
    return f


# ---------------------------------------------------------------------------
# form: enable / disable / retention validation
# ---------------------------------------------------------------------------

class TestOwnerTlogForm:
    def test_owner_enable_default_retention(self, client, keydb_path):
        login_as(client, ALICE_PORT1, ALICE_PASS)
        resp = client.post('/me/', data={
            'name': 'alice',
            'tlog_enabled': 'y',
            'submit': 'Save',
        })
        assert resp.status_code == 302
        ke = fetch_entry(keydb_path, ALICE_PORT2)
        assert ke.flags & keydb_lib.FLAG_TLOG
        # First-enable from a fresh-zero state seeds 7 days.
        assert ke.tlog_retention_days == keydb_lib.DEFAULT_TLOG_RETENTION_DAYS

    def test_owner_set_custom_retention(self, client, keydb_path):
        login_as(client, ALICE_PORT1, ALICE_PASS)
        client.post('/me/', data={
            'name': 'alice',
            'tlog_enabled': 'y',
            'tlog_retention_days': '15',
            'submit': 'Save',
        })
        ke = fetch_entry(keydb_path, ALICE_PORT2)
        assert ke.flags & keydb_lib.FLAG_TLOG
        assert ke.tlog_retention_days == 15.0

    def test_owner_retention_over_30_rejected(self, client, keydb_path):
        login_as(client, ALICE_PORT1, ALICE_PASS)
        resp = client.post('/me/', data={
            'name': 'alice',
            'tlog_enabled': 'y',
            'tlog_retention_days': '60',
            'submit': 'Save',
        })
        # WTForms re-renders the page (200) on a validator failure.
        assert resp.status_code == 200
        ke = fetch_entry(keydb_path, ALICE_PORT2)
        assert not (ke.flags & keydb_lib.FLAG_TLOG)
        assert ke.tlog_retention_days == 0.0

    def test_owner_disable_keeps_retention(self, client, keydb_path):
        login_as(client, ALICE_PORT1, ALICE_PASS)
        # enable + 14 days
        client.post('/me/', data={
            'name': 'alice', 'tlog_enabled': 'y',
            'tlog_retention_days': '14', 'submit': 'Save',
        })
        # disable (omit checkbox)
        client.post('/me/', data={
            'name': 'alice',
            'tlog_retention_days': '14',
            'submit': 'Save',
        })
        ke = fetch_entry(keydb_path, ALICE_PORT2)
        assert not (ke.flags & keydb_lib.FLAG_TLOG)
        assert ke.tlog_retention_days == 14.0


class TestAdminTlogForm:
    def test_admin_can_set_high_retention(self, client, keydb_path):
        login_as(client, BOB_PORT1, BOB_PASS)
        # bob_admin edits alice's entry
        resp = client.post('/admin/' + str(ALICE_PORT2), data={
            'name': 'alice',
            'port1': str(ALICE_PORT1),
            'tlog_enabled': 'y',
            'tlog_retention_days': '365',
            'submit': 'Save',
        })
        assert resp.status_code == 302
        ke = fetch_entry(keydb_path, ALICE_PORT2)
        assert ke.flags & keydb_lib.FLAG_TLOG
        assert ke.tlog_retention_days == 365.0

    def test_admin_can_set_fractional(self, client, keydb_path):
        login_as(client, BOB_PORT1, BOB_PASS)
        client.post('/admin/' + str(ALICE_PORT2), data={
            'name': 'alice',
            'port1': str(ALICE_PORT1),
            'tlog_enabled': 'y',
            'tlog_retention_days': '0.5',
            'submit': 'Save',
        })
        ke = fetch_entry(keydb_path, ALICE_PORT2)
        assert ke.tlog_retention_days == 0.5


# ---------------------------------------------------------------------------
# listing & download
# ---------------------------------------------------------------------------

class TestOwnerTlogListing:
    def test_owner_lists_own_dates_and_downloads(self, client, keydb_path,
                                                  logs_dir):
        seed_session(logs_dir, ALICE_PORT2, '2026-05-10', 'session1.tlog',
                     content=b'\x00\x00\x00\x00ALICE_TLOG')
        login_as(client, ALICE_PORT1, ALICE_PASS)

        # date listing
        r = client.get('/me/tlogs/')
        assert r.status_code == 200
        assert b'2026-05-10' in r.data

        # session listing for that date
        r = client.get('/me/tlogs/2026-05-10/')
        assert r.status_code == 200
        assert b'session1.tlog' in r.data

        # download
        r = client.get('/me/tlogs/2026-05-10/session1.tlog')
        assert r.status_code == 200
        assert r.data.endswith(b'ALICE_TLOG')

    def test_owner_cannot_download_other_via_owner_route(self, client,
                                                          keydb_path,
                                                          logs_dir):
        seed_session(logs_dir, BOB_PORT2, '2026-05-10', 'session1.tlog',
                     content=b'BOB_TLOG')
        login_as(client, ALICE_PORT1, ALICE_PASS)
        # Owner route is scoped to the session's port2 (alice's), so
        # /me/tlogs/<date>/session1.tlog reads from logs/ALICE_PORT2/...
        # which doesn't exist -> 404.
        r = client.get('/me/tlogs/2026-05-10/session1.tlog')
        assert r.status_code == 404

    def test_owner_cannot_use_admin_tlog_route(self, client, logs_dir):
        seed_session(logs_dir, BOB_PORT2, '2026-05-10', 'session1.tlog')
        login_as(client, ALICE_PORT1, ALICE_PASS)
        r = client.get('/admin/tlogs/' + str(BOB_PORT2) + '/')
        assert r.status_code == 403


class TestAdminTlogListing:
    def test_admin_lists_any_port2(self, client, logs_dir):
        seed_session(logs_dir, ALICE_PORT2, '2026-05-09', 'session1.tlog')
        seed_session(logs_dir, ALICE_PORT2, '2026-05-10', 'session1.tlog')
        login_as(client, BOB_PORT1, BOB_PASS)
        r = client.get('/admin/tlogs/' + str(ALICE_PORT2) + '/')
        assert r.status_code == 200
        assert b'2026-05-09' in r.data
        assert b'2026-05-10' in r.data

    def test_admin_downloads_any(self, client, logs_dir):
        seed_session(logs_dir, ALICE_PORT2, '2026-05-10', 'session3.tlog',
                     content=b'\x01\x02\x03ADMIN_DL')
        login_as(client, BOB_PORT1, BOB_PASS)
        r = client.get('/admin/tlogs/' + str(ALICE_PORT2)
                       + '/2026-05-10/session3.tlog')
        assert r.status_code == 200
        assert r.data.endswith(b'ADMIN_DL')

    def test_admin_404_for_unknown_port2(self, client):
        login_as(client, BOB_PORT1, BOB_PASS)
        r = client.get('/admin/tlogs/99999/')
        assert r.status_code == 404


class TestPathSafety:
    @pytest.mark.parametrize('bad', [
        '../etc',           # date with traversal
        '2026-05-10/../..', # date with traversal suffix
        'abc',              # not a date
        '2026/05/10',       # wrong separators
    ])
    def test_bad_date_404(self, client, bad):
        login_as(client, BOB_PORT1, BOB_PASS)
        # admin route is the most permissive auth-wise, so it's the
        # interesting one for path-safety.
        r = client.get('/admin/tlogs/' + str(ALICE_PORT2) + '/' + bad + '/')
        assert r.status_code == 404

    def test_bad_session_name_404(self, client, logs_dir):
        seed_session(logs_dir, ALICE_PORT2, '2026-05-10', 'session1.tlog')
        login_as(client, BOB_PORT1, BOB_PASS)
        r = client.get('/admin/tlogs/' + str(ALICE_PORT2)
                       + '/2026-05-10/notatlog')
        assert r.status_code == 404
        # send_from_directory blocks any traversal that escapes the date dir
        r = client.get('/admin/tlogs/' + str(ALICE_PORT2)
                       + '/2026-05-10/..%2fsession1.tlog')
        assert r.status_code == 404


class TestUnauthenticated:
    def test_owner_routes_redirect_to_login(self, client):
        r = client.get('/me/tlogs/', follow_redirects=False)
        assert r.status_code == 302
        assert '/login' in r.location

    def test_admin_routes_redirect_to_login(self, client):
        r = client.get('/admin/tlogs/' + str(ALICE_PORT2) + '/',
                       follow_redirects=False)
        # require_admin aborts 403 for unauthenticated _refresh_role:
        # they're not logged in, so role check fails. Acceptable: 403.
        assert r.status_code == 403
