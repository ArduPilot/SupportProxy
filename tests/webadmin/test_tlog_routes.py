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

    def test_owner_enable_binlog_via_form(self, client, keydb_path):
        login_as(client, ALICE_PORT1, ALICE_PASS)
        resp = client.post('/me/', data={
            'name': 'alice',
            'binlog_enabled': 'y',
            'submit': 'Save',
        })
        assert resp.status_code == 302
        ke = fetch_entry(keydb_path, ALICE_PORT2)
        assert ke.flags & keydb_lib.FLAG_BINLOG
        # First-enable seeds 7 days for binlog too (shared with tlog).
        assert ke.tlog_retention_days == keydb_lib.DEFAULT_TLOG_RETENTION_DAYS

    def test_owner_disable_binlog_keeps_retention(self, client, keydb_path):
        login_as(client, ALICE_PORT1, ALICE_PASS)
        # enable + 20 days
        client.post('/me/', data={
            'name': 'alice', 'binlog_enabled': 'y',
            'tlog_retention_days': '20', 'submit': 'Save',
        })
        # disable (omit checkbox)
        client.post('/me/', data={
            'name': 'alice', 'tlog_retention_days': '20',
            'submit': 'Save',
        })
        ke = fetch_entry(keydb_path, ALICE_PORT2)
        assert not (ke.flags & keydb_lib.FLAG_BINLOG)
        assert ke.tlog_retention_days == 20.0

    def test_owner_tlog_and_binlog_independent_toggles(self, client, keydb_path):
        """The two flags are toggled independently on one POST."""
        login_as(client, ALICE_PORT1, ALICE_PASS)
        client.post('/me/', data={
            'name': 'alice',
            'tlog_enabled': 'y',
            'binlog_enabled': 'y',
            'submit': 'Save',
        })
        ke = fetch_entry(keydb_path, ALICE_PORT2)
        assert ke.flags & keydb_lib.FLAG_TLOG
        assert ke.flags & keydb_lib.FLAG_BINLOG
        # Drop only tlog.
        client.post('/me/', data={
            'name': 'alice',
            'binlog_enabled': 'y',
            'submit': 'Save',
        })
        ke = fetch_entry(keydb_path, ALICE_PORT2)
        assert not (ke.flags & keydb_lib.FLAG_TLOG)
        assert ke.flags & keydb_lib.FLAG_BINLOG

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

    def test_admin_enable_binlog_via_form(self, client, keydb_path):
        login_as(client, BOB_PORT1, BOB_PASS)
        resp = client.post('/admin/' + str(ALICE_PORT2), data={
            'name': 'alice',
            'port1': str(ALICE_PORT1),
            'binlog_enabled': 'y',
            'submit': 'Save',
        })
        assert resp.status_code == 302
        ke = fetch_entry(keydb_path, ALICE_PORT2)
        assert ke.flags & keydb_lib.FLAG_BINLOG

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

class TestSessionNaturalSort:
    """Session files must sort by their numeric N, not lexically. With
    a plain string sort 'session10.tlog' lands between 'session1.tlog'
    and 'session2.tlog'."""

    def test_owner_sessions_in_natural_order(self, client, keydb_path,
                                              logs_dir):
        # Seed in a deliberately scrambled order so the listing has to
        # actually sort.
        for n in (1, 11, 2, 10, 3, 20, 9):
            seed_session(logs_dir, ALICE_PORT2, '2026-05-10',
                         'session%d.tlog' % n, content=b'X')
        login_as(client, ALICE_PORT1, ALICE_PASS)
        r = client.get('/me/tlogs/2026-05-10/')
        assert r.status_code == 200
        body = r.data.decode()
        names = ['session%d.tlog' % n for n in (1, 11, 2, 10, 3, 20, 9)]
        positions = sorted((body.index(n), n) for n in names)
        ordered = [p[1] for p in positions]
        assert ordered == ['session1.tlog', 'session2.tlog', 'session3.tlog',
                           'session9.tlog', 'session10.tlog',
                           'session11.tlog', 'session20.tlog'], \
            'got order %r' % ordered

    def test_mixed_tlog_and_bin_natural_order(self, client, logs_dir):
        # tlog9 and bin10 in the same dir — natural sort by numeric N
        # comes first; ties go to extension order (tlog < bin
        # alphabetically lower-cased).
        seed_session(logs_dir, ALICE_PORT2, '2026-05-10',
                     'session2.tlog', content=b'X')
        seed_session(logs_dir, ALICE_PORT2, '2026-05-10',
                     'session10.bin',  content=b'X')
        seed_session(logs_dir, ALICE_PORT2, '2026-05-10',
                     'session10.tlog', content=b'X')
        login_as(client, BOB_PORT1, BOB_PASS)
        r = client.get('/admin/tlogs/' + str(ALICE_PORT2) + '/2026-05-10/')
        body = r.data.decode()
        # session2 (numeric 2) must come before either session10.
        assert body.index('session2.tlog') < body.index('session10.bin')
        assert body.index('session2.tlog') < body.index('session10.tlog')


class TestBinFileListing:
    """`.bin` files (ArduPilot dataflash logs over MAVLink) live in the
    same per-date dir as `.tlog` files and are surfaced through the
    same listing + download endpoints. The regex broadening in
    webadmin/tlogs.py is the only change."""

    def test_bin_appears_in_owner_listing(self, client, keydb_path,
                                            logs_dir):
        seed_session(logs_dir, ALICE_PORT2, '2026-05-10', 'session1.tlog',
                     content=b'TLOG')
        seed_session(logs_dir, ALICE_PORT2, '2026-05-10', 'session1.bin',
                     content=b'BIN')
        login_as(client, ALICE_PORT1, ALICE_PASS)
        r = client.get('/me/tlogs/2026-05-10/')
        assert r.status_code == 200
        assert b'session1.tlog' in r.data
        assert b'session1.bin' in r.data

    def test_bin_appears_in_admin_listing(self, client, logs_dir):
        seed_session(logs_dir, ALICE_PORT2, '2026-05-10', 'session2.bin',
                     content=b'BIN')
        login_as(client, BOB_PORT1, BOB_PASS)
        r = client.get('/admin/tlogs/' + str(ALICE_PORT2) + '/2026-05-10/')
        assert r.status_code == 200
        assert b'session2.bin' in r.data

    def test_owner_can_download_bin(self, client, keydb_path, logs_dir):
        seed_session(logs_dir, ALICE_PORT2, '2026-05-10', 'session1.bin',
                     content=b'\x00\x01ARDUPILOT_LOG')
        login_as(client, ALICE_PORT1, ALICE_PASS)
        r = client.get('/me/tlogs/2026-05-10/session1.bin')
        assert r.status_code == 200
        assert r.data.endswith(b'ARDUPILOT_LOG')

    def test_bin_download_is_no_store(self, client, keydb_path, logs_dir):
        """Same private/no-store header as tlog downloads — bin contains
        identical-sensitivity vehicle telemetry."""
        seed_session(logs_dir, ALICE_PORT2, '2026-05-10', 'session1.bin',
                     content=b'BIN')
        login_as(client, ALICE_PORT1, ALICE_PASS)
        r = client.get('/me/tlogs/2026-05-10/session1.bin')
        assert r.status_code == 200
        cc = r.headers.get('Cache-Control', '')
        assert 'no-store' in cc
        assert 'private' in cc
        assert 'public' not in cc

    def test_bogus_extension_still_404s(self, client, logs_dir):
        """The session-file regex caps the extension to tlog|bin so
        seeded .log / .txt / .pem files are not exposed."""
        d = logs_dir / str(ALICE_PORT2) / '2026-05-10'
        d.mkdir(parents=True, exist_ok=True)
        (d / 'session1.log').write_bytes(b'X')
        (d / 'session1.pem').write_bytes(b'X')
        login_as(client, BOB_PORT1, BOB_PASS)
        r = client.get('/admin/tlogs/' + str(ALICE_PORT2)
                       + '/2026-05-10/session1.log')
        assert r.status_code == 404
        r = client.get('/admin/tlogs/' + str(ALICE_PORT2)
                       + '/2026-05-10/session1.pem')
        assert r.status_code == 404


class TestTlogDownloadCacheHeaders:
    """Tlog payloads contain raw vehicle telemetry. They must not be
    cached by browsers or intermediaries — even though the rest of
    the app's static assets (logo, CSS, JS) are aggressively cached
    via SEND_FILE_MAX_AGE_DEFAULT. The download endpoint overrides
    the cache header explicitly."""

    def test_owner_download_is_no_store(self, client, keydb_path, logs_dir):
        seed_session(logs_dir, ALICE_PORT2, '2026-05-10', 'session1.tlog',
                     content=b'TLOG')
        login_as(client, ALICE_PORT1, ALICE_PASS)
        r = client.get('/me/tlogs/2026-05-10/session1.tlog')
        assert r.status_code == 200
        cc = r.headers.get('Cache-Control', '')
        assert 'no-store' in cc
        assert 'private' in cc
        assert 'public' not in cc
        assert 'max-age=86400' not in cc

    def test_admin_download_is_no_store(self, client, keydb_path, logs_dir):
        seed_session(logs_dir, ALICE_PORT2, '2026-05-10', 'session1.tlog',
                     content=b'TLOG')
        login_as(client, BOB_PORT1, BOB_PASS)
        r = client.get('/admin/tlogs/' + str(ALICE_PORT2)
                       + '/2026-05-10/session1.tlog')
        assert r.status_code == 200
        cc = r.headers.get('Cache-Control', '')
        assert 'no-store' in cc
        assert 'private' in cc


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
