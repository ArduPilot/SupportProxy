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


def set_log_access(keydb_path, port2, access):
    db = keydb_lib.open_db(keydb_path)
    db.transaction_start()
    ke = keydb_lib.KeyEntry(port2)
    assert ke.fetch(db)
    ke.set_log_access(access)
    ke.store(db)
    db.transaction_prepare_commit()
    db.transaction_commit()
    db.close()


# ---------------------------------------------------------------------------
# form: enable / disable / retention validation
# ---------------------------------------------------------------------------

class TestOwnerTlogForm:
    def test_owner_can_make_logs_public(self, client, keydb_path):
        login_as(client, ALICE_PORT1, ALICE_PASS)
        resp = client.post('/me/', data={
            'name': 'alice',
            'log_access': str(keydb_lib.LOG_ACCESS_PUBLIC),
            'submit': 'Save',
        })
        assert resp.status_code == 302
        assert (fetch_entry(keydb_path, ALICE_PORT2).log_access()
                == keydb_lib.LOG_ACCESS_PUBLIC)

    def test_owner_form_offers_all_log_access_choices(self, client):
        login_as(client, ALICE_PORT1, ALICE_PASS)
        body = client.get('/me/').get_data(as_text=True)
        assert '>Private<' in body
        assert '>Login Required<' in body
        assert '>Public<' in body

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
        assert ke.log_retention_days == keydb_lib.DEFAULT_LOG_RETENTION_DAYS

    def test_owner_set_custom_retention(self, client, keydb_path):
        login_as(client, ALICE_PORT1, ALICE_PASS)
        client.post('/me/', data={
            'name': 'alice',
            'tlog_enabled': 'y',
            'log_retention_days': '15',
            'submit': 'Save',
        })
        ke = fetch_entry(keydb_path, ALICE_PORT2)
        assert ke.flags & keydb_lib.FLAG_TLOG
        assert ke.log_retention_days == 15.0

    def test_owner_retention_over_30_rejected(self, client, keydb_path):
        login_as(client, ALICE_PORT1, ALICE_PASS)
        resp = client.post('/me/', data={
            'name': 'alice',
            'tlog_enabled': 'y',
            'log_retention_days': '60',
            'submit': 'Save',
        })
        # WTForms re-renders the page (200) on a validator failure.
        assert resp.status_code == 200
        ke = fetch_entry(keydb_path, ALICE_PORT2)
        assert not (ke.flags & keydb_lib.FLAG_TLOG)
        assert ke.log_retention_days == 0.0

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
        assert ke.log_retention_days == keydb_lib.DEFAULT_LOG_RETENTION_DAYS

    def test_owner_disable_binlog_keeps_retention(self, client, keydb_path):
        login_as(client, ALICE_PORT1, ALICE_PASS)
        # enable + 20 days
        client.post('/me/', data={
            'name': 'alice', 'binlog_enabled': 'y',
            'log_retention_days': '20', 'submit': 'Save',
        })
        # disable (omit checkbox)
        client.post('/me/', data={
            'name': 'alice', 'log_retention_days': '20',
            'submit': 'Save',
        })
        ke = fetch_entry(keydb_path, ALICE_PORT2)
        assert not (ke.flags & keydb_lib.FLAG_BINLOG)
        assert ke.log_retention_days == 20.0

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
            'log_retention_days': '14', 'submit': 'Save',
        })
        # disable (omit checkbox)
        client.post('/me/', data={
            'name': 'alice',
            'log_retention_days': '14',
            'submit': 'Save',
        })
        ke = fetch_entry(keydb_path, ALICE_PORT2)
        assert not (ke.flags & keydb_lib.FLAG_TLOG)
        assert ke.log_retention_days == 14.0


class TestAdminTlogForm:
    def test_admin_can_require_login_for_logs(self, client, keydb_path):
        login_as(client, BOB_PORT1, BOB_PASS)
        resp = client.post('/admin/' + str(ALICE_PORT2), data={
            'name': 'alice',
            'port1': str(ALICE_PORT1),
            'log_access': str(keydb_lib.LOG_ACCESS_LOGIN_REQUIRED),
            'submit': 'Save',
        })
        assert resp.status_code == 302
        assert (fetch_entry(keydb_path, ALICE_PORT2).log_access()
                == keydb_lib.LOG_ACCESS_LOGIN_REQUIRED)

    def test_admin_can_set_high_retention(self, client, keydb_path):
        login_as(client, BOB_PORT1, BOB_PASS)
        # bob_admin edits alice's entry
        resp = client.post('/admin/' + str(ALICE_PORT2), data={
            'name': 'alice',
            'port1': str(ALICE_PORT1),
            'tlog_enabled': 'y',
            'log_retention_days': '365',
            'submit': 'Save',
        })
        assert resp.status_code == 302
        ke = fetch_entry(keydb_path, ALICE_PORT2)
        assert ke.flags & keydb_lib.FLAG_TLOG
        assert ke.log_retention_days == 365.0

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
            'log_retention_days': '0.5',
            'submit': 'Save',
        })
        ke = fetch_entry(keydb_path, ALICE_PORT2)
        assert ke.log_retention_days == 0.5

    def test_owner_can_enable_fixed_timezone(self, client, keydb_path):
        import keydb_lib
        login_as(client, ALICE_PORT1, ALICE_PASS)
        client.post('/me/', data={
            'name': 'alice',
            'use_tz': 'y',
            'tz_offset_hours': '5.5',
            'submit': 'Save',
        })
        ke = fetch_entry(keydb_path, ALICE_PORT2)
        assert abs(ke.tz_offset_hours - 5.5) < 1e-6
        assert ke.flags & keydb_lib.FLAG_USE_TZ

    def test_owner_unticking_use_tz_reverts_to_local(self, client, keydb_path):
        import keydb_lib
        login_as(client, ALICE_PORT1, ALICE_PASS)
        # enable, then submit again without the box -> flag cleared,
        # offset retained.
        client.post('/me/', data={
            'name': 'alice', 'use_tz': 'y', 'tz_offset_hours': '5.5',
            'submit': 'Save'})
        client.post('/me/', data={
            'name': 'alice', 'tz_offset_hours': '5.5', 'submit': 'Save'})
        ke = fetch_entry(keydb_path, ALICE_PORT2)
        assert not (ke.flags & keydb_lib.FLAG_USE_TZ)
        assert abs(ke.tz_offset_hours - 5.5) < 1e-6

    def test_owner_timezone_out_of_range_rejected(self, client, keydb_path):
        login_as(client, ALICE_PORT1, ALICE_PASS)
        r = client.post('/me/', data={
            'name': 'alice',
            'use_tz': 'y',
            'tz_offset_hours': '20',
            'submit': 'Save',
        })
        # form validation fails -> re-render, value not stored
        ke = fetch_entry(keydb_path, ALICE_PORT2)
        assert ke.tz_offset_hours == 0.0


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
        r = client.get('/me/logs/2026-05-10/')
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
        r = client.get('/admin/logs/' + str(ALICE_PORT2) + '/2026-05-10/')
        body = r.data.decode()
        # session2 (numeric 2) must come before either session10.
        assert body.index('session2.tlog') < body.index('session10.bin')
        assert body.index('session2.tlog') < body.index('session10.tlog')


class TestBinFileListing:
    """`.bin` files (ArduPilot dataflash logs over MAVLink) live in the
    same per-date dir as `.tlog` files and are surfaced through the
    same listing + download endpoints. The regex broadening in
    webadmin/logs.py is the only change."""

    def test_bin_appears_in_owner_listing(self, client, keydb_path,
                                            logs_dir):
        seed_session(logs_dir, ALICE_PORT2, '2026-05-10', 'session1.tlog',
                     content=b'TLOG')
        seed_session(logs_dir, ALICE_PORT2, '2026-05-10', 'session1.bin',
                     content=b'BIN')
        login_as(client, ALICE_PORT1, ALICE_PASS)
        r = client.get('/me/logs/2026-05-10/')
        assert r.status_code == 200
        assert b'session1.tlog' in r.data
        assert b'session1.bin' in r.data

    def test_bin_appears_in_admin_listing(self, client, logs_dir):
        seed_session(logs_dir, ALICE_PORT2, '2026-05-10', 'session2.bin',
                     content=b'BIN')
        login_as(client, BOB_PORT1, BOB_PASS)
        r = client.get('/admin/logs/' + str(ALICE_PORT2) + '/2026-05-10/')
        assert r.status_code == 200
        assert b'session2.bin' in r.data

    def test_owner_can_download_bin(self, client, keydb_path, logs_dir):
        seed_session(logs_dir, ALICE_PORT2, '2026-05-10', 'session1.bin',
                     content=b'\x00\x01ARDUPILOT_LOG')
        login_as(client, ALICE_PORT1, ALICE_PASS)
        r = client.get('/me/logs/2026-05-10/session1.bin')
        assert r.status_code == 200
        assert r.data.endswith(b'ARDUPILOT_LOG')

    def test_bin_download_is_no_store(self, client, keydb_path, logs_dir):
        """Same private/no-store header as tlog downloads — bin contains
        identical-sensitivity vehicle telemetry."""
        seed_session(logs_dir, ALICE_PORT2, '2026-05-10', 'session1.bin',
                     content=b'BIN')
        login_as(client, ALICE_PORT1, ALICE_PASS)
        r = client.get('/me/logs/2026-05-10/session1.bin')
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
        r = client.get('/admin/logs/' + str(ALICE_PORT2)
                       + '/2026-05-10/session1.log')
        assert r.status_code == 404
        r = client.get('/admin/logs/' + str(ALICE_PORT2)
                       + '/2026-05-10/session1.pem')
        assert r.status_code == 404


class TestTimestampNames:
    """Session files are named by YYYY_MM_DD_HH:MM:SS timestamp now.
    The listing regex must accept them (with the ':' in the name) and
    downloads must work despite the colons in the URL path."""

    TS = '2026_07_19_09:37:10'

    def test_timestamp_names_listed(self, client, keydb_path, logs_dir):
        seed_session(logs_dir, ALICE_PORT2, '2026-07-19',
                     self.TS + '.tlog', content=b'TLOG')
        seed_session(logs_dir, ALICE_PORT2, '2026-07-19',
                     self.TS + '.bin', content=b'BIN')
        login_as(client, ALICE_PORT1, ALICE_PASS)
        r = client.get('/me/logs/2026-07-19/')
        assert r.status_code == 200
        assert (self.TS + '.tlog').encode() in r.data
        assert (self.TS + '.bin').encode() in r.data

    def test_timestamp_name_downloads(self, client, keydb_path, logs_dir):
        seed_session(logs_dir, ALICE_PORT2, '2026-07-19',
                     self.TS + '.bin', content=b'\x00ARDUPILOT')
        login_as(client, ALICE_PORT1, ALICE_PASS)
        r = client.get('/me/logs/2026-07-19/' + self.TS + '.bin')
        assert r.status_code == 200
        assert r.data.endswith(b'ARDUPILOT')

    def test_collision_suffix_name_ok(self, client, keydb_path, logs_dir):
        seed_session(logs_dir, ALICE_PORT2, '2026-07-19',
                     self.TS + '-2.tlog', content=b'X')
        login_as(client, ALICE_PORT1, ALICE_PASS)
        r = client.get('/me/logs/2026-07-19/')
        assert (self.TS + '-2.tlog').encode() in r.data
        r = client.get('/me/logs/2026-07-19/' + self.TS + '-2.tlog')
        assert r.status_code == 200

    def test_pid_ns_fallback_name_browsable(self, client, keydb_path,
                                            logs_dir):
        # The exhaustion fallback is a single big numeric "-N" suffix
        # (pid+nanoseconds concatenated); it must list and download like
        # any other session file.
        fb = self.TS + '-149785439335901.bin'
        seed_session(logs_dir, ALICE_PORT2, '2026-07-19', fb, content=b'F')
        login_as(client, ALICE_PORT1, ALICE_PASS)
        r = client.get('/me/logs/2026-07-19/')
        assert fb.encode() in r.data
        r = client.get('/me/logs/2026-07-19/' + fb)
        assert r.status_code == 200

    def test_collision_suffix_chronological_order(self, client, keydb_path,
                                                  logs_dir):
        # The unsuffixed original is the first session that second and
        # must list BEFORE its -2 / -10 collision siblings, even though
        # lexically '-' < '.'.
        for suffix in ('-10', '', '-2'):
            seed_session(logs_dir, ALICE_PORT2, '2026-07-19',
                         self.TS + suffix + '.bin', content=b'X')
        login_as(client, ALICE_PORT1, ALICE_PASS)
        body = client.get('/me/logs/2026-07-19/').data.decode()
        i_base = body.index(self.TS + '.bin')
        i_2 = body.index(self.TS + '-2.bin')
        i_10 = body.index(self.TS + '-10.bin')
        assert i_base < i_2 < i_10, \
            'collision suffixes out of order: base=%d -2=%d -10=%d' % (
                i_base, i_2, i_10)


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
        r = client.get('/me/logs/2026-05-10/session1.tlog')
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
        r = client.get('/admin/logs/' + str(ALICE_PORT2)
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
        r = client.get('/me/logs/')
        assert r.status_code == 200
        assert b'2026-05-10' in r.data

        # session listing for that date
        r = client.get('/me/logs/2026-05-10/')
        assert r.status_code == 200
        assert b'session1.tlog' in r.data

        # download
        r = client.get('/me/logs/2026-05-10/session1.tlog')
        assert r.status_code == 200
        assert r.data.endswith(b'ALICE_TLOG')

    def test_owner_cannot_download_other_via_owner_route(self, client,
                                                          keydb_path,
                                                          logs_dir):
        seed_session(logs_dir, BOB_PORT2, '2026-05-10', 'session1.tlog',
                     content=b'BOB_TLOG')
        login_as(client, ALICE_PORT1, ALICE_PASS)
        # Owner route is scoped to the session's port2 (alice's), so
        # /me/logs/<date>/session1.tlog reads from logs/ALICE_PORT2/...
        # which doesn't exist -> 404.
        r = client.get('/me/logs/2026-05-10/session1.tlog')
        assert r.status_code == 404

    def test_owner_cannot_use_admin_tlog_route(self, client, logs_dir):
        seed_session(logs_dir, BOB_PORT2, '2026-05-10', 'session1.tlog')
        login_as(client, ALICE_PORT1, ALICE_PASS)
        r = client.get('/admin/logs/' + str(BOB_PORT2) + '/')
        assert r.status_code == 403


class TestAdminTlogListing:
    def test_admin_lists_any_port2(self, client, logs_dir):
        seed_session(logs_dir, ALICE_PORT2, '2026-05-09', 'session1.tlog')
        seed_session(logs_dir, ALICE_PORT2, '2026-05-10', 'session1.tlog')
        login_as(client, BOB_PORT1, BOB_PASS)
        r = client.get('/admin/logs/' + str(ALICE_PORT2) + '/')
        assert r.status_code == 200
        assert b'2026-05-09' in r.data
        assert b'2026-05-10' in r.data

    def test_admin_downloads_any(self, client, logs_dir):
        seed_session(logs_dir, ALICE_PORT2, '2026-05-10', 'session3.tlog',
                     content=b'\x01\x02\x03ADMIN_DL')
        login_as(client, BOB_PORT1, BOB_PASS)
        r = client.get('/admin/logs/' + str(ALICE_PORT2)
                       + '/2026-05-10/session3.tlog')
        assert r.status_code == 200
        assert r.data.endswith(b'ADMIN_DL')

    def test_admin_404_for_unknown_port2(self, client):
        login_as(client, BOB_PORT1, BOB_PASS)
        r = client.get('/admin/logs/99999/')
        assert r.status_code == 404


class TestSharedLogAccess:
    def test_public_listing_and_download_need_no_login(self, client,
                                                        keydb_path,
                                                        logs_dir):
        seed_session(logs_dir, ALICE_PORT2, '2026-08-25',
                     'session1.tlog', content=b'PUBLIC_LOG')
        set_log_access(keydb_path, ALICE_PORT2,
                       keydb_lib.LOG_ACCESS_PUBLIC)

        base = '/admin/logs/%d/2026-08-25/' % ALICE_PORT2
        listing = client.get(base)
        assert listing.status_code == 200
        assert b'session1.tlog' in listing.data
        assert b'Read-only log access' in listing.data
        assert b'edit entry' not in listing.data
        assert b'/delete' not in listing.data

        download = client.get(base + 'session1.tlog')
        assert download.status_code == 200
        assert download.data.endswith(b'PUBLIC_LOG')

    def test_public_video_playback_routes_need_no_login(self, client,
                                                         keydb_path,
                                                         logs_dir):
        name = '2026_08_25_10:00:00.v1.ts'
        seed_session(logs_dir, ALICE_PORT2, '2026-08-25', name,
                     content=b'\x47PUBLIC_VIDEO')
        set_log_access(keydb_path, ALICE_PORT2,
                       keydb_lib.LOG_ACCESS_PUBLIC)
        base = '/admin/logs/%d/2026-08-25/%s' % (ALICE_PORT2, name)

        assert client.get(base + '/watch').status_code == 200
        stream = client.get(base + '/stream')
        assert stream.status_code == 200
        assert stream.data == b'\x47PUBLIC_VIDEO'

    def test_login_required_redirects_anonymous_reader(self, client,
                                                        keydb_path):
        set_log_access(keydb_path, BOB_PORT2,
                       keydb_lib.LOG_ACCESS_LOGIN_REQUIRED)
        url = '/admin/logs/%d/' % BOB_PORT2
        r = client.get(url, follow_redirects=False)
        assert r.status_code == 302
        assert '/login' in r.location
        assert 'next=' in r.location

    def test_login_required_accepts_any_valid_login_read_only(self, client,
                                                               keydb_path,
                                                               logs_dir):
        seed_session(logs_dir, BOB_PORT2, '2026-08-25',
                     'session2.bin', content=b'LOGIN_LOG')
        set_log_access(keydb_path, BOB_PORT2,
                       keydb_lib.LOG_ACCESS_LOGIN_REQUIRED)
        login_as(client, ALICE_PORT1, ALICE_PASS)

        base = '/admin/logs/%d/2026-08-25/' % BOB_PORT2
        listing = client.get(base)
        assert listing.status_code == 200
        assert b'session2.bin' in listing.data
        assert b'Read-only log access' in listing.data
        assert b'/delete' not in listing.data
        assert client.get(base + 'session2.bin').data.endswith(b'LOGIN_LOG')

    def test_shared_access_never_grants_delete(self, client, keydb_path,
                                                logs_dir):
        path = seed_session(logs_dir, ALICE_PORT2, '2026-08-25',
                            'session1.tlog')
        set_log_access(keydb_path, ALICE_PORT2,
                       keydb_lib.LOG_ACCESS_PUBLIC)
        r = client.post('/admin/logs/%d/2026-08-25/session1.tlog/delete'
                        % ALICE_PORT2)
        assert r.status_code == 403
        assert path.exists()


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
        r = client.get('/admin/logs/' + str(ALICE_PORT2) + '/' + bad + '/')
        assert r.status_code == 404

    def test_bad_session_name_404(self, client, logs_dir):
        seed_session(logs_dir, ALICE_PORT2, '2026-05-10', 'session1.tlog')
        login_as(client, BOB_PORT1, BOB_PASS)
        r = client.get('/admin/logs/' + str(ALICE_PORT2)
                       + '/2026-05-10/notatlog')
        assert r.status_code == 404
        # send_from_directory blocks any traversal that escapes the date dir
        r = client.get('/admin/logs/' + str(ALICE_PORT2)
                       + '/2026-05-10/..%2fsession1.tlog')
        assert r.status_code == 404


class TestUnauthenticated:
    def test_owner_routes_redirect_to_login(self, client):
        r = client.get('/me/logs/', follow_redirects=False)
        assert r.status_code == 302
        assert '/login' in r.location

    def test_admin_routes_redirect_to_login(self, client):
        r = client.get('/admin/logs/' + str(ALICE_PORT2) + '/',
                       follow_redirects=False)
        # require_admin aborts 403 for unauthenticated _refresh_role:
        # they're not logged in, so role check fails. Acceptable: 403.
        assert r.status_code == 403


# ---------------------------------------------------------------------------
# video segments in the log browser
# ---------------------------------------------------------------------------

class TestVideoSegments:
    """Recordings live beside the tlogs and must be browsable the same way."""

    def test_owner_sees_and_downloads_a_segment(self, client, logs_dir):
        seed_session(logs_dir, ALICE_PORT2, '2026-08-01',
                     '2026_08_01_10:00:00.v1.ts', b'\x47VIDEO')
        login_as(client, ALICE_PORT1, ALICE_PASS)
        html = client.get('/me/logs/2026-08-01/').get_data(as_text=True)
        assert '2026_08_01_10:00:00.v1.ts' in html

        r = client.get('/me/logs/2026-08-01/2026_08_01_10:00:00.v1.ts')
        assert r.status_code == 200
        assert r.get_data() == b'\x47VIDEO'

    def test_all_three_slots_are_listed(self, client, logs_dir):
        for slot in (1, 2, 3):
            seed_session(logs_dir, ALICE_PORT2, '2026-08-01',
                         '2026_08_01_10:00:00.v%d.ts' % slot, b'\x47')
        login_as(client, ALICE_PORT1, ALICE_PASS)
        html = client.get('/me/logs/2026-08-01/').get_data(as_text=True)
        for slot in (1, 2, 3):
            assert '2026_08_01_10:00:00.v%d.ts' % slot in html

    def test_segments_sort_with_the_collision_suffix(self, client, logs_dir):
        """The -N ordering fix must apply to the compound .vN.ts
        extension too, not just .tlog/.bin."""
        for name in ('2026_08_01_10:00:00-10.v1.ts',
                     '2026_08_01_10:00:00.v1.ts',
                     '2026_08_01_10:00:00-2.v1.ts'):
            seed_session(logs_dir, ALICE_PORT2, '2026-08-01', name, b'\x47')
        login_as(client, ALICE_PORT1, ALICE_PASS)
        html = client.get('/me/logs/2026-08-01/').get_data(as_text=True)
        first = html.index('2026_08_01_10:00:00.v1.ts')
        second = html.index('2026_08_01_10:00:00-2.v1.ts')
        tenth = html.index('2026_08_01_10:00:00-10.v1.ts')
        assert first < second < tenth, \
            'video segments not in natural collision order'

    @pytest.mark.parametrize('bad', [
        '2026_08_01_10:00:00.v6.ts',     # slot out of range
        '2026_08_01_10:00:00.ts',        # no slot
        '2026_08_01_10:00:00.v1.tsx',    # not a segment
        'evil.ts',
    ])
    def test_non_segment_names_are_refused(self, client, logs_dir, bad):
        seed_session(logs_dir, ALICE_PORT2, '2026-08-01', bad, b'X')
        login_as(client, ALICE_PORT1, ALICE_PASS)
        r = client.get('/me/logs/2026-08-01/%s' % bad)
        assert r.status_code == 404, \
            '%s should not be servable' % bad
