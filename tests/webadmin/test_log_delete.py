"""Deleting recordings from the web UI.

Destructive and reachable by every owner, so the access boundary and the
path handling matter more than the markup: an owner may only ever reach
their own entry, and nothing outside the session-name grammar may be
removed however the request is spelled.
"""
import os
import time

import pytest

from webadmin import create_app

from _test_helpers import (ALICE_PASS, ALICE_PORT1, ALICE_PORT2, BOB_PASS,
                           BOB_PORT1, BOB_PORT2, login_as)

DATE = '2026-08-03'
NAME = '2026_08_03_10:00:00.tlog'
VIDEO = '2026_08_03_10:00:00.v1.ts'


@pytest.fixture
def logs_app(keydb_path, tmp_path):
    return create_app({
        'TESTING': True,
        'WTF_CSRF_ENABLED': False,
        'SESSION_COOKIE_SECURE': False,
        'KEYDB_PATH': keydb_path,
        'LOGS_DIR': str(tmp_path / 'logs'),
        'SECRET_KEY': 'test',
    })


@pytest.fixture
def logs_client(logs_app):
    return logs_app.test_client()


def _seed(app, port2, names=(NAME, VIDEO), age_s=3600):
    d = os.path.join(app.config['LOGS_DIR'], str(port2), DATE)
    os.makedirs(d, exist_ok=True)
    for n in names:
        p = os.path.join(d, n)
        with open(p, 'wb') as f:
            f.write(b'x' * 128)
        old = time.time() - age_s
        os.utime(p, (old, old))
    return d


class TestOwnerDelete:
    def test_owner_deletes_own_recording(self, logs_client, logs_app,
                                         keydb_path):
        d = _seed(logs_app, ALICE_PORT2)
        login_as(logs_client, ALICE_PORT1, ALICE_PASS)
        r = logs_client.post('/me/logs/%s/%s/delete' % (DATE, NAME),
                             follow_redirects=True)
        assert r.status_code == 200
        assert not os.path.exists(os.path.join(d, NAME))
        assert os.path.exists(os.path.join(d, VIDEO)), 'deleted too much'

    def test_owner_deletes_a_video(self, logs_client, logs_app, keydb_path):
        d = _seed(logs_app, ALICE_PORT2)
        login_as(logs_client, ALICE_PORT1, ALICE_PASS)
        logs_client.post('/me/logs/%s/%s/delete' % (DATE, VIDEO),
                         follow_redirects=True)
        assert not os.path.exists(os.path.join(d, VIDEO))

    def test_owner_deletes_a_whole_day(self, logs_client, logs_app,
                                       keydb_path):
        d = _seed(logs_app, ALICE_PORT2)
        login_as(logs_client, ALICE_PORT1, ALICE_PASS)
        r = logs_client.post('/me/logs/%s/delete' % DATE,
                             follow_redirects=True)
        assert 'Deleted 2 files' in r.get_data(as_text=True)
        assert not os.path.isdir(d), 'emptied date dir should be removed'

    def test_owner_cannot_touch_another_entry(self, logs_client, logs_app,
                                              keydb_path):
        """The owner routes carry no port2, so there is nothing to
        tamper with -- assert the other entry's files survive."""
        other = _seed(logs_app, BOB_PORT2)
        _seed(logs_app, ALICE_PORT2)
        login_as(logs_client, ALICE_PORT1, ALICE_PASS)
        logs_client.post('/me/logs/%s/delete' % DATE, follow_redirects=True)
        assert os.path.exists(os.path.join(other, NAME))


class TestAdminDelete:
    def test_admin_deletes_any_entry(self, logs_client, logs_app, keydb_path):
        d = _seed(logs_app, ALICE_PORT2)
        login_as(logs_client, BOB_PORT1, BOB_PASS)      # bob is admin
        logs_client.post('/admin/logs/%d/%s/%s/delete'
                         % (ALICE_PORT2, DATE, NAME), follow_redirects=True)
        assert not os.path.exists(os.path.join(d, NAME))

    def test_non_admin_is_refused(self, logs_client, logs_app, keydb_path):
        d = _seed(logs_app, BOB_PORT2)
        login_as(logs_client, ALICE_PORT1, ALICE_PASS)  # alice is not admin
        r = logs_client.post('/admin/logs/%d/%s/%s/delete'
                             % (BOB_PORT2, DATE, NAME))
        assert r.status_code == 403
        assert os.path.exists(os.path.join(d, NAME))


class TestRefusals:
    def test_a_file_still_being_written_is_kept(self, logs_client, logs_app,
                                                keydb_path):
        """Unlinking a file the daemon still holds does not stop it
        writing -- the space stays used and the file just disappears
        from the listing."""
        d = _seed(logs_app, ALICE_PORT2, names=(NAME,), age_s=0)
        login_as(logs_client, ALICE_PORT1, ALICE_PASS)
        r = logs_client.post('/me/logs/%s/%s/delete' % (DATE, NAME),
                             follow_redirects=True)
        assert 'still being written' in r.get_data(as_text=True)
        assert os.path.exists(os.path.join(d, NAME))

    def test_day_delete_keeps_active_files_and_says_so(self, logs_client,
                                                       logs_app, keydb_path):
        d = _seed(logs_app, ALICE_PORT2, names=(NAME,), age_s=3600)
        _seed(logs_app, ALICE_PORT2, names=(VIDEO,), age_s=0)
        login_as(logs_client, ALICE_PORT1, ALICE_PASS)
        r = logs_client.post('/me/logs/%s/delete' % DATE,
                             follow_redirects=True)
        body = r.get_data(as_text=True)
        assert 'Deleted 1 file' in body
        assert '1 left in place' in body
        assert os.path.exists(os.path.join(d, VIDEO))

    def test_unrelated_files_are_never_removed(self, logs_client, logs_app,
                                               keydb_path):
        """Only names the session grammar accepts are touched, so a
        whole-day delete cannot take anything else in the directory."""
        d = _seed(logs_app, ALICE_PORT2)
        keep = os.path.join(d, 'notes.txt')
        with open(keep, 'w') as f:
            f.write('keep me')
        login_as(logs_client, ALICE_PORT1, ALICE_PASS)
        logs_client.post('/me/logs/%s/delete' % DATE, follow_redirects=True)
        assert os.path.exists(keep)
        assert os.path.isdir(d), 'dir with survivors must not be removed'

    @pytest.mark.parametrize('bad', [
        '../../etc/passwd',
        '..%2f..%2fetc%2fpasswd',
        'session1.tlog/../../../x',
    ])
    def test_traversal_is_refused(self, logs_client, logs_app, keydb_path,
                                  bad):
        _seed(logs_app, ALICE_PORT2)
        login_as(logs_client, ALICE_PORT1, ALICE_PASS)
        r = logs_client.post('/me/logs/%s/%s/delete' % (DATE, bad))
        assert r.status_code in (400, 404, 308)

    def test_bad_date_is_refused(self, logs_client, logs_app, keydb_path):
        login_as(logs_client, ALICE_PORT1, ALICE_PASS)
        r = logs_client.post('/me/logs/..%2f..%2fetc/delete')
        assert r.status_code in (400, 404, 308)


class TestCsrf:
    def test_delete_requires_a_token(self, keydb_path, tmp_path):
        app = create_app({
            'TESTING': True,
            'WTF_CSRF_ENABLED': True,
            'SESSION_COOKIE_SECURE': False,
            'KEYDB_PATH': keydb_path,
            'LOGS_DIR': str(tmp_path / 'logs'),
            'SECRET_KEY': 'csrftest',
        })
        d = _seed(app, ALICE_PORT2)
        c = app.test_client()
        login_as(c, ALICE_PORT1, ALICE_PASS)
        r = c.post('/me/logs/%s/%s/delete' % (DATE, NAME))
        assert r.status_code == 400
        assert os.path.exists(os.path.join(d, NAME))
