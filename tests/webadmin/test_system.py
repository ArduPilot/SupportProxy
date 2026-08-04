"""The server page: the daemon's own log, and restarting it.

Both are admin-only and both are more dangerous than the rest of the
UI -- the log carries whatever the daemon printed, and the restart drops
every live session -- so the access checks matter more than the markup.
"""
import os

import pytest

from webadmin import proxylog

from webadmin import create_app

from _test_helpers import (ALICE_PASS, ALICE_PORT1, BOB_PASS, BOB_PORT1,
                           login_as)


@pytest.fixture
def csrf_client(keydb_path):
    """CSRF on, as production runs it."""
    return create_app({
        'TESTING': True,
        'WTF_CSRF_ENABLED': True,
        'SESSION_COOKIE_SECURE': False,
        'KEYDB_PATH': keydb_path,
        'SECRET_KEY': 'csrftest',
    }).test_client()


def _write_log(app, text):
    path = proxylog.log_path(app)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w') as f:
        f.write(text)
    return path


class TestAccess:
    def test_owner_cannot_see_the_server_page(self, client, keydb_path):
        login_as(client, ALICE_PORT1, ALICE_PASS)
        assert client.get('/admin/system/').status_code == 403

    def test_owner_cannot_read_the_log(self, client, keydb_path):
        login_as(client, ALICE_PORT1, ALICE_PASS)
        assert client.get('/admin/system/log').status_code == 403

    def test_owner_cannot_restart(self, client, keydb_path):
        login_as(client, ALICE_PORT1, ALICE_PASS)
        assert client.post('/admin/system/restart').status_code == 403

    def test_logged_out_is_refused(self, client, keydb_path):
        r = client.get('/admin/system/')
        assert r.status_code in (302, 403)

    def test_admin_sees_the_page(self, client, keydb_path):
        login_as(client, BOB_PORT1, BOB_PASS)
        r = client.get('/admin/system/')
        assert r.status_code == 200
        assert 'Restart proxy' in r.get_data(as_text=True)


class TestLogTail:
    def test_first_fetch_returns_the_tail(self, client, app, keydb_path):
        _write_log(app, 'alpha\nbravo\ncharlie\n')
        login_as(client, BOB_PORT1, BOB_PASS)
        d = client.get('/admin/system/log').get_json()
        assert 'charlie' in d['text']
        assert d['offset'] > 0

    def test_incremental_fetch_returns_only_new_bytes(self, client, app,
                                                      keydb_path):
        path = _write_log(app, 'one\n')
        login_as(client, BOB_PORT1, BOB_PASS)
        first = client.get('/admin/system/log').get_json()
        with open(path, 'a') as f:
            f.write('two\n')
        second = client.get(
            '/admin/system/log?offset=%d' % first['offset']).get_json()
        assert second['text'] == 'two\n'
        assert not second['restarted']

    def test_rotation_is_reported_not_silently_appended(self, client, app,
                                                        keydb_path):
        """copytruncate leaves the file shorter than the reader's offset.

        Without noticing, the page would append forever to an offset
        past the end and quietly show nothing new.
        """
        path = _write_log(app, 'x' * 5000)
        login_as(client, BOB_PORT1, BOB_PASS)
        first = client.get('/admin/system/log').get_json()
        with open(path, 'w') as f:          # truncate, as logrotate does
            f.write('after rotation\n')
        d = client.get(
            '/admin/system/log?offset=%d' % first['offset']).get_json()
        assert d['restarted']
        assert 'after rotation' in d['text']

    def test_rotation_is_caught_even_if_the_log_regrows(self, client, app,
                                                         keydb_path):
        """Truncated in place, then grown past the reader's offset.

        This is what copytruncate does, and neither size nor inode sees
        it: the file is longer than the old offset again, and the inode
        never changed. Only the contents did.
        """
        path = _write_log(app, 'x' * 200 + '\n')
        login_as(client, BOB_PORT1, BOB_PASS)
        first = client.get('/admin/system/log').get_json()
        before = os.stat(path).st_ino
        with open(path, 'w') as f:            # truncate in place
            f.write('y' * 5000 + '\nnew generation\n')
        assert os.stat(path).st_ino == before, 'meant to keep the inode'
        d = client.get('/admin/system/log?offset=%d&ident=%s'
                       % (first['offset'], first['ident'])).get_json()
        assert d['restarted']
        assert 'new generation' in d['text']

    def test_rotation_is_caught_when_the_inode_is_reused(self, client, app,
                                                         keydb_path):
        """Replaced by a new file that happens to get the old inode.

        Observed on CI: unlink-and-create handed the freed inode
        straight back, so an identity built only from (dev, inode) saw
        no change and the page appended the new generation to the old
        as though it were contiguous.
        """
        path = _write_log(app, 'x' * 200 + '\n')
        login_as(client, BOB_PORT1, BOB_PASS)
        first = client.get('/admin/system/log').get_json()
        os.unlink(path)
        with open(path, 'w') as f:
            f.write('z' * 5000 + '\nsecond generation\n')
        d = client.get('/admin/system/log?offset=%d&ident=%s'
                       % (first['offset'], first['ident'])).get_json()
        assert d['restarted']
        assert 'second generation' in d['text']

    def test_a_viewer_password_is_redacted(self, client, app, keydb_path):
        """Not just the 60-second token: ?pw= is a long-lived
        credential, and the old pattern knew nothing about it."""
        _write_log(app, 'video: websocket viewer on /v1?pw=hunter2 (TLS)\n')
        login_as(client, BOB_PORT1, BOB_PASS)
        d = client.get('/admin/system/log').get_json()
        assert 'hunter2' not in d['text']
        assert '<redacted>' in d['text']

    def test_an_uppercase_token_is_redacted(self, client, app, keydb_path):
        """The old pattern demanded lowercase hex after a literal dot."""
        _write_log(app, 'viewer on /v1?t=1785664967.DEADBEEFCAFE0123\n')
        login_as(client, BOB_PORT1, BOB_PASS)
        d = client.get('/admin/system/log').get_json()
        assert 'DEADBEEFCAFE0123' not in d['text']

    def test_viewer_tokens_are_redacted(self, client, app, keydb_path):
        _write_log(app, 'video: websocket viewer on /v1?t=1785664967.'
                        'deadbeefcafe0123 (TLS)\n')
        login_as(client, BOB_PORT1, BOB_PASS)
        d = client.get('/admin/system/log').get_json()
        assert 'deadbeefcafe0123' not in d['text']
        assert '<redacted>' in d['text']

    def test_missing_log_is_not_an_error(self, client, app, keydb_path):
        path = proxylog.log_path(app)
        if os.path.exists(path):
            os.unlink(path)
        login_as(client, BOB_PORT1, BOB_PASS)
        d = client.get('/admin/system/log').get_json()
        assert d['text'] == ''


class TestRestart:
    def test_restart_requires_csrf(self, csrf_client, keydb_path):
        login_as(csrf_client, BOB_PORT1, BOB_PASS)
        r = csrf_client.post('/admin/system/restart', data={})
        assert r.status_code == 400

    def test_restart_reports_when_no_daemon_is_running(self, client,
                                                       keydb_path,
                                                       monkeypatch):
        monkeypatch.setattr(proxylog, 'find_daemon', lambda w=None: None)
        login_as(client, BOB_PORT1, BOB_PASS)
        r = client.post('/admin/system/restart', follow_redirects=True)
        assert 'no running supportproxy process' in r.get_data(as_text=True)

    def test_restart_signals_the_pid_it_found(self, client, keydb_path,
                                              monkeypatch):
        sent = {}
        monkeypatch.setattr(proxylog, 'find_daemon', lambda w=None: 4242)
        # Force the non-pidfd path so the fake kill is what runs.
        monkeypatch.delattr(proxylog.os, 'pidfd_open', raising=False)
        monkeypatch.setattr(proxylog, '_comm',
                            lambda pid: proxylog.SUPPORTPROXY_COMM)
        monkeypatch.setattr(proxylog.os, 'kill',
                            lambda pid, sig: sent.update(pid=pid, sig=sig))
        login_as(client, BOB_PORT1, BOB_PASS)
        r = client.post('/admin/system/restart', follow_redirects=True)
        assert sent == {'pid': 4242, 'sig': proxylog.signal.SIGTERM}
        assert '4242' in r.get_data(as_text=True)


class TestFindDaemon:
    """Which process gets signalled.

    min(pid) over everything named supportproxy is not an identity: it
    picks up a second instance on the same host, and a session child
    that was reparented when its own parent exited. Both mean the
    restart hits the wrong process.
    """

    def _tree(self, monkeypatch, tree, cwds):
        monkeypatch.setattr(proxylog, '_systemd_main_pid', lambda u=None: None)
        monkeypatch.setattr(proxylog.os, 'listdir',
                            lambda p: [str(k) for k in tree])
        monkeypatch.setattr(proxylog, '_comm',
                            lambda pid: tree.get(pid, (None, None))[0])
        monkeypatch.setattr(proxylog, '_ppid',
                            lambda pid: tree.get(pid, (None, None))[1])
        monkeypatch.setattr(proxylog, '_cwd', lambda pid: cwds.get(pid))

    def test_prefers_the_parent_over_its_children(self, monkeypatch):
        tree = {100: (proxylog.SUPPORTPROXY_COMM, 1),
                101: (proxylog.SUPPORTPROXY_COMM, 100),
                102: (proxylog.SUPPORTPROXY_COMM, 100),
                200: ('something-else', 1)}
        self._tree(monkeypatch, tree, {p: '/srv/proxy' for p in tree})
        assert proxylog.find_daemon('/srv/proxy') == 100

    def test_ignores_another_instance(self, monkeypatch):
        """A staging daemon with a lower pid must not be signalled."""
        tree = {50: (proxylog.SUPPORTPROXY_COMM, 1),
                100: (proxylog.SUPPORTPROXY_COMM, 1)}
        self._tree(monkeypatch, tree,
                   {50: '/srv/staging', 100: '/srv/proxy'})
        assert proxylog.find_daemon('/srv/proxy') == 100

    def test_ignores_a_reparented_child(self, monkeypatch):
        """An orphaned session child has ppid 1 and the right cwd, so
        only the comm of its parent distinguished it before -- and once
        reparented there is no such parent. It must not win on pid."""
        tree = {90: (proxylog.SUPPORTPROXY_COMM, 1),
                100: (proxylog.SUPPORTPROXY_COMM, 1)}
        self._tree(monkeypatch, tree, {90: '/other', 100: '/srv/proxy'})
        assert proxylog.find_daemon('/srv/proxy') == 100

    def test_systemd_is_authoritative(self, monkeypatch):
        monkeypatch.setattr(proxylog, '_systemd_main_pid', lambda u=None: 777)
        monkeypatch.setattr(proxylog, '_comm',
                            lambda pid: proxylog.SUPPORTPROXY_COMM)
        assert proxylog.find_daemon('/srv/proxy') == 777
