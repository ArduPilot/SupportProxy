"""The main menu: the same tabs for everyone, extra ones for admins."""
import re

from _test_helpers import (ALICE_PASS, ALICE_PORT1, BOB_PASS, BOB_PORT1,
                           login_as)

SHARED = ['Dashboard', 'Video', 'Logs']
ADMIN_ONLY = ['All entries', 'Connections', 'Server']


def _nav(html):
    m = re.search(r'<nav class="main-nav".*?</nav>', html, re.S)
    assert m, 'no main menu on the page'
    return m.group(0)


def _tabs(html):
    return re.findall(r'<a [^>]*>([^<]+)</a>', _nav(html))


def _current(html):
    return re.findall(r'<a [^>]*class="[^"]*\bcurrent\b[^"]*"[^>]*>([^<]+)</a>',
                      _nav(html))


class TestMainMenu:
    def test_owner_gets_the_shared_tabs_only(self, client):
        login_as(client, ALICE_PORT1, ALICE_PASS)
        html = client.get('/me/').get_data(as_text=True)
        assert _tabs(html) == SHARED

    def test_admin_gets_the_shared_tabs_then_the_admin_ones(self, client):
        login_as(client, BOB_PORT1, BOB_PASS)
        html = client.get('/me/').get_data(as_text=True)
        assert _tabs(html) == SHARED + ADMIN_ONLY

    def test_no_menu_for_a_visitor_who_is_not_logged_in(self, client):
        html = client.get('/login').get_data(as_text=True)
        assert 'class="main-nav"' not in html

    def test_the_current_tab_is_marked(self, client):
        login_as(client, BOB_PORT1, BOB_PASS)
        for url, tab in (('/me/', 'Dashboard'), ('/video/', 'Video'),
                         ('/me/logs/', 'Logs'),
                         ('/admin/', 'All entries'),
                         ('/admin/connections', 'Connections'),
                         ('/admin/system/', 'Server')):
            html = client.get(url).get_data(as_text=True)
            assert _current(html) == [tab], (url, _current(html))

    def test_an_entrys_logs_are_still_under_all_entries(self, client):
        from _test_helpers import ALICE_PORT2
        login_as(client, BOB_PORT1, BOB_PASS)
        html = client.get('/admin/logs/%d/' % ALICE_PORT2).get_data(
            as_text=True)
        assert _current(html) == ['All entries']

    def test_who_and_log_out_are_in_the_title_bar(self, client):
        login_as(client, BOB_PORT1, BOB_PASS)
        html = client.get('/me/').get_data(as_text=True)
        head = re.search(r'<header>.*?</header>', html, re.S).group(0)
        assert 'logged in as port' in head and '(admin)' in head
        assert 'action="/logout"' in head
        assert 'action="/logout"' not in _nav(html)

    def test_a_non_admin_reading_shared_logs_is_on_logs(self, client,
                                                        keydb_path):
        import keydb_lib
        from _test_helpers import ALICE_PORT2
        db = keydb_lib.open_db(keydb_path)
        db.transaction_start()
        ke = keydb_lib.KeyEntry(ALICE_PORT2)
        assert ke.fetch(db)
        ke.set_log_access(keydb_lib.LOG_ACCESS_LOGIN_REQUIRED)
        ke.store(db)
        db.transaction_prepare_commit()
        db.transaction_commit()
        db.close()
        login_as(client, ALICE_PORT1, ALICE_PASS)
        resp = client.get('/admin/logs/%d/' % ALICE_PORT2)
        assert resp.status_code == 200
        assert _current(resp.get_data(as_text=True)) == ['Logs']
