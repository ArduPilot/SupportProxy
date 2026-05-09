"""Login flows: both port columns, wrong passphrase, unknown port."""
from _test_helpers import (ALICE_PASS, ALICE_PORT1, ALICE_PORT2,
                           BOB_PASS, BOB_PORT1, BOB_PORT2, login_as)


class TestLogin:
    def test_login_with_port1(self, client):
        resp = login_as(client, ALICE_PORT1, ALICE_PASS)
        assert resp.status_code == 302
        with client.session_transaction() as sess:
            assert sess['owner'] == ALICE_PORT2
            assert sess['is_admin'] is False

    def test_login_with_port2(self, client):
        resp = login_as(client, ALICE_PORT2, ALICE_PASS)
        assert resp.status_code == 302
        with client.session_transaction() as sess:
            assert sess['owner'] == ALICE_PORT2

    def test_admin_login_sets_admin_role(self, client):
        login_as(client, BOB_PORT1, BOB_PASS)
        with client.session_transaction() as sess:
            assert sess['owner'] == BOB_PORT2
            assert sess['is_admin'] is True

    def test_wrong_passphrase_fails(self, client):
        resp = login_as(client, ALICE_PORT1, 'nope')
        assert resp.status_code == 200
        assert b'Login failed' in resp.data
        with client.session_transaction() as sess:
            assert 'owner' not in sess

    def test_unknown_port_fails(self, client):
        resp = login_as(client, 9999, ALICE_PASS)
        assert resp.status_code == 200
        assert b'Login failed' in resp.data
        with client.session_transaction() as sess:
            assert 'owner' not in sess

    def test_logout_clears_session(self, client):
        login_as(client, ALICE_PORT1, ALICE_PASS)
        client.post('/logout')
        with client.session_transaction() as sess:
            assert 'owner' not in sess

    def test_index_redirects_to_login_when_anon(self, client):
        resp = client.get('/')
        assert resp.status_code == 302
        assert resp.location.endswith('/login')

    def test_index_redirects_to_admin_for_admin(self, client):
        login_as(client, BOB_PORT1, BOB_PASS)
        resp = client.get('/')
        assert resp.status_code == 302
        assert '/admin/' in resp.location

    def test_index_redirects_to_me_for_owner(self, client):
        login_as(client, ALICE_PORT1, ALICE_PASS)
        resp = client.get('/')
        assert resp.status_code == 302
        assert '/me/' in resp.location

    def test_login_open_redirect_blocked(self, client):
        """`next=//evil.example/path` is a scheme-relative URL — Flask
        would 302 to it as an external redirect. Reject it and fall
        back to the local landing page."""
        resp = client.post(
            '/login?next=//evil.example/path',
            data={'port': ALICE_PORT1, 'passphrase': ALICE_PASS,
                  'submit': 'Log in'},
            follow_redirects=False)
        assert resp.status_code == 302
        assert 'evil.example' not in (resp.location or ''), resp.location

    def test_login_safe_local_next_honoured(self, client):
        """A normal /me-style next path should still be honoured."""
        resp = client.post(
            '/login?next=/me/',
            data={'port': ALICE_PORT1, 'passphrase': ALICE_PASS,
                  'submit': 'Log in'},
            follow_redirects=False)
        assert resp.status_code == 302
        assert resp.location.endswith('/me/'), resp.location


class TestWebuiJson:
    """webui.json next to keys.tdb customises the app at startup."""

    def test_title_from_webui_json_appears_in_pages(self, tmp_path):
        # Write a keys.tdb plus a webui.json next to it, and an app
        # pointing at that keys.tdb. The fixture-based `client` in this
        # module uses test_config to override settings, which would
        # mask webui.json — we want to exercise the file-load path
        # specifically, so build a fresh app from scratch here.
        import json
        import keydb_lib
        from webadmin import create_app

        keydb_path = str(tmp_path / 'keys.tdb')
        db = keydb_lib.init_db(keydb_path)
        db.transaction_start()
        keydb_lib.add_entry(db, ALICE_PORT1, ALICE_PORT2, 'alice', ALICE_PASS)
        db.transaction_prepare_commit()
        db.transaction_commit()
        db.close()

        with open(tmp_path / 'webui.json', 'w') as f:
            json.dump({"title": "Support Proxy XYZ",
                       "mode": "standalone",
                       "port": 9099}, f)

        app = create_app({
            'TESTING': True,
            'WTF_CSRF_ENABLED': False,
            'SESSION_COOKIE_SECURE': False,
            'KEYDB_PATH': keydb_path,
            'SECRET_KEY': 'webuijson-title-test',
        })
        # test_config doesn't set WEBUI_TITLE, so the file's value wins
        assert app.config['WEBUI_TITLE'] == 'Support Proxy XYZ'

        # And the customised title actually reaches the rendered page
        resp = app.test_client().get('/login')
        assert resp.status_code == 200
        assert b'Support Proxy XYZ' in resp.data

    def test_apache_mode_sets_behind_proxy(self, tmp_path):
        import json
        import keydb_lib
        from webadmin import create_app

        keydb_path = str(tmp_path / 'keys.tdb')
        keydb_lib.init_db(keydb_path).close()
        with open(tmp_path / 'webui.json', 'w') as f:
            json.dump({"mode": "apache"}, f)

        app = create_app({
            'TESTING': True,
            'WTF_CSRF_ENABLED': False,
            'SESSION_COOKIE_SECURE': False,
            'KEYDB_PATH': keydb_path,
            'SECRET_KEY': 't',
        })
        assert app.config['BEHIND_PROXY'] is True

    def test_missing_webui_json_uses_default_title(self, client):
        """When no webui.json sits beside keys.tdb the default title
        is what shows up in pages."""
        resp = client.get('/login')
        assert resp.status_code == 200
        assert b'SupportProxy admin' in resp.data
