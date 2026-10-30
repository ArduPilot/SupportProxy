"""The browser playback page and its viewer tokens.

The token exists so the viewer password never appears in a URL, where
it would land in history, proxy logs and Referer headers. It is signed
with the entry's existing MAVLink key, which the video child already
loads -- so browser playback introduces no new shared secret.
"""
import time

import pytest

import keydb_lib
from webadmin import videotoken

from _test_helpers import (ALICE_PASS, ALICE_PORT1, ALICE_PORT2, BOB_PASS,
                           BOB_PORT1, BOB_PORT2, fetch_entry, login_as)

VPORT = 21001


def _enable_video(keydb_path, port2, ports=(VPORT,), viewer_pass=None):
    db = keydb_lib.open_db(keydb_path)
    db.transaction_start()
    keydb_lib.set_flag(db, port2, 'video')
    keydb_lib.set_video_ports(db, port2, list(ports))
    if viewer_pass:
        keydb_lib.set_video_viewer_pass(db, port2, viewer_pass)
    db.transaction_prepare_commit()
    db.transaction_commit()
    db.close()


class TestVideoPage:
    def test_page_lists_configured_slots(self, client, keydb_path):
        _enable_video(keydb_path, ALICE_PORT2, ports=(VPORT, VPORT + 1))
        login_as(client, ALICE_PORT1, ALICE_PASS)
        html = client.get('/video/').get_data(as_text=True)
        assert 'Slot 1' in html and str(VPORT) in html
        assert 'Slot 2' in html and str(VPORT + 1) in html
        assert 'Slot 3' not in html, 'unallocated slot should not appear'

    def test_page_explains_when_no_ports_allocated(self, client, keydb_path):
        db = keydb_lib.open_db(keydb_path)
        db.transaction_start()
        keydb_lib.set_flag(db, ALICE_PORT2, 'video')
        db.transaction_prepare_commit(); db.transaction_commit(); db.close()
        login_as(client, ALICE_PORT1, ALICE_PASS)
        html = client.get('/video/').get_data(as_text=True)
        assert 'No video ports have been allocated' in html

    def test_page_says_when_video_is_disabled(self, client, keydb_path):
        login_as(client, ALICE_PORT1, ALICE_PASS)
        html = client.get('/video/').get_data(as_text=True)
        assert 'not enabled' in html

    def test_player_is_served_locally_not_from_a_cdn(self, client, keydb_path):
        """A published page must be self-contained: an external script
        tag is a third party able to change what runs in the operator's
        browser."""
        _enable_video(keydb_path, ALICE_PORT2)
        login_as(client, ALICE_PORT1, ALICE_PASS)
        html = client.get('/video/').get_data(as_text=True)
        assert 'vendor/mpegts.js/mpegts.js' in html
        assert '//cdn' not in html and 'unpkg' not in html
        r = client.get('/static/vendor/mpegts.js/mpegts.js')
        assert r.status_code == 200 and len(r.get_data()) > 100000

    def test_fallback_command_is_offered(self, client, keydb_path):
        """HEVC cannot play in most browsers, so the page must always
        offer a way to watch outside it."""
        _enable_video(keydb_path, ALICE_PORT2)
        login_as(client, ALICE_PORT1, ALICE_PASS)
        html = client.get('/video/').get_data(as_text=True)
        # Matches the command, not its exact spelling: it carries
        # low-latency flags between the binary and the URL.
        assert 'ffplay' in html
        assert 'http://' in html
        assert '/v1.ts' in html
        assert 'rtsp://localhost:' in html
        assert '/view/v1' in html and '-rtsp_transport tcp' in html
        assert 'Mission Planner' in html and 'appsink name=outsink' in html

    def test_fallback_mentions_the_password_when_one_is_set(self, client,
                                                            keydb_path):
        _enable_video(keydb_path, ALICE_PORT2, viewer_pass='watchme')
        login_as(client, ALICE_PORT1, ALICE_PASS)
        html = client.get('/video/').get_data(as_text=True)
        assert 'YOUR_VIEWER_PASSWORD' in html
        # and never the password itself
        assert 'watchme' not in html

    def test_owner_cannot_view_another_entry(self, client, keydb_path):
        _enable_video(keydb_path, BOB_PORT2)
        login_as(client, ALICE_PORT1, ALICE_PASS)
        r = client.get('/video/?port2=%d' % BOB_PORT2)
        assert r.status_code == 403

    def test_admin_can_view_another_entry(self, client, keydb_path):
        _enable_video(keydb_path, ALICE_PORT2)
        login_as(client, BOB_PORT1, BOB_PASS)
        r = client.get('/video/?port2=%d' % ALICE_PORT2)
        assert r.status_code == 200
        assert 'Slot 1' in r.get_data(as_text=True)

    def test_anonymous_is_redirected(self, client, keydb_path):
        r = client.get('/video/')
        assert r.status_code in (301, 302)


class TestViewerToken:
    def test_token_round_trips(self, keydb_path):
        ke = fetch_entry(keydb_path, ALICE_PORT2)
        tok = videotoken.mint(ke.secret_key, ALICE_PORT2, 0)
        assert videotoken.verify(ke.secret_key, ALICE_PORT2, 0, tok)

    def test_token_is_bound_to_entry_and_slot(self, keydb_path):
        ke = fetch_entry(keydb_path, ALICE_PORT2)
        tok = videotoken.mint(ke.secret_key, ALICE_PORT2, 0)
        assert not videotoken.verify(ke.secret_key, ALICE_PORT2, 1, tok), \
            'token accepted for a different slot'
        assert not videotoken.verify(ke.secret_key, BOB_PORT2, 0, tok), \
            'token accepted for a different entry'

    def test_token_expires(self, keydb_path):
        ke = fetch_entry(keydb_path, ALICE_PORT2)
        now = time.time()
        tok = videotoken.mint(ke.secret_key, ALICE_PORT2, 0, ttl_s=10, now=now)
        assert videotoken.verify(ke.secret_key, ALICE_PORT2, 0, tok, now=now)
        assert not videotoken.verify(ke.secret_key, ALICE_PORT2, 0, tok,
                                     now=now + 11)

    def test_tampering_is_rejected(self, keydb_path):
        ke = fetch_entry(keydb_path, ALICE_PORT2)
        tok = videotoken.mint(ke.secret_key, ALICE_PORT2, 0)
        flipped = tok[:-1] + ('0' if tok[-1] != '0' else '1')
        assert not videotoken.verify(ke.secret_key, ALICE_PORT2, 0, flipped)
        for junk in ('', 'nope', '.', '123.', 'abc.def'):
            assert not videotoken.verify(ke.secret_key, ALICE_PORT2, 0, junk)

    def test_a_different_key_does_not_verify(self, keydb_path):
        ke = fetch_entry(keydb_path, ALICE_PORT2)
        other = fetch_entry(keydb_path, BOB_PORT2)
        tok = videotoken.mint(ke.secret_key, ALICE_PORT2, 0)
        assert not videotoken.verify(other.secret_key, ALICE_PORT2, 0, tok)

    def test_page_token_is_valid_for_its_slot(self, client, keydb_path):
        """The token the page hands the player must actually work."""
        import re
        _enable_video(keydb_path, ALICE_PORT2)
        login_as(client, ALICE_PORT1, ALICE_PASS)
        html = client.get('/video/').get_data(as_text=True)
        m = re.search(r'"token":\s*"(\d+\.[0-9a-f]{64})"', html) \
            or re.search(r'token:\s*"(\d+\.[0-9a-f]{64})"', html)
        assert m, 'no token found in the page'
        ke = fetch_entry(keydb_path, ALICE_PORT2)
        assert videotoken.verify(ke.secret_key, ALICE_PORT2, 0, m.group(1))

    def test_page_never_leaks_the_secret_key(self, client, keydb_path):
        _enable_video(keydb_path, ALICE_PORT2)
        login_as(client, ALICE_PORT1, ALICE_PASS)
        html = client.get('/video/').get_data(as_text=True)
        ke = fetch_entry(keydb_path, ALICE_PORT2)
        assert bytes(ke.secret_key).hex() not in html.lower()


class TestTokenEndpoint:
    """A player reconnects for as long as the page is open, but a token
    lasts a minute -- so the page has to be able to mint fresh ones or
    reconnecting stops working after the first minute. It mints a
    credential, so who can ask for which entry matters."""

    def _enable(self, keydb_path, port2, port=40001):
        db = keydb_lib.open_db(keydb_path)
        db.transaction_start()
        ke = keydb_lib.KeyEntry(port2)
        ke.fetch(db)
        ke.flags |= keydb_lib.FLAG_VIDEO
        ke.video_ports = [port, 0, 0]
        ke.store(db)
        db.transaction_prepare_commit()
        db.transaction_commit()
        db.close()

    def test_owner_gets_a_valid_token_for_their_own_entry(self, client,
                                                          keydb_path):
        self._enable(keydb_path, ALICE_PORT2)
        login_as(client, ALICE_PORT1, ALICE_PASS)
        r = client.get('/video/token?slot=0')
        assert r.status_code == 200
        tok = r.get_json()['token']
        db = keydb_lib.open_db(keydb_path)
        db.transaction_start()
        ke = keydb_lib.KeyEntry(ALICE_PORT2)
        ke.fetch(db)
        db.transaction_cancel()
        db.close()
        assert videotoken.verify(ke.secret_key, ALICE_PORT2, 0, tok)

    def test_admin_can_mint_for_another_entry(self, client, keydb_path):
        self._enable(keydb_path, ALICE_PORT2)
        login_as(client, BOB_PORT1, BOB_PASS)
        r = client.get('/video/token?port2=%d&slot=0' % ALICE_PORT2)
        assert r.status_code == 200
        assert r.get_json()['token']

    def test_owner_cannot_mint_for_another_entry(self, client, keydb_path):
        """Otherwise any owner could mint themselves into any stream."""
        self._enable(keydb_path, BOB_PORT2)
        login_as(client, ALICE_PORT1, ALICE_PASS)
        r = client.get('/video/token?port2=%d&slot=0' % BOB_PORT2)
        assert r.status_code == 403

    def test_anonymous_is_refused(self, client, keydb_path):
        self._enable(keydb_path, ALICE_PORT2)
        r = client.get('/video/token?slot=0')
        assert r.status_code in (302, 401, 403)

    def test_slot_must_be_allocated(self, client, keydb_path):
        self._enable(keydb_path, ALICE_PORT2)
        login_as(client, ALICE_PORT1, ALICE_PASS)
        assert client.get('/video/token?slot=1').status_code == 404

    def test_slot_must_be_in_range(self, client, keydb_path):
        self._enable(keydb_path, ALICE_PORT2)
        login_as(client, ALICE_PORT1, ALICE_PASS)
        for bad in ('-1', '3', '99', 'x', ''):
            assert client.get('/video/token?slot=%s' % bad).status_code \
                in (400, 404), bad

    def test_refused_when_video_is_disabled(self, client, keydb_path):
        login_as(client, ALICE_PORT1, ALICE_PASS)
        assert client.get('/video/token?slot=0').status_code == 404

    def test_tokens_differ_between_slots(self, client, keydb_path):
        db = keydb_lib.open_db(keydb_path)
        db.transaction_start()
        ke = keydb_lib.KeyEntry(ALICE_PORT2)
        ke.fetch(db)
        ke.flags |= keydb_lib.FLAG_VIDEO
        ke.video_ports = [40001, 40002, 0]
        ke.store(db)
        db.transaction_prepare_commit()
        db.transaction_commit()
        db.close()
        login_as(client, ALICE_PORT1, ALICE_PASS)
        a = client.get('/video/token?slot=0').get_json()['token']
        b = client.get('/video/token?slot=1').get_json()['token']
        assert a != b, 'a slot-0 token must not open slot 1'


class TestPlayerReconnect:
    def test_page_fetches_fresh_tokens(self, client, keydb_path):
        """The page carries the token URL, not just one minted token:
        reusing the render-time token means reconnecting stops working
        after its 60s lifetime, which presents as 'only works if I
        reload'."""
        db = keydb_lib.open_db(keydb_path)
        db.transaction_start()
        ke = keydb_lib.KeyEntry(ALICE_PORT2)
        ke.fetch(db)
        ke.flags |= keydb_lib.FLAG_VIDEO
        ke.video_ports = [40001, 0, 0]
        ke.store(db)
        db.transaction_prepare_commit()
        db.transaction_commit()
        db.close()
        login_as(client, ALICE_PORT1, ALICE_PASS)
        html = client.get('/video/').get_data(as_text=True)
        assert '/video/token' in html
        # And it must react to a clean close, not only to an error --
        # the proxy ends the stream deliberately when a publisher goes.
        assert 'LOADING_COMPLETE' in html


class TestPlayerTeardown:
    """The reconnect shipped twice without working. Both times the cause
    was in this script, which no server-side test exercises, so the
    contract it has to honour is asserted here directly."""

    def _page(self, client, keydb_path):
        db = keydb_lib.open_db(keydb_path)
        db.transaction_start()
        ke = keydb_lib.KeyEntry(ALICE_PORT2)
        ke.fetch(db)
        ke.flags |= keydb_lib.FLAG_VIDEO
        ke.video_ports = [40001, 0, 0]
        ke.store(db)
        db.transaction_prepare_commit()
        db.transaction_commit()
        db.close()
        login_as(client, ALICE_PORT1, ALICE_PASS)
        return client.get('/video/').get_data(as_text=True)

    def test_detaches_the_media_element_before_destroying(self, client,
                                                          keydb_path):
        """mpegts.js needs pause -> unload -> detachMediaElement ->
        destroy. Skipping detachMediaElement leaves the <video> bound to
        the old, ended MediaSource, so the next player cannot attach and
        the reconnect silently does nothing until a page reload."""
        html = self._page(client, keydb_path)
        for call in ('pause()', 'unload()', 'detachMediaElement()',
                     'destroy()'):
            assert call in html, 'teardown is missing %s' % call
        assert html.index('detachMediaElement()') < html.index('destroy()'), \
            'detachMediaElement must come before destroy'

    def test_reacts_to_a_clean_close_not_only_an_error(self, client,
                                                       keydb_path):
        html = self._page(client, keydb_path)
        assert 'LOADING_COMPLETE' in html

    def test_refreshes_the_token_per_connect(self, client, keydb_path):
        html = self._page(client, keydb_path)
        assert '/video/token' in html

    def test_a_codec_failure_does_not_retry_forever(self, client,
                                                    keydb_path):
        html = self._page(client, keydb_path)
        assert 'MEDIA_ERROR' in html
        assert 'codecFailed' in html

    def test_progress_comes_from_the_element_not_mpegts(self, client,
                                                        keydb_path):
        """The status and the error-counter reset must not hang on
        MEDIA_INFO.

        MediaInfo.isComplete() requires hasAudio to be exactly true or
        false; it starts null and is only set when audio metadata
        arrives, so a video-only stream -- the backend's default, -an --
        never fires MEDIA_INFO at all. Resetting the media-error counter
        only there let three transient errors over a page's lifetime
        latch a stream that was playing fine.
        """
        html = self._page(client, keydb_path)
        assert "addEventListener('playing'" in html
        assert "addEventListener('loadedmetadata'" in html
        # the reset must live in the element handler, not only MEDIA_INFO
        playing = html.index("addEventListener('playing'")
        assert 'mediaErrors = 0' in html[playing:playing + 400]

    def test_only_an_unsupported_codec_is_permanent(self, client,
                                                    keydb_path):
        """A transient MEDIA_ERROR must retry, not latch.

        Treating every MEDIA_ERROR as permanent gave up on the first
        append failure -- which Chrome raises far more readily than
        Firefox -- so an H.264 stream Firefox was playing reported
        "cannot decode, probably HEVC" in Chrome and never retried.
        """
        html = self._page(client, keydb_path)
        assert 'MEDIA_CODEC_UNSUPPORTED' in html
        assert 'MEDIA_FORMAT_UNSUPPORTED' in html
        # The permanent branch must be guarded by the detail, not by the
        # error type alone.
        assert 'ErrorDetails' in html

    def test_reconnects_are_serialised(self, client, keydb_path):
        """Several events fire for one disconnect; each must not start
        its own player."""
        html = self._page(client, keydb_path)
        assert 'pending' in html

    def test_retry_backs_off(self, client, keydb_path):
        """Without a publisher there is nothing to connect to, so a
        tight retry is a busy loop on both ends."""
        html = self._page(client, keydb_path)
        assert 'retryMs' in html and 'Math.min' in html


class TestPictureInPictureSurvivesReconnect:
    """Picture-in-Picture is bound to the <video> element.

    Replacing the element on reconnect -- which an earlier version did,
    defensively -- drops PIP back into the page in Firefox and leaves an
    orphaned, frozen PIP window in Chrome. The element has to live for
    the whole page; only the player is torn down, and detachMediaElement
    is what makes the element reusable.
    """

    def _page(self, client, keydb_path):
        db = keydb_lib.open_db(keydb_path)
        db.transaction_start()
        ke = keydb_lib.KeyEntry(ALICE_PORT2)
        ke.fetch(db)
        ke.flags |= keydb_lib.FLAG_VIDEO
        ke.video_ports = [40001, 0, 0]
        ke.store(db)
        db.transaction_prepare_commit()
        db.transaction_commit()
        db.close()
        login_as(client, ALICE_PORT1, ALICE_PASS)
        return client.get('/video/').get_data(as_text=True)

    def test_the_element_is_server_rendered_not_built_per_connect(
            self, client, keydb_path):
        html = self._page(client, keydb_path)
        assert '<video id="player1"' in html
        assert "createElement('video')" not in html, \
            'building the element in JS means replacing it on reconnect'
        assert 'replaceChildren' not in html

    def test_teardown_does_not_touch_the_element(self, client, keydb_path):
        """Clearing src ends playback on the element, and some browsers
        exit PIP when that happens."""
        html = self._page(client, keydb_path)
        start = html.index('function teardown()')
        end = html.index('function schedule()')
        body = html[start:end]
        assert 'detachMediaElement()' in body
        assert 'removeAttribute' not in body, \
            'teardown must not clear the element src'
        assert 'video =' not in body, 'teardown must not swap the element'

    def test_ended_handler_is_registered_once(self, client, keydb_path):
        """The element outlives every player now, so registering this
        per connection would stack up a handler per attempt."""
        html = self._page(client, keydb_path)
        assert html.count("addEventListener('ended'") == 1
        # Slice start()'s own body: to its closing brace, which is the
        # first line that is exactly four spaces and a brace. start() is
        # the last function, so slicing to end-of-file would sweep in
        # the once-registered handler that follows it.
        i = html.index('function start(')
        j = html.index('\n    }', i)
        assert "addEventListener('ended'" not in html[i:j], \
            'registered per connection rather than once'

    def test_pip_is_not_disabled(self, client, keydb_path):
        html = self._page(client, keydb_path)
        assert 'disablePictureInPicture' not in html


class TestFallbackCommandsAreLowLatency:
    """ffplay's default probe is analyzeduration=5s and it spends all of
    it before showing a frame. Measured against the live stream with the
    clock burned into the picture: 5.0s behind with the defaults, under
    a second with these flags. A command without them makes the proxy
    look slow when it is not."""

    def _page(self, client, keydb_path):
        db = keydb_lib.open_db(keydb_path)
        db.transaction_start()
        ke = keydb_lib.KeyEntry(ALICE_PORT2)
        ke.fetch(db)
        ke.flags |= keydb_lib.FLAG_VIDEO
        ke.video_ports = [40001, 0, 0]
        ke.store(db)
        db.transaction_prepare_commit()
        db.transaction_commit()
        db.close()
        login_as(client, ALICE_PORT1, ALICE_PASS)
        return client.get('/video/').get_data(as_text=True)

    def test_ffplay_command_caps_the_probe(self, client, keydb_path):
        html = self._page(client, keydb_path)
        assert 'analyzeduration' in html, \
            'without this the default 5s probe is the lag'
        assert 'nobuffer' in html
        assert 'low_delay' in html

    def test_ffplay_still_probes_enough_to_find_the_stream(self, client,
                                                          keydb_path):
        """-analyzeduration 0 makes ffplay give up with 'not enough
        frames to estimate rate', so the probe is shortened, not
        removed."""
        html = self._page(client, keydb_path)
        assert 'analyzeduration 0' not in html
        assert 'probesize' in html

    def test_vlc_command_caps_its_cache(self, client, keydb_path):
        html = self._page(client, keydb_path)
        assert 'network-caching' in html


def test_raw_thermal_offers_desktop_viewer(client, keydb_path, monkeypatch):
    from types import SimpleNamespace
    from webadmin import connections
    import conntdb_lib
    _enable_video(keydb_path, ALICE_PORT2, ports=(VPORT, VPORT+1, VPORT+2))
    monkeypatch.setattr(connections, 'list_for_port2', lambda port: [SimpleNamespace(
        stream_idx=2, role=conntdb_lib.CONN_ROLE_VIDEO_PUB, app_proto=conntdb_lib.CONN_APP_MATROSKA)])
    login_as(client, ALICE_PORT1, ALICE_PASS)
    html = client.get('/video/').get_data(as_text=True)
    assert 'view_raw_thermal.py' in html and '/v3.mkv' in html
    assert 'id="player3"' not in html and 'id="player1"' in html


class TestShareToken:
    def test_round_trips(self, keydb_path):
        ke = fetch_entry(keydb_path, ALICE_PORT2)
        tok = videotoken.mint_share(ke.secret_key, ALICE_PORT2, 0, 3600)
        assert videotoken.check_share(ke.secret_key, ALICE_PORT2, 0, tok) == 'ok'

    def test_expires(self, keydb_path):
        ke = fetch_entry(keydb_path, ALICE_PORT2)
        now = time.time()
        tok = videotoken.mint_share(ke.secret_key, ALICE_PORT2, 0, 10, now=now)
        assert videotoken.check_share(ke.secret_key, ALICE_PORT2, 0, tok,
                                      now=now + 11) == 'expired'

    def test_is_bound_to_entry_and_slot(self, keydb_path):
        ke = fetch_entry(keydb_path, ALICE_PORT2)
        tok = videotoken.mint_share(ke.secret_key, ALICE_PORT2, 0, 3600)
        assert videotoken.check_share(ke.secret_key, ALICE_PORT2, 1, tok) == 'invalid'
        assert videotoken.check_share(ke.secret_key, BOB_PORT2, 0, tok) == 'invalid'

    def test_extending_the_expiry_invalidates_it(self, keydb_path):
        ke = fetch_entry(keydb_path, ALICE_PORT2)
        tok = videotoken.mint_share(ke.secret_key, ALICE_PORT2, 0, 60)
        _, _, mac = tok.partition('.')
        forged = '%d.%s' % (int(time.time()) + 10 ** 7, mac)
        assert videotoken.check_share(ke.secret_key, ALICE_PORT2, 0, forged) == 'invalid'

    def test_expiry_is_readable_from_the_token(self, keydb_path):
        ke = fetch_entry(keydb_path, ALICE_PORT2)
        tok = videotoken.mint_share(ke.secret_key, ALICE_PORT2, 0, 10, now=1000)
        assert videotoken.share_expiry(tok) == 1010

    def test_junk_is_invalid(self, keydb_path):
        ke = fetch_entry(keydb_path, ALICE_PORT2)
        for junk in ('', 'nope', '.', '123.', 'abc.def', '1.\u00e9'):
            assert videotoken.check_share(ke.secret_key, ALICE_PORT2, 0,
                                          junk) == 'invalid'

    def test_view_and_share_tokens_are_not_interchangeable(self, keydb_path):
        ke = fetch_entry(keydb_path, ALICE_PORT2)
        view = videotoken.mint(ke.secret_key, ALICE_PORT2, 0)
        share = videotoken.mint_share(ke.secret_key, ALICE_PORT2, 0, 60)
        assert videotoken.check_share(ke.secret_key, ALICE_PORT2, 0, view) == 'invalid'
        assert not videotoken.verify(ke.secret_key, ALICE_PORT2, 0, share)


@pytest.fixture(autouse=True)
def _fresh_hls_slots(monkeypatch):
    """The test client never closes a response, which is when a slot is
    given back, so each test gets its own set rather than leaking one."""
    import threading
    from webadmin import routes_video
    monkeypatch.setattr(routes_video, '_hls_slots',
                        threading.BoundedSemaphore(
                            routes_video.HLS_MAX_CONCURRENT))


class _FakeVideoChild:
    """Answers the two requests the watch page proxies, on a free port."""

    def __init__(self, playlist_status=200, truncate_segment=False):
        import http.server
        import threading
        outer = self
        outer.requests = []
        outer.playlist_status = playlist_status
        outer.truncate_segment = truncate_segment

        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                outer.requests.append(self.path)
                if self.path.startswith('/v1.m3u8') and outer.playlist_status == 200:
                    body = b'#EXTM3U\n#EXTINF:2.0,\nv1-5-1.ts?t=12.abc\n'
                    code = 200
                elif self.path.startswith('/v1-5-7.ts'):
                    body, code = b'\x47' + b'\0' * 187, 200
                else:
                    body, code = b'no\n', 503
                self.send_response(code)
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                if outer.truncate_segment and code == 200 \
                        and self.path.startswith('/v1-5-7.ts'):
                    # promise the whole segment, send part, then hang up
                    self.wfile.write(body[:50])
                    self.close_connection = True
                    return
                self.wfile.write(body)

        self.httpd = http.server.HTTPServer(('127.0.0.1', 0), H)
        self.port = self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


class TestShareLink:
    def _share(self, client, hours=1, slot=0):
        r = client.post('/video/share', data={'slot': slot, 'hours': hours})
        assert r.status_code == 200, r.get_data(as_text=True)
        return r.get_json()['url']

    def _path(self, url):
        from urllib.parse import urlparse
        return urlparse(url).path

    def test_owner_creates_link_and_anonymous_can_open_it(self, app, keydb_path):
        _enable_video(keydb_path, ALICE_PORT2)
        owner = app.test_client()
        login_as(owner, ALICE_PORT1, ALICE_PASS)
        path = self._path(self._share(owner))
        anon = app.test_client()
        r = anon.get(path)
        assert r.status_code == 200
        html = r.get_data(as_text=True)
        assert 'watch.js' in html and 'index.m3u8' in html
        assert r.headers['Referrer-Policy'] == 'no-referrer'
        ke = fetch_entry(keydb_path, ALICE_PORT2)
        assert bytes(ke.secret_key).hex() not in html.lower()

    def test_share_requires_login_and_a_valid_lifetime(self, app, keydb_path):
        _enable_video(keydb_path, ALICE_PORT2)
        anon = app.test_client()
        r = anon.post('/video/share', data={'slot': 0, 'hours': 1})
        assert r.status_code in (301, 302)
        owner = app.test_client()
        login_as(owner, ALICE_PORT1, ALICE_PASS)
        for hours in (0, 2, 99999):
            assert owner.post('/video/share', data={'slot': 0,
                                                    'hours': hours}).status_code == 400
        assert owner.post('/video/share',
                          data={'slot': 2, 'hours': 1}).status_code == 404

    def test_owner_cannot_share_another_entry(self, app, keydb_path):
        _enable_video(keydb_path, BOB_PORT2)
        owner = app.test_client()
        login_as(owner, ALICE_PORT1, ALICE_PASS)
        r = owner.post('/video/share?port2=%d' % BOB_PORT2,
                       data={'slot': 0, 'hours': 1})
        assert r.status_code == 403

    def test_expired_link_says_so(self, app, keydb_path):
        _enable_video(keydb_path, ALICE_PORT2)
        ke = fetch_entry(keydb_path, ALICE_PORT2)
        tok = videotoken.mint_share(ke.secret_key, ALICE_PORT2, 0, 60,
                                    now=time.time() - 3600)
        r = app.test_client().get('/watch/%d/0/%s/' % (ALICE_PORT2, tok))
        assert r.status_code == 410
        assert 'expired' in r.get_data(as_text=True)

    def test_bad_links_are_all_404(self, app, keydb_path):
        _enable_video(keydb_path, ALICE_PORT2)
        ke = fetch_entry(keydb_path, ALICE_PORT2)
        good = videotoken.mint_share(ke.secret_key, ALICE_PORT2, 0, 3600)
        c = app.test_client()
        assert c.get('/watch/%d/0/%s/' % (ALICE_PORT2, good)).status_code == 200
        for path in ('/watch/%d/0/%s/' % (ALICE_PORT2, good[:-1] + 'x'),
                     '/watch/%d/1/%s/' % (ALICE_PORT2, good),
                     '/watch/%d/0/%s/' % (BOB_PORT2, good),
                     '/watch/%d/9/%s/' % (ALICE_PORT2, good),
                     '/watch/%d/0/junk/' % ALICE_PORT2):
            assert c.get(path).status_code == 404, path

    def test_link_has_one_spelling(self, app, keydb_path):
        _enable_video(keydb_path, ALICE_PORT2)
        ke = fetch_entry(keydb_path, ALICE_PORT2)
        good = videotoken.mint_share(ke.secret_key, ALICE_PORT2, 0, 3600)
        exp, mac = good.split('.')
        c = app.test_client()
        assert c.get('/watch/%d/0/%s/' % (ALICE_PORT2, good)).status_code == 200
        # the same signed value, spelled differently, is not the same link
        for alt in ('+' + exp, '0' + exp, exp[:3] + '_' + exp[3:],
                    exp + ' ', '\u0661' + exp[1:]):
            r = c.get('/watch/%d/0/%s.%s/' % (ALICE_PORT2, alt, mac))
            assert r.status_code == 404, alt

    def test_hls_is_capped_so_the_admin_ui_keeps_a_worker(self, app,
                                                          keydb_path):
        from webadmin import routes_video
        up = _FakeVideoChild()
        held = []
        try:
            _enable_video(keydb_path, ALICE_PORT2, ports=(up.port,))
            ke = fetch_entry(keydb_path, ALICE_PORT2)
            tok = videotoken.mint_share(ke.secret_key, ALICE_PORT2, 0, 3600)
            url = '/watch/%d/0/%s/index.m3u8' % (ALICE_PORT2, tok)
            c = app.test_client()
            # sequential requests give their slot back once sent
            for _ in range(routes_video.HLS_MAX_CONCURRENT + 3):
                assert c.get(url, buffered=True).status_code == 200
            # with every slot in use, the next one is told to retry
            while routes_video._hls_slots.acquire(blocking=False):
                held.append(1)
            assert len(held) == routes_video.HLS_MAX_CONCURRENT
            r = c.get(url)
            assert r.status_code == 503
            assert r.headers['Retry-After']
        finally:
            for _ in held:
                routes_video._hls_slots.release()
            up.close()

    def test_link_dies_when_video_is_disabled(self, app, keydb_path):
        ke = fetch_entry(keydb_path, ALICE_PORT2)
        tok = videotoken.mint_share(ke.secret_key, ALICE_PORT2, 0, 3600)
        r = app.test_client().get('/watch/%d/0/%s/' % (ALICE_PORT2, tok))
        assert r.status_code == 404

    def test_ws_token_is_a_valid_viewer_token(self, app, keydb_path):
        _enable_video(keydb_path, ALICE_PORT2)
        ke = fetch_entry(keydb_path, ALICE_PORT2)
        tok = videotoken.mint_share(ke.secret_key, ALICE_PORT2, 0, 3600)
        r = app.test_client().get('/watch/%d/0/%s/ws-token' % (ALICE_PORT2, tok))
        assert r.status_code == 200
        assert videotoken.verify(ke.secret_key, ALICE_PORT2, 0,
                                 r.get_json()['token'])

    def test_ws_token_carries_the_links_expiry(self, app, keydb_path):
        _enable_video(keydb_path, ALICE_PORT2)
        ke = fetch_entry(keydb_path, ALICE_PORT2)
        now = int(time.time())
        tok = videotoken.mint_share(ke.secret_key, ALICE_PORT2, 0, 3600,
                                    now=now)
        r = app.test_client().get('/watch/%d/0/%s/ws-token' % (ALICE_PORT2, tok))
        vt = r.get_json()['token']
        _, until, _ = vt.split('.')
        assert int(until) == now + 3600
        # the child ends the viewer when the link does
        assert not videotoken.verify(ke.secret_key, ALICE_PORT2, 0, vt,
                                     now=now + 3601)
        # the end time is signed: it cannot be pushed out
        forged = '%s.%d.%s' % (vt.split('.')[0], now + 7200, vt.split('.')[2])
        assert not videotoken.verify(ke.secret_key, ALICE_PORT2, 0, forged)

    def test_port2_beyond_the_keydb_range_is_404(self, app, keydb_path):
        r = app.test_client().get('/watch/%d/0/1.abc/' % (2 ** 31))
        assert r.status_code == 404
        r = app.test_client().get('/watch/%d/0/1.abc/' % (2 ** 63))
        assert r.status_code == 404

    def test_playlist_segment_urls_do_not_carry_the_token(self, app,
                                                         keydb_path):
        up = _FakeVideoChild()
        try:
            _enable_video(keydb_path, ALICE_PORT2, ports=(up.port,))
            ke = fetch_entry(keydb_path, ALICE_PORT2)
            tok = videotoken.mint_share(ke.secret_key, ALICE_PORT2, 0, 3600)
            r = app.test_client().get(
                '/watch/%d/0/%s/index.m3u8' % (ALICE_PORT2, tok))
            assert b'v1-5-1.ts\n' in r.get_data()
            assert b't=' not in r.get_data()
        finally:
            up.close()

    def test_a_viewer_token_is_not_a_share_link(self, app, keydb_path):
        _enable_video(keydb_path, ALICE_PORT2)
        ke = fetch_entry(keydb_path, ALICE_PORT2)
        view = videotoken.mint(ke.secret_key, ALICE_PORT2, 0)
        r = app.test_client().get('/watch/%d/0/%s/' % (ALICE_PORT2, view))
        assert r.status_code == 404

    def test_hls_is_proxied_from_the_video_port(self, app, keydb_path):
        up = _FakeVideoChild()
        try:
            _enable_video(keydb_path, ALICE_PORT2, ports=(up.port,))
            ke = fetch_entry(keydb_path, ALICE_PORT2)
            tok = videotoken.mint_share(ke.secret_key, ALICE_PORT2, 0, 3600)
            base = '/watch/%d/0/%s/' % (ALICE_PORT2, tok)
            c = app.test_client()
            r = c.get(base + 'index.m3u8')
            assert r.status_code == 200
            assert r.headers['Content-Type'].startswith('application/vnd.apple.mpegurl')
            assert r.headers['Cache-Control'] == 'no-cache'
            assert r.get_data().startswith(b'#EXTM3U')
            r = c.get(base + 'v1-5-7.ts')
            assert r.status_code == 200
            assert r.headers['Content-Type'] == 'video/mp2t'
            assert r.get_data()[:1] == b'\x47'
            # the upstream got a viewer token, not the share token
            assert all('t=' in p and tok not in p for p in up.requests)
            up_tok = up.requests[0].split('t=', 1)[1]
            assert videotoken.verify(ke.secret_key, ALICE_PORT2, 0, up_tok)
            # a segment for another slot's number is refused
            assert c.get(base + 'v2-5-7.ts').status_code == 404
        finally:
            up.close()

    def test_hls_reports_an_idle_stream_as_retryable(self, app, keydb_path):
        up = _FakeVideoChild(playlist_status=503)
        try:
            _enable_video(keydb_path, ALICE_PORT2, ports=(up.port,))
            ke = fetch_entry(keydb_path, ALICE_PORT2)
            tok = videotoken.mint_share(ke.secret_key, ALICE_PORT2, 0, 3600)
            r = app.test_client().get(
                '/watch/%d/0/%s/index.m3u8' % (ALICE_PORT2, tok))
            assert r.status_code == 503
        finally:
            up.close()

    def test_hls_segment_cut_short_is_503_not_cached(self, app, keydb_path):
        up = _FakeVideoChild(truncate_segment=True)
        try:
            _enable_video(keydb_path, ALICE_PORT2, ports=(up.port,))
            ke = fetch_entry(keydb_path, ALICE_PORT2)
            tok = videotoken.mint_share(ke.secret_key, ALICE_PORT2, 0, 3600)
            r = app.test_client().get(
                '/watch/%d/0/%s/v1-5-7.ts' % (ALICE_PORT2, tok))
            assert r.status_code == 503
            assert 'max-age' not in r.headers.get('Cache-Control', '')
        finally:
            up.close()

    def test_hls_with_the_video_child_down_is_503(self, app, keydb_path):
        import socket
        s = socket.socket()
        s.bind(('127.0.0.1', 0))
        port = s.getsockname()[1]
        s.close()
        _enable_video(keydb_path, ALICE_PORT2, ports=(port,))
        ke = fetch_entry(keydb_path, ALICE_PORT2)
        tok = videotoken.mint_share(ke.secret_key, ALICE_PORT2, 0, 3600)
        r = app.test_client().get(
            '/watch/%d/0/%s/index.m3u8' % (ALICE_PORT2, tok))
        assert r.status_code == 503
