"""Login throttle: per-IP failure cap + constant slowdown.

The default fixture-built app sets TESTING=True which skips the
throttle (so the rest of the suite isn't gated by it). These tests
build a non-TESTING app explicitly to exercise the live behaviour,
and reset the in-memory state between cases.
"""
import time

import pytest

from webadmin import create_app, throttle

from _test_helpers import (ALICE_PASS, ALICE_PORT1, ALICE_PORT2,
                           BOB_PASS, BOB_PORT1, BOB_PORT2)


@pytest.fixture(autouse=True)
def _reset_throttle():
    throttle.reset_for_tests()
    yield
    throttle.reset_for_tests()


@pytest.fixture
def live_app(keydb_path):
    """Like the default `app` fixture but TESTING=False so the throttle
    is active. Still WTF_CSRF_ENABLED=False (we're not testing CSRF
    here) and SESSION_COOKIE_SECURE=False (test client speaks HTTP)."""
    return create_app({
        'TESTING': False,
        'WTF_CSRF_ENABLED': False,
        'SESSION_COOKIE_SECURE': False,
        'KEYDB_PATH': keydb_path,
        'SECRET_KEY': 'test',
    })


@pytest.fixture
def live_client(live_app):
    return live_app.test_client()


def _try_login(client, port, passphrase):
    return client.post('/login',
                       data={'port': port, 'passphrase': passphrase},
                       follow_redirects=False)


class TestLoginThrottle:
    def test_correct_login_resets_failure_count(self, live_client):
        # A few wrong attempts...
        for _ in range(3):
            r = _try_login(live_client, ALICE_PORT1, 'wrong')
            assert r.status_code == 200  # form re-renders
        # ...followed by a correct one. The success should clear the
        # IP's failure history.
        r = _try_login(live_client, ALICE_PORT1, ALICE_PASS)
        assert r.status_code == 302
        # The IP's failure list is now empty.
        assert not throttle.is_blocked('127.0.0.1')

    def test_blocks_after_max_failures(self, live_client):
        # Bound the wall-clock cost: each failed attempt sleeps
        # ~0.5s in the route. With MAX_FAILURES_PER_WINDOW=10 we'd
        # spend ~5s here — that's the deliberate brute-force cost.
        # We're really verifying the counter behaviour, so cap at
        # the threshold + 1.
        for _ in range(throttle.MAX_FAILURES_PER_WINDOW):
            _try_login(live_client, ALICE_PORT1, 'wrong')
        # The 11th attempt — even with the right passphrase — must be
        # rejected because the counter is over the cap.
        r = _try_login(live_client, ALICE_PORT1, ALICE_PASS)
        assert r.status_code == 200
        assert b'Too many failed login attempts' in r.data

    def test_separate_ips_dont_share_counter(self, live_app):
        c1 = live_app.test_client()
        # Bob hits from a different remote_addr; the test client's
        # base_url + REMOTE_ADDR-via-environ_overrides is the
        # cleanest way to fake it.
        for _ in range(throttle.MAX_FAILURES_PER_WINDOW):
            c1.post('/login',
                    data={'port': ALICE_PORT1, 'passphrase': 'wrong'},
                    environ_overrides={'REMOTE_ADDR': '10.0.0.1'})
        # 10.0.0.1 is now blocked.
        r1 = c1.post('/login',
                     data={'port': ALICE_PORT1, 'passphrase': ALICE_PASS},
                     environ_overrides={'REMOTE_ADDR': '10.0.0.1'})
        assert r1.status_code == 200
        # 10.0.0.2 should still be able to log in cleanly.
        r2 = c1.post('/login',
                     data={'port': ALICE_PORT1, 'passphrase': ALICE_PASS},
                     environ_overrides={'REMOTE_ADDR': '10.0.0.2'})
        assert r2.status_code == 302

    def test_window_expiry_drops_old_failures(self, live_client, monkeypatch):
        """The 60s sliding window should release blocked IPs once the
        timestamps age out. We fake time.monotonic to skip ahead."""
        for _ in range(throttle.MAX_FAILURES_PER_WINDOW):
            _try_login(live_client, ALICE_PORT1, 'wrong')
        assert throttle.is_blocked('127.0.0.1')

        # Advance the throttle's clock past the window.
        future = time.monotonic() + throttle.WINDOW_SECONDS + 1.0
        monkeypatch.setattr(throttle.time, 'monotonic', lambda: future)
        assert not throttle.is_blocked('127.0.0.1')


class TestThrottleSkippedUnderTesting:
    """The standard `app` fixture sets TESTING=True. Confirm the
    throttle is bypassed there, otherwise the rest of the webadmin
    suite would start failing intermittently as login_as is called
    repeatedly from 127.0.0.1."""

    def test_many_failures_under_testing_dont_block(self, client):
        for _ in range(throttle.MAX_FAILURES_PER_WINDOW + 5):
            r = client.post('/login',
                            data={'port': ALICE_PORT1, 'passphrase': 'wrong'})
            assert r.status_code == 200
        # Even after exceeding the cap, a real login still works
        # because the throttle never recorded anything.
        r = client.post('/login',
                        data={'port': ALICE_PORT1, 'passphrase': ALICE_PASS})
        assert r.status_code == 302
