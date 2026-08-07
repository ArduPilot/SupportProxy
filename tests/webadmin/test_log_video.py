"""Watching video from the logs view.

A recorded segment is only useful if you can actually look at it, so the
logs listing offers "watch" beside "download" for video files and a link
to the live player for the entry. An admin reaches any entry's stream;
an owner reaches only their own.
"""
import os
import subprocess
import time

import pytest

import keydb_lib

from _test_helpers import (ALICE_PASS, ALICE_PORT1, ALICE_PORT2, BOB_PASS,
                           BOB_PORT1, BOB_PORT2, login_as)

from webadmin import create_app


@pytest.fixture
def logs_dir(tmp_path):
    p = tmp_path / 'logs'
    p.mkdir()
    return p


@pytest.fixture
def app(keydb_path, logs_dir):
    """Point LOGS_DIR at a per-test tmpdir.

    The default fixture leaves it as the relative 'logs', which resolves
    under the per-*worker* directory the root conftest chdirs into --
    shared by every test in that worker, so seeded files leak between
    them and a "this file is absent" assertion silently passes or fails
    on whatever ran first.
    """
    return create_app({
        'TESTING': True,
        'WTF_CSRF_ENABLED': False,
        'SESSION_COOKIE_SECURE': False,
        'KEYDB_PATH': keydb_path,
        'LOGS_DIR': str(logs_dir),
        'SECRET_KEY': 'test',
    })

DATE = '2026-08-02'
VIDEO = '2026_08_02_11:11:19.v1.ts'
VIDEO2 = '2026_08_02_11:13:24-2.v1.ts'
TLOG = '2026_08_02_11:09:10.tlog'
VPORT = 40001

# A tiny but structurally real MPEG-TS payload: sync byte, then filler.
TS_BYTES = (bytes([0x47, 0x40, 0x00, 0x10]) + b'\xff' * 184) * 4


def _seed_logs(app, port2, names=(VIDEO, TLOG)):
    root = os.path.join(app.config['LOGS_DIR'], str(port2), DATE)
    os.makedirs(root, exist_ok=True)
    for n in names:
        with open(os.path.join(root, n), 'wb') as f:
            f.write(TS_BYTES if n.endswith('.ts') else b'\xfd' * 100)
    return root


def _seed_real_ts(app, port2):
    """Seed a genuinely decodable segment, generated with ffmpeg.

    The synthetic TS_BYTES above is structurally valid but contains no
    actual video, so a remux of it produces nothing -- these tests need
    a file ffmpeg can really read.
    """
    import shutil as _sh
    if _sh.which('ffmpeg') is None:
        return None
    root = os.path.join(app.config['LOGS_DIR'], str(port2), DATE)
    os.makedirs(root, exist_ok=True)
    dest = os.path.join(root, VIDEO)
    subprocess.run(
        ['ffmpeg', '-hide_banner', '-loglevel', 'error', '-f', 'lavfi',
         '-i', 'testsrc2=size=128x72:rate=10', '-t', '1',
         '-c:v', 'libx264', '-preset', 'ultrafast', '-g', '10',
         '-pix_fmt', 'yuv420p', '-f', 'mpegts', dest, '-y'],
        check=True)
    return root


def _our_ffmpeg_count():
    """ffmpeg processes this test process started.

    Counting every ffmpeg on the machine made this fail whenever a
    sibling xdist worker happened to start one between the two samples
    -- a leak reported against a test that leaked nothing. The remux
    spawns its ffmpeg as our direct child, so that is what to count.
    """
    mine = 0
    us = os.getpid()
    for name in os.listdir('/proc'):
        if not name.isdigit():
            continue
        pid = int(name)
        try:
            with open('/proc/%d/comm' % pid) as f:
                if f.read().strip() != 'ffmpeg':
                    continue
            with open('/proc/%d/status' % pid) as f:
                for line in f:
                    if line.startswith('PPid:'):
                        if int(line.split()[1]) == us:
                            mine += 1
                        break
        except (OSError, ValueError):
            continue
    return mine


def _enable_video(keydb_path, port2, ports=(VPORT, 0, 0)):
    db = keydb_lib.open_db(keydb_path)
    db.transaction_start()
    ke = keydb_lib.KeyEntry(port2)
    ke.fetch(db)
    ke.flags |= keydb_lib.FLAG_VIDEO
    ke.video_ports = list(ports)
    ke.store(db)
    db.transaction_prepare_commit()
    db.transaction_commit()
    db.close()


class TestWatchLinkInLogsView:
    def test_video_file_offers_watch(self, client, app, keydb_path):
        _seed_logs(app, ALICE_PORT2)
        login_as(client, BOB_PORT1, BOB_PASS)
        html = client.get('/admin/logs/%d/%s/' % (ALICE_PORT2, DATE)) \
            .get_data(as_text=True)
        assert 'aria-label="Play"' in html
        assert VIDEO in html

    def test_tlog_offers_download_only(self, client, app, keydb_path):
        """A .tlog has nothing to watch; offering a player would be a
        dead link."""
        _seed_logs(app, ALICE_PORT2, names=(TLOG,))
        login_as(client, BOB_PORT1, BOB_PASS)
        html = client.get('/admin/logs/%d/%s/' % (ALICE_PORT2, DATE)) \
            .get_data(as_text=True)
        assert 'aria-label="Download"' in html
        assert 'aria-label="Play"' not in html

    def test_owner_sees_watch_on_their_own(self, client, app, keydb_path):
        _seed_logs(app, ALICE_PORT2)
        login_as(client, ALICE_PORT1, ALICE_PASS)
        html = client.get('/me/logs/%s/' % DATE).get_data(as_text=True)
        assert 'aria-label="Play"' in html

    def test_collision_suffixed_video_is_recognised(self, client, app,
                                                    keydb_path):
        """<ts>-2.v1.ts is a real filename the recorder produces on a
        same-second collision, and it must still be playable."""
        _seed_logs(app, ALICE_PORT2, names=(VIDEO2,))
        login_as(client, BOB_PORT1, BOB_PASS)
        html = client.get('/admin/logs/%d/%s/' % (ALICE_PORT2, DATE)) \
            .get_data(as_text=True)
        assert 'aria-label="Play"' in html


class TestWatchPage:
    def test_admin_can_open_any_entry(self, client, app, keydb_path):
        _seed_logs(app, ALICE_PORT2)
        login_as(client, BOB_PORT1, BOB_PASS)
        r = client.get('/admin/logs/%d/%s/%s/watch'
                       % (ALICE_PORT2, DATE, VIDEO))
        assert r.status_code == 200
        html = r.get_data(as_text=True)
        assert '<video' in html
        # Native <video> on a remuxed MP4, not a JS player: this must
        # keep working with JavaScript disabled.
        assert 'play.mp4' in html

    def test_owner_can_open_their_own(self, client, app, keydb_path):
        _seed_logs(app, ALICE_PORT2)
        login_as(client, ALICE_PORT1, ALICE_PASS)
        r = client.get('/me/logs/%s/%s/watch' % (DATE, VIDEO))
        assert r.status_code == 200

    def test_watching_a_tlog_is_refused(self, client, app, keydb_path):
        _seed_logs(app, ALICE_PORT2)
        login_as(client, BOB_PORT1, BOB_PASS)
        r = client.get('/admin/logs/%d/%s/%s/watch'
                       % (ALICE_PORT2, DATE, TLOG))
        assert r.status_code == 404

    def test_traversal_is_refused(self, client, app, keydb_path):
        login_as(client, BOB_PORT1, BOB_PASS)
        for bad in ('..%2f..%2fevil.v1.ts', 'evil.v1.ts%00', '../evil.v1.ts'):
            r = client.get('/admin/logs/%d/%s/%s/watch'
                           % (ALICE_PORT2, DATE, bad))
            assert r.status_code in (301, 308, 404), bad


class TestStreamRoute:
    def test_serves_inline_not_as_a_download(self, client, app, keydb_path):
        """A player cannot use a Content-Disposition: attachment."""
        _seed_logs(app, ALICE_PORT2)
        login_as(client, BOB_PORT1, BOB_PASS)
        r = client.get('/admin/logs/%d/%s/%s/stream'
                       % (ALICE_PORT2, DATE, VIDEO))
        assert r.status_code == 200
        assert 'attachment' not in r.headers.get('Content-Disposition', '')
        assert r.headers['Content-Type'].startswith('video/')
        assert r.get_data() == TS_BYTES

    def test_supports_range_so_seeking_works(self, client, app, keydb_path):
        _seed_logs(app, ALICE_PORT2)
        login_as(client, BOB_PORT1, BOB_PASS)
        r = client.get('/admin/logs/%d/%s/%s/stream'
                       % (ALICE_PORT2, DATE, VIDEO),
                       headers={'Range': 'bytes=0-187'})
        assert r.status_code == 206
        assert len(r.get_data()) == 188

    def test_recordings_are_not_cached(self, client, app, keydb_path):
        _seed_logs(app, ALICE_PORT2)
        login_as(client, BOB_PORT1, BOB_PASS)
        r = client.get('/admin/logs/%d/%s/%s/stream'
                       % (ALICE_PORT2, DATE, VIDEO))
        assert 'no-store' in r.headers['Cache-Control']

    def test_streaming_a_tlog_is_refused(self, client, app, keydb_path):
        """Otherwise the inline path becomes a way to render raw
        telemetry in a browser tab."""
        _seed_logs(app, ALICE_PORT2)
        login_as(client, BOB_PORT1, BOB_PASS)
        r = client.get('/admin/logs/%d/%s/%s/stream'
                       % (ALICE_PORT2, DATE, TLOG))
        assert r.status_code == 404


class TestAccessControl:
    def test_owner_cannot_stream_another_entry(self, client, app,
                                               keydb_path):
        """The owner route resolves port2 from the session, so there is
        no parameter to tamper with -- assert that stays true."""
        _seed_logs(app, BOB_PORT2)
        _seed_logs(app, ALICE_PORT2, names=())
        login_as(client, ALICE_PORT1, ALICE_PASS)
        r = client.get('/me/logs/%s/%s/stream' % (DATE, VIDEO))
        assert r.status_code == 404

    def test_owner_cannot_use_the_admin_route(self, client, app, keydb_path):
        _seed_logs(app, BOB_PORT2)
        login_as(client, ALICE_PORT1, ALICE_PASS)
        r = client.get('/admin/logs/%d/%s/%s/stream'
                       % (BOB_PORT2, DATE, VIDEO))
        assert r.status_code in (302, 403)

    def test_anonymous_is_refused(self, client, app, keydb_path):
        _seed_logs(app, ALICE_PORT2)
        for url in ('/admin/logs/%d/%s/%s/stream' % (ALICE_PORT2, DATE, VIDEO),
                    '/me/logs/%s/%s/stream' % (DATE, VIDEO)):
            r = client.get(url)
            assert r.status_code in (302, 401, 403), url


class TestLiveVideoLinks:
    def test_admin_list_links_to_each_entry_with_video(self, client,
                                                       keydb_path):
        """The video page already accepted ?port2= for admins; nothing
        linked to it, so reaching another entry's stream meant editing
        the URL by hand."""
        _enable_video(keydb_path, ALICE_PORT2)
        login_as(client, BOB_PORT1, BOB_PASS)
        html = client.get('/admin/').get_data(as_text=True)
        assert 'port2=%d' % ALICE_PORT2 in html

    def test_no_video_link_for_an_entry_without_video(self, client,
                                                      keydb_path):
        login_as(client, BOB_PORT1, BOB_PASS)
        html = client.get('/admin/').get_data(as_text=True)
        assert '/video/?port2=' not in html

    def test_logs_page_links_to_the_live_player(self, client, app,
                                                keydb_path):
        _enable_video(keydb_path, ALICE_PORT2)
        _seed_logs(app, ALICE_PORT2)
        login_as(client, BOB_PORT1, BOB_PASS)
        html = client.get('/admin/logs/%d/' % ALICE_PORT2) \
            .get_data(as_text=True)
        assert 'watch live video' in html

    def test_no_live_link_when_no_port_is_allocated(self, client, app,
                                                    keydb_path):
        """Video enabled but no port bound means nothing to watch."""
        _enable_video(keydb_path, ALICE_PORT2, ports=(0, 0, 0))
        _seed_logs(app, ALICE_PORT2)
        login_as(client, BOB_PORT1, BOB_PASS)
        html = client.get('/admin/logs/%d/' % ALICE_PORT2) \
            .get_data(as_text=True)
        assert 'watch live video' not in html

    def test_admin_can_open_another_entrys_live_player(self, client,
                                                       keydb_path):
        _enable_video(keydb_path, ALICE_PORT2)
        login_as(client, BOB_PORT1, BOB_PASS)
        r = client.get('/video/?port2=%d' % ALICE_PORT2)
        assert r.status_code == 200
        assert str(VPORT) in r.get_data(as_text=True)

    def test_owner_cannot_open_another_entrys_live_player(self, client,
                                                          keydb_path):
        _enable_video(keydb_path, BOB_PORT2)
        login_as(client, ALICE_PORT1, ALICE_PASS)
        assert client.get('/video/?port2=%d' % BOB_PORT2).status_code == 403


class TestRemuxToMp4:
    """Browsers cannot demux MPEG-TS, so the recording is remuxed to
    fragmented MP4 on the way out. It is a stream copy, so this costs
    no decoding."""

    def _skip_without_ffmpeg(self):
        import shutil
        if shutil.which('ffmpeg') is None:
            pytest.skip('ffmpeg not installed')

    def test_serves_a_real_mp4(self, client, app, keydb_path, tmp_path):
        self._skip_without_ffmpeg()
        root = _seed_real_ts(app, ALICE_PORT2)
        assert root
        login_as(client, BOB_PORT1, BOB_PASS)
        r = client.get('/admin/logs/%d/%s/%s/play.mp4'
                       % (ALICE_PORT2, DATE, VIDEO))
        assert r.status_code == 200
        assert r.headers['Content-Type'].startswith('video/mp4')
        data = r.get_data()
        # An MP4 starts with a box length then 'ftyp'.
        assert data[4:8] == b'ftyp', data[:16]
        assert len(data) > 1000

    def test_inline_not_attachment(self, client, app, keydb_path):
        self._skip_without_ffmpeg()
        _seed_real_ts(app, ALICE_PORT2)
        login_as(client, BOB_PORT1, BOB_PASS)
        r = client.get('/admin/logs/%d/%s/%s/play.mp4'
                       % (ALICE_PORT2, DATE, VIDEO))
        assert 'attachment' not in r.headers.get('Content-Disposition', '')

    def test_not_cached(self, client, app, keydb_path):
        self._skip_without_ffmpeg()
        _seed_real_ts(app, ALICE_PORT2)
        login_as(client, BOB_PORT1, BOB_PASS)
        r = client.get('/admin/logs/%d/%s/%s/play.mp4'
                       % (ALICE_PORT2, DATE, VIDEO))
        assert 'no-store' in r.headers['Cache-Control']

    def test_tlog_is_refused(self, client, app, keydb_path):
        _seed_logs(app, ALICE_PORT2)
        login_as(client, BOB_PORT1, BOB_PASS)
        r = client.get('/admin/logs/%d/%s/%s/play.mp4'
                       % (ALICE_PORT2, DATE, TLOG))
        assert r.status_code == 404

    def test_missing_file_is_404_not_a_hanging_ffmpeg(self, client, app,
                                                      keydb_path):
        _seed_logs(app, ALICE_PORT2, names=())
        login_as(client, BOB_PORT1, BOB_PASS)
        r = client.get('/admin/logs/%d/%s/%s/play.mp4'
                       % (ALICE_PORT2, DATE, VIDEO))
        assert r.status_code == 404

    def test_owner_route_is_scoped_to_their_own_entry(self, client, app,
                                                      keydb_path):
        self._skip_without_ffmpeg()
        _seed_real_ts(app, BOB_PORT2)
        login_as(client, ALICE_PORT1, ALICE_PASS)
        r = client.get('/me/logs/%s/%s/play.mp4' % (DATE, VIDEO))
        assert r.status_code == 404

    def test_no_ffmpeg_left_running_afterwards(self, client, app,
                                               keydb_path):
        """The generator kills ffmpeg in a finally, so a client that
        disconnects mid-stream cannot leak one."""
        self._skip_without_ffmpeg()
        _seed_real_ts(app, ALICE_PORT2)
        login_as(client, BOB_PORT1, BOB_PASS)
        before = _our_ffmpeg_count()
        r = client.get('/admin/logs/%d/%s/%s/play.mp4'
                       % (ALICE_PORT2, DATE, VIDEO))
        r.get_data()
        r.close()
        time.sleep(0.5)
        after = _our_ffmpeg_count()
        assert after <= before
