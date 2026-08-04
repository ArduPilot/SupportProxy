"""scripts/test_video.py -- the test-pattern publisher and stream checker.

The tool exists to tell a human whether a video port works, so the thing
worth guarding is that it can still say "no". A checker that always
passes is worse than no checker. The encoder command construction is
covered without invoking ffmpeg or gstreamer; the full round trip is
covered by one end-to-end case behind the same markers as the other
video tests.
"""
import argparse
import os
import shlex
import shutil
import subprocess
import sys
import time

import pytest

_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)
sys.path.insert(0, os.path.join(_REPO_ROOT, 'scripts'))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import test_video as tv                                    # noqa: E402
import keydb_lib                                           # noqa: E402
from test_video_child import (Proxy, _Mav, _make_workdir,   # noqa: E402
                              _port_bound, VPORT, PORT_ENG)

TOOL = os.path.join(_REPO_ROOT, 'scripts', 'test_video.py')


def _args(**over):
    base = dict(host='127.0.0.1', port=40001, transport='udp',
                publish_pass='', rtsp_path='cam', codec='h264',
                size='1280x720', fps=25, bitrate='2M', gop_seconds=2,
                audio=False, duration=0, encoder='ffmpeg', label='',
                font_size=0, loglevel='warning', dry_run=False,
                verbose=False)
    base.update(over)
    return argparse.Namespace(**base)


class TestPublishUrl:
    def test_udp_uses_seven_packet_datagrams(self):
        """A datagram that splits a TS packet across two is rejected by
        the proxy, so pkt_size is not decoration."""
        url = tv.publish_url(_args(transport='udp'))
        assert url == 'udp://127.0.0.1:40001?pkt_size=1316'
        assert 1316 % 188 == 0

    def test_rtsp_carries_the_publish_password_in_the_query(self):
        """The request-line query is the only place RTSP can carry a
        credential without the proxy parsing the session."""
        url = tv.publish_url(_args(transport='rtsp', publish_pass='s3cret'))
        assert url == 'rtsp://127.0.0.1:40001/cam?pw=s3cret'

    def test_rtsp_without_a_password_has_no_query(self):
        url = tv.publish_url(_args(transport='rtsp'))
        assert '?' not in url


# Anything that shells out to the tool needs a usable encoder; the tool
# exits 2 without one. Skip rather than fail, so the suite is honest on a
# machine that has no ffmpeg -- CI installs it (scripts/setup_ci.sh) so
# these do run there.
needs_encoder = pytest.mark.skipif(
    shutil.which('ffmpeg') is None and shutil.which('gst-launch-1.0') is None,
    reason='needs ffmpeg or gstreamer')


class TestFfmpegCommand:
    """Pure command construction -- no encoder needs to exist.

    ffmpeg_publish_cmd() probes the local binary to decide whether it can
    use drawtext, so without that stub these assert on a command built
    for a machine with no ffmpeg, and -vf is simply absent.
    """

    @pytest.fixture(autouse=True)
    def _with_drawtext(self, monkeypatch):
        monkeypatch.setattr(tv, 'ffmpeg_has_filter', lambda name: True)

    def test_drawtext_colon_is_escaped_inside_quotes(self):
        """Measured behaviour: the value needs BOTH the surrounding
        single quotes and a backslash on the colon. Either alone still
        splits the filter argument and ffmpeg refuses the graph."""
        cmd = tv.ffmpeg_publish_cmd(_args())
        vf = cmd[cmd.index('-vf') + 1]
        assert "text='" in vf
        assert r'%{pts\:hms}' in vf
        assert r'%{pts\\:hms}' not in vf, 'double-escaped: prints a backslash'

    def test_x_is_clamped_so_wide_text_is_not_clipped_both_ends(self):
        cmd = tv.ffmpeg_publish_cmd(_args(size='320x180'))
        vf = cmd[cmd.index('-vf') + 1]
        assert 'max(0' in vf

    def test_font_scales_with_frame_height(self):
        small = tv._font_size(_args(size='320x180'))
        big = tv._font_size(_args(size='1920x1080'))
        assert small < big
        assert small >= 12, 'must stay legible on a small frame'

    def test_explicit_font_size_wins(self):
        assert tv._font_size(_args(size='320x180', font_size=40)) == 40

    def test_label_apostrophe_is_dropped_not_left_to_break_the_graph(self):
        cmd = tv.ffmpeg_publish_cmd(_args(label="tridge's laptop"))
        vf = cmd[cmd.index('-vf') + 1]
        assert 'tridges laptop' in vf

    def test_audio_off_by_default_matching_the_proxy(self):
        assert '-an' in tv.ffmpeg_publish_cmd(_args())
        assert '-an' not in tv.ffmpeg_publish_cmd(_args(audio=True))

    def test_hevc_selects_the_right_encoder(self):
        assert 'libx265' in tv.ffmpeg_publish_cmd(_args(codec='hevc'))

    def test_keyframe_interval_follows_gop_seconds(self):
        cmd = tv.ffmpeg_publish_cmd(_args(fps=30, gop_seconds=2))
        assert cmd[cmd.index('-g') + 1] == '60'


class TestGstCommand:
    def test_each_word_is_its_own_argument(self):
        """gst-launch takes every argv element as one pipeline token and
        does NOT split on spaces, so 'videotestsrc is-live=true' passed
        as a single argument is a syntax error."""
        argv = tv.gst_publish_cmd(_args(encoder='gst'))
        assert 'videotestsrc' in argv
        assert not any(a.startswith('videotestsrc ') for a in argv)

    def test_separators_are_present(self):
        argv = tv.gst_publish_cmd(_args(encoder='gst'))
        assert argv.count('!') >= 6

    def test_quoted_font_stays_one_argument(self):
        argv = tv.gst_publish_cmd(_args(encoder='gst', font_size=18))
        assert 'font-desc=Sans 18' in argv

    def test_alignment_7_for_udp(self):
        """mpegtsmux must emit 7-packet groups to match the datagram."""
        argv = tv.gst_publish_cmd(_args(encoder='gst'))
        assert 'alignment=7' in argv

    def test_duration_bounds_the_source(self):
        argv = tv.gst_publish_cmd(_args(encoder='gst', duration=4, fps=25))
        assert 'num-buffers=100' in argv


class TestKbits:
    @pytest.mark.parametrize('spec,want', [
        ('2M', 2000), ('2000k', 2000), ('500k', 500), ('2000000', 2000)])
    def test_conversion(self, spec, want):
        assert tv._kbits(spec) == want


class TestAnalyser:
    """The analyser is what turns "bytes arrived" into "a stream
    arrived", so its refusals matter more than its acceptances."""

    def test_empty_input_is_not_a_stream(self):
        an = tv.TSAnalyser()
        ok, problems = an.verdict(0)
        assert not ok
        assert 'no MPEG-TS packets' in problems[0]

    def test_garbage_is_not_a_stream(self):
        an = tv.TSAnalyser()
        an.feed(b'\xde\xad\xbe\xef' * 1000)
        ok, _ = an.verdict(0)
        assert not ok

    def test_real_stream_is_accepted(self):
        import tsgen
        g = tsgen.TSGen()
        an = tv.TSAnalyser()
        for dgram in g.datagrams(g.stream(400)):
            an.feed(dgram)
        ok, problems = an.verdict(0)
        assert ok, problems
        rep = an.report()
        assert rep['pat_sections'] > 0
        assert rep['random_access_points'] > 0
        assert rep['continuity_errors'] == 0

    def test_resyncs_after_leading_junk(self):
        """A viewer that joins mid-packet must not be reported as a
        broken stream -- it should resync and say how much it dropped."""
        import tsgen
        g = tsgen.TSGen()
        an = tv.TSAnalyser()
        an.feed(b'\x00' * 37)
        for dgram in g.datagrams(g.stream(400)):
            an.feed(dgram)
        assert an.packets > 0
        assert an.unsynced == 37

    def test_missing_pat_is_reported(self):
        an = tv.TSAnalyser()
        # 188-byte packets on a non-zero PID: syntactically fine, but a
        # viewer could never find the video.
        pkt = bytes([0x47, 0x01, 0x00, 0x10]) + b'\xff' * 184
        an.feed(pkt * 50)
        ok, problems = an.verdict(0)
        assert not ok
        assert any('PAT' in p for p in problems)


class TestCli:
    def test_caps_runs(self):
        r = subprocess.run([sys.executable, TOOL, 'caps', '--json'],
                           capture_output=True, text=True, timeout=60)
        assert r.returncode == 0
        import json
        assert 'ffmpeg' in json.loads(r.stdout)

    @needs_encoder
    def test_dry_run_emits_a_runnable_command(self):
        r = subprocess.run([sys.executable, TOOL, 'publish', '--port',
                            '40001', '--dry-run'],
                           capture_output=True, text=True, timeout=60)
        assert r.returncode == 0
        argv = shlex.split(r.stdout.strip())
        assert argv[0] in ('ffmpeg', 'gst-launch-1.0')

    def test_port_is_required(self):
        r = subprocess.run([sys.executable, TOOL, 'publish'],
                           capture_output=True, text=True, timeout=60)
        assert r.returncode != 0


@pytest.mark.slow
@needs_encoder
class TestEndToEnd:
    """One real round trip: test pattern -> proxy -> viewer -> verdict."""

    def _proxy(self, tmp_path, **kw):
        wd = _make_workdir(tmp_path, **kw)
        return wd, Proxy(wd)

    def _wait_bound(self):
        for _ in range(100):
            if _port_bound(VPORT):
                return True
            time.sleep(0.1)
        return False

    def _check(self, *extra):
        return subprocess.run(
            [sys.executable, TOOL, 'check', '--host', '127.0.0.1',
             '--port', str(VPORT), '--size', '320x180', '--duration', '4',
             '--settle', '3'] + list(extra),
            capture_output=True, text=True, timeout=120)

    def test_publish_and_view_round_trip(self, tmp_path):
        if not os.path.exists(os.path.join(_REPO_ROOT, 'supportproxy')):
            pytest.skip('supportproxy not built')
        wd, px = self._proxy(tmp_path)
        try:
            assert self._wait_bound()
            _Mav()                      # latch conn1 from 127.0.0.1
            time.sleep(1.5)
            r = self._check()
            assert r.returncode == 0, r.stdout + r.stderr
            assert 'H.264' in r.stdout
        finally:
            px.proc.terminate()

    def _with_viewer_pass(self, tmp_path, pw):
        wd, px = self._proxy(tmp_path)
        db = keydb_lib.open_db(str(wd / 'keys.tdb'))
        db.transaction_start()
        keydb_lib.set_video_viewer_pass(db, PORT_ENG, pw)
        db.transaction_prepare_commit()
        db.transaction_commit()
        db.close()
        return px

    def test_the_wrong_viewer_password_fails(self, tmp_path):
        """The guard that matters: a checker that cannot fail is
        worthless. Each case gets its own proxy -- a publisher holds its
        slot for 10s after going quiet, so a second run against the same
        proxy would be refused as slot-busy and 'fail' for the wrong
        reason."""
        if not os.path.exists(os.path.join(_REPO_ROOT, 'supportproxy')):
            pytest.skip('supportproxy not built')
        px = self._with_viewer_pass(tmp_path, 'hunter2')
        try:
            assert self._wait_bound()
            _Mav()
            time.sleep(1.5)
            assert self._check('--viewer-pass', 'wrong').returncode != 0
        finally:
            px.proc.terminate()

    def test_the_right_viewer_password_passes(self, tmp_path):
        if not os.path.exists(os.path.join(_REPO_ROOT, 'supportproxy')):
            pytest.skip('supportproxy not built')
        px = self._with_viewer_pass(tmp_path, 'hunter2')
        try:
            assert self._wait_bound()
            _Mav()
            time.sleep(1.5)
            r = self._check('--viewer-pass', 'hunter2')
            assert r.returncode == 0, r.stdout + r.stderr
        finally:
            px.proc.terminate()


class TestNoOrphanPublisher:
    """Killing the wrapper must take ffmpeg with it.

    An orphaned publisher keeps sending, and because one publisher holds
    a slot, it then refuses the *next* publisher as slot-busy. A leaked
    test publisher quietly takes over a real video port -- which is
    exactly what happened on the live server during this work.
    """

    def test_ffmpeg_dies_with_its_parent(self, tmp_path):
        import shutil
        if shutil.which('ffmpeg') is None:
            pytest.skip('ffmpeg not installed')
        # Publish to a port nothing is listening on: the publisher still
        # runs, which is all this needs.
        p = subprocess.Popen(
            [sys.executable, TOOL, 'publish', '--host', '127.0.0.1',
             '--port', '9', '--size', '128x72'],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            child = None
            for _ in range(60):
                time.sleep(0.2)
                out = subprocess.run(['pgrep', '-P', str(p.pid), '-x', 'ffmpeg'],
                                     capture_output=True, text=True).stdout
                if out.strip():
                    child = int(out.split()[0])
                    break
            assert child, 'ffmpeg never started'

            p.kill()          # the worst case: no chance to clean up
            p.wait()
            for _ in range(50):
                time.sleep(0.2)
                if subprocess.run(['kill', '-0', str(child)],
                                  capture_output=True).returncode != 0:
                    return    # gone, as it should be
            raise AssertionError('ffmpeg %d outlived its parent' % child)
        finally:
            if p.poll() is None:
                p.kill()
                p.wait()

    def test_the_helper_is_wired_in(self):
        """Both spawn sites must go through it, or one path leaks."""
        src = open(TOOL).read()
        assert 'PR_SET_PDEATHSIG' in src or 'prctl' in src
        assert src.count('_spawn(') >= 3   # def + publish + check
        assert 'subprocess.Popen(cmd)' not in src, \
            'a raw Popen bypasses the death-signal helper'
