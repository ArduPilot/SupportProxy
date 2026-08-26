"""RTSP ingest, spliced to a loopback ffmpeg.

SupportProxy parses no RTSP: it keeps the public port, authorises the
source address, and hands the connection untouched to an ffmpeg on
loopback. The spike established why -- waiting to classify deadlocks
(RTSP is request/response), and answering OPTIONS ourselves makes
ffmpeg reject the following ANNOUNCE because its listener wants the
first request it sees to be CSeq 1.

These need a real ffmpeg, so they skip without one.
"""
import os
import re
import shutil
import socket
import subprocess
import sys
import time

import pytest

_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import keydb_lib  # noqa: E402
import rtmp_client  # noqa: E402
from test_video_child import (Proxy, _Mav, PORT_ENG, PORT_USER,  # noqa: E402
                              PASSPHRASE, VPORT)

pytestmark = pytest.mark.skipif(shutil.which('ffmpeg') is None,
                                reason='RTSP ingest needs ffmpeg')

# A short clip generated once per session: enough to carry a couple of
# keyframes so the stream becomes joinable.
_CLIP = None


@pytest.fixture(scope='session')
def clip(tmp_path_factory):
    """A real H.264 clip, so the backend does real work.

    Synthetic TS is right for the scanner tests, but this path hands
    bytes to ffmpeg's RTSP demuxer and H.264 parser -- those need a
    genuine elementary stream.
    """
    d = tmp_path_factory.mktemp('clip')
    path = str(d / 'clip.mp4')
    subprocess.run([
        'ffmpeg', '-hide_banner', '-loglevel', 'error', '-y',
        '-f', 'lavfi', '-i', 'testsrc=size=320x240:rate=15:duration=12',
        '-c:v', 'libx264', '-preset', 'ultrafast', '-g', '15',
        '-pix_fmt', 'yuv420p', path,
    ], check=True, capture_output=True)
    return path


def _workdir(tmp_path, record=True, publish_pass=None,
             rtmp_path=None, session_ok=False):
    p = tmp_path / 'work'
    p.mkdir()
    db = keydb_lib.init_db(str(p / 'keys.tdb'))
    db.transaction_start()
    keydb_lib.add_entry(db, PORT_USER, PORT_ENG, 'rtsp', PASSPHRASE)
    keydb_lib.set_flag(db, PORT_ENG, 'video')
    keydb_lib.set_video_ports(db, PORT_ENG, [VPORT])
    if record:
        keydb_lib.set_video_slot_flag(db, PORT_ENG, 0, 'record')
    if publish_pass:
        keydb_lib.set_video_publish_pass(db, PORT_ENG, publish_pass)
    if rtmp_path:
        keydb_lib.set_video_rtmp_path(db, PORT_ENG, 0, rtmp_path)
    if session_ok:
        keydb_lib.set_video_slot_flag(db, PORT_ENG, 0, 'session_ok')
    db.transaction_prepare_commit()
    db.transaction_commit()
    db.close()
    return p


class RtspSession:
    def __init__(self, workdir, with_mav=True):
        self.workdir = workdir
        self.proxy = Proxy(workdir)
        assert self.proxy.wait_for(r'video slot 0 listening'), self.proxy.log
        self.mav = None
        if with_mav:
            self.mav = _Mav()
            assert self.proxy.wait_for(r'have UDP conn1'), self.proxy.log
            time.sleep(1.2)
        self.pub = None

    def publish(self, clip, loop=True):
        argv = ['ffmpeg', '-hide_banner', '-loglevel', 'error', '-re']
        if loop:
            argv += ['-stream_loop', '-1']
        argv += ['-i', clip, '-c:v', 'copy', '-an',
                 '-f', 'rtsp', '-rtsp_transport', 'tcp',
                 'rtsp://127.0.0.1:%d/cam' % VPORT]
        self.pub = subprocess.Popen(argv, stdout=subprocess.DEVNULL,
                                    stderr=subprocess.PIPE)
        return self.pub

    def publish_rtmp_burst(self, clip, path='PhoenixFPV/FPV', port=None):
        """Publish as fast as the link allows -- no -re pacing.

        This is the case the paced publisher never exercised: a burst
        fills the socket to the backend, and the old relay slept inside
        the event loop retrying that write, which stopped it draining
        ffmpeg's stdout and deadlocked the pair.
        """
        argv = ['ffmpeg', '-hide_banner', '-loglevel', 'error',
                '-stream_loop', '-1', '-i', clip, '-c:v', 'copy', '-an',
                '-f', 'flv',
                'rtmp://127.0.0.1:%d/%s' % (port or VPORT, path)]
        self.pub = subprocess.Popen(argv, stdout=subprocess.DEVNULL,
                                    stderr=subprocess.PIPE)
        return self.pub

    def publish_rtmp(self, clip, path='PhoenixFPV/FPV', loop=True,
                     port=None):
        """Publish over RTMP, the way the camera does.

        The app and stream in the URL are what the proxy reads off the
        wire, so this is also how a test picks the path and, with a
        query on the stream name, the publish credential.
        """
        argv = ['ffmpeg', '-hide_banner', '-loglevel', 'error', '-re']
        if loop:
            argv += ['-stream_loop', '-1']
        argv += ['-i', clip, '-c:v', 'copy', '-an',
                 '-f', 'flv',
                 'rtmp://127.0.0.1:%d/%s' % (port or VPORT, path)]
        self.pub = subprocess.Popen(argv, stdout=subprocess.DEVNULL,
                                    stderr=subprocess.PIPE)
        return self.pub

    def stop_publisher(self):
        if self.pub and self.pub.poll() is None:
            self.pub.terminate()
            try:
                self.pub.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.pub.kill()
                self.pub.wait(timeout=5)
        self.pub = None

    def stop(self):
        self.stop_publisher()
        if self.mav:
            self.mav.stop()
        self.proxy.stop()


def _no_stray_ffmpeg():
    """No ffmpeg still pointed at our video port.

    A publisher started with -stream_loop -1 keeps retrying, so a
    leftover from the previous test would otherwise take the slot the
    next test is trying to publish into.
    """
    out = subprocess.run(['pgrep', '-a', '-x', 'ffmpeg'],
                         capture_output=True, text=True).stdout
    return not any(':%d/' % VPORT in ln for ln in out.splitlines())


def _settle(timeout=45):
    # 45s not 25: the backpressure tests run an unpaced -stream_loop -1
    # publisher, which under a loaded -j16 run takes longer to die than
    # the paced ones this was sized for.
    deadline = time.time() + timeout
    while time.time() < deadline:
        if (_no_stray_ffmpeg() and _port_free(VPORT)
                and _port_free(PORT_USER) and _port_free(PORT_ENG)):
            return True
        time.sleep(0.3)
    return False


def _settle_state():
    """What is still held, for an assertion message worth reading."""
    held = [name for name, port in (('video', VPORT), ('user', PORT_USER),
                                    ('eng', PORT_ENG)) if not _port_free(port)]
    out = subprocess.run(['pgrep', '-a', '-x', 'ffmpeg'],
                         capture_output=True, text=True).stdout
    return 'ports held: %s; ffmpeg: %r' % (held or 'none', out.splitlines())


def _port_free(port):
    """True when nothing holds `port` (read from /proc/net/tcp).

    TIME_WAIT does not count. An accepted connection's local port *is*
    the listening port, so refusing a publisher leaves the video port in
    TIME_WAIT for 60 s -- longer than this waits -- while the proxy
    (SO_REUSEADDR) can rebind it immediately. Counting it made the next
    test fail for something that was never in its way.
    """
    want = '%04X' % port
    for proto in ('tcp', 'udp'):
        try:
            with open('/proc/net/' + proto) as f:
                next(f)
                for line in f:
                    f_ = line.split()
                    if f_[1].split(':')[1].upper() != want:
                        continue
                    if proto == 'tcp' and f_[3] == '06':   # TIME_WAIT
                        continue
                    return False
        except OSError:
            pass
    return True


@pytest.fixture
def session(tmp_path):
    """One proxy per test.

    These tests share a port set and, unlike the other video files,
    also leave ffmpeg subprocesses behind. Waiting for the video port
    to be released before yielding keeps a slow teardown from failing
    the next test rather than its own.
    """
    _settle()

    made = {}

    def _start(**kw):
        made['s'] = RtspSession(_workdir(tmp_path, **{
            k: v for k, v in kw.items()
            if k in ('record', 'publish_pass', 'session_ok')}),
            with_mav=kw.get('with_mav', True))
        return made['s']

    yield _start
    if 's' in made:
        made['s'].stop()
    _settle()


def _ffmpeg_children(proxy):
    """ffmpeg processes descended from this proxy."""
    out = subprocess.run(['pgrep', '-a', '-x', 'ffmpeg'],
                         capture_output=True, text=True).stdout
    return [ln for ln in out.splitlines() if 'rtsp://127.0.0.1' in ln]


@pytest.mark.integration
class TestRtspIngest:
    def test_publish_is_accepted_and_becomes_joinable(self, session, clip):
        s = session()
        s.publish(clip)
        assert s.proxy.wait_for(r'RTSP backend pid \d+', timeout=20), s.proxy.log
        assert s.proxy.wait_for(r'RTSP publisher', timeout=20), s.proxy.log
        assert s.proxy.wait_for(r'join=ready', timeout=40), s.proxy.log

        st = re.findall(r'stats: (\d+) KiB, (\d+) pkts, pat=(\d+) pmt=(\d+) '
                        r'rai=(\d+)', s.proxy.log)
        assert st, s.proxy.log
        kib, pkts, pat, pmt, rai = (int(x) for x in st[-1])
        assert pkts > 0 and pat > 0 and pmt > 0 and rai > 0, st[-1]

    def test_recording_is_written(self, session, clip):
        s = session()
        s.publish(clip)
        assert s.proxy.wait_for(r'recording to .*\.v1\.ts', timeout=30), \
            s.proxy.log
        d = (s.workdir / 'logs' / str(PORT_ENG)
             / time.strftime('%Y-%m-%d', time.localtime()))
        deadline = time.time() + 20
        segs = []
        while time.time() < deadline:
            segs = [f for f in d.iterdir() if f.name.endswith('.v1.ts')] \
                if d.is_dir() else []
            if segs and segs[0].stat().st_size > 10000:
                break
            time.sleep(0.5)
        assert segs and segs[0].stat().st_size > 10000, \
            'no usable recording from an RTSP publish:\n%s' % s.proxy.log
        blob = segs[0].read_bytes()
        assert blob[0] == 0x47 and len(blob) % 188 == 0

    def test_viewer_gets_the_rtsp_stream(self, session, clip):
        """The whole point: an RTSP publisher feeds the same fan-out as
        a UDP one."""
        import socket
        s = session()
        s.publish(clip)
        assert s.proxy.wait_for(r'join=ready', timeout=40), s.proxy.log

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect(('127.0.0.1', VPORT))
        try:
            sock.sendall(b'GET /v1.ts HTTP/1.1\r\nHost: x\r\n\r\n')
            got = b''
            deadline = time.time() + 8
            while time.time() < deadline and len(got) < 40000:
                try:
                    c = sock.recv(65536)
                except socket.timeout:
                    continue
                if not c:
                    break
                got += c
        finally:
            sock.close()
        assert b'200 OK' in got, got[:200]
        body = got.split(b'\r\n\r\n', 1)[1]
        assert len(body) > 10000, len(body)
        assert body[0] == 0x47, 'viewer stream does not start at a packet'

    def test_publish_rejected_without_a_mavlink_session(self, session, clip):
        s = session(with_mav=False)
        s.publish(clip, loop=False)
        assert s.proxy.wait_for(r'rejected .*no MAVLink session', timeout=20), \
            s.proxy.log
        assert 'RTSP backend pid' not in s.proxy.log, \
            'a backend was started for an unauthorised publisher'

    def test_second_publisher_is_refused(self, session, clip):
        s = session()
        s.publish(clip)
        assert s.proxy.wait_for(r'RTSP publisher', timeout=20), s.proxy.log
        second = subprocess.Popen(
            ['ffmpeg', '-hide_banner', '-loglevel', 'error', '-re',
             '-i', clip, '-c:v', 'copy', '-an', '-f', 'rtsp',
             '-rtsp_transport', 'tcp', 'rtsp://127.0.0.1:%d/cam2' % VPORT],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            assert s.proxy.wait_for(r'another publisher holds this slot',
                                    timeout=20), s.proxy.log
        finally:
            second.terminate()
            second.wait(timeout=5)

    def test_no_orphan_backend_after_the_publisher_leaves(self, session, clip):
        s = session()
        s.publish(clip)
        assert s.proxy.wait_for(r'RTSP backend pid \d+', timeout=20), s.proxy.log
        assert _ffmpeg_children(s.proxy), 'no backend running while publishing'

        s.stop_publisher()
        assert s.proxy.wait_for(r'RTSP publisher gone', timeout=25), s.proxy.log
        deadline = time.time() + 15
        while time.time() < deadline and _ffmpeg_children(s.proxy):
            time.sleep(0.5)
        assert not _ffmpeg_children(s.proxy), \
            'backend outlived the publisher: %r' % _ffmpeg_children(s.proxy)

    def test_backend_dies_with_the_proxy(self, session, clip):
        s = session()
        s.publish(clip)
        assert s.proxy.wait_for(r'RTSP backend pid \d+', timeout=20), s.proxy.log
        assert _ffmpeg_children(s.proxy)
        s.stop_publisher()
        s.proxy.stop()
        deadline = time.time() + 15
        while time.time() < deadline and _ffmpeg_children(s.proxy):
            time.sleep(0.5)
        assert not _ffmpeg_children(s.proxy), \
            'backend outlived the proxy: %r' % _ffmpeg_children(s.proxy)


def _publish_with(url_suffix, clip, seconds=6):
    return subprocess.Popen(
        ['ffmpeg', '-hide_banner', '-loglevel', 'error', '-re',
         '-stream_loop', '-1', '-i', clip, '-c:v', 'copy', '-an',
         '-f', 'rtsp', '-rtsp_transport', 'tcp',
         'rtsp://127.0.0.1:%d/cam%s' % (VPORT, url_suffix)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


@pytest.mark.integration
class TestPublishPassword:
    """Path A: a publish password, with no MAVLink session anywhere.

    This is the path for CGNAT, for video on a different link from
    telemetry, and for anyone who does not want address matching to be
    the gate at all. The password replaces the MAVLink check rather
    than adding to it.

    RTSP carries it in the request-line URI. That is the only place it
    can go without us answering anything: Basic auth would mean
    replying 401 and renumbering CSeq, which is exactly what makes the
    opaque splice work.
    """

    def test_accepted_with_no_mavlink_session_at_all(self, session, clip):
        # ffmpeg later resolves the SDP control URI as
        # ?pw=pubsecret/streamid=0. Reaching join=ready therefore also
        # covers the guard's exact-password-plus-control-path handling.
        s = session(with_mav=False, publish_pass='pubsecret')
        s.pub = _publish_with('?pw=pubsecret', clip)
        assert s.proxy.wait_for(r'RTSP publisher', timeout=25), s.proxy.log
        assert s.proxy.wait_for(r'join=ready', timeout=40), s.proxy.log
        assert 'no MAVLink session' not in s.proxy.log

    def test_wrong_password_refused(self, session, clip):
        s = session(with_mav=False, publish_pass='pubsecret')
        s.pub = _publish_with('?pw=wrong', clip)
        assert s.proxy.wait_for(r'wrong publish password', timeout=25), \
            s.proxy.log
        assert 'RTSP publisher' not in s.proxy.log

    def test_missing_password_says_so_precisely(self, session, clip):
        """Distinct from 'wrong', and distinct from 'this transport
        cannot carry one' -- an operator debugging this needs to know
        which of the three it is."""
        s = session(with_mav=False, publish_pass='pubsecret')
        s.pub = _publish_with('', clip)
        assert s.proxy.wait_for(r'none was supplied', timeout=25), s.proxy.log

    def test_udp_says_it_cannot_carry_a_password(self, session, clip):
        import socket
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        import tsgen
        s = session(with_mav=False, publish_pass='pubsecret')
        g = tsgen.TSGen()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            for dg in g.datagrams(g.stream(60, gop=10, psi_every=20)):
                sock.sendto(dg, ('127.0.0.1', VPORT))
                time.sleep(0.003)
        finally:
            sock.close()
        assert s.proxy.wait_for(r'cannot carry one', timeout=20), s.proxy.log

    def test_password_replaces_the_mavlink_check(self, session, clip):
        """With a password set, a valid MAVLink session is not enough on
        its own -- otherwise setting one would not actually tighten
        anything for a transport that can carry it."""
        s = session(with_mav=True,          # a session IS present
                    publish_pass='pubsecret')
        s.pub = _publish_with('?pw=wrong', clip)
        assert s.proxy.wait_for(r'wrong publish password', timeout=25), \
            s.proxy.log
        assert 'RTSP publisher' not in s.proxy.log


@pytest.mark.integration
class TestSessionOkSlot:
    """VIDEO_SLOT_SESSION_OK: one slot opts back out of password-only.

    A camera speaking RTMP out of its own firmware, and plain MPEG-TS
    over UDP, have nowhere to put a credential. Without this the entry
    faced an all-or-nothing choice: set a password and those streams
    stop, or leave it off and every slot is admitted on its source
    address. The flag is per slot and opt-in, so the streams that can
    present a password still have to.
    """

    def test_udp_is_admitted_by_the_session_on_a_flagged_slot(self, session):
        import socket
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        import tsgen
        s = session(with_mav=True, publish_pass='pubsecret', session_ok=True)
        g = tsgen.TSGen()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            for dg in g.datagrams(g.stream(60, gop=10, psi_every=20)):
                sock.sendto(dg, ('127.0.0.1', VPORT))
                time.sleep(0.003)
        finally:
            sock.close()
        assert s.proxy.wait_for(r'join=ready', timeout=25), s.proxy.log
        assert 'cannot carry one' not in s.proxy.log

    def test_an_unflagged_slot_still_refuses_the_same_publisher(self, session):
        """The property the design turns on: a MAVLink session does not
        become a way past a publish password unless a slot says so."""
        import socket
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        import tsgen
        s = session(with_mav=True, publish_pass='pubsecret', session_ok=False)
        g = tsgen.TSGen()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            for dg in g.datagrams(g.stream(60, gop=10, psi_every=20)):
                sock.sendto(dg, ('127.0.0.1', VPORT))
                time.sleep(0.003)
        finally:
            sock.close()
        assert s.proxy.wait_for(r'cannot carry one', timeout=20), s.proxy.log
        assert 'join=ready' not in s.proxy.log

    def test_a_wrong_password_is_still_refused_on_a_flagged_slot(self,
                                                                session, clip):
        """The fallback is for a publisher that offered nothing. A
        credential that was offered and is wrong must not be silently
        downgraded to address matching, or a typo would look like it
        worked."""
        s = session(with_mav=True, publish_pass='pubsecret', session_ok=True)
        s.pub = _publish_with('?pw=wrong', clip)
        assert s.proxy.wait_for(r'wrong publish password', timeout=25), \
            s.proxy.log
        assert 'RTSP publisher' not in s.proxy.log

    @pytest.mark.parametrize('target', [
        '/cam?mode=x&pw=wrong',
        '/cam?pw=%00wrong',
    ])
    def test_malformed_or_nonfirst_password_never_falls_back(self, session,
                                                              target):
        """Presence is independent of decoded value and query position."""
        s = session(with_mav=True, publish_pass='pubsecret', session_ok=True)
        sock = socket.create_connection(('127.0.0.1', VPORT), 5)
        try:
            req = ('OPTIONS rtsp://127.0.0.1:%d%s RTSP/1.0\r\n'
                   'CSeq: 1\r\n\r\n' % (VPORT, target)).encode()
            sock.sendall(req)
            assert s.proxy.wait_for(r'wrong publish password', timeout=10), \
                s.proxy.log
            assert 'RTSP publisher' not in s.proxy.log
        finally:
            sock.close()

    def test_fragmented_request_line_waits_for_the_credential(self, session):
        """Do not authorise from a TCP prefix before ?pw= has arrived."""
        s = session(with_mav=True, publish_pass='pubsecret', session_ok=True)
        sock = socket.create_connection(('127.0.0.1', VPORT), 5)
        try:
            sock.sendall(('OPTIONS rtsp://127.0.0.1:%d/cam' % VPORT).encode())
            time.sleep(1.0)
            assert 'RTSP publisher' not in s.proxy.log, s.proxy.log
            sock.sendall(b'?pw=wrong RTSP/1.0\r\nCSeq: 1\r\n\r\n')
            assert s.proxy.wait_for(r'wrong publish password', timeout=10), \
                s.proxy.log
            assert 'RTSP publisher' not in s.proxy.log
        finally:
            sock.close()

    def test_wrong_password_on_later_rtsp_request_is_refused(self, session):
        """Session fallback on OPTIONS must not hide a credential later."""
        s = session(with_mav=True, publish_pass='pubsecret', session_ok=True)
        sock = socket.create_connection(('127.0.0.1', VPORT), 5)
        sock.settimeout(10)
        try:
            sock.sendall(
                ('OPTIONS rtsp://127.0.0.1:%d/cam RTSP/1.0\r\n'
                 'CSeq: 1\r\n\r\n' % VPORT).encode())
            assert b'RTSP/1.0 200' in sock.recv(4096)
            sock.sendall(
                ('ANNOUNCE rtsp://127.0.0.1:%d/cam?pw=wrong RTSP/1.0\r\n'
                 'CSeq: 2\r\nContent-Length: 0\r\n\r\n' % VPORT).encode())
            assert s.proxy.wait_for(r'wrong publish password', timeout=10), \
                s.proxy.log
        finally:
            sock.close()

    def test_ambiguous_rtsp_body_length_is_refused(self, session):
        """A framing disagreement must not hide a later credential."""
        s = session(with_mav=True, publish_pass='pubsecret', session_ok=True)
        sock = socket.create_connection(('127.0.0.1', VPORT), 5)
        sock.settimeout(10)
        try:
            sock.sendall(
                ('OPTIONS rtsp://127.0.0.1:%d/cam RTSP/1.0\r\n'
                 'CSeq: 1\r\n\r\n' % VPORT).encode())
            assert b'RTSP/1.0 200' in sock.recv(4096)
            sock.sendall(
                b'ANNOUNCE rtsp://127.0.0.1/cam RTSP/1.0\r\n'
                b'CSeq: 2\r\nContent-Length: 64\r\n'
                b'Content-Length: 0\r\n\r\n')
            assert s.proxy.wait_for(r'RTSP publisher gone', timeout=10), \
                s.proxy.log
        finally:
            sock.close()

    def test_offering_none_falls_back_on_a_flagged_slot(self, session, clip):
        s = session(with_mav=True, publish_pass='pubsecret', session_ok=True)
        s.pub = _publish_with('', clip)
        assert s.proxy.wait_for(r'RTSP publisher', timeout=25), s.proxy.log
        assert 'none was supplied' not in s.proxy.log

    def test_the_flag_is_not_a_blanket_bypass(self, session):
        """With no MAVLink session anywhere it refuses, and says why --
        the flag redirects to path B, it does not skip admission."""
        import socket
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        import tsgen
        s = session(with_mav=False, publish_pass='pubsecret', session_ok=True)
        g = tsgen.TSGen()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            for dg in g.datagrams(g.stream(30, gop=10, psi_every=20)):
                sock.sendto(dg, ('127.0.0.1', VPORT))
                time.sleep(0.003)
        finally:
            sock.close()
        assert s.proxy.wait_for(r'no MAVLink session', timeout=20), s.proxy.log
        assert 'join=ready' not in s.proxy.log


class TestRtspPublisherRestart:
    """Restarting an RTSP publisher, which is the case that mattered.

    A publish password forces RTSP -- plain MPEG-TS/UDP cannot carry a
    credential -- so this is the transport a passworded entry actually
    uses. The publisher-gone handling was added to the UDP idle-release
    path only, and every test for it used a UDP publisher, so RTSP kept
    the original bug: viewers stayed attached across a restart and were
    fed a second stream's timestamps, which stalls a browser player for
    good and then shows up as the viewer being lapped.
    """

    def test_viewer_is_ended_when_the_rtsp_publisher_goes(self, tmp_path,
                                                          clip):
        s = RtspSession(_workdir(tmp_path))
        try:
            s.publish(clip)
            assert s.proxy.wait_for(r'RTSP publisher', timeout=25), s.proxy.log
            assert s.proxy.wait_for(r'join=ready', timeout=30), s.proxy.log

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect(('127.0.0.1', VPORT))
            sock.sendall(b'GET /v1.ts HTTP/1.1\r\nHost: x\r\n\r\n')
            got = sock.recv(65536)
            assert b'200' in got, got[:200]

            s.stop_publisher()
            assert s.proxy.wait_for(r'RTSP publisher gone', timeout=25), \
                s.proxy.log

            # The viewer must be closed, not left attached to a stream
            # that has ended.
            closed = False
            deadline = time.time() + 15
            while time.time() < deadline:
                try:
                    if sock.recv(65536) == b'':
                        closed = True
                        break
                except socket.timeout:
                    break
                except OSError:
                    closed = True
                    break
            sock.close()
            assert closed, 'viewer survived the RTSP publisher going away'
        finally:
            s.stop()

    def test_reason_is_logged_for_rtsp(self, tmp_path, clip):
        s = RtspSession(_workdir(tmp_path))
        try:
            s.publish(clip)
            assert s.proxy.wait_for(r'join=ready', timeout=30), s.proxy.log
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect(('127.0.0.1', VPORT))
            sock.sendall(b'GET /v1.ts HTTP/1.1\r\nHost: x\r\n\r\n')
            sock.recv(65536)
            s.stop_publisher()
            # Match the viewer's drop line, not close_rtsp's own
            # "RTSP publisher gone" -- that one is logged either way and
            # so proves nothing about the viewer being ended.
            assert s.proxy.wait_for(
                r'viewer disconnected .*\(publisher gone\)', timeout=25), \
                s.proxy.log
            sock.close()
        finally:
            s.stop()


class TestRtmpIngest:
    """RTMP publish, with the protocol spoken here rather than spliced.

    ffmpeg's RTMP listener answers FCPublish with a bare command name
    and publish with nothing, which a real camera waits out and then
    hangs up on, so this path terminates RTMP itself and hands the
    backend FLV. The camera can publish over RTMP but not RTSP -- its
    RTSP OPTIONS offers no ANNOUNCE -- so this is the transport the
    direct camera stream actually uses.
    """

    def test_rtmp_publisher_is_ingested(self, tmp_path, clip):
        s = RtspSession(_workdir(tmp_path, rtmp_path='PhoenixFPV/FPV'))
        try:
            s.publish_rtmp(clip)
            assert s.proxy.wait_for(r'RTMP publisher', timeout=25), s.proxy.log
            assert s.proxy.wait_for(r'join=ready', timeout=40), s.proxy.log
        finally:
            s.stop()

    def test_it_is_not_mistaken_for_a_viewer(self, tmp_path, clip):
        """An RTMP connection arrives in a viewer slot, because
        classification only happens once bytes arrive. It must be
        handed to the ingest splice, not answered as a viewer."""
        s = RtspSession(_workdir(tmp_path, rtmp_path='PhoenixFPV/FPV'))
        try:
            s.publish_rtmp(clip)
            assert s.proxy.wait_for(r'RTMP publisher', timeout=25), s.proxy.log
            assert 'viewer disconnected' not in s.proxy.log
        finally:
            s.stop()

    def test_unconfigured_slot_takes_any_path(self, tmp_path, clip):
        """With the protocol parsed here, the app and stream are read
        off the wire rather than declared in advance, so a blank path
        is no longer a misconfiguration -- the slot takes whatever the
        camera publishes."""
        s = RtspSession(_workdir(tmp_path))     # no rtmp_path
        try:
            s.publish_rtmp(clip, path='whatever/stream')
            assert s.proxy.wait_for(r'RTMP publishing whatever/stream',
                                    timeout=25), s.proxy.log
            assert s.proxy.wait_for(r'join=ready', timeout=40), s.proxy.log
        finally:
            s.stop()

    def test_a_configured_path_still_restricts(self, tmp_path, clip):
        """Set, it is an access control: a publisher on another path is
        refused rather than quietly taking the slot."""
        s = RtspSession(_workdir(tmp_path, rtmp_path='PhoenixFPV/FPV'))
        try:
            s.publish_rtmp(clip, path='someone/else')
            assert s.proxy.wait_for(r'slot expects PhoenixFPV/FPV',
                                    timeout=25), s.proxy.log
            assert 'join=ready' not in s.proxy.log
        finally:
            s.stop()

    def test_the_stream_is_recorded(self, tmp_path, clip):
        wd = _workdir(tmp_path, record=True, rtmp_path='PhoenixFPV/FPV')
        s = RtspSession(wd)
        try:
            s.publish_rtmp(clip)
            assert s.proxy.wait_for(r'recording to', timeout=40), s.proxy.log
            s.stop_publisher()
            time.sleep(2)
            segs = list((wd / 'logs' / str(PORT_ENG)).rglob('*.v1.ts'))
            assert segs, 'no recording written'
            assert segs[0].stat().st_size > 10000
        finally:
            s.stop()

    def test_squatters_cannot_deny_publishing(self, tmp_path, clip):
        """An unauthenticated handshake must not own the publisher slot.

        One 0x03 byte classifies a connection as RTMP. If that reserved
        the slot, a peer could take it, wait out the deadline and
        reconnect for ever -- and letting a newcomer evict the incumbent
        only makes it last-arrival-wins, which denies the camera just as
        effectively. Handshakes negotiate side by side instead and the
        slot is awarded on publish, after admission.

        The squatters are kept connected for the whole test, and keep
        arriving after the publisher does, which is what the earlier
        version of this test failed to do.
        """
        wd = _workdir(tmp_path, record=True)
        s = RtspSession(wd)
        squatters = []
        try:
            for _ in range(3):
                c = socket.create_connection(('127.0.0.1', VPORT), 5)
                c.sendall(b'\x03')
                squatters.append(c)
            time.sleep(1.0)
            s.publish_rtmp(clip)
            # Keep squatting while the real publisher negotiates.
            for _ in range(3):
                try:
                    c = socket.create_connection(('127.0.0.1', VPORT), 5)
                    c.sendall(b'\x03')
                    squatters.append(c)
                except OSError:
                    pass
                time.sleep(0.3)
            assert s.proxy.wait_for(r'RTMP publishing', timeout=30), \
                s.proxy.log
            assert s.proxy.wait_for(r'join=ready', timeout=40), s.proxy.log
        finally:
            for c in squatters:
                try:
                    c.close()
                except OSError:
                    pass
            s.stop()

    def test_a_squatter_cannot_evict_a_live_publisher(self, tmp_path, clip):
        """Once publishing, the slot is held against new handshakes."""
        wd = _workdir(tmp_path, record=True)
        s = RtspSession(wd)
        squatters = []
        try:
            s.publish_rtmp(clip)
            assert s.proxy.wait_for(r'join=ready', timeout=40), s.proxy.log
            for _ in range(4):
                c = socket.create_connection(('127.0.0.1', VPORT), 5)
                c.sendall(b'\x03')
                squatters.append(c)
            time.sleep(3)
            assert 'publisher gone' not in s.proxy.log, s.proxy.log
        finally:
            for c in squatters:
                try:
                    c.close()
                except OSError:
                    pass
            s.stop()

    def test_a_silent_flood_does_not_block_classification(self, tmp_path,
                                                          clip):
        """Sockets that never speak must not fill the viewer table.

        A publisher is classified from a viewer slot, so a flood of
        silent connections used to stop one being recognised at all.
        What bounds it is a per-source-address cap, not a reserve: a
        publisher is indistinguishable at accept time, since any
        credential it carries arrives later. Several addresses can still
        fill the table between them -- see the per-IP cap in video.cpp.
        """
        wd = _workdir(tmp_path, record=True)
        s = RtspSession(wd)
        flood = []
        try:
            # From another address: 127/8 is all loopback, so this is a
            # different source to the publisher's 127.0.0.1, which is
            # what the per-address cap keys on.
            for _ in range(40):          # more than the 32-entry table
                try:
                    c = socket.socket()
                    c.bind(('127.0.0.2', 0))
                    c.settimeout(5)
                    c.connect(('127.0.0.1', VPORT))
                    flood.append(c)
                except OSError:
                    break
            time.sleep(1.5)
            s.publish_rtmp(clip)
            assert s.proxy.wait_for(r'RTMP publishing', timeout=30), \
                s.proxy.log
        finally:
            for c in flood:
                try:
                    c.close()
                except OSError:
                    pass
            s.stop()

    def test_publisher_row_reports_its_real_transport(self, tmp_path, clip):
        """connections.tdb must not call an RTMP publisher UDP/MPEG-TS."""
        import conntdb_lib
        wd = _workdir(tmp_path, record=True)
        s = RtspSession(wd)
        try:
            s.publish_rtmp(clip)
            assert s.proxy.wait_for(r'join=ready', timeout=40), s.proxy.log
            time.sleep(6)                # let a tick write the rows
            rows = conntdb_lib.list_active(
                str(wd / conntdb_lib.CONN_FILE), max_age_s=60)
            pub = [r for r in rows
                   if r.role == conntdb_lib.CONN_ROLE_VIDEO_PUB]
            assert pub, 'no video publisher row: %r' % (rows,)
            assert pub[0].transport_name == 'tcp', pub[0].transport_name
            assert pub[0].app_proto == conntdb_lib.CONN_APP_RTMP
        finally:
            s.stop()

    def _flv_of(self, clip, tmp_path):
        """The clip as FLV, so its tags can be replayed over RTMP."""
        out = str(tmp_path / 'src.flv')
        subprocess.run(['ffmpeg', '-v', 'error', '-i', clip, '-c:v', 'copy',
                        '-an', '-f', 'flv', out, '-y'],
                       check=True, capture_output=True)
        return rtmp_client.read_flv_tags(out)

    def test_media_pipelined_with_publish_is_kept(self, tmp_path, clip):
        """A publisher that does not wait for onStatus must still work.

        feed() drains everything buffered, so media in the same segment
        as publish was parsed while publishing_ was still false and
        dropped -- taking the AVC sequence header, and with it the
        parameter sets, so the backend could not open the stream. ffmpeg
        never sends this shape because it waits for onStatus first.
        """
        tags = self._flv_of(clip, tmp_path)
        wd = _workdir(tmp_path, record=True)
        s = RtspSession(wd)
        pub = None
        try:
            pub = rtmp_client.RtmpPublisher('127.0.0.1', VPORT)
            pub.handshake()
            pub.connect()
            # publish + the sequence header + the first frames, one write
            pub.publish(first_tags=tags[:3], pipeline=True)
            for ttype, ts, body in tags[3:]:
                pub.send_tag(ttype, ts, body)
                time.sleep(0.004)
            assert s.proxy.wait_for(r'join=ready', timeout=40), s.proxy.log
        finally:
            if pub:
                pub.close()
            s.stop()

    def test_repeated_script_tags_do_not_kill_the_backend(self, tmp_path,
                                                          clip):
        """A publisher may re-send onMetaData throughout the stream.

        gstreamer's flvmux does exactly that rather than emitting it
        once at the head, and ffmpeg's FLV demuxer surfaces the repeats
        as a second, data stream. The backend mapped every input stream
        into MPEG-TS, which has no encoder for that one, so ffmpeg died
        on "Error selecting an encoder" before writing a byte: the slot
        sat at 0 KiB with the backend apparently running. ffmpeg's own
        FLV has no such stream, which is why publishing with ffmpeg
        worked and the stock gst-launch pipeline never produced a frame.
        """
        meta = (rtmp_client._amf_str('@setDataFrame')
                + rtmp_client._amf_str('onMetaData')
                + rtmp_client._amf_obj({'width': 1280.0, 'height': 720.0,
                                        'videocodecid': 7.0}))
        tags = self._flv_of(clip, tmp_path)
        wd = _workdir(tmp_path, record=True)
        s = RtspSession(wd)
        pub = None
        try:
            pub = rtmp_client.RtmpPublisher('127.0.0.1', VPORT)
            pub.handshake()
            pub.connect()
            pub.publish(first_tags=tags[:1])
            for i, (ttype, ts, body) in enumerate(tags[1:]):
                pub.send_tag(ttype, ts, body)
                # Interleaved the way flvmux does, not just at the head.
                if i % 5 == 0:
                    pub.send_tag(18, ts, meta)
                time.sleep(0.004)
            assert s.proxy.wait_for(r'join=ready', timeout=40), s.proxy.log
        finally:
            if pub:
                pub.close()
            s.stop()

    def test_a_split_chunk_does_not_inflate_timestamps(self, tmp_path, clip):
        """A chunk header split from its payload must not double its delta.

        The parser committed the header before checking the payload was
        buffered, so a short read re-parsed it and applied the timestamp
        delta again. Ordinary TCP segmentation is enough; the effect is
        a recording longer than the media it contains.
        """
        tags = [t for t in self._flv_of(clip, tmp_path) if t[0] == 9]
        wd = _workdir(tmp_path, record=True)
        s = RtspSession(wd)
        pub = None
        try:
            pub = rtmp_client.RtmpPublisher('127.0.0.1', VPORT)
            pub.handshake()
            pub.connect()
            pub.publish(first_tags=tags[:1])
            prev = tags[0][1]
            sent = 0
            # All of them: ffmpeg's default -analyzeduration is 5 s of
            # media, so a shorter burst produces no output at all and
            # the test would fail for the wrong reason.
            for ttype, ts, body in tags[1:]:
                # fmt 1 carries a delta, and every other one is split
                pub.send_tag(ttype, ts - prev, body, fmt=1,
                             split=(sent % 2 == 1))
                prev = ts
                sent += 1
                time.sleep(0.01)
            expected = (prev - tags[0][1]) / 1000.0
            assert s.proxy.wait_for(r'recording to', timeout=40), s.proxy.log
            time.sleep(2)
        finally:
            if pub:
                pub.close()
            s.stop()

        segs = list((wd / 'logs' / str(PORT_ENG)).rglob('*.v1.ts'))
        assert segs, 'no recording written'
        out = subprocess.run(
            ['ffprobe', '-v', 'error', '-select_streams', 'v:0',
             '-show_entries', 'packet=pts_time', '-of', 'csv=p=0',
             str(segs[0])], capture_output=True, text=True).stdout
        pts = [float(r.rstrip(',')) for r in out.strip().splitlines()
               if r.rstrip(',')]
        assert len(pts) > 10, 'too few packets to judge: %d' % len(pts)
        span = pts[-1] - pts[0]
        # Doubling the deltas on every other frame would put the span
        # about 50% over; allow generous slack for the last frame.
        assert span < expected * 1.25 + 0.3, (
            'timestamp span %.2f s for %.2f s of media -- deltas applied '
            'more than once' % (span, expected))

    def test_h264_publisher_gets_the_nal_rewriting_filter(self, tmp_path,
                                                          clip):
        """H.264 over RTMP must go through h264_metadata.

        ffmpeg's own AVCC to Annex-B conversion emits a zero-length NAL
        ahead of every access unit for the real camera's stream, which
        is invalid H.264: Chrome's MP4 parser refuses the sample
        ("Failed to prepare video sample for decode") while Firefox
        plays it regardless. h264_metadata rewrites the units and
        removes them -- measured on camera capture, 8362 empty units to
        none -- but it is codec-specific, so it must be chosen from the
        codec the FLV names rather than applied blind.

        This asserts the choice, not the byte-level outcome: an ffmpeg
        publisher does not reproduce whatever the camera does, so the
        empty units simply do not appear in a synthetic stream (see
        test_no_zero_length_nal_units, which is a general invariant
        rather than a regression guard for this bug).
        """
        s = RtspSession(_workdir(tmp_path))
        try:
            s.publish_rtmp(clip)
            assert s.proxy.wait_for(r'bsf h264_metadata', timeout=25), \
                s.proxy.log
        finally:
            s.stop()

    def test_no_zero_length_nal_units(self, tmp_path, clip):
        """Ingested video must contain no empty NAL units.

        A general invariant, not a regression guard: an ffmpeg publisher
        does not reproduce the camera stream shape that made ffmpeg emit
        them, so this passes with or without the filter that fixes it.
        Kept because empty NAL units are invalid H.264 whatever produces
        them, and only a byte check finds them -- Firefox plays them
        happily and ffprobe reports no error.
        """
        wd = _workdir(tmp_path, record=True)
        s = RtspSession(wd)
        try:
            s.publish_rtmp(clip)
            assert s.proxy.wait_for(r'recording to', timeout=40), s.proxy.log
            assert s.proxy.wait_for(r'join=ready', timeout=40), s.proxy.log
            s.stop_publisher()
            time.sleep(2)
            segs = list((wd / 'logs' / str(PORT_ENG)).rglob('*.v1.ts'))
            assert segs, 'no recording written'
        finally:
            s.stop()

        es = str(tmp_path / 'es.264')
        subprocess.run(['ffmpeg', '-v', 'error', '-i', str(segs[0]),
                        '-c', 'copy', '-f', 'h264', es, '-y'],
                       check=True, capture_output=True)
        data = open(es, 'rb').read()
        starts = []
        i = 0
        while i < len(data) - 3:
            if data[i] == 0 and data[i + 1] == 0:
                if data[i + 2] == 1:
                    starts.append((i, 3))
                    i += 3
                    continue
                if data[i + 2] == 0 and data[i + 3] == 1:
                    starts.append((i, 4))
                    i += 4
                    continue
            i += 1
        empty = 0
        for k, (p, ln) in enumerate(starts):
            end = starts[k + 1][0] if k + 1 < len(starts) else len(data)
            if end - (p + ln) == 0:
                empty += 1
        assert starts, 'no NAL units found'
        assert empty == 0, ('%d of %d NAL units are zero-length'
                            % (empty, len(starts)))

    def test_publish_password_in_the_stream_key(self, tmp_path, clip):
        """Parsing the protocol gives RTMP somewhere to carry a
        credential: a query on the stream name, which is the single
        "stream key" field a camera or OBS offers.
        """
        s = RtspSession(_workdir(tmp_path, publish_pass='secret'),
                        with_mav=False)
        try:
            s.publish_rtmp(clip, path='PhoenixFPV/FPV?pw=secret')
            assert s.proxy.wait_for(r'RTMP publishing PhoenixFPV/FPV',
                                    timeout=25), s.proxy.log
            assert s.proxy.wait_for(r'join=ready', timeout=40), s.proxy.log
        finally:
            s.stop()

    def test_publish_password_refuses_the_wrong_one(self, tmp_path, clip):
        s = RtspSession(_workdir(tmp_path, publish_pass='secret'),
                        with_mav=False)
        try:
            s.publish_rtmp(clip, path='PhoenixFPV/FPV?pw=wrong')
            assert s.proxy.wait_for(r'rejected', timeout=25), s.proxy.log
            assert 'RTMP publishing' not in s.proxy.log
        finally:
            s.stop()

    def test_publish_password_refuses_when_absent(self, tmp_path, clip):
        """No credential at all, with one required: still refused, and
        with the reason that says one was missing rather than wrong."""
        s = RtspSession(_workdir(tmp_path, publish_pass='secret'),
                        with_mav=False)
        try:
            s.publish_rtmp(clip)
            assert s.proxy.wait_for(r'rejected', timeout=25), s.proxy.log
            assert 'RTMP publishing' not in s.proxy.log
        finally:
            s.stop()

    @pytest.mark.parametrize('stream', [
        'FPV?pw=wrong&pw=',
        'FPV?pw=%00wrong',
    ])
    def test_supplied_rtmp_password_cannot_become_absent(self, tmp_path,
                                                         stream):
        """Duplicates and decoded NULs remain supplied wrong credentials.

        This uses the MAVLink fallback so the pre-fix collapse to an empty
        C string would be observable as successful publishing.
        """
        wd = _workdir(tmp_path, publish_pass='secret', session_ok=True)
        s = RtspSession(wd, with_mav=True)
        pub = None
        try:
            pub = rtmp_client.RtmpPublisher(
                '127.0.0.1', VPORT, app='PhoenixFPV', stream=stream)
            pub.handshake()
            pub.connect()
            pub.publish()
            assert s.proxy.wait_for(r'wrong publish password', timeout=15), \
                s.proxy.log
            assert 'RTMP publishing' not in s.proxy.log
        finally:
            if pub:
                pub.close()
            s.stop()

    @pytest.mark.parametrize('source', ['duplicate_app', 'fcpublish'])
    def test_earlier_rtmp_password_cannot_be_erased(self, tmp_path, source):
        """Every pre-publish credential source preserves explicit presence."""
        wd = _workdir(tmp_path, publish_pass='secret', session_ok=True)
        s = RtspSession(wd, with_mav=True)
        pub = None
        try:
            pub = rtmp_client.RtmpPublisher(
                '127.0.0.1', VPORT, app='PhoenixFPV', stream='FPV')
            pub.handshake()
            if source == 'duplicate_app':
                pub.connect(properties=[
                    ('app', 'PhoenixFPV?pw=wrong'),
                    ('app', 'PhoenixFPV'),
                    ('tcUrl', 'rtmp://127.0.0.1/PhoenixFPV'),
                ])
                assert s.proxy.wait_for(r'duplicate connect property',
                                        timeout=15), s.proxy.log
            else:
                pub.connect()
                pub.fcpublish('FPV?pw=wrong')
                pub.publish()
                assert s.proxy.wait_for(r'wrong publish password',
                                        timeout=15), s.proxy.log
            assert 'RTMP publishing' not in s.proxy.log
        finally:
            if pub:
                pub.close()
            s.stop()

    def test_no_orphan_backend_after_the_rtmp_publisher_leaves(
            self, tmp_path, clip):
        s = RtspSession(_workdir(tmp_path, rtmp_path='PhoenixFPV/FPV'))
        try:
            s.publish_rtmp(clip)
            assert s.proxy.wait_for(r'RTMP publisher', timeout=25), s.proxy.log
            s.stop_publisher()
            assert s.proxy.wait_for(r'publisher gone', timeout=30), s.proxy.log
        finally:
            s.stop()
        assert _settle(), ('a backend ffmpeg outlived the session -- %s'
                           % _settle_state())

    def test_restart_ends_the_stream_for_viewers(self, tmp_path, clip):
        """Same contract as RTSP: a new publisher is a new stream, so
        viewers are ended rather than spliced onto it."""
        s = RtspSession(_workdir(tmp_path, rtmp_path='PhoenixFPV/FPV'))
        try:
            s.publish_rtmp(clip)
            assert s.proxy.wait_for(r'join=ready', timeout=40), s.proxy.log
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect(('127.0.0.1', VPORT))
            sock.sendall(b'GET /v1.ts HTTP/1.1\r\nHost: x\r\n\r\n')
            assert b'200' in sock.recv(65536)
            s.stop_publisher()
            assert s.proxy.wait_for(
                r'viewer disconnected .*\(publisher gone\)', timeout=30), \
                s.proxy.log
            sock.close()
        finally:
            s.stop()


class TestSpliceBackpressure:
    """The relay must never wait inside the event loop.

    It is the only thread: it also drains ffmpeg's stdout, so sleeping
    on a short write to the backend stops that draining, ffmpeg's stdout
    pipe fills, ffmpeg stops reading its input, and neither side moves
    again. Only an unpaced publisher reaches that state.
    """

    def test_unpaced_publisher_still_produces_media(self, tmp_path, clip):
        s = RtspSession(_workdir(tmp_path, rtmp_path='PhoenixFPV/FPV'))
        try:
            s.publish_rtmp_burst(clip)
            assert s.proxy.wait_for(r'RTMP publisher', timeout=25), s.proxy.log
            assert s.proxy.wait_for(r'join=ready', timeout=60), s.proxy.log
        finally:
            s.stop()

    def test_unpaced_publisher_keeps_flowing(self, tmp_path, clip):
        """join=ready once is not enough -- a deadlock can set in after
        the first burst. Require the byte count to keep climbing."""
        s = RtspSession(_workdir(tmp_path, rtmp_path='PhoenixFPV/FPV'))
        try:
            s.publish_rtmp_burst(clip)
            assert s.proxy.wait_for(r'join=ready', timeout=60), s.proxy.log
            first = _last_kib(s.proxy.log)
            deadline = time.time() + 30
            while time.time() < deadline:
                time.sleep(2)
                if _last_kib(s.proxy.log) > first:
                    return
            raise AssertionError(
                'ingest stalled at %d KiB -- the splice is wedged' % first)
        finally:
            s.stop()

    def test_a_viewer_that_never_reads_does_not_wedge_ingest(self, tmp_path,
                                                             clip):
        """The other direction of the same hazard."""
        s = RtspSession(_workdir(tmp_path, rtmp_path='PhoenixFPV/FPV'))
        sock = None
        try:
            s.publish_rtmp_burst(clip)
            assert s.proxy.wait_for(r'join=ready', timeout=60), s.proxy.log
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect(('127.0.0.1', VPORT))
            sock.sendall(b'GET /v1.ts HTTP/1.1\r\nHost: x\r\n\r\n')
            sock.recv(4096)          # then deliberately stop reading
            first = _last_kib(s.proxy.log)
            deadline = time.time() + 30
            while time.time() < deadline:
                time.sleep(2)
                if _last_kib(s.proxy.log) > first:
                    return
            raise AssertionError(
                'ingest stalled at %d KiB behind a silent viewer' % first)
        finally:
            if sock:
                sock.close()
            s.stop()


def _last_kib(log):
    """KiB from the most recent stats line, or 0."""
    hits = re.findall(r'stats: (\d+) KiB', log)
    return int(hits[-1]) if hits else 0
