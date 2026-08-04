"""The independent video child: lifecycle and publisher admission.

The defining property is independence from the MAVLink process tree.
The MAVLink child idles out after 10 s, and video has to survive that;
and with a publish password video has to work with no MAVLink session
at all. So the video child is a long-lived direct child of the parent,
and it -- not the parent -- binds the video ports, which makes "video
only exists when enabled" structural rather than a policy check.

Phase 1 has no media path: bytes are admitted, counted and discarded.
These tests are about the process model and the admission decision.
"""
import os
import re
import socket
import subprocess
import sys
import threading
import time

import pytest

_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

import conntdb_lib  # noqa: E402
import keydb_lib  # noqa: E402

SUPPORTPROXY_BIN = os.path.join(_REPO_ROOT, 'supportproxy')

_w = os.environ.get('PYTEST_XDIST_WORKER', 'gw0')
_W = int(_w[2:]) if _w.startswith('gw') else 0
PORT_USER = 18200 + _W * 8
PORT_ENG = 18201 + _W * 8
VPORT = 18202 + _W * 8
VPORT2 = 18203 + _W * 8

PASSPHRASE = 'vidchild'

os.environ.setdefault('MAVLINK_DIALECT', 'all')
os.environ.setdefault('MAVLINK20', '1')


def _make_workdir(tmp_path, flags=('video',), vports=(VPORT,), **kw):
    p = tmp_path / 'work'
    p.mkdir()
    db = keydb_lib.init_db(str(p / 'keys.tdb'))
    db.transaction_start()
    keydb_lib.add_entry(db, PORT_USER, PORT_ENG, 'vid', PASSPHRASE)
    for f in flags:
        keydb_lib.set_flag(db, PORT_ENG, f)
    if vports:
        keydb_lib.set_video_ports(db, PORT_ENG, list(vports))
    if kw.get('publish_pass'):
        keydb_lib.set_video_publish_pass(db, PORT_ENG, kw['publish_pass'])
    if kw.get('grace') is not None:
        keydb_lib.set_video_grace(db, PORT_ENG, kw['grace'])
    db.transaction_prepare_commit()
    db.transaction_commit()
    db.close()
    return p


class Proxy:
    def __init__(self, workdir):
        self.workdir = workdir
        self.proc = subprocess.Popen(
            [SUPPORTPROXY_BIN], cwd=str(workdir), env=os.environ.copy(),
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            bufsize=1, text=True)
        self.lines = []
        self._ready = threading.Event()
        self._t = threading.Thread(target=self._drain, daemon=True)
        self._t.start()
        if not self._ready.wait(timeout=10):
            self.stop()
            raise RuntimeError('proxy did not start: %r' % (self.lines,))

    def _drain(self):
        for line in iter(self.proc.stdout.readline, ''):
            self.lines.append(line)
            if 'Added port %d/%d' % (PORT_USER, PORT_ENG) in line:
                self._ready.set()
        self.proc.stdout.close()

    @property
    def log(self):
        return ''.join(self.lines)

    def wait_for(self, pattern, timeout=15):
        deadline = time.time() + timeout
        while time.time() < deadline:
            if re.search(pattern, self.log):
                return True
            time.sleep(0.2)
        return False

    def children(self):
        out = subprocess.run(['pgrep', '-P', str(self.proc.pid)],
                             capture_output=True, text=True).stdout
        return [int(x) for x in out.split()]

    def video_pid(self):
        """The child holding the video port, identified by its fd count."""
        for pid in self.children():
            try:
                links = os.listdir('/proc/%d/fd' % pid)
            except OSError:
                continue
            socks = 0
            for fd in links:
                try:
                    if 'socket' in os.readlink('/proc/%d/fd/%s' % (pid, fd)):
                        socks += 1
                except OSError:
                    pass
            # the cleanup child closes every socket; the video child
            # holds two per configured slot
            if socks > 0:
                return pid
        return None

    def stop(self):
        self.proc.terminate()
        try:
            self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait(timeout=5)
        self._t.join(timeout=2)


@pytest.fixture
def proxy(tmp_path):
    made = {}

    def _make(**kw):
        wd = _make_workdir(tmp_path, **kw)
        made['p'] = Proxy(wd)
        made['wd'] = wd
        return made['p']

    yield _make
    if 'p' in made:
        made['p'].stop()


def _port_bound(port, proto='udp'):
    """True if anything is listening on `port`, read from /proc/net."""
    path = '/proc/net/' + ('udp' if proto == 'udp' else 'tcp')
    want = '%04X' % port
    with open(path) as f:
        next(f)
        for line in f:
            local = line.split()[1]
            if local.split(':')[1].upper() == want:
                return True
    return False


class Publisher:
    """A UDP publisher on ONE socket.

    Reusing the socket matters: the proxy latches a publisher by
    (address, port), so a fresh socket per burst would present a new
    source port each time and never take the established-publisher fast
    path -- which is not how a real publisher behaves.
    """

    def __init__(self, port):
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def send(self, n=3):
        for _ in range(n):
            self.sock.sendto(b'\x47' + b'\x00' * 187, ('127.0.0.1', self.port))
            time.sleep(0.05)

    def close(self):
        self.sock.close()


def _send_ts(port, n=3):
    pub = Publisher(port)
    try:
        pub.send(n)
    finally:
        pub.close()


class _Mav:
    """A MAVLink user-side session on port1, driven in a thread."""

    def __init__(self, signed=False):
        from pymavlink import mavutil
        self.mavutil = mavutil
        self.conn = mavutil.mavlink_connection(
            'udpout:127.0.0.1:%d' % PORT_USER, source_system=1,
            source_component=1, use_native=False)
        if signed:
            import hashlib
            self.conn.setup_signing(
                hashlib.sha256(PASSPHRASE.encode()).digest(),
                sign_outgoing=True)
        self._stop = threading.Event()
        self._t = threading.Thread(target=self._run, daemon=True)
        self._t.start()

    def _run(self):
        m = self.mavutil.mavlink
        while not self._stop.is_set():
            try:
                self.conn.mav.heartbeat_send(
                    m.MAV_TYPE_QUADROTOR, m.MAV_AUTOPILOT_ARDUPILOTMEGA,
                    0, 0, m.MAV_STATE_ACTIVE)
            except Exception:
                pass
            time.sleep(0.3)

    def stop(self):
        self._stop.set()
        self._t.join(timeout=2)
        try:
            self.conn.close()
        except Exception:
            pass


def _video_rows(workdir):
    path = conntdb_lib.conn_path_for(str(workdir / 'keys.tdb'))
    return [c for c in conntdb_lib.list_active(path, max_age_s=3600)
            if c.is_video]


def _mav_rows(workdir):
    path = conntdb_lib.conn_path_for(str(workdir / 'keys.tdb'))
    return [c for c in conntdb_lib.list_active(path, max_age_s=3600)
            if not c.is_video]


@pytest.mark.integration
class TestVideoChildLifecycle:
    def test_port_bound_with_no_mavlink_session(self, proxy):
        """The headline property: video does not wait on MAVLink."""
        p = proxy()
        assert p.wait_for(r'video slot 0 listening'), p.log
        assert _port_bound(VPORT, 'udp'), 'video UDP port not bound'
        assert _port_bound(VPORT, 'tcp'), 'video TCP port not bound'

    def test_video_child_holds_no_mavlink_fds(self, proxy):
        """Being a child of the parent, it never inherits session fds."""
        p = proxy(vports=(VPORT,))
        assert p.wait_for(r'video child \d+ ready'), p.log
        vpid = p.video_pid()
        assert vpid is not None, p.log
        socks = [os.readlink('/proc/%d/fd/%s' % (vpid, fd))
                 for fd in os.listdir('/proc/%d/fd' % vpid)]
        n_socks = len([s for s in socks if 'socket' in s])
        # exactly one UDP + one TCP listener for the single slot
        assert n_socks == 2, 'expected 2 sockets, got %d: %r' % (n_socks, socks)

    def test_disable_video_stops_child_and_frees_port(self, proxy, tmp_path):
        p = proxy()
        assert p.wait_for(r'video child \d+ ready'), p.log
        assert _port_bound(VPORT, 'udp')

        db = keydb_lib.open_db(str(tmp_path / 'work' / 'keys.tdb'))
        db.transaction_start()
        keydb_lib.clear_flag(db, PORT_ENG, 'video')
        db.transaction_prepare_commit(); db.transaction_commit(); db.close()

        assert p.wait_for(r'video child \d+ stopping \(video disabled\)'), p.log
        deadline = time.time() + 10
        while time.time() < deadline and _port_bound(VPORT, 'udp'):
            time.sleep(0.2)
        assert not _port_bound(VPORT, 'udp'), 'port still bound after disable'

    def test_killed_video_child_is_respawned(self, proxy):
        p = proxy()
        assert p.wait_for(r'video child \d+ ready'), p.log
        first = p.video_pid()
        assert first is not None
        os.kill(first, 9)
        assert p.wait_for(r'video child %d exited' % first), p.log
        deadline = time.time() + 20
        second = None
        while time.time() < deadline:
            second = p.video_pid()
            if second is not None and second != first:
                break
            time.sleep(0.3)
        assert second is not None and second != first, \
            'video child not respawned:\n%s' % p.log

    def test_parent_exit_leaves_no_orphan(self, proxy):
        p = proxy()
        assert p.wait_for(r'video child \d+ ready'), p.log
        vpid = p.video_pid()
        p.stop()
        deadline = time.time() + 10
        while time.time() < deadline and os.path.exists('/proc/%d' % vpid):
            time.sleep(0.2)
        assert not os.path.exists('/proc/%d' % vpid), \
            'video child %d outlived the parent' % vpid

    def test_port_change_rebinds(self, proxy, tmp_path):
        p = proxy(vports=(VPORT,))
        assert p.wait_for(r'video child \d+ ready'), p.log

        db = keydb_lib.open_db(str(tmp_path / 'work' / 'keys.tdb'))
        db.transaction_start()
        keydb_lib.set_video_ports(db, PORT_ENG, [VPORT2])
        db.transaction_prepare_commit(); db.transaction_commit(); db.close()

        assert p.wait_for(r'video config changed'), p.log
        deadline = time.time() + 20
        while time.time() < deadline:
            if _port_bound(VPORT2, 'udp') and not _port_bound(VPORT, 'udp'):
                break
            time.sleep(0.3)
        assert _port_bound(VPORT2, 'udp'), 'new port not bound:\n%s' % p.log
        assert not _port_bound(VPORT, 'udp'), 'old port still bound'


@pytest.mark.integration
class TestVideoAdmission:
    def test_publish_rejected_without_mavlink(self, proxy):
        p = proxy()
        assert p.wait_for(r'video slot 0 listening'), p.log
        _send_ts(VPORT)
        assert p.wait_for(r'rejected .*no MAVLink session'), p.log

    def test_publish_accepted_with_mavlink_from_same_ip(self, proxy):
        p = proxy()
        assert p.wait_for(r'video slot 0 listening'), p.log
        mav = _Mav()
        try:
            assert p.wait_for(r'have UDP conn1'), p.log
            time.sleep(1.0)          # let the session's ConnEntry land
            for _ in range(10):
                _send_ts(VPORT, n=2)
                if re.search(r'video slot 0 publisher', p.log):
                    break
                time.sleep(0.5)
            assert re.search(r'video slot 0 publisher', p.log), p.log
        finally:
            mav.stop()

    def test_video_survives_mavlink_going_away(self, proxy):
        """The whole point of decoupling: a telemetry dropout must not
        revoke a publisher that is already streaming."""
        p = proxy(grace=60)
        assert p.wait_for(r'video slot 0 listening'), p.log
        pub = Publisher(VPORT)
        mav = _Mav()
        try:
            assert p.wait_for(r'have UDP conn1'), p.log
            time.sleep(1.0)
            for _ in range(10):
                pub.send(2)
                if re.search(r'video slot 0 publisher', p.log):
                    break
                time.sleep(0.5)
            assert re.search(r'video slot 0 publisher', p.log), p.log
        finally:
            mav.stop()

        # MAVLink is gone. Keep publishing across the session child's
        # 10 s idle-out -- a real publisher does not stop just because
        # telemetry dropped, and going silent here would trip the
        # separate publisher-idle release and test the wrong thing.
        try:
            marker = len(p.lines)
            deadline = time.time() + 16
            while time.time() < deadline:
                pub.send(2)
                time.sleep(0.4)

            assert p.video_pid() is not None, \
                'video child died with the MAVLink session:\n%s' % p.log
            later = ''.join(p.lines[marker:])
            assert 'rejected' not in later, \
                'publisher revoked after MAVLink went away:\n%s' % later
        finally:
            pub.close()

    def test_publisher_can_start_during_a_mavlink_outage(self, proxy):
        """Within the grace window, a publisher may start with the
        MAVLink session already gone.

        This is what the grace window is for, and it only works because
        the last-known-good session outlives its connections.tdb row --
        the row is deleted as soon as the session child exits.
        """
        p = proxy(grace=120)
        assert p.wait_for(r'video slot 0 listening'), p.log
        mav = _Mav()
        try:
            assert p.wait_for(r'have UDP conn1'), p.log
            time.sleep(1.5)      # let the session's ConnEntry be written
        finally:
            mav.stop()

        # Wait out the session child so its row is gone entirely.
        assert p.wait_for(r'Child \d+ exited', timeout=25), p.log
        time.sleep(1.0)

        marker = len(p.lines)
        for _ in range(10):
            _send_ts(VPORT, n=2)
            if re.search(r'video slot 0 publisher', ''.join(p.lines[marker:])):
                break
            time.sleep(0.5)
        later = ''.join(p.lines[marker:])
        assert 'video slot 0 publisher' in later, \
            'publisher refused inside the grace window:\n%s' % later

    def test_publish_password_cannot_be_met_over_plain_udp(self, proxy):
        """Path A takes precedence, and plain MPEG-TS/UDP carries no
        credential -- so a passworded entry refuses UDP publish even
        with a live MAVLink session from the same address."""
        p = proxy(publish_pass='pubpw')
        assert p.wait_for(r'video slot 0 listening'), p.log
        mav = _Mav()
        try:
            assert p.wait_for(r'have UDP conn1'), p.log
            time.sleep(1.0)
            _send_ts(VPORT, n=4)
            # The reason is specifically "this transport cannot carry a
            # password", not "wrong password" -- a udpsink never sent
            # one, and saying "wrong" would send an operator looking for
            # a typo that isn't there.
            assert p.wait_for(r'rejected .*cannot carry one'), p.log
            assert 'video slot 0 publisher' not in p.log
        finally:
            mav.stop()

    def test_bidi_entry_requires_authenticated_session(self, proxy):
        """An unsigned session on a bidi entry must not authorise video."""
        p = proxy(flags=('video', 'bidi_sign'))
        assert p.wait_for(r'video slot 0 listening'), p.log
        mav = _Mav(signed=False)      # unsigned: never authenticates
        try:
            time.sleep(2.0)
            _send_ts(VPORT, n=4)
            assert p.wait_for(r'rejected'), p.log
            assert 'video slot 0 publisher' not in p.log, \
                'unsigned session authorised video on a bidi entry:\n%s' % p.log
        finally:
            mav.stop()


@pytest.mark.integration
class TestVideoConnRows:
    def test_publisher_row_written_in_video_index_range(self, proxy, tmp_path):
        p = proxy()
        assert p.wait_for(r'video slot 0 listening'), p.log
        mav = _Mav()
        try:
            assert p.wait_for(r'have UDP conn1'), p.log
            time.sleep(1.0)
            for _ in range(10):
                _send_ts(VPORT, n=2)
                if re.search(r'video slot 0 publisher', p.log):
                    break
                time.sleep(0.5)
            assert re.search(r'video slot 0 publisher', p.log), p.log

            wd = tmp_path / 'work'
            deadline = time.time() + 15
            rows = []
            while time.time() < deadline:
                rows = _video_rows(wd)
                if rows:
                    break
                time.sleep(0.5)
            assert rows, 'no video ConnEntry written:\n%s' % p.log
            r = rows[0]
            assert r.conn_index >= conntdb_lib.VIDEO_CONN_INDEX_BASE
            assert r.role == conntdb_lib.CONN_ROLE_VIDEO_PUB
            assert r.stream_idx == 0
            assert r.port2 == PORT_ENG

            # and the MAVLink row must still be there: the two writers
            # each clear only their own index range
            assert _mav_rows(wd), \
                'video snapshot erased the MAVLink rows:\n%s' % p.log
        finally:
            mav.stop()
