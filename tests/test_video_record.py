"""Video segment recording and the partitioned disk quotas.

The guarantee worth testing hardest is that video can never evict
telemetry. Video is orders of magnitude larger per second than a tlog,
so a single mtime-sorted pool would let a few minutes of recording
delete a whole flight's telemetry. The two budgets are enforced
independently, and this file pins that down from both directions.
"""
import os
import re
import subprocess
import sys
import time

import pytest

_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import keydb_lib  # noqa: E402
import tsgen  # noqa: E402
from test_video_child import (Proxy, Publisher, _Mav, PORT_ENG,  # noqa: E402
                              PORT_USER, PASSPHRASE, VPORT)


def _workdir(tmp_path, record=True, quota_mb=0, env=None):
    p = tmp_path / 'work'
    p.mkdir()
    db = keydb_lib.init_db(str(p / 'keys.tdb'))
    db.transaction_start()
    keydb_lib.add_entry(db, PORT_USER, PORT_ENG, 'vid', PASSPHRASE)
    keydb_lib.set_flag(db, PORT_ENG, 'video')
    keydb_lib.set_video_ports(db, PORT_ENG, [VPORT])
    if record:
        keydb_lib.set_video_slot_flag(db, PORT_ENG, 0, 'record')
    if quota_mb:
        keydb_lib.set_video_quota(db, PORT_ENG, quota_mb)
    db.transaction_prepare_commit()
    db.transaction_commit()
    db.close()
    return p


def _today_dir(workdir):
    d = workdir / 'logs' / str(PORT_ENG) / time.strftime('%Y-%m-%d',
                                                         time.localtime())
    return d


def _segments(workdir):
    d = _today_dir(workdir)
    if not d.is_dir():
        return []
    return sorted([f for f in d.iterdir() if f.name.endswith('.ts')],
                  key=lambda f: f.name)


def _telem(workdir):
    d = _today_dir(workdir)
    if not d.is_dir():
        return []
    return sorted([f for f in d.iterdir()
                   if f.suffix in ('.tlog', '.bin')], key=lambda f: f.name)


class Session:
    """A proxy with a MAVLink session and an authorised video publisher."""

    def __init__(self, workdir, env=None):
        self.workdir = workdir
        environ = os.environ.copy()
        if env:
            environ.update(env)
        self._env_backup = os.environ.copy()
        os.environ.update(env or {})
        try:
            self.proxy = Proxy(workdir)
        finally:
            os.environ.clear()
            os.environ.update(self._env_backup)
        assert self.proxy.wait_for(r'video slot 0 listening'), self.proxy.log
        self.mav = _Mav()
        assert self.proxy.wait_for(r'have UDP conn1'), self.proxy.log
        time.sleep(1.2)
        self.pub = Publisher(VPORT)

    def publish(self, data, pause=0.003):
        for dg in tsgen.TSGen().datagrams(data):
            self.pub.sock.sendto(dg, ('127.0.0.1', VPORT))
            time.sleep(pause)

    def stop(self):
        try:
            self.pub.close()
        except Exception:
            pass
        self.mav.stop()
        self.proxy.stop()


@pytest.fixture
def session(tmp_path):
    made = {}

    def _start(env=None, **kw):
        wd = _workdir(tmp_path, **kw)
        made['s'] = Session(wd, env=env)
        return made['s']

    yield _start
    if 's' in made:
        made['s'].stop()


@pytest.mark.integration
class TestRecording:
    def test_segment_is_written_and_byte_exact(self, session):
        """The recording must be the publisher's own bytes.

        Not merely 'a valid TS file': fan-out and recording both promise
        the original stream, so the file has to appear verbatim in what
        was sent.
        """
        s = session()
        g = tsgen.TSGen()
        data = g.stream(400, gop=10, psi_every=20)
        sent = b''.join(g.datagrams(data))
        s.publish(data)

        deadline = time.time() + 20
        while time.time() < deadline and not _segments(s.workdir):
            time.sleep(0.5)
        segs = _segments(s.workdir)
        assert segs, 'no segment written:\n%s' % s.proxy.log

        # let the writer flush, then compare
        time.sleep(2)
        blob = segs[0].read_bytes()
        assert len(blob) > 0
        assert blob[0] == 0x47, 'segment does not start with a sync byte'
        assert len(blob) % 188 == 0, 'segment is not a whole number of packets'
        assert blob in sent, \
            'recording is not a verbatim span of what was published'

    def test_segment_name_and_slot(self, session):
        s = session()
        s.publish(tsgen.TSGen().stream(150, gop=10, psi_every=20))
        deadline = time.time() + 20
        while time.time() < deadline and not _segments(s.workdir):
            time.sleep(0.5)
        segs = _segments(s.workdir)
        assert segs, s.proxy.log
        assert re.match(r'^\d{4}_\d{2}_\d{2}_\d{2}:\d{2}:\d{2}(-\d+)?\.v1\.ts$',
                        segs[0].name), segs[0].name

    def test_no_recording_when_slot_flag_is_off(self, session):
        s = session(record=False)
        s.publish(tsgen.TSGen().stream(150, gop=10, psi_every=20))
        time.sleep(3)
        assert not _segments(s.workdir), \
            'recorded with the record flag off: %r' % (_segments(s.workdir),)

    def test_rotation_produces_multiple_segments(self, session):
        s = session(env={'SUPPORTPROXY_VIDEO_SEGMENT_SECONDS': '2'})
        g = tsgen.TSGen()
        for _ in range(6):
            s.publish(g.stream(120, gop=10, psi_every=20), pause=0.01)
            time.sleep(0.5)

        deadline = time.time() + 20
        while time.time() < deadline and len(_segments(s.workdir)) < 2:
            time.sleep(0.5)
        segs = _segments(s.workdir)
        assert len(segs) >= 2, \
            'expected rotation into several segments, got %r\n%s' \
            % ([f.name for f in segs], s.proxy.log)
        # every segment must be independently usable
        for f in segs:
            blob = f.read_bytes()
            if not blob:
                continue
            assert blob[0] == 0x47, '%s does not start at a packet' % f.name
            assert len(blob) % 188 == 0, '%s is not packet-aligned' % f.name

    def test_stream_without_keyframes_still_rotates(self, session):
        """A muxer that never signals a random access point must not
        produce an unbounded segment -- the quota pass can never evict
        the file currently being written."""
        s = session(env={'SUPPORTPROXY_VIDEO_SEGMENT_SECONDS': '2'})
        g = tsgen.TSGen()
        out = bytearray()
        for i in range(600):
            if i % 20 == 0:
                out += g.pat()
                out += g.pmt()
            out += g.video(key=False)      # never a keyframe
        data = bytes(out)
        deadline = time.time() + 60
        while time.time() < deadline and len(_segments(s.workdir)) < 2:
            s.publish(data, pause=0.004)
            time.sleep(0.5)
        segs = _segments(s.workdir)
        assert len(segs) >= 2, \
            'no rotation without keyframes (forced cut missing):\n%s' \
            % s.proxy.log
        assert 'forced cut' in s.proxy.log, \
            'expected a forced cut to be logged:\n%s' % s.proxy.log


@pytest.mark.integration
class TestQuotaPartition:
    def test_video_quota_never_evicts_telemetry(self, session, tmp_path):
        """The headline guarantee.

        A tiny video budget plus a fast cleanup interval must delete old
        .ts segments and leave seeded .tlog/.bin files completely alone,
        however old they are.
        """
        s = session(env={
            'SUPPORTPROXY_PORT2_VIDEO_QUOTA_BYTES': str(256 * 1024),
            'SUPPORTPROXY_VIDEO_SEGMENT_SECONDS': '1',
            'SUPPORTPROXY_CLEANUP_INTERVAL': '0.5',
            # Without shrinking the grace, every segment a short test
            # writes is still "live" and none is evictable -- the quota
            # pass would correctly free nothing.
            'SUPPORTPROXY_ACTIVE_FILE_GRACE': '1',
        })
        # seed telemetry files that are old enough to be quota candidates
        d = _today_dir(s.workdir)
        d.mkdir(parents=True, exist_ok=True)
        old = time.time() - 3600
        seeded = []
        for name in ('2020_01_01_00:00:00.tlog', '2020_01_01_00:00:00.bin'):
            f = d / name
            f.write_bytes(b'\x00' * 4096)
            os.utime(f, (old, old))
            seeded.append(f)

        g = tsgen.TSGen()
        deadline = time.time() + 45
        while time.time() < deadline:
            s.publish(g.stream(300, gop=10, psi_every=20), pause=0.002)
            time.sleep(0.5)
            if re.search(r'removed .* for video quota', s.proxy.log):
                break

        assert re.search(r'removed .* for video quota', s.proxy.log), \
            'video quota never fired:\n%s' % s.proxy.log[-4000:]
        for f in seeded:
            assert f.exists(), \
                '%s was evicted by the video quota:\n%s' % (f.name,
                                                            s.proxy.log[-4000:])
        assert 'for telemetry quota' not in s.proxy.log, \
            'telemetry quota pass ran on video pressure:\n%s' % s.proxy.log

    def test_per_entry_quota_overrides_the_default(self, session, tmp_path):
        """KeyEntry.video_quota_mb must win over the server default."""
        s = session(quota_mb=1, env={          # 1 MB
            'SUPPORTPROXY_PORT2_VIDEO_QUOTA_BYTES': str(4 * 1024 * 1024 * 1024),
            'SUPPORTPROXY_VIDEO_SEGMENT_SECONDS': '1',
            'SUPPORTPROXY_CLEANUP_INTERVAL': '0.5',
            'SUPPORTPROXY_ACTIVE_FILE_GRACE': '1',
        })
        g = tsgen.TSGen()
        deadline = time.time() + 45
        while time.time() < deadline:
            s.publish(g.stream(300, gop=10, psi_every=20), pause=0.002)
            time.sleep(0.5)
            if re.search(r'removed .* for video quota', s.proxy.log):
                break
        assert re.search(r'removed .* for video quota', s.proxy.log), \
            'per-entry quota did not override the larger default:\n%s' \
            % s.proxy.log[-4000:]
