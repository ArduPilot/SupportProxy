"""MPEG-TS/UDP ingest and the join-point scanner, end to end.

Phase 2 has no viewers yet, so the scanner's conclusions are observed
through the per-tick stats line. What matters here is that a real
datagram stream is accepted, parsed into a program, and reaches the
point where a viewer *could* join -- and that malformed input is
counted and dropped rather than half-parsed.
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

import tsgen  # noqa: E402
from test_video_child import (Proxy, Publisher, _Mav, _make_workdir,  # noqa: E402
                              _port_bound, VPORT)

SUPPORTPROXY_BIN = os.path.join(_REPO_ROOT, 'supportproxy')

STATS_RE = re.compile(
    r'video slot (\d+) stats: (\d+) KiB, (\d+) pkts, pat=(\d+) pmt=(\d+) '
    r'rai=(\d+) cc_err=(\d+) crc_err=(\d+) bad_dgram=(\d+) '
    r'vpid=0x([0-9a-f]+) stype=0x([0-9a-f]+) join=(\w+)')


def last_stats(proxy):
    """Parse the most recent stats line, or None."""
    m = None
    for line in proxy.lines:
        found = STATS_RE.search(line)
        if found:
            m = found
    if m is None:
        return None
    return {
        'slot': int(m.group(1)), 'kib': int(m.group(2)),
        'packets': int(m.group(3)), 'pat': int(m.group(4)),
        'pmt': int(m.group(5)), 'rai': int(m.group(6)),
        'cc_err': int(m.group(7)), 'crc_err': int(m.group(8)),
        'bad_dgram': int(m.group(9)), 'vpid': int(m.group(10), 16),
        'stype': int(m.group(11), 16), 'join': m.group(12),
    }


def wait_stats(proxy, predicate, timeout=20):
    deadline = time.time() + timeout
    while time.time() < deadline:
        st = last_stats(proxy)
        if st is not None and predicate(st):
            return st
        time.sleep(0.5)
    return last_stats(proxy)


@pytest.fixture
def running(tmp_path):
    """A proxy with video enabled and an authorised publisher."""
    made = {}

    def _start(**kw):
        wd = _make_workdir(tmp_path, **kw)
        p = Proxy(wd)
        made['p'] = p
        assert p.wait_for(r'video slot 0 listening'), p.log
        mav = _Mav()
        made['mav'] = mav
        assert p.wait_for(r'have UDP conn1'), p.log
        time.sleep(1.2)          # let the session's ConnEntry land
        return p

    yield _start
    if 'mav' in made:
        made['mav'].stop()
    if 'p' in made:
        made['p'].stop()


def _publish(port, data, chunk_pause=0.004):
    """Send a stream as 1316-byte datagrams from one socket."""
    pub = Publisher(port)
    try:
        for dg in tsgen.TSGen().datagrams(data):
            pub.sock.sendto(dg, ('127.0.0.1', port))
            time.sleep(chunk_pause)
    finally:
        pub.close()
    return pub


@pytest.mark.integration
class TestTSIngest:
    def test_stream_is_parsed_and_joinable(self, running):
        p = running()
        g = tsgen.TSGen()
        data = g.stream(400, gop=10, psi_every=20)
        _publish(VPORT, data)

        st = wait_stats(p, lambda s: s['join'] == 'ready')
        assert st is not None, 'no stats line at all:\n%s' % p.log
        assert st['join'] == 'ready', \
            'scanner never reached a joinable state: %r\n%s' % (st, p.log)
        assert st['pat'] > 0 and st['pmt'] > 0, st
        assert st['rai'] > 0, st
        assert st['vpid'] == tsgen.DEFAULT_VIDEO_PID, st
        assert st['stype'] == tsgen.STREAM_H264, st
        assert st['crc_err'] == 0, 'CRC errors on a clean stream: %r' % (st,)
        assert st['bad_dgram'] == 0, 'good datagrams rejected: %r' % (st,)

    def test_hevc_stream_type_is_reported(self, running):
        """The scanner must identify HEVC, which the browser path can't
        play -- that distinction drives the viewer fallback later."""
        p = running()
        g = tsgen.TSGen(stream_type=tsgen.STREAM_HEVC)
        _publish(VPORT, g.stream(300, gop=10, psi_every=20))
        st = wait_stats(p, lambda s: s['join'] == 'ready')
        assert st is not None and st['stype'] == tsgen.STREAM_HEVC, \
            '%r\n%s' % (st, p.log)

    def test_no_keyframes_means_not_joinable(self, running):
        """PSI alone is not enough: without a random access point there
        is nowhere a decoder could start."""
        p = running()
        g = tsgen.TSGen()
        out = bytearray()
        for i in range(300):
            if i % 20 == 0:
                out += g.pat()
                out += g.pmt()
            out += g.video(key=False)
        _publish(VPORT, bytes(out))

        st = wait_stats(p, lambda s: s['pmt'] > 0)
        assert st is not None, p.log
        assert st['pat'] > 0 and st['pmt'] > 0, st
        assert st['rai'] == 0, 'no keyframes were sent: %r' % (st,)
        assert st['join'] == 'waiting', \
            'claimed joinable with no random access point: %r' % (st,)

    def test_misaligned_datagrams_are_counted_and_dropped(self, running):
        """Junk from the *established* publisher must be dropped.

        The same socket throughout: a fresh one would present a new
        source port and be refused as a second publisher, which is a
        different rule and would not exercise the ingest validation.
        """
        p = running()
        g = tsgen.TSGen()
        dgs = g.datagrams(g.stream(100, gop=10, psi_every=20))
        expect_packets = len(dgs) * tsgen.PACKETS_PER_DATAGRAM
        n_junk = 10

        pub = Publisher(VPORT)
        try:
            for dg in dgs:
                pub.sock.sendto(dg, ('127.0.0.1', VPORT))
                time.sleep(0.004)
            for _ in range(n_junk):
                # 201 bytes: not a multiple of 188, so not TS
                pub.sock.sendto(b'\x47' + b'\x11' * 200, ('127.0.0.1', VPORT))
                time.sleep(0.02)

            st = wait_stats(p, lambda s: s['bad_dgram'] >= n_junk)
            assert st is not None and st['bad_dgram'] == n_junk, \
                'misaligned datagrams not counted: %r\n%s' % (st, p.log)
            # Compare against what was sent, not against an earlier stats
            # line -- those are emitted on a timer and can be sampled
            # mid-stream.
            assert st['packets'] == expect_packets, \
                'junk reached the scanner: %d packets, expected %d' \
                % (st['packets'], expect_packets)
            assert st['crc_err'] == 0, \
                'garbage reached the PSI parser: %r' % (st,)
        finally:
            pub.close()

    def test_second_publisher_is_refused_with_its_own_reason(self, running):
        """A second sender is refused because the slot is taken -- not
        because its address failed the MAVLink check, which it passed."""
        p = running()
        g = tsgen.TSGen()
        first = Publisher(VPORT)
        try:
            for dg in g.datagrams(g.stream(60, gop=10, psi_every=20)):
                first.sock.sendto(dg, ('127.0.0.1', VPORT))
                time.sleep(0.004)
            assert p.wait_for(r'video slot 0 publisher'), p.log

            second = Publisher(VPORT)
            try:
                for dg in g.datagrams(g.stream(30, gop=10, psi_every=20)):
                    second.sock.sendto(dg, ('127.0.0.1', VPORT))
                    time.sleep(0.004)
            finally:
                second.close()

            assert p.wait_for(r'another publisher holds this slot'), \
                'second publisher not refused with a slot-busy reason:\n%s' \
                % p.log
            assert 'address does not match' not in p.log, \
                'refusal blamed the address, which was fine:\n%s' % p.log
        finally:
            first.close()

    def test_recovers_after_a_gap(self, running):
        """A publisher that pauses and resumes must keep parsing.

        Datagram loss is normal on a lossy link; the scanner has to pick
        the program back up rather than wedge.
        """
        p = running()
        g = tsgen.TSGen()
        _publish(VPORT, g.stream(120, gop=10, psi_every=20))
        st = wait_stats(p, lambda s: s['join'] == 'ready')
        assert st is not None and st['join'] == 'ready', p.log
        first_rai = st['rai']

        time.sleep(2.0)
        _publish(VPORT, g.stream(120, gop=10, psi_every=20))
        st2 = wait_stats(p, lambda s: s['rai'] > first_rai)
        assert st2 is not None and st2['rai'] > first_rai, \
            'scanner stopped after a gap: %r -> %r\n%s' % (st, st2, p.log)
        assert st2['join'] == 'ready', st2


@pytest.mark.integration
class TestScannerSelftest:
    def test_selftest_and_fuzz_pass(self):
        """The in-process unit checks and a short fuzz run.

        Kept in the normal suite so a regression in the PSI parsing --
        lengths and CRCs taken straight off the wire -- fails here
        rather than only in a dedicated campaign.
        """
        r = subprocess.run([SUPPORTPROXY_BIN, '--selftest-video'],
                           capture_output=True, text=True, timeout=120)
        assert r.returncode == 0, r.stdout + r.stderr
        assert 'videots selftest: OK' in r.stdout
        assert 'videostream selftest: OK' in r.stdout
        assert 'videots fuzz: OK' in r.stdout

    @pytest.mark.parametrize('seed', [2, 3, 42])
    def test_fuzz_other_seeds(self, seed):
        r = subprocess.run(
            [SUPPORTPROXY_BIN, '--selftest-video', '4000', str(seed)],
            capture_output=True, text=True, timeout=120)
        assert r.returncode == 0, r.stdout + r.stderr
