"""Tests for the tlog cleanup process.

We don't link the cleanup C++ logic into Python, so we drive it as a
short-lived child process. To exercise the loop without real wall-clock
delays, we set SUPPORTPROXY_CLEANUP_INTERVAL to a sub-second float.

Approach:
  * Build a tmpdir with keys.tdb (entry has KEY_FLAG_TLOG, retention_seconds)
  * Seed logs/<port2>/<date>/sessionN.tlog with old + new mtimes
  * Spawn `supportproxy` from tmpdir; the cleanup child forks at startup,
    runs an immediate pass, then ticks again every CLEANUP_INTERVAL
  * Wait briefly, terminate, assert old files gone, new files present
"""
import os
import shutil
import signal
import subprocess
import sys
import time

import pytest

_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

import keydb_lib  # noqa: E402

SUPPORTPROXY_BIN = os.path.join(_REPO_ROOT, 'supportproxy')


@pytest.fixture
def proxy_workdir(tmp_path):
    """Tmpdir with a keys.tdb and an empty logs/ tree, isolated from the
    suite's other working directory choices."""
    p = tmp_path / 'work'
    p.mkdir()
    db_path = str(p / 'keys.tdb')
    db = keydb_lib.init_db(db_path)
    yield p, db_path, db
    db.close()


def _add_entry(db, port1, port2, name='clean', retention=0.1):
    db.transaction_start()
    keydb_lib.add_entry(db, port1, port2, name, 'pw')
    keydb_lib.set_flag(db, port2, 'tlog')
    keydb_lib.set_log_retention(db, port2, retention)
    db.transaction_prepare_commit()
    db.transaction_commit()


def _seed(workdir, port2, date, session_name, age_seconds):
    """Write a fake tlog at logs/<port2>/<date>/<session_name> with mtime
    set to (now - age_seconds)."""
    d = workdir / 'logs' / str(port2) / date
    d.mkdir(parents=True, exist_ok=True)
    f = d / session_name
    f.write_bytes(b'\x00' * 64)
    now = time.time()
    os.utime(f, (now - age_seconds, now - age_seconds))
    return f


def _start_proxy(workdir, interval='0.3'):
    env = os.environ.copy()
    env['SUPPORTPROXY_CLEANUP_INTERVAL'] = interval
    proc = subprocess.Popen([SUPPORTPROXY_BIN], cwd=str(workdir), env=env,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    return proc


def _terminate(proc):
    proc.send_signal(signal.SIGTERM)
    try:
        proc.wait(timeout=3)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=2)


def _wait_for_state(predicate, timeout=5.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(0.1)
    return False


@pytest.mark.skipif(not os.path.exists(SUPPORTPROXY_BIN),
                    reason='supportproxy binary not built')
class TestTlogCleanup:
    def test_old_files_removed_new_kept(self, proxy_workdir):
        workdir, _, db = proxy_workdir
        # 0.1 days = 8640 s. Files older than that get cleaned.
        _add_entry(db, 26001, 26002, retention=0.1)
        old = _seed(workdir, 26002, '2026-05-09', 'session1.tlog',
                    age_seconds=10000)
        new = _seed(workdir, 26002, '2026-05-10', 'session1.tlog',
                    age_seconds=100)
        proc = _start_proxy(workdir)
        try:
            assert _wait_for_state(lambda: not old.exists(), timeout=5.0), \
                'old file was not removed'
            assert new.exists(), 'recent file was removed unexpectedly'
        finally:
            _terminate(proc)

    def test_retention_zero_keeps_everything(self, proxy_workdir):
        workdir, _, db = proxy_workdir
        _add_entry(db, 26101, 26102, retention=0.0)
        # Even a year-old file must survive when retention is 0 (forever).
        ancient = _seed(workdir, 26102, '2025-01-01', 'session1.tlog',
                        age_seconds=365 * 86400)
        proc = _start_proxy(workdir)
        try:
            # give cleanup at least one tick to (incorrectly) act
            time.sleep(1.0)
            assert ancient.exists(), \
                'retention=0 should not remove anything'
        finally:
            _terminate(proc)

    def test_empty_date_dirs_removed(self, proxy_workdir):
        workdir, _, db = proxy_workdir
        _add_entry(db, 26201, 26202, retention=0.0001)  # ~8.6s
        date_dir = workdir / 'logs' / '26202' / '2026-05-09'
        old = _seed(workdir, 26202, '2026-05-09', 'session1.tlog',
                    age_seconds=300)
        proc = _start_proxy(workdir)
        try:
            assert _wait_for_state(lambda: not date_dir.exists(), timeout=5.0), \
                'empty date dir was not removed'
            assert not old.exists()
        finally:
            _terminate(proc)

    def test_missing_logs_dir_is_ok(self, proxy_workdir):
        """Cleanup child must not crash when logs/ doesn't exist."""
        workdir, _, db = proxy_workdir
        _add_entry(db, 26301, 26302, retention=0.001)
        # Note: no logs/ tree exists yet.
        proc = _start_proxy(workdir)
        try:
            time.sleep(0.8)
            assert proc.poll() is None, 'proxy crashed'
        finally:
            _terminate(proc)

    def test_quota_deletes_oldest_even_with_retention_zero(self, proxy_workdir):
        """The per-port-pair 1 GiB quota is enforced INDEPENDENTLY of
        the per-entry retention. With retention=0 (keep forever) the
        retention pass is a no-op, but the quota pass must still
        delete oldest files until total <= 1 GiB.

        Uses sparse files (truncate) to fake large apparent sizes
        without consuming real disk."""
        workdir, _, db = proxy_workdir
        _add_entry(db, 26401, 26402, retention=0.0)  # forever

        # Three sparse session files, totalling 1.2 GiB. Sort order
        # oldest -> newest: a (600 MB), b (400 MB), c (200 MB).
        # Quota cap = 1 GiB → 1.2 GiB > cap → drop oldest until under.
        # After deleting a (600 MB), total = 600 MB <= 1 GiB. Stops.
        a = _seed(workdir, 26402, '2026-05-08', 'session1.bin',
                  age_seconds=300)
        b = _seed(workdir, 26402, '2026-05-09', 'session1.bin',
                  age_seconds=200)
        c = _seed(workdir, 26402, '2026-05-10', 'session1.bin',
                  age_seconds=100)
        # Resize each to a large apparent size (sparse).
        os.truncate(a, 600 * 1024 * 1024)
        os.truncate(b, 400 * 1024 * 1024)
        os.truncate(c, 200 * 1024 * 1024)
        # Re-set mtimes after the truncate (which updates them).
        now = time.time()
        os.utime(a, (now - 300, now - 300))
        os.utime(b, (now - 200, now - 200))
        os.utime(c, (now - 100, now - 100))

        proc = _start_proxy(workdir)
        try:
            # Quota pass runs once at startup + on each cleanup tick.
            assert _wait_for_state(lambda: not a.exists(), timeout=5.0), \
                'oldest file should have been removed by quota pass'
            # Newer two stay.
            assert b.exists(), 'middle file deleted unexpectedly'
            assert c.exists(), 'newest file deleted unexpectedly'
        finally:
            _terminate(proc)
