"""Unit tests for the tlog-related schema and CLI changes.

These tests don't need the supportproxy binary running; they exercise
keydb_lib's pack/unpack and the keydb.py CLI directly against a fresh
TDB in a tmpdir.
"""
import os
import struct
import subprocess
import sys

import pytest

_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

import keydb_lib  # noqa: E402

KEYDB_PY = os.path.join(_REPO_ROOT, 'keydb.py')


def test_pack_format_size_is_168():
    """The on-disk record is 168 bytes after appending log_retention_days
    + reserved[16]."""
    assert struct.calcsize(keydb_lib.PACK_FORMAT) == 168
    assert keydb_lib.KEYENTRY_CURRENT_SIZE == 168


def test_pack_unpack_roundtrip():
    e = keydb_lib.KeyEntry(10002)
    e.port1 = 10001
    e.name = 'TestEntry'
    e.set_passphrase('hunter2')
    e.flags = keydb_lib.FLAG_TLOG | keydb_lib.FLAG_ADMIN
    e.log_retention_days = 0.0001
    data = e.pack()
    assert len(data) == 168

    e2 = keydb_lib.KeyEntry(0)
    e2.unpack(data)
    assert e2.port1 == 10001
    assert e2.name == 'TestEntry'
    assert e2.flags == keydb_lib.FLAG_TLOG | keydb_lib.FLAG_ADMIN
    # float32 quantisation: tolerate ~1e-7 relative error
    assert abs(e2.log_retention_days - 0.0001) < 1e-7
    assert e2.reserved == [0] * 15


def test_legacy_104byte_record_zero_extends():
    """Records written by the pre-tlog schema decode cleanly with
    retention=0.0 (forever) and reserved all zero."""
    LEGACY_FMT = '<QQ32siIII32sI4x'
    e = keydb_lib.KeyEntry(20002)
    e.port1 = 20001
    e.name = 'OldEntry'
    e.set_passphrase('legacy')
    e.flags = keydb_lib.FLAG_ADMIN
    name = e.name.encode('UTF-8').ljust(32, b'\x00')[:32]
    legacy = struct.pack(LEGACY_FMT,
                         e.magic, e.timestamp, bytes(e.secret_key),
                         e.port1, e.connections, e.count1, e.count2,
                         name, e.flags)
    assert len(legacy) == 104

    decoded = keydb_lib.KeyEntry(0)
    decoded.unpack(legacy)
    assert decoded.port1 == 20001
    assert decoded.flags == keydb_lib.FLAG_ADMIN
    assert decoded.log_retention_days == 0.0
    assert decoded.fc_sysid == 0
    assert decoded.reserved == [0] * 15

    # Re-pack: should emit the full 168-byte modern layout.
    re = decoded.pack()
    assert len(re) == 168


def test_forward_compat_tail_is_preserved():
    """When a future schema appends bytes beyond ours, we must round-trip
    them verbatim so older code doesn't truncate the new fields."""
    e = keydb_lib.KeyEntry(30002)
    e.port1 = 30001
    e.name = 'FutureEntry'
    e.set_passphrase('future')
    payload = e.pack()
    extra = b'\xab\xcd\xef\x01\x02\x03\x04\x05'
    future = payload + extra

    decoded = keydb_lib.KeyEntry(0)
    decoded.unpack(future)
    assert decoded._tail == extra
    re = decoded.pack()
    assert re.endswith(extra)
    assert len(re) == 168 + len(extra)


def test_flag_names_includes_tlog():
    """The tlog flag is exposed via FLAG_NAMES so setflag/clearflag work."""
    assert 'tlog' in keydb_lib.FLAG_NAMES
    assert keydb_lib.FLAG_NAMES['tlog'] == keydb_lib.FLAG_TLOG
    assert keydb_lib.FLAG_TLOG == 1 << 2


def test_flag_names_includes_binlog():
    """The binlog flag is exposed via FLAG_NAMES so setflag/clearflag work."""
    assert 'binlog' in keydb_lib.FLAG_NAMES
    assert keydb_lib.FLAG_NAMES['binlog'] == keydb_lib.FLAG_BINLOG
    assert keydb_lib.FLAG_BINLOG == 1 << 3


def test_binlog_flag_round_trip(tmp_path):
    """Both tlog and binlog can coexist on the same entry."""
    p = str(tmp_path / 'keys.tdb')
    db = keydb_lib.init_db(p)
    db.transaction_start()
    keydb_lib.add_entry(db, 18001, 18002, 'bin_test', 'pw')
    keydb_lib.set_flag(db, 18002, 'binlog')
    keydb_lib.set_flag(db, 18002, 'tlog')
    ke = keydb_lib.KeyEntry(18002)
    ke.fetch(db)
    db.transaction_cancel()
    assert ke.flags & keydb_lib.FLAG_BINLOG
    assert ke.flags & keydb_lib.FLAG_TLOG
    names = ke.flag_names()
    assert 'binlog' in names
    assert 'tlog' in names


def test_cli_setflag_binlog(tmp_path):
    p = str(tmp_path / 'keys.tdb')
    _run_cli(p, 'initialise')
    _run_cli(p, 'add', '19001', '19002', 'CliBin', 'pw')
    r = _run_cli(p, 'setflag', '19002', 'binlog')
    assert r.returncode == 0
    r = _run_cli(p, 'flags', '19002')
    assert 'binlog' in r.stdout


def test_setflag_tlog_auto_defaults_retention(tmp_path):
    """Enabling tlog from a fresh-zero state seeds the default retention."""
    p = str(tmp_path / 'keys.tdb')
    db = keydb_lib.init_db(p)
    db.transaction_start()
    keydb_lib.add_entry(db, 11001, 11002, 'auto-default', 'pw')
    keydb_lib.set_flag(db, 11002, 'tlog')
    ke = keydb_lib.KeyEntry(11002)
    ke.fetch(db)
    db.transaction_cancel()
    assert ke.flags & keydb_lib.FLAG_TLOG
    assert ke.log_retention_days == keydb_lib.DEFAULT_LOG_RETENTION_DAYS


def test_setflag_tlog_keeps_explicit_zero(tmp_path):
    """If retention has been *explicitly* set to 0 (forever), toggling
    the flag off and on again should NOT silently overwrite it.

    Implementation-wise: set_flag only auto-defaults when the bit was off
    AND retention was already 0. Once we've cleared the flag (bit off,
    retention preserved at 0 from earlier), re-enabling will re-default
    — which is the documented behaviour. So this test asserts the
    'first-enable-from-fresh-zero' contract rather than the stronger
    'never overwrite explicit zero' invariant.
    """
    p = str(tmp_path / 'keys.tdb')
    db = keydb_lib.init_db(p)
    db.transaction_start()
    keydb_lib.add_entry(db, 12001, 12002, 'persist', 'pw')
    # First enable: default kicks in.
    ke = keydb_lib.set_flag(db, 12002, 'tlog')
    assert ke.log_retention_days == keydb_lib.DEFAULT_LOG_RETENTION_DAYS
    # Owner explicitly raises retention; later toggle flag off then on:
    keydb_lib.set_log_retention(db, 12002, 14.0)
    keydb_lib.clear_flag(db, 12002, 'tlog')
    # Cleared flag; retention still 14 (not zeroed).
    ke2 = keydb_lib.KeyEntry(12002)
    ke2.fetch(db)
    assert ke2.log_retention_days == 14.0
    # Re-enabling from non-zero retention should NOT touch retention.
    keydb_lib.set_flag(db, 12002, 'tlog')
    ke3 = keydb_lib.KeyEntry(12002)
    ke3.fetch(db)
    db.transaction_cancel()
    assert ke3.log_retention_days == 14.0
    assert ke3.flags & keydb_lib.FLAG_TLOG


def test_set_log_retention_rejects_negative(tmp_path):
    p = str(tmp_path / 'keys.tdb')
    db = keydb_lib.init_db(p)
    db.transaction_start()
    keydb_lib.add_entry(db, 13001, 13002, 'neg', 'pw')
    with pytest.raises(keydb_lib.CLIError):
        keydb_lib.set_log_retention(db, 13002, -1.0)
    db.transaction_cancel()


# -- CLI smoke tests ---------------------------------------------------------

def _run_cli(keydb_path, *args):
    return subprocess.run(
        ['python3', KEYDB_PY, '--keydb', keydb_path, *args],
        capture_output=True, text=True, cwd=_REPO_ROOT)


def test_cli_setretention_accepts_float(tmp_path):
    p = str(tmp_path / 'keys.tdb')
    r = _run_cli(p, 'initialise')
    assert r.returncode == 0, r.stderr
    r = _run_cli(p, 'add', '14001', '14002', 'CliTest', 'pw')
    assert r.returncode == 0, r.stderr
    r = _run_cli(p, 'setretention', '14002', '0.0001')
    assert r.returncode == 0, r.stderr
    assert '0.0001' in r.stdout

    # Verify the value is now stored.
    r = _run_cli(p, 'list')
    assert r.returncode == 0
    assert '14001/14002' in r.stdout


def test_cli_setretention_zero_says_forever(tmp_path):
    p = str(tmp_path / 'keys.tdb')
    _run_cli(p, 'initialise')
    _run_cli(p, 'add', '15001', '15002', 'CliZero', 'pw')
    r = _run_cli(p, 'setretention', '15002', '0')
    assert r.returncode == 0
    assert 'forever' in r.stdout.lower()


def test_cli_setflag_tlog_then_list_shows_retention(tmp_path):
    p = str(tmp_path / 'keys.tdb')
    _run_cli(p, 'initialise')
    _run_cli(p, 'add', '16001', '16002', 'CliTlog', 'pw')
    r = _run_cli(p, 'setflag', '16002', 'tlog')
    assert r.returncode == 0
    r = _run_cli(p, 'list')
    assert 'flags=tlog' in r.stdout
    assert 'log_retention=7' in r.stdout


def test_fc_sysid_default_is_zero(tmp_path):
    p = str(tmp_path / 'keys.tdb')
    db = keydb_lib.init_db(p)
    db.transaction_start()
    keydb_lib.add_entry(db, 17001, 17002, 'default', 'pw')
    ke = keydb_lib.KeyEntry(17002)
    ke.fetch(db)
    db.transaction_cancel()
    assert ke.fc_sysid == 0


def test_set_fc_sysid_round_trip(tmp_path):
    p = str(tmp_path / 'keys.tdb')
    db = keydb_lib.init_db(p)
    db.transaction_start()
    keydb_lib.add_entry(db, 17101, 17102, 'sysid', 'pw')
    keydb_lib.set_fc_sysid(db, 17102, 42)
    ke = keydb_lib.KeyEntry(17102)
    ke.fetch(db)
    db.transaction_cancel()
    assert ke.fc_sysid == 42


def test_set_fc_sysid_rejects_out_of_range(tmp_path):
    p = str(tmp_path / 'keys.tdb')
    db = keydb_lib.init_db(p)
    db.transaction_start()
    keydb_lib.add_entry(db, 17201, 17202, 'oob', 'pw')
    with pytest.raises(keydb_lib.CLIError):
        keydb_lib.set_fc_sysid(db, 17202, -1)
    with pytest.raises(keydb_lib.CLIError):
        keydb_lib.set_fc_sysid(db, 17202, 256)
    db.transaction_cancel()


def test_cli_setsysid_then_list_shows_sysid(tmp_path):
    p = str(tmp_path / 'keys.tdb')
    _run_cli(p, 'initialise')
    _run_cli(p, 'add', '17301', '17302', 'CliSysid', 'pw')
    r = _run_cli(p, 'setsysid', '17302', '7')
    assert r.returncode == 0, r.stderr
    assert 'fc_sysid=7' in r.stdout
    r = _run_cli(p, 'list')
    assert 'fc_sysid=7' in r.stdout
    # Clearing back to 0 hides it from list output again.
    r = _run_cli(p, 'setsysid', '17302', '0')
    assert r.returncode == 0
    r = _run_cli(p, 'list')
    assert 'fc_sysid' not in r.stdout


def test_legacy_104byte_record_decodes_fc_sysid_zero(tmp_path):
    """A pre-tlog 104-byte record zero-extends; fc_sysid lands at the
    same offset as one of the now-reserved slots, so it must decode to
    0 on records written by the old schema."""
    LEGACY_FMT = '<QQ32siIII32sI4x'
    e = keydb_lib.KeyEntry(17402)
    e.port1 = 17401
    e.name = 'LegacyFcSysid'
    e.set_passphrase('legacy')
    name = e.name.encode('UTF-8').ljust(32, b'\x00')[:32]
    legacy = struct.pack(LEGACY_FMT,
                         e.magic, e.timestamp, bytes(e.secret_key),
                         e.port1, e.connections, e.count1, e.count2,
                         name, e.flags)
    decoded = keydb_lib.KeyEntry(0)
    decoded.unpack(legacy)
    assert decoded.fc_sysid == 0
