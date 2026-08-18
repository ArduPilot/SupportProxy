"""Video port allocation, option setters, and the keydb.py CLI actions.

Video ports share the listening-port namespace with port1/port2, so the
uniqueness rule has to be bidirectional: a video port must not take a
port some other entry already binds, *and* a new entry must not take a
port already used for video. Both directions are tested here.
"""
import os
import subprocess
import sys

import pytest

_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

import keydb_lib  # noqa: E402
from keydb_lib import CLIError  # noqa: E402

KEYDB_PY = os.path.join(_REPO_ROOT, 'keydb.py')

PORT1, PORT2 = 20001, 20002
OTHER1, OTHER2 = 30001, 30002


@pytest.fixture
def db(tmp_path):
    """A keys.tdb with two entries, inside an open transaction."""
    d = keydb_lib.init_db(str(tmp_path / 'keys.tdb'))
    d.transaction_start()
    keydb_lib.add_entry(d, PORT1, PORT2, 'vid', 'pw')
    keydb_lib.add_entry(d, OTHER1, OTHER2, 'other', 'pw2')
    yield d
    try:
        d.transaction_cancel()
    except Exception:
        pass
    d.close()


def _ports(d, port2=PORT2):
    ke = keydb_lib.KeyEntry(port2)
    assert ke.fetch(d)
    return ke.video_ports


def test_set_and_clear_video_ports(db):
    keydb_lib.set_video_ports(db, PORT2, [21001, 21002])
    assert _ports(db) == [21001, 21002, 0, 0, 0]
    keydb_lib.set_video_ports(db, PORT2, [])
    assert _ports(db) == [0, 0, 0, 0, 0]


@pytest.mark.parametrize('bad,msg', [
    ([OTHER1], 'already in use'),          # another entry's port1
    ([OTHER2], 'already in use'),          # another entry's port2
    ([PORT1], 'own port1/port2'),          # our own port1
    ([PORT2], 'own port1/port2'),          # our own port2
    ([22000, 22000], 'listed twice'),      # duplicate in one call
    ([80000], 'out of range'),             # above the port range
    ([80], 'out of range'),                # below VIDEO_PORT_MIN
    ([1] * (keydb_lib.MAX_VIDEO_PORTS + 1), 'at most'),   # too many
])
def test_video_port_collisions_rejected(db, bad, msg):
    with pytest.raises(CLIError) as ei:
        keydb_lib.set_video_ports(db, PORT2, bad)
    assert msg in str(ei.value)
    # a rejected call must not have partially applied
    assert _ports(db) == [0, 0, 0, 0, 0]


def test_video_port_blocks_a_later_add(db):
    """The check is bidirectional: a new entry can't take a video port."""
    keydb_lib.set_video_ports(db, PORT2, [21001])
    with pytest.raises(CLIError) as ei:
        keydb_lib.add_entry(db, 21001, 40002, 'clash', 'pw')
    assert 'already in use' in str(ei.value)


def test_video_port_can_be_reassigned_to_itself(db):
    """Re-setting the same ports must not collide with the entry's own."""
    keydb_lib.set_video_ports(db, PORT2, [21001, 21002])
    keydb_lib.set_video_ports(db, PORT2, [21001, 21002])
    assert _ports(db) == [21001, 21002, 0, 0, 0]
    # and reordering is fine
    keydb_lib.set_video_ports(db, PORT2, [21002, 21001])
    assert _ports(db) == [21002, 21001, 0, 0, 0]


def test_ports_in_use_excludes_named_entry(db):
    keydb_lib.set_video_ports(db, PORT2, [21001])
    all_used = keydb_lib.ports_in_use(db)
    assert {PORT1, PORT2, OTHER1, OTHER2, 21001} <= all_used
    mine_excluded = keydb_lib.ports_in_use(db, exclude_port2=PORT2)
    assert {OTHER1, OTHER2} <= mine_excluded
    assert not ({PORT1, PORT2, 21001} & mine_excluded)


def test_get_port_sets_returns_three_sets(db):
    keydb_lib.set_video_ports(db, PORT2, [21001])
    p1, p2, pv = keydb_lib.get_port_sets(db)
    assert PORT1 in p1 and OTHER1 in p1
    assert PORT2 in p2 and OTHER2 in p2
    assert pv == {21001}


def test_slot_and_entry_flags(db):
    keydb_lib.set_video_slot_flag(db, PORT2, 0, 'record')
    keydb_lib.set_video_slot_flag(db, PORT2, 1, 'srt')
    keydb_lib.set_video_entry_flag(db, PORT2, 'audio')
    ke = keydb_lib.KeyEntry(PORT2)
    assert ke.fetch(db)
    assert ke.slot_opt_names(0) == ['record']
    assert ke.slot_opt_names(1) == ['srt']
    assert ke.entry_opt_names() == ['audio']

    keydb_lib.set_video_slot_flag(db, PORT2, 0, 'record', on=False)
    ke.fetch(db)
    assert ke.slot_opt_names(0) == []
    assert ke.slot_opt_names(1) == ['srt']    # untouched


def test_unknown_flag_names_rejected(db):
    with pytest.raises(CLIError):
        keydb_lib.set_video_slot_flag(db, PORT2, 0, 'nosuchflag')
    with pytest.raises(CLIError):
        keydb_lib.set_video_entry_flag(db, PORT2, 'nosuchopt')
    with pytest.raises(CLIError):
        keydb_lib.set_video_slot_flag(db, PORT2, 9, 'record')


def test_quota_and_grace_bounds(db):
    keydb_lib.set_video_quota(db, PORT2, 4096)
    keydb_lib.set_video_grace(db, PORT2, 90)
    ke = keydb_lib.KeyEntry(PORT2)
    assert ke.fetch(db)
    assert ke.video_quota_mb == 4096 and ke.mav_grace_seconds() == 90

    with pytest.raises(CLIError):
        keydb_lib.set_video_quota(db, PORT2, -1)
    with pytest.raises(CLIError):
        keydb_lib.set_video_grace(db, PORT2, -1)
    with pytest.raises(CLIError):
        keydb_lib.set_video_grace(db, PORT2,
                                  keydb_lib.VIDEO_MAV_GRACE_MAX_S + 1)

    # 0 means "use the default", not "no grace"
    keydb_lib.set_video_grace(db, PORT2, 0)
    ke.fetch(db)
    assert ke.mav_grace_seconds() == keydb_lib.VIDEO_MAV_GRACE_DEFAULT_S


def test_video_passwords_via_setters(db):
    keydb_lib.set_video_viewer_pass(db, PORT2, 'viewpw')
    keydb_lib.set_video_publish_pass(db, PORT2, 'pubpw')
    ke = keydb_lib.KeyEntry(PORT2)
    assert ke.fetch(db)
    assert ke.video_viewer_pass_matches('viewpw')
    assert ke.video_publish_pass_matches('pubpw')
    assert ke.passphrase_matches('pw')       # MAVLink passphrase untouched

    keydb_lib.set_video_viewer_pass(db, PORT2, '')
    ke.fetch(db)
    assert not ke.video_viewer_pass_set()
    assert ke.video_publish_pass_set()       # independent


# --- CLI -----------------------------------------------------------------

def _cli(workdir, *argv):
    return subprocess.run(
        [sys.executable, KEYDB_PY] + list(argv),
        cwd=str(workdir), capture_output=True, text=True)


@pytest.fixture
def cli_db(tmp_path):
    _cli(tmp_path, 'initialise')
    _cli(tmp_path, 'add', str(PORT1), str(PORT2), 'vid', 'pw')
    return tmp_path


def test_cli_setvideo_and_video_summary(cli_db):
    assert _cli(cli_db, 'setflag', str(PORT2), 'video').returncode == 0
    r = _cli(cli_db, 'setvideo', str(PORT2), '21001', '21002')
    assert r.returncode == 0, r.stderr
    assert '21001,21002' in r.stdout

    assert _cli(cli_db, 'videoflag', str(PORT2), '0', 'record').returncode == 0
    assert _cli(cli_db, 'videoflag', str(PORT2), '1', 'srt').returncode == 0
    assert _cli(cli_db, 'videoopt', str(PORT2), 'audio').returncode == 0
    assert _cli(cli_db, 'setviewerpass', str(PORT2), 'vp').returncode == 0

    out = _cli(cli_db, 'video', str(PORT2)).stdout
    assert 'video: enabled' in out
    assert 'slot 0: port 21001  mpegts +record' in out
    assert 'slot 1: port 21002  srt' in out
    assert 'options: audio' in out
    assert 'viewer password: set' in out
    assert 'publish password: not set' in out


def test_cli_rejects_colliding_video_port(cli_db):
    _cli(cli_db, 'add', str(OTHER1), str(OTHER2), 'other', 'pw2')
    r = _cli(cli_db, 'setvideo', str(PORT2), str(OTHER1))
    assert r.returncode == 1
    assert 'already in use' in r.stdout + r.stderr


def test_cli_clears_ports_and_passwords(cli_db):
    _cli(cli_db, 'setvideo', str(PORT2), '21001')
    _cli(cli_db, 'setviewerpass', str(PORT2), 'vp')

    assert _cli(cli_db, 'setvideo', str(PORT2)).returncode == 0
    assert _cli(cli_db, 'setviewerpass', str(PORT2)).returncode == 0

    out = _cli(cli_db, 'video', str(PORT2)).stdout
    assert 'no video ports configured' in out
    assert 'viewer password: not set' in out


def test_cli_videoflag_off(cli_db):
    _cli(cli_db, 'setvideo', str(PORT2), '21001')
    _cli(cli_db, 'videoflag', str(PORT2), '0', 'record')
    assert 'record' in _cli(cli_db, 'video', str(PORT2)).stdout
    r = _cli(cli_db, 'videoflag', str(PORT2), '0', 'record', 'off')
    assert r.returncode == 0
    assert '+record' not in _cli(cli_db, 'video', str(PORT2)).stdout


class TestSuggestVideoPorts:
    """Automatic allocation counts up from VIDEO_PORT_BASE."""

    def test_starts_at_the_base(self, db):
        ke = keydb_lib.add_entry(db, 10001, 10002, 'a', 'p')
        got = keydb_lib.suggest_video_ports(db, ke, 1)
        assert got[0] == keydb_lib.VIDEO_PORT_BASE
        assert got[1:] == [0] * (keydb_lib.MAX_VIDEO_PORTS - 1)

    def test_consecutive_within_one_entry(self, db):
        ke = keydb_lib.add_entry(db, 10001, 10002, 'a', 'p')
        assert keydb_lib.suggest_video_ports(db, ke, 3)[:3] == [
            keydb_lib.VIDEO_PORT_BASE,
            keydb_lib.VIDEO_PORT_BASE + 1,
            keydb_lib.VIDEO_PORT_BASE + 2]

    def test_skips_ports_another_entry_holds(self, db):
        base = keydb_lib.VIDEO_PORT_BASE
        other = keydb_lib.add_entry(db, 10001, 10002, 'a', 'p')
        other.video_ports = [base, base + 2, 0, 0, 0]
        other.store(db)
        ke = keydb_lib.add_entry(db, 10003, 10004, 'b', 'p')
        assert keydb_lib.suggest_video_ports(db, ke, 2)[:3] == [
            base + 1, base + 3, 0]

    def test_skips_port1_and_port2(self, db):
        base = keydb_lib.VIDEO_PORT_BASE
        ke = keydb_lib.add_entry(db, base, base + 1, 'a', 'p')
        assert keydb_lib.suggest_video_ports(db, ke, 1) == [base + 2] + [0] * (keydb_lib.MAX_VIDEO_PORTS - 1)

    def test_keeps_an_already_allocated_port(self, db):
        """An entry that is already streaming on a port must not be
        renumbered just because its edit page was opened."""
        base = keydb_lib.VIDEO_PORT_BASE
        ke = keydb_lib.add_entry(db, 10001, 10002, 'a', 'p')
        ke.video_ports = [50000, 0, 0]
        got = keydb_lib.suggest_video_ports(db, ke, 2, keep=ke.video_ports)
        assert got == [50000, base, 0, 0, 0]

    def test_kept_port_is_not_reused_for_another_slot(self, db):
        base = keydb_lib.VIDEO_PORT_BASE
        ke = keydb_lib.add_entry(db, 10001, 10002, 'a', 'p')
        ke.video_ports = [0, base, 0, 0, 0]
        got = keydb_lib.suggest_video_ports(db, ke, 2, keep=ke.video_ports)
        assert got[:3] == [base + 1, base, 0]
        assert len(set(p for p in got if p)) == 2

    def test_suggestions_validate(self, db):
        """What the page offers must be storable, or the admin gets an
        error on a form they did not edit."""
        ke = keydb_lib.add_entry(db, 10001, 10002, 'a', 'p')
        got = keydb_lib.suggest_video_ports(db, ke, 3)
        assert keydb_lib.validate_video_ports(db, ke, got) == got


class TestVideoPortCount:
    def test_no_ports_reads_as_one(self, db):
        ke = keydb_lib.add_entry(db, 10001, 10002, 'a', 'p')
        assert ke.video_port_count() == 1

    def test_counts_the_highest_slot_not_the_total(self, db):
        ke = keydb_lib.add_entry(db, 10001, 10002, 'a', 'p')
        ke.video_ports = [40001, 0, 40003]
        assert ke.video_port_count() == 3

    def test_two(self, db):
        ke = keydb_lib.add_entry(db, 10001, 10002, 'a', 'p')
        ke.video_ports = [40001, 40002, 0]
        assert ke.video_port_count() == 2
