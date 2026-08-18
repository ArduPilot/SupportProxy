"""Schema tests for the video fields in keys.tdb and connections.tdb.

Both records are an ABI shared with C++ (keydb.h / conntdb.h carry
matching static_asserts). These tests cover the Python half and, more
importantly, the forward/backward-compatibility contract: a record
written by an older build must read back with the video fields unset,
and a record written by a newer build must survive a read-modify-write
here without losing its tail.
"""
import struct
import sys
import os

_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

import conntdb_lib  # noqa: E402
import keydb_lib  # noqa: E402

# The record layout as the pre-video schema wrote it.
PREVIDEO_KEY_FMT = "<QQ32siIII32sIfIf14I"
PREVIDEO_CONN_FMT = "<QQQiiIIIIHBBII4x"


def _entry(port2=11001):
    e = keydb_lib.KeyEntry(port2)
    e.port1 = port2 - 1
    e.name = 'vid'
    e.set_passphrase('pw')
    return e


def test_keyentry_video_roundtrip():
    e = _entry()
    e.video_ports = [20001, 20002, 0]
    e.set_slot_opts(0, keydb_lib.VIDEO_SLOT_SRT | keydb_lib.VIDEO_SLOT_RECORD)
    e.set_slot_opts(1, keydb_lib.VIDEO_SLOT_RAW_TCP)
    e.video_flags = keydb_lib.video_set_entry_opts(
        e.video_flags, keydb_lib.VIDEO_OPT_AUDIO)
    e.set_video_viewer_pass('viewpw')
    e.set_video_publish_pass('pubpw')
    e.video_quota_mb = 4096
    e.video_mav_grace_s = 90

    blob = e.pack()
    assert len(blob) == 456

    d = keydb_lib.KeyEntry(0)
    d.unpack(blob)
    assert d.video_ports == [20001, 20002, 0, 0, 0]
    assert d.active_video_ports() == [(0, 20001), (1, 20002)]
    assert set(d.slot_opt_names(0)) == {'srt', 'record'}
    assert set(d.slot_opt_names(1)) == {'raw_tcp'}
    assert d.slot_opt_names(2) == []
    assert d.entry_opt_names() == ['audio']
    assert d.video_quota_mb == 4096
    assert d.mav_grace_seconds() == 90


def test_slot_opts_are_independent():
    """Each slot owns its own byte; setting one must not disturb another."""
    e = _entry()
    e.set_slot_opts(0, keydb_lib.VIDEO_SLOT_SRT)
    e.set_slot_opts(1, keydb_lib.VIDEO_SLOT_RECORD)
    e.set_slot_opts(2, keydb_lib.VIDEO_SLOT_RAW_TCP)
    e.video_flags = keydb_lib.video_set_entry_opts(
        e.video_flags, keydb_lib.VIDEO_OPT_AUDIO)

    assert e.slot_opts(0) == keydb_lib.VIDEO_SLOT_SRT
    assert e.slot_opts(1) == keydb_lib.VIDEO_SLOT_RECORD
    assert e.slot_opts(2) == keydb_lib.VIDEO_SLOT_RAW_TCP
    assert keydb_lib.video_entry_opts(e.video_flags) == keydb_lib.VIDEO_OPT_AUDIO

    # rewriting slot 1 leaves the others (and the entry byte) alone
    e.set_slot_opts(1, 0)
    assert e.slot_opts(0) == keydb_lib.VIDEO_SLOT_SRT
    assert e.slot_opts(1) == 0
    assert e.slot_opts(2) == keydb_lib.VIDEO_SLOT_RAW_TCP
    assert keydb_lib.video_entry_opts(e.video_flags) == keydb_lib.VIDEO_OPT_AUDIO


def test_video_passwords_are_independent_and_clearable():
    e = _entry()
    assert not e.video_viewer_pass_set()
    assert not e.video_publish_pass_set()

    e.set_video_viewer_pass('viewer')
    e.set_video_publish_pass('publish')
    assert e.video_viewer_pass_matches('viewer')
    assert not e.video_viewer_pass_matches('publish')
    assert e.video_publish_pass_matches('publish')
    assert not e.video_publish_pass_matches('viewer')

    # The MAVLink passphrase must be untouched by either.
    assert e.passphrase_matches('pw')

    # Clearing must not leave a password that the empty string satisfies.
    e.set_video_viewer_pass('')
    assert not e.video_viewer_pass_set()
    assert not e.video_viewer_pass_matches('')
    assert not e.video_viewer_pass_matches('viewer')
    assert e.video_publish_pass_set()


def test_grace_zero_means_default():
    e = _entry()
    assert e.video_mav_grace_s == 0
    assert e.mav_grace_seconds() == keydb_lib.VIDEO_MAV_GRACE_DEFAULT_S
    e.video_mav_grace_s = 120
    assert e.mav_grace_seconds() == 120


def test_prevideo_keyentry_zero_extends():
    """A 168-byte record from the previous schema reads with video unset."""
    e = _entry(12002)
    name = e.name.encode('UTF-8').ljust(32, b'\x00')[:32]
    old = struct.pack(PREVIDEO_KEY_FMT,
                      e.magic, 7, bytes(e.secret_key), e.port1,
                      3, 4, 5, name, keydb_lib.FLAG_TLOG, 7.0, 42, 10.0,
                      *([0] * 14))
    assert len(old) == 168

    d = keydb_lib.KeyEntry(0)
    d.unpack(old)
    # pre-video fields survive
    assert d.port1 == e.port1 and d.name == 'vid'
    assert d.flags == keydb_lib.FLAG_TLOG
    assert d.fc_sysid == 42 and d.tz_offset_hours == 10.0
    # video fields default off
    assert d.video_ports == [0] * keydb_lib.MAX_VIDEO_PORTS
    assert d.video_flags == 0
    assert d.video_quota_mb == 0
    assert not d.video_viewer_pass_set()
    assert not d.video_publish_pass_set()
    assert d.mav_grace_seconds() == keydb_lib.VIDEO_MAV_GRACE_DEFAULT_S
    # and re-packing upgrades it in place without losing anything
    assert len(d.pack()) == keydb_lib.KEYENTRY_CURRENT_SIZE


def test_keyentry_future_tail_preserved():
    """A newer build's extra bytes must survive read-modify-write here."""
    e = _entry()
    e.video_ports = [20001, 0, 0]
    future = e.pack() + b'\xAB' * 16
    d = keydb_lib.KeyEntry(0)
    d.unpack(future)
    assert d._tail == b'\xAB' * 16
    assert d.pack() == future


def test_connentry_video_fields_roundtrip():
    rec = struct.pack(
        conntdb_lib.PACK_FORMAT,
        conntdb_lib.CONN_MAGIC, 1, 2, 11001,
        conntdb_lib.VIDEO_CONN_INDEX_BASE, 99, 0, 0,
        0x0100007f, 0x3930, 1, 0, 0, 0,
        conntdb_lib.CONN_ROLE_VIDEO_PUB, 2, conntdb_lib.CONN_APP_MPEGTS, 1)
    assert len(rec) == 72

    ce = conntdb_lib.ConnEntry.unpack(rec)
    assert ce.role == conntdb_lib.CONN_ROLE_VIDEO_PUB
    assert ce.role_name == 'video-pub'
    assert ce.stream_idx == 2
    assert ce.app_name == 'mpegts'
    assert ce.authenticated == 1
    assert ce.is_video


def test_prevideo_connentry_fails_closed():
    """A 64-byte record must zero-extend, leaving authenticated == 0.

    That direction matters: authenticated gates video publish on bidi
    entries, so an old record must not read as authenticated.
    """
    old = struct.pack(PREVIDEO_CONN_FMT,
                      conntdb_lib.CONN_MAGIC, 100, 200, 11001, 0, 4242,
                      7, 8, 0x0100007f, 0x3930, 1, 1, 0, 0)
    assert len(old) == 64

    ce = conntdb_lib.ConnEntry.unpack(old)
    assert ce.pid == 4242 and ce.is_user == 1
    assert ce.role == conntdb_lib.CONN_ROLE_MAVLINK
    assert ce.authenticated == 0
    assert not ce.is_video


def test_video_conn_index_range_is_disjoint():
    """Video rows must not collide with MAVLink conn_index values.

    MAVLink uses 0 (user) and 1..MAX_COMM2_LINKS (engineer slots), which
    is 100 in mavlink_msgs.h.
    """
    assert conntdb_lib.VIDEO_CONN_INDEX_BASE > 100 + 1
    for slot in range(keydb_lib.MAX_VIDEO_PORTS):
        pub = (conntdb_lib.VIDEO_CONN_INDEX_BASE
               + slot * conntdb_lib.VIDEO_CONN_STRIDE)
        assert pub > 100
        # viewers for one slot must not run into the next slot's publisher
        last_sub = pub + conntdb_lib.VIDEO_CONN_STRIDE - 1
        next_pub = pub + conntdb_lib.VIDEO_CONN_STRIDE
        assert last_sub < next_pub


def test_five_slots_round_trip():
    """All five slots survive a pack/unpack, including the split.

    Slots 0-2 live in the fields the 344-byte record had; 3 and 4 are in
    fields appended after reserved[]. Nothing outside keydb_lib should
    be able to tell.
    """
    e = keydb_lib.KeyEntry(4242)
    e.video_ports = [40001, 40002, 40003, 40004, 40005]
    e.video_rtmp_path = ['a/1', 'b/2', 'c/3', 'd/4', 'e/5']
    for slot in range(keydb_lib.MAX_VIDEO_PORTS):
        e.set_slot_opts(slot, keydb_lib.VIDEO_SLOT_RECORD)
    e.video_flags = keydb_lib.video_set_entry_opts(
        e.video_flags, keydb_lib.VIDEO_OPT_AUDIO)

    d = keydb_lib.KeyEntry(4242)
    d.unpack(e.pack())
    assert d.video_ports == [40001, 40002, 40003, 40004, 40005]
    assert d.video_rtmp_path == ['a/1', 'b/2', 'c/3', 'd/4', 'e/5']
    for slot in range(keydb_lib.MAX_VIDEO_PORTS):
        assert d.slot_opts(slot) & keydb_lib.VIDEO_SLOT_RECORD, slot
    assert keydb_lib.video_entry_opts(d.video_flags) \
        & keydb_lib.VIDEO_OPT_AUDIO


def test_slot_three_does_not_clobber_the_entry_options():
    """The low flags word is full: three slot bytes plus the entry byte.

    A fourth slot byte at shift 24 would land exactly on the entry-wide
    options, which is why slots past the third have their own word.
    """
    e = keydb_lib.KeyEntry(4243)
    e.video_flags = keydb_lib.video_set_entry_opts(
        e.video_flags, keydb_lib.VIDEO_OPT_AUDIO)
    e.set_slot_opts(3, 0xFF)
    e.set_slot_opts(4, 0xFF)
    assert keydb_lib.video_entry_opts(e.video_flags) \
        & keydb_lib.VIDEO_OPT_AUDIO, 'entry options lost'

    d = keydb_lib.KeyEntry(4243)
    d.unpack(e.pack())
    assert keydb_lib.video_entry_opts(d.video_flags) \
        & keydb_lib.VIDEO_OPT_AUDIO
    assert d.slot_opts(3) == 0xFF and d.slot_opts(4) == 0xFF


def test_three_slot_record_still_reads():
    """A record written before slots 3-4 existed must be untouched.

    The three inline fields stay exactly where they were, so an existing
    database keeps working and an older binary can still read what a
    newer one writes.
    """
    e = keydb_lib.KeyEntry(4244)
    e.video_ports = [40001, 40002, 40003, 0, 0]
    e.video_rtmp_path = ['x/1', 'y/2', 'z/3', '', '']
    e.set_slot_opts(1, keydb_lib.VIDEO_SLOT_RECORD)
    e.video_flags = keydb_lib.video_set_entry_opts(
        e.video_flags, keydb_lib.VIDEO_OPT_AUDIO)
    old = e.pack()[:344]            # truncated, as an old writer would
    assert len(old) == 344

    d = keydb_lib.KeyEntry(4244)
    d.unpack(old)
    assert d.video_ports == [40001, 40002, 40003, 0, 0]
    assert d.video_rtmp_path == ['x/1', 'y/2', 'z/3', '', '']
    assert d.slot_opts(1) & keydb_lib.VIDEO_SLOT_RECORD
    assert keydb_lib.video_entry_opts(d.video_flags) \
        & keydb_lib.VIDEO_OPT_AUDIO
