"""Tests for per-row 'Kill connection' buttons.

The webadmin sets CONN_FLAG_DROP_REQUESTED on the (port2, conn_index)
ConnEntry and signals SIGUSR1; the C++ child does the actual close.
We monkeypatch os.kill + /proc/comm seam so the tests don't signal
real processes — but we DO let the flag-set hit a synthesized
connections.tdb so we can assert it lands on the right record.
"""
import os
import socket
import struct
import time

import pytest
import tdb

import conntdb_lib
from webadmin import connections as conn_db

from _test_helpers import (ALICE_PASS, ALICE_PORT1, ALICE_PORT2,
                           BOB_PASS, BOB_PORT1, BOB_PORT2, login_as)


def _pack_entry(*, port2, conn_index, peer_ip, peer_port, transport,
                is_user, connected_at, last_update, rx=0, tx=0,
                pid=12345, flags=0):
    return struct.pack(
        conn_db.PACK_FORMAT,
        conn_db.CONN_MAGIC, connected_at, last_update,
        port2, conn_index,
        pid, rx, tx,
        struct.unpack("<I", socket.inet_aton(peer_ip))[0],
        socket.htons(peer_port),
        transport, 1 if is_user else 0,
        flags, 0,  # flags, _pad
    )


def _seed_connections(keydb_path, records):
    conn_path = os.path.join(os.path.dirname(os.path.abspath(keydb_path)),
                             conn_db.CONN_FILE)
    db = tdb.open(conn_path, hash_size=1024, tdb_flags=0,
                  flags=os.O_RDWR | os.O_CREAT, mode=0o600)
    db.transaction_start()
    for r in records:
        db.store(struct.pack(conn_db.KEY_FORMAT, r['port2'], r['conn_index']),
                 _pack_entry(**r), tdb.REPLACE)
    db.transaction_prepare_commit()
    db.transaction_commit()
    db.close()


def _read_entry(keydb_path, port2, conn_index):
    conn_path = os.path.join(os.path.dirname(os.path.abspath(keydb_path)),
                             conn_db.CONN_FILE)
    db = tdb.open(conn_path, hash_size=1024, tdb_flags=0,
                  flags=os.O_RDWR, mode=0o600)
    try:
        v = db.get(struct.pack(conn_db.KEY_FORMAT, port2, conn_index))
        return conntdb_lib.ConnEntry.unpack(v) if v else None
    finally:
        db.close()


@pytest.fixture
def fake_kill(monkeypatch):
    """Replace os.kill + comm reader so tests don't actually signal
    anything. Returns a stub object: .calls is the list of (pid, sig)
    tuples; .comm.table maps pid -> comm string ('supportproxy' default)."""
    calls = []

    def fake_os_kill(pid, sig):
        calls.append((pid, sig))

    def fake_comm(pid):
        return fake_comm.table.get(pid, 'supportproxy')

    fake_comm.table = {}
    monkeypatch.setattr(conntdb_lib.os, 'kill', fake_os_kill)
    monkeypatch.setattr(conntdb_lib, '_proc_comm', fake_comm)
    fake_kill.calls = calls
    fake_kill.comm = fake_comm
    return fake_kill


# ---------------------------------------------------------------------------

class TestOwnerKill:
    def test_owner_drops_engineer(self, client, keydb_path, fake_kill):
        now = int(time.time())
        _seed_connections(keydb_path, [
            dict(port2=ALICE_PORT2, conn_index=0, peer_ip='10.0.0.1',
                 peer_port=12345, transport=0, is_user=True,
                 connected_at=now - 5, last_update=now, pid=99001),
            dict(port2=ALICE_PORT2, conn_index=1, peer_ip='10.0.0.2',
                 peer_port=22222, transport=1, is_user=False,
                 connected_at=now - 2, last_update=now, pid=99001),
        ])
        login_as(client, ALICE_PORT1, ALICE_PASS)
        resp = client.post('/me/kill/1')
        assert resp.status_code == 302
        # SIGUSR1 sent, exactly one signal (one PID).
        import signal as sig
        assert fake_kill.calls == [(99001, sig.SIGUSR1)]
        # Flag landed on conn_index=1 only, not on user (conn_index=0).
        eng = _read_entry(keydb_path, ALICE_PORT2, 1)
        user = _read_entry(keydb_path, ALICE_PORT2, 0)
        assert eng.flags & conntdb_lib.CONN_FLAG_DROP_REQUESTED
        assert not (user.flags & conntdb_lib.CONN_FLAG_DROP_REQUESTED)

    def test_owner_drops_user_side(self, client, keydb_path, fake_kill):
        """Killing the user row is allowed; the C++ child interprets
        conn_index=0 as 'end the whole session'."""
        now = int(time.time())
        _seed_connections(keydb_path, [
            dict(port2=ALICE_PORT2, conn_index=0, peer_ip='10.0.0.1',
                 peer_port=12345, transport=0, is_user=True,
                 connected_at=now - 5, last_update=now, pid=99002),
        ])
        login_as(client, ALICE_PORT1, ALICE_PASS)
        resp = client.post('/me/kill/0')
        assert resp.status_code == 302
        import signal as sig
        assert fake_kill.calls == [(99002, sig.SIGUSR1)]
        user = _read_entry(keydb_path, ALICE_PORT2, 0)
        assert user.flags & conntdb_lib.CONN_FLAG_DROP_REQUESTED

    def test_owner_kill_unknown_conn_index_flashes_error(self, client,
                                                           keydb_path,
                                                           fake_kill):
        login_as(client, ALICE_PORT1, ALICE_PASS)
        resp = client.post('/me/kill/5', follow_redirects=True)
        assert resp.status_code == 200
        assert b'not found' in resp.data
        assert fake_kill.calls == []

    def test_owner_kill_does_not_reach_other_port2(self, client, keydb_path,
                                                    fake_kill):
        """Owner POSTs to /me/kill/<conn_index>. Server uses
        current_owner() to pick port2, so a record under a different
        port2 is invisible — even with matching conn_index."""
        now = int(time.time())
        _seed_connections(keydb_path, [
            dict(port2=BOB_PORT2, conn_index=1, peer_ip='10.0.0.3',
                 peer_port=33333, transport=0, is_user=False,
                 connected_at=now - 5, last_update=now, pid=99003),
        ])
        login_as(client, ALICE_PORT1, ALICE_PASS)
        resp = client.post('/me/kill/1')
        assert resp.status_code == 302
        assert fake_kill.calls == []
        bob_entry = _read_entry(keydb_path, BOB_PORT2, 1)
        assert not (bob_entry.flags & conntdb_lib.CONN_FLAG_DROP_REQUESTED)

    def test_unauthenticated_owner_kill_redirects_to_login(self, client):
        resp = client.post('/me/kill/0')
        assert resp.status_code == 302
        assert '/login' in resp.location


class TestAdminKill:
    def test_admin_drops_any_engineer(self, client, keydb_path, fake_kill):
        now = int(time.time())
        _seed_connections(keydb_path, [
            dict(port2=ALICE_PORT2, conn_index=0, peer_ip='10.0.0.1',
                 peer_port=12345, transport=0, is_user=True,
                 connected_at=now - 5, last_update=now, pid=99004),
            dict(port2=ALICE_PORT2, conn_index=2, peer_ip='10.0.0.4',
                 peer_port=44444, transport=1, is_user=False,
                 connected_at=now - 1, last_update=now, pid=99004),
        ])
        login_as(client, BOB_PORT1, BOB_PASS)
        resp = client.post('/admin/%d/kill/2' % ALICE_PORT2)
        assert resp.status_code == 302
        import signal as sig
        assert fake_kill.calls == [(99004, sig.SIGUSR1)]
        eng2 = _read_entry(keydb_path, ALICE_PORT2, 2)
        user = _read_entry(keydb_path, ALICE_PORT2, 0)
        assert eng2.flags & conntdb_lib.CONN_FLAG_DROP_REQUESTED
        assert not (user.flags & conntdb_lib.CONN_FLAG_DROP_REQUESTED)

    def test_admin_kill_no_active_flashes_error(self, client, fake_kill):
        login_as(client, BOB_PORT1, BOB_PASS)
        resp = client.post('/admin/%d/kill/0' % ALICE_PORT2,
                           follow_redirects=True)
        assert resp.status_code == 200
        assert b'not found' in resp.data
        assert fake_kill.calls == []

    def test_owner_cannot_use_admin_kill_route(self, client, keydb_path,
                                                 fake_kill):
        now = int(time.time())
        _seed_connections(keydb_path, [
            dict(port2=BOB_PORT2, conn_index=0, peer_ip='10.0.0.3',
                 peer_port=33333, transport=0, is_user=True,
                 connected_at=now - 5, last_update=now, pid=99005),
        ])
        login_as(client, ALICE_PORT1, ALICE_PASS)
        resp = client.post('/admin/%d/kill/0' % BOB_PORT2)
        assert resp.status_code == 403
        assert fake_kill.calls == []
        bob_entry = _read_entry(keydb_path, BOB_PORT2, 0)
        assert not (bob_entry.flags & conntdb_lib.CONN_FLAG_DROP_REQUESTED)


class TestPidValidation:
    def test_pid_with_wrong_comm_does_not_get_signaled(self, client,
                                                       keydb_path, fake_kill):
        """A PID whose /proc/<pid>/comm doesn't say 'supportproxy' (e.g.
        because it has been recycled) must NOT be signaled, even though
        the flag write did succeed (transactional with fetch)."""
        now = int(time.time())
        _seed_connections(keydb_path, [
            dict(port2=ALICE_PORT2, conn_index=0, peer_ip='10.0.0.1',
                 peer_port=12345, transport=0, is_user=True,
                 connected_at=now - 5, last_update=now, pid=99006),
        ])
        # PID 99006 is now an unrelated process, e.g. 'sshd'.
        fake_kill.comm.table[99006] = 'sshd'

        login_as(client, ALICE_PORT1, ALICE_PASS)
        resp = client.post('/me/kill/0', follow_redirects=True)
        assert resp.status_code == 200
        assert b'not found or already gone' in resp.data
        assert fake_kill.calls == []

    def test_dead_pid_is_skipped(self, client, keydb_path, fake_kill):
        """If /proc/<pid>/comm returns None (file missing → process
        gone), no signal is sent."""
        now = int(time.time())
        _seed_connections(keydb_path, [
            dict(port2=ALICE_PORT2, conn_index=0, peer_ip='10.0.0.1',
                 peer_port=12345, transport=0, is_user=True,
                 connected_at=now - 5, last_update=now, pid=99007),
        ])
        fake_kill.comm.table[99007] = None

        login_as(client, ALICE_PORT1, ALICE_PASS)
        resp = client.post('/me/kill/0', follow_redirects=True)
        assert resp.status_code == 200
        assert fake_kill.calls == []


class TestForwardCompat:
    def test_existing_tail_bytes_are_preserved_through_drop_set(self,
                                                                  client,
                                                                  keydb_path,
                                                                  fake_kill):
        """A future on-disk schema may add bytes after our struct.
        request_drop must rewrite the record without truncating that tail."""
        now = int(time.time())
        # Inject a record with extra trailing bytes (simulating a newer
        # writer) by writing it with our pack-and-append.
        conn_path = os.path.join(os.path.dirname(os.path.abspath(keydb_path)),
                                 conn_db.CONN_FILE)
        body = _pack_entry(port2=ALICE_PORT2, conn_index=0,
                           peer_ip='10.0.0.1', peer_port=12345, transport=0,
                           is_user=True, connected_at=now - 5,
                           last_update=now, pid=99008)
        future_tail = b'\xab\xcd\xef\x01\x02\x03\x04\x05'
        db = tdb.open(conn_path, hash_size=1024, tdb_flags=0,
                      flags=os.O_RDWR | os.O_CREAT, mode=0o600)
        db.transaction_start()
        db.store(struct.pack(conn_db.KEY_FORMAT, ALICE_PORT2, 0),
                 body + future_tail, tdb.REPLACE)
        db.transaction_prepare_commit()
        db.transaction_commit()
        db.close()

        login_as(client, ALICE_PORT1, ALICE_PASS)
        client.post('/me/kill/0')

        # tail must still be there after request_drop's read-modify-write.
        db = tdb.open(conn_path, hash_size=1024, tdb_flags=0,
                      flags=os.O_RDWR, mode=0o600)
        try:
            v = db.get(struct.pack(conn_db.KEY_FORMAT, ALICE_PORT2, 0))
        finally:
            db.close()
        assert v is not None
        assert v.endswith(future_tail)
