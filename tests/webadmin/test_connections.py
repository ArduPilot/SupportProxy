"""Tests for the live-connections feature: writes a synthesized
connections.tdb next to keys.tdb and verifies the reader, the
admin /admin/connections page, and the owner /me/ page all surface
records correctly.

The C++ side (per-port-pair child writing into connections.tdb) is
exercised separately by tests/test_connections.py — here we only
test the read path.
"""
import os
import socket
import struct
import time

import tdb

import keydb_lib
from webadmin import connections as conn_db

from _test_helpers import (ALICE_PASS, ALICE_PORT1, ALICE_PORT2, BOB_PASS,
                           BOB_PORT1, BOB_PORT2, login_as)


def _pack_entry(*, port2, conn_index, peer_ip, peer_port, transport,
                is_user, connected_at, last_update, rx=0, tx=0, pid=12345):
    return struct.pack(
        conn_db.PACK_FORMAT,
        conn_db.CONN_MAGIC, connected_at, last_update,
        port2, conn_index,
        pid, rx, tx,
        struct.unpack("<I", socket.inet_aton(peer_ip))[0],
        socket.htons(peer_port),
        transport, 1 if is_user else 0,
        0, 0,  # flags + pad
    )


def _pack_key(port2, conn_index):
    return struct.pack(conn_db.KEY_FORMAT, port2, conn_index)


def _seed_connections(keydb_path, records):
    """Write the given (kwargs) records into connections.tdb next to
    keydb_path. Each kwargs dict is forwarded to _pack_entry."""
    conn_path = os.path.join(os.path.dirname(os.path.abspath(keydb_path)),
                             conn_db.CONN_FILE)
    db = tdb.open(conn_path, hash_size=1024, tdb_flags=0,
                  flags=os.O_RDWR | os.O_CREAT, mode=0o600)
    db.transaction_start()
    for r in records:
        db.store(_pack_key(r['port2'], r['conn_index']),
                 _pack_entry(**r), tdb.REPLACE)
    db.transaction_prepare_commit()
    db.transaction_commit()
    db.close()


class TestConnectionsReader:
    def test_no_file_means_empty(self, app, keydb_path):
        # ensure no connections.tdb exists yet
        conn_path = os.path.join(os.path.dirname(os.path.abspath(keydb_path)),
                                 conn_db.CONN_FILE)
        assert not os.path.exists(conn_path)
        with app.app_context():
            assert list(conn_db.iter_active()) == []

    def test_reads_records(self, app, keydb_path):
        now = int(time.time())
        _seed_connections(keydb_path, [
            dict(port2=ALICE_PORT2, conn_index=0, peer_ip='10.0.0.1',
                 peer_port=12345, transport=0, is_user=True,
                 connected_at=now - 5, last_update=now, rx=10, tx=20),
            dict(port2=ALICE_PORT2, conn_index=1, peer_ip='10.0.0.2',
                 peer_port=22222, transport=1, is_user=False,
                 connected_at=now - 2, last_update=now, rx=3, tx=1),
        ])
        with app.app_context():
            entries = conn_db.list_active(now=now)
        assert len(entries) == 2
        # sorted by (port2, conn_index)
        assert entries[0].conn_index == 0
        assert entries[0].is_user == 1
        assert entries[0].peer_ip == '10.0.0.1'
        assert entries[0].peer_port == 12345
        assert entries[0].transport_name == 'udp'
        assert entries[0].uptime_s(now=now) == 5
        assert entries[1].transport_name == 'tcp'

    def test_stale_records_dropped(self, app, keydb_path):
        now = int(time.time())
        _seed_connections(keydb_path, [
            dict(port2=ALICE_PORT2, conn_index=0, peer_ip='10.0.0.1',
                 peer_port=1, transport=0, is_user=True,
                 connected_at=now - 100, last_update=now - 60),
            dict(port2=ALICE_PORT2, conn_index=1, peer_ip='10.0.0.2',
                 peer_port=2, transport=0, is_user=False,
                 connected_at=now - 5, last_update=now),
        ])
        with app.app_context():
            entries = conn_db.list_active(now=now, max_age_s=30)
        assert len(entries) == 1
        assert entries[0].conn_index == 1

    def test_list_for_port2_filters(self, app, keydb_path):
        now = int(time.time())
        _seed_connections(keydb_path, [
            dict(port2=ALICE_PORT2, conn_index=0, peer_ip='10.0.0.1',
                 peer_port=1, transport=0, is_user=True,
                 connected_at=now, last_update=now),
            dict(port2=BOB_PORT2, conn_index=0, peer_ip='10.0.0.9',
                 peer_port=1, transport=0, is_user=True,
                 connected_at=now, last_update=now),
        ])
        with app.app_context():
            assert len(conn_db.list_for_port2(ALICE_PORT2, now=now)) == 1
            assert len(conn_db.list_for_port2(BOB_PORT2, now=now)) == 1


class TestConnectionsRoutes:
    def test_admin_sees_all(self, client, keydb_path):
        now = int(time.time())
        _seed_connections(keydb_path, [
            dict(port2=ALICE_PORT2, conn_index=0, peer_ip='10.0.0.1',
                 peer_port=11111, transport=2, is_user=True,
                 connected_at=now - 3, last_update=now, rx=5, tx=6),
            dict(port2=BOB_PORT2, conn_index=1, peer_ip='10.0.0.2',
                 peer_port=22222, transport=3, is_user=False,
                 connected_at=now - 4, last_update=now),
        ])
        login_as(client, BOB_PORT1, BOB_PASS)
        resp = client.get('/admin/connections')
        assert resp.status_code == 200
        body = resp.data.decode()
        assert '10.0.0.1:11111' in body
        assert '10.0.0.2:22222' in body
        assert 'ws' in body  # transport label rendered
        assert 'wss' in body

    def test_owner_sees_only_own(self, client, keydb_path):
        now = int(time.time())
        _seed_connections(keydb_path, [
            dict(port2=ALICE_PORT2, conn_index=0, peer_ip='10.0.0.1',
                 peer_port=11111, transport=0, is_user=True,
                 connected_at=now, last_update=now),
            dict(port2=BOB_PORT2, conn_index=0, peer_ip='10.0.0.2',
                 peer_port=22222, transport=0, is_user=True,
                 connected_at=now, last_update=now),
        ])
        login_as(client, ALICE_PORT1, ALICE_PASS)
        resp = client.get('/me/')
        assert resp.status_code == 200
        body = resp.data.decode()
        assert '10.0.0.1:11111' in body
        # Bob's connection must NOT leak into Alice's view
        assert '10.0.0.2:22222' not in body

    def test_non_admin_denied_admin_route(self, client, keydb_path):
        login_as(client, ALICE_PORT1, ALICE_PASS)
        assert client.get('/admin/connections').status_code == 403

    def test_anonymous_denied(self, client):
        # require_admin aborts with 403 for non-admins, including
        # anonymous (matches existing /admin/ behaviour).
        assert client.get('/admin/connections').status_code == 403
