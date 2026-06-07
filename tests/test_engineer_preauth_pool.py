"""Regression test for Codex finding #2 (engineer-side pre-auth slot
DoS) and the structural half of #3.

Pre-fix: an unauthenticated client could open a TCP connection or send
a single UDP datagram and consume a conn2 slot indefinitely. With
MAX_COMM2_LINKS = 100 slots per port pair, ~100 idle attacker sockets
DoS the legitimate support engineer.

Fix: the per-pair child closes any conn2 slot that has not validated
a signed packet within CONN2_PREAUTH_SECONDS (=5s), measured from
slot creation. Slot counters are decremented properly on close, so
unauthenticated churn no longer monotonically inflates max_conn2_count.
"""
import os
import socket
import time

import pytest
from pymavlink import mavutil

os.environ.setdefault('MAVLINK_DIALECT', 'all')
os.environ.setdefault('MAVLINK20', '1')

from test_config import TEST_PORT_USER, TEST_PORT_ENGINEER, TEST_PASSPHRASE
from test_connections import passphrase_to_key, BaseConnectionTest


class TestEngineerPreauthPool(BaseConnectionTest):

    def test_unsigned_tcp_hog_doesnt_block_signed_engineer(self, test_server):
        # Fill most engineer slots with unauthenticated TCP connections.
        # Pre-fix these would camp until the proxy died / the user gave
        # up; post-fix the pre-auth deadline reaps them after ~5 s.
        hogs = []
        try:
            for _ in range(60):
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(2.0)
                s.connect(("127.0.0.1", TEST_PORT_ENGINEER))
                hogs.append(s)

            # Wait past the pre-auth deadline so the proxy reaps them.
            time.sleep(7)

            # consume stale output, then bring up a legitimate signed
            # engineer + a user side so the forwarding path is alive
            test_server.get_new_output_since_last_check()

            user = mavutil.mavlink_connection(
                f'udpout:127.0.0.1:{TEST_PORT_USER}', source_system=1)
            user.mav.heartbeat_send(
                mavutil.mavlink.MAV_TYPE_QUADROTOR,
                mavutil.mavlink.MAV_AUTOPILOT_ARDUPILOTMEGA, 0, 0, 0)
            time.sleep(0.3)

            key = passphrase_to_key(TEST_PASSPHRASE)
            eng = mavutil.mavlink_connection(
                f'udpout:127.0.0.1:{TEST_PORT_ENGINEER}',
                source_system=11, source_component=21)
            eng.setup_signing(key, sign_outgoing=True)
            for _ in range(6):
                eng.mav.heartbeat_send(
                    mavutil.mavlink.MAV_TYPE_GCS,
                    mavutil.mavlink.MAV_AUTOPILOT_INVALID, 0, 0, 0)
                time.sleep(0.3)
            eng.close()
            user.close()
        finally:
            for s in hogs:
                try:
                    s.close()
                except OSError:
                    pass

        self.assert_with_proxy_log(
            test_server,
            test_server.proc.poll() is None,
            "supportproxy died under TCP hog + signed engineer connect")

        stdout, stderr = test_server.get_new_output_since_last_check()
        combined = stdout + stderr
        # the legitimate engineer must have validated at least one signed
        # packet (proves the slot was available)
        self.assert_with_proxy_log(
            test_server,
            "Got good signature" in combined,
            "legitimate signed engineer never validated — slots not freed")
