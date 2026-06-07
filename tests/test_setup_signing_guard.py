"""Regression test for Codex finding #6: a signed SETUP_SIGNING with
all-zero secret_key and zero initial_timestamp would persist into
keys.tdb. The next load_signing_key() would then unwire status->signing
and the generated parser would accept signed-flag frames without
checking a secret. The fix rejects that exact combination at
handle_setup_signing(), and load_signing_key() safe-fails if zero ever
lands in keys.tdb through another path.
"""
import os
import time

import pytest
from pymavlink import mavutil

os.environ.setdefault('MAVLINK_DIALECT', 'all')
os.environ.setdefault('MAVLINK20', '1')

from test_config import TEST_PORT_USER, TEST_PORT_ENGINEER, TEST_PASSPHRASE
from test_connections import passphrase_to_key, BaseConnectionTest


class TestSetupSigningGuard(BaseConnectionTest):

    def test_all_zero_setup_signing_rejected(self, test_server):
        self.wait_for_connection_close(test_server)
        # consume any stale output so the log assertion below only sees
        # output produced by this test
        test_server.get_new_output_since_last_check()

        key = passphrase_to_key(TEST_PASSPHRASE)

        # establish a user side so the engineer→user forward path exists
        user = mavutil.mavlink_connection(
            f'udpout:127.0.0.1:{TEST_PORT_USER}', source_system=1)
        user.mav.heartbeat_send(
            mavutil.mavlink.MAV_TYPE_QUADROTOR,
            mavutil.mavlink.MAV_AUTOPILOT_ARDUPILOTMEGA, 0, 0, 0)
        time.sleep(0.3)

        eng = mavutil.mavlink_connection(
            f'udpout:127.0.0.1:{TEST_PORT_ENGINEER}',
            source_system=11, source_component=21)
        eng.setup_signing(key, sign_outgoing=True)

        try:
            # drive enough signed heartbeats for the proxy to log
            # 'Got good signature' (and to defeat any pymavlink first-
            # packet edge case)
            for _ in range(6):
                eng.mav.heartbeat_send(
                    mavutil.mavlink.MAV_TYPE_GCS,
                    mavutil.mavlink.MAV_AUTOPILOT_INVALID,
                    0, 0, 0)
                time.sleep(0.3)

            # malicious SETUP_SIGNING: zero key + zero timestamp
            eng.mav.setup_signing_send(0, 0, b'\x00' * 32, 0)
            time.sleep(1.0)

            # post-rejection, signed heartbeats with the original key
            # must still validate (the proxy did not rotate its key)
            for _ in range(3):
                eng.mav.heartbeat_send(
                    mavutil.mavlink.MAV_TYPE_GCS,
                    mavutil.mavlink.MAV_AUTOPILOT_INVALID,
                    0, 0, 0)
                time.sleep(0.3)
        finally:
            eng.close()
            user.close()

        self.assert_with_proxy_log(
            test_server,
            test_server.proc.poll() is None,
            "supportproxy died after a malicious SETUP_SIGNING")

        # the rejection log line must appear, and the post-rejection
        # signed traffic must not have triggered a 'Set new signing key'
        stdout, stderr = test_server.get_new_output_since_last_check()
        combined = stdout + stderr
        self.assert_with_proxy_log(
            test_server,
            "Rejecting SETUP_SIGNING" in combined,
            "expected 'Rejecting SETUP_SIGNING' log line not seen")
        self.assert_with_proxy_log(
            test_server,
            "Set new signing key" not in combined,
            "proxy persisted the all-zero key (saw 'Set new signing key')")
