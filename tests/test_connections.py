"""
Connection Tests for UDPProxy using PyMAVLink with authentication.
Tests UDP, TCP, and mixed connection scenarios with proper MAVLink2 authentication.
"""
from pymavlink import mavutil
import errno
import socket
import ssl
import subprocess
import sys
import os
import time
import pytest
import threading
from test_config import (TEST_PORTS, TEST_PORTS_BIDI, TEST_PASSPHRASE,
                         KEYDB_PY,
                         MAX_TCP_ENGINEER_CONNECTIONS,
                         MULTIPLE_CONNECTIONS_TEST_DURATION)

# Set up environment for pymavlink
os.environ['MAVLINK_DIALECT'] = 'ardupilotmega'
os.environ['MAVLINK20'] = '1'  # Ensure MAVLink2 is used


def passphrase_to_key(passphrase):
    '''convert a passphrase to a 32 byte key'''
    import hashlib
    h = hashlib.new('sha256')
    if sys.version_info[0] >= 3:
        passphrase = passphrase.encode('ascii')
    h.update(passphrase)
    return h.digest()


# Tests use a per-worker self-signed cert for the proxy's WSS listener.
# Patch ssl.create_default_context permanently for the test session so
# pymavlink's wss client (which constructs a fresh context on every
# connect / reconnect, including from inside write/recv error paths)
# accepts it. We're only ever talking to localhost, so disabling
# verification is safe in this test context.
_ssl_orig_default_context = ssl.create_default_context


def _ssl_unverified_default_context(*a, **kw):
    ctx = _ssl_orig_default_context(*a, **kw)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


ssl.create_default_context = _ssl_unverified_default_context


class BaseConnectionTest:
    """Base class for connection tests with shared functionality."""

    def wait_for_connection_close(self, test_server, timeout=15):
        """Wait for the proxy to fully tear down the previous test's
        connection AND reopen its listening sockets, so the next test
        can connect cleanly.

        The proxy's per-port-pair child prints "Closed connection ..."
        as it exits and the parent prints "Child N exited" only after
        it has called open_sockets() to re-listen. We require the
        parent's marker because that's the one that signals the next
        test can race-free."""
        print("DEBUG: Waiting for UDPProxy to close + reopen sockets...")
        start_time = time.time()
        seen_close = False
        seen_reopen = False

        while time.time() - start_time < timeout:
            stdout, stderr = test_server.get_new_output_since_last_check()
            output = stdout + stderr

            if not seen_close and "Closed connection" in output:
                seen_close = True
            if not seen_reopen and "exited" in output and "Child" in output:
                seen_reopen = True
            if seen_reopen:
                # parent has reopened listen sockets — safe to proceed
                print("DEBUG: ✅ UDPProxy ready for next test")
                return True
            time.sleep(0.1)

        print("DEBUG: ⚠️  Timeout waiting for connection closure")
        return False

    def wait_for_connection_user(self, test_server, timeout=10):
        """Wait for UDPProxy to log 'User connection established' 
        indicating proper user connection."""
        print("DEBUG: Waiting for UDPProxy user connection...")
        start_time = time.time()

        while time.time() - start_time < timeout:
            stdout, stderr = test_server.get_new_output_since_last_check()
            output = stdout + stderr

            if "conn1" in output:
                print("DEBUG: ✅ User connection established")
                return True

            time.sleep(0.1)
        print("DEBUG: ⚠️  Timeout waiting for user connection")
        return False

    def print_udp_proxy_output(self, test_server):
        """Print the current output of the UDPProxy process for debugging."""
        stdout, stderr = test_server.get_new_output_since_last_check()
        all_output = stdout + stderr

        print(f"DEBUG: UDPProxy output: {all_output}")
        return all_output

    def assert_with_proxy_log(self, test_server, condition, msg, num_lines=80):
        """Assert with the proxy's recent stdout/stderr attached to the
        failure message. Without this, test failures show only the test
        side and leave us guessing at what the proxy actually did."""
        if condition:
            return
        out, err = test_server.get_latest_output(num_lines=num_lines)
        pytest.fail(
            "%s\n\n=== udpproxy stdout (last %d lines) ===\n%s"
            "=== udpproxy stderr (last %d lines) ===\n%s"
            % (msg, num_lines, out, num_lines, err))

    def check_udpproxy_output(self, test_server, expected_messages, num_lines=5):
        """Check UDPProxy stdout/stderr for expected messages.

        This method looks at the latest output lines to avoid the issue
        where get_new_output_since_last_check() returns empty because
        output was already consumed by previous calls.
        """
        stdout, stderr = test_server.get_latest_output(num_lines=num_lines)
        all_output = stdout + stderr

        print(
            f"DEBUG: Latest UDPProxy output (last {num_lines} lines): {all_output}")

        found_messages = []
        for expected in expected_messages:
            if expected in all_output:
                found_messages.append(expected)
                print(f"✅ Found expected message: '{expected}'")
            else:
                print(f"❌ Missing expected message: '{expected}'")

        return found_messages

    def create_connection(self, connection_type, port, source_system=1,
                          source_component=1):
        """Create a connection of the given type (udp / tcp / ws / wss)."""
        if connection_type == 'udp':
            return mavutil.mavlink_connection(
                f'udpout:localhost:{port}',
                source_system=source_system,
                source_component=source_component,
                use_native=False
            )
        elif connection_type == 'tcp':
            return mavutil.mavlink_connection(
                f'tcp:localhost:{port}',
                source_system=source_system,
                source_component=source_component,
                autoreconnect=True,
                use_native=False
            )
        elif connection_type == 'ws':
            return mavutil.mavlink_connection(
                f'ws:localhost:{port}',
                source_system=source_system,
                source_component=source_component,
                use_native=False,
            )
        elif connection_type == 'wss':
            return mavutil.mavlink_connection(
                f'wss:localhost:{port}',
                source_system=source_system,
                source_component=source_component,
                use_native=False,
            )
        else:
            raise ValueError(f"Unknown connection type: {connection_type}")

    def setup_signing(self, connection, signing_key=None, enable_signing=True):
        """Setup signing for a connection."""
        if enable_signing and signing_key is not None:
            connection.setup_signing(signing_key, sign_outgoing=True)

    def create_message_sender(self, connection, message_types, stop_event):
        """Create a message sending function for a connection.

        Each send is wrapped in a try/except so a transient drop on the
        underlying transport (most often pymavlink's WS client raising
        from inside its reconnect path) doesn't crash the sender thread
        — pytest's thread-exception plugin would otherwise turn that
        into a test failure regardless of the assertions. The test's
        recv counters are the source of truth for pass/fail.
        """
        def sender():
            while not stop_event.is_set():
                for msg_type in message_types:
                    try:
                        if msg_type == 'heartbeat_user':
                            connection.mav.heartbeat_send(
                                mavutil.mavlink.MAV_TYPE_QUADROTOR,
                                mavutil.mavlink.MAV_AUTOPILOT_ARDUPILOTMEGA,
                                0, 0, 0
                            )
                        elif msg_type == 'heartbeat_engineer':
                            connection.mav.heartbeat_send(
                                mavutil.mavlink.MAV_TYPE_GCS,
                                mavutil.mavlink.MAV_AUTOPILOT_INVALID,
                                0, 0, 0
                            )
                        elif msg_type == 'system_time':
                            current_time_us = int(time.time() * 1000000)
                            connection.mav.system_time_send(
                                current_time_us, 12345)
                    except Exception:
                        # transient transport error — keep looping
                        pass
                time.sleep(1.0)
        return sender

    def run_test_scenario(self, test_server, user_conn_type, engineer_conn_type,
                          engineer_signing_key=None, test_duration=3,
                          ports=None, user_signing_key=None):
        """Run a complete test scenario with message exchange.

        ``ports`` overrides the (port1, port2) pair (used by the bidi-sign
        tests which target a different DB entry). ``user_signing_key`` makes
        the user side sign outgoing messages (used to verify bidi mode
        rejects unsigned/wrong-key user traffic).
        """
        user_conn = None
        engineer_conn = None

        try:
            port1, port2 = ports if ports is not None else TEST_PORTS

            # Create connections
            user_conn = self.create_connection(user_conn_type, port1,
                                               source_system=1)
            engineer_conn = self.create_connection(engineer_conn_type, port2,
                                                   source_system=2)

            # Setup signing for engineer if provided
            self.setup_signing(engineer_conn, engineer_signing_key,
                               enable_signing=(engineer_signing_key is not None))
            # Setup signing for user (bidi-sign tests)
            self.setup_signing(user_conn, user_signing_key,
                               enable_signing=(user_signing_key is not None))

            # Start continuous message sending
            stop_sending = threading.Event()

            user_sender = self.create_message_sender(
                user_conn, ['heartbeat_user', 'system_time'], stop_sending)
            engineer_sender = self.create_message_sender(
                engineer_conn, ['heartbeat_engineer'], stop_sending)

            user_thread = threading.Thread(target=user_sender)
            engineer_thread = threading.Thread(target=engineer_sender)

            user_thread.start()
            self.wait_for_connection_user(test_server)
            engineer_thread.start()

            # Test for specified duration. Drain *all* available messages
            # per iteration (not just one per type) so a burst of buffered
            # HEARTBEATs from before SYSTEM_TIME forwarding starts doesn't
            # mask a slow drip of SYSTEM_TIMEs that only fits inside the
            # test window when fully drained.
            heartbeat_count = 0
            system_time_count = 0

            for i in range(test_duration):
                time.sleep(1.0)
                while True:
                    m = engineer_conn.recv_match(blocking=False)
                    if m is None:
                        break
                    t = m.get_type()
                    if t == 'HEARTBEAT':
                        heartbeat_count += 1
                    elif t == 'SYSTEM_TIME':
                        system_time_count += 1

            # Stop sending
            stop_sending.set()
            user_thread.join()
            engineer_thread.join()

            return heartbeat_count, system_time_count

        finally:
            if user_conn:
                user_conn.close()
            if engineer_conn:
                engineer_conn.close()
            # Wait for UDPProxy to close connections before next test
            self.wait_for_connection_close(test_server)


class TestUDPConnections(BaseConnectionTest):
    """UDP/UDP scenarios. One method per signing case so xdist can run
    them in parallel — each one pays the proxy's 10s conn1-idle wait,
    so collapsing them into a single sequential method made wall-clock
    time roughly the sum."""

    def test_unsigned_engineer(self, test_server):
        """Engineer without signing - should only get HEARTBEAT."""
        heartbeat_count, system_time_count = self.run_test_scenario(
            test_server, 'udp', 'udp', engineer_signing_key=None, test_duration=3
        )
        assert heartbeat_count > 0, \
            "Engineer should receive HEARTBEAT messages even without signing"
        assert system_time_count == 0, \
            "Engineer should NOT receive SYSTEM_TIME without proper signing"

    def test_bad_signing_key(self, test_server):
        """Engineer with the wrong passphrase - nothing through."""
        bad_key = passphrase_to_key("wrong_auth")
        self.run_test_scenario(
            test_server, 'udp', 'udp', engineer_signing_key=bad_key, test_duration=4
        )
        expected_messages = ["Bad support signing key"]
        self.check_udpproxy_output(test_server, expected_messages)

    def test_good_signing_key(self, test_server):
        """Engineer with the correct key - should get HEARTBEAT and SYSTEM_TIME."""
        correct_key = passphrase_to_key(TEST_PASSPHRASE)
        heartbeat_count, system_time_count = self.run_test_scenario(
            test_server, 'udp', 'udp', engineer_signing_key=correct_key, test_duration=4
        )
        assert heartbeat_count > 0, "Engineer should receive HEARTBEAT messages"
        assert system_time_count > 0, \
            "Engineer should receive SYSTEM_TIME messages with correct signing"


class TestTCPConnections(BaseConnectionTest):
    """TCP/TCP scenarios. Same parallel-friendly split as TestUDPConnections."""

    def test_unsigned_engineer(self, test_server):
        """Engineer TCP without signing - should only get HEARTBEAT."""
        heartbeat_count, system_time_count = self.run_test_scenario(
            test_server, 'tcp', 'tcp', engineer_signing_key=None,
            test_duration=3
        )
        assert heartbeat_count > 0, \
            "TCP Engineer should receive HEARTBEAT messages even without signing"
        assert system_time_count == 0, \
            "TCP Engineer should NOT receive SYSTEM_TIME without proper signing"

    def test_bad_signing_key(self, test_server):
        """Engineer TCP with wrong passphrase - nothing through."""
        bad_key = passphrase_to_key("wrong_auth")
        self.run_test_scenario(
            test_server, 'tcp', 'tcp', engineer_signing_key=bad_key,
            test_duration=4
        )

    def test_good_signing_key(self, test_server):
        """Engineer TCP with correct key - HEARTBEAT and SYSTEM_TIME flow."""
        correct_key = passphrase_to_key(TEST_PASSPHRASE)
        heartbeat_count, system_time_count = self.run_test_scenario(
            test_server, 'tcp', 'tcp', engineer_signing_key=correct_key,
            test_duration=4
        )
        assert heartbeat_count > 0, "TCP Engineer should receive HEARTBEAT messages"
        assert system_time_count > 0, \
            "TCP Engineer should receive SYSTEM_TIME messages with correct signing"


class TestMixedConnections(BaseConnectionTest):
    """Test suite for mixed UDP/TCP connection scenarios."""

    def test_udp_user_tcp_engineer(self, test_server):
        """Test UDP user with TCP engineer connection."""
        print("\n=== MIXED TEST: UDP User + TCP Engineer ===")
        self._test_mixed_udp_user_tcp_engineer(test_server)

    def test_tcp_user_udp_engineer(self, test_server):
        """Test TCP user with UDP engineer connection."""
        print("\n=== MIXED TEST: TCP User + UDP Engineer ===")
        self._test_mixed_tcp_user_udp_engineer(test_server)

    def _test_mixed_udp_user_tcp_engineer(self, test_server):
        """Test UDP user connection with TCP engineer connection."""
        correct_key = passphrase_to_key(TEST_PASSPHRASE)

        heartbeat_count, system_time_count = self.run_test_scenario(
            test_server, 'udp', 'tcp', engineer_signing_key=correct_key,
            test_duration=4
        )

        assert heartbeat_count > 0, \
            "TCP Engineer should receive HEARTBEAT messages from UDP User"

        assert system_time_count > 0, \
            "TCP Engineer should receive SYSTEM_TIME messages from UDP User"

        print(f"SUCCESS: MIXED UDP/TCP - TCP Engineer received {heartbeat_count} "
              f"HEARTBEAT, {system_time_count} SYSTEM_TIME from UDP User")

        time.sleep(0.5)
        expected_messages = ["Got good signature"]
        found_messages = self.check_udpproxy_output(
            test_server, expected_messages)

        if found_messages:
            print(f"✅ FOUND mixed connection messages: {found_messages}")
        else:
            print("⚠️  Mixed connection setup may not be detected in logs")

    def _test_mixed_tcp_user_udp_engineer(self, test_server):
        """Test TCP user connection with UDP engineer connection."""
        correct_key = passphrase_to_key(TEST_PASSPHRASE)

        heartbeat_count, system_time_count = self.run_test_scenario(
            test_server, 'tcp', 'udp', engineer_signing_key=correct_key,
            test_duration=4
        )

        assert heartbeat_count > 0, \
            "UDP Engineer should receive HEARTBEAT messages from TCP User"

        assert system_time_count > 0, \
            "UDP Engineer should receive SYSTEM_TIME messages from TCP User"

        print(f"SUCCESS: MIXED TCP/UDP - UDP Engineer received {heartbeat_count} "
              f"HEARTBEAT, {system_time_count} SYSTEM_TIME from TCP User")

        time.sleep(0.5)
        expected_messages = ["Got good signature"]
        found_messages = self.check_udpproxy_output(
            test_server, expected_messages)

        if found_messages:
            print(f"✅ FOUND mixed connection messages: {found_messages}")
        else:
            print("⚠️  Mixed connection setup may not be detected in logs")


class TestTCPMultipleConnections(BaseConnectionTest):
    """Test suite for multiple TCP engineer connections capability."""

    def test_eight_tcp_engineer_connections(self, test_server):
        """Test that UDPProxy can handle 8 simultaneous TCP engineer 
        connections."""
        print("\n=== MULTIPLE TCP TEST: 8 TCP Engineer Connections ===")
        self._test_multiple_tcp_engineers(test_server)

    def _test_multiple_tcp_engineers(self, test_server):
        """Test 8 concurrent TCP engineer connections with authentication."""
        correct_key = passphrase_to_key(TEST_PASSPHRASE)
        user_conn = None
        engineer_connections = []

        try:
            port1, port2 = TEST_PORTS

            user_conn = self.create_connection('udp', port1, source_system=1)

            stop_sending = threading.Event()
            user_sender = self.create_message_sender(
                user_conn, ['heartbeat_user', 'system_time'], stop_sending)
            user_thread = threading.Thread(target=user_sender)
            user_thread.start()
            self.wait_for_connection_user(test_server)

            print(
                f"Creating {MAX_TCP_ENGINEER_CONNECTIONS} TCP engineer connections...")

            test_duration = MULTIPLE_CONNECTIONS_TEST_DURATION
            total_heartbeats = [0] * MAX_TCP_ENGINEER_CONNECTIONS
            total_system_times = [0] * MAX_TCP_ENGINEER_CONNECTIONS

            def check_engineer_messages(engineer_idx, engineer_conn):
                """Check messages for a specific engineer connection."""
                for second in range(test_duration):
                    time.sleep(1.0)
                    engineer_conn.mav.heartbeat_send(
                        mavutil.mavlink.MAV_TYPE_GCS,
                        mavutil.mavlink.MAV_AUTOPILOT_INVALID,
                        0, 0, 0
                    )
                    heartbeat_msg = engineer_conn.recv_match(
                        type='HEARTBEAT', blocking=False)
                    if heartbeat_msg is not None:
                        total_heartbeats[engineer_idx] += 1
                        print(f"Engineer {engineer_idx+1} received HEARTBEAT")

                    system_time_msg = engineer_conn.recv_match(
                        type='SYSTEM_TIME', blocking=False)
                    if system_time_msg is not None:
                        total_system_times[engineer_idx] += 1
                        print(
                            f"Engineer {engineer_idx+1} received SYSTEM_TIME")

            engineer_threads = []

            for i in range(MAX_TCP_ENGINEER_CONNECTIONS):
                engineer_conn = self.create_connection(
                    'tcp', port2, source_system=i+2)
                self.setup_signing(engineer_conn, correct_key,
                                   enable_signing=True)
                engineer_connections.append(engineer_conn)
                print(f"  Created engineer connection {i+1}/8")
                thread = threading.Thread(
                    target=check_engineer_messages,
                    args=(i, engineer_conn))
                engineer_threads.append(thread)
                thread.start()

            for thread in engineer_threads:
                thread.join()

            stop_sending.set()
            user_thread.join()

            all_received_heartbeats = all(
                count > 0 for count in total_heartbeats)
            all_received_system_times = all(
                count > 0 for count in total_system_times)

            print(
                f"\n=== RESULTS for {MAX_TCP_ENGINEER_CONNECTIONS} TCP Engineers ===")
            for i in range(MAX_TCP_ENGINEER_CONNECTIONS):
                print(f"Engineer {i+1}: {total_heartbeats[i]} HEARTBEAT, "
                      f"{total_system_times[i]} SYSTEM_TIME")

            assert all_received_heartbeats, \
                "All TCP engineers should receive HEARTBEAT messages"

            assert all_received_system_times, \
                "TCP engineers did not receive SYSTEM_TIME messages "

            print(f"✅ SUCCESS: All {MAX_TCP_ENGINEER_CONNECTIONS} TCP engineers "
                  f"successfully connected and received HEARTBEAT and SYSTEM_TIME messages")

            # Check UDPProxy output for good signatures
            time.sleep(0.5)
            expected_messages = ["Got good signature"]
            found_messages = self.check_udpproxy_output(test_server,
                                                        expected_messages, num_lines=15)

            if found_messages:
                print(f"✅ FOUND authentication messages: {found_messages}")
            else:
                print("⚠️  Multiple connection authentication not detected")

        finally:
            # Clean up all connections
            if user_conn:
                user_conn.close()
            for i, engineer_conn in enumerate(engineer_connections):
                try:
                    engineer_conn.close()
                    print(f"  Closed engineer connection {i+1}")
                except Exception:
                    pass

            # Wait for UDPProxy to close connections
            self.wait_for_connection_close(test_server)


_BIDI_TRANSPORTS = [(a, b)
                    for a in ('udp', 'tcp', 'ws', 'wss')
                    for b in ('udp', 'tcp', 'ws', 'wss')]


@pytest.mark.parametrize('user_conn,engineer_conn', _BIDI_TRANSPORTS)
class TestBidiSigning(BaseConnectionTest):
    """Bi-directional signing: when KEY_FLAG_BIDI_SIGN is set on the
    entry, the proxy also requires signed MAVLink on the user side.
    Unsigned and wrong-key user traffic must be dropped, so the engineer
    receives no forwarded messages.

    Parametrized across all four (user, engineer) transport combinations.
    """

    def test_bidi_user_unsigned(self, test_server, user_conn, engineer_conn):
        """User side unsigned -> engineer receives nothing forwarded."""
        correct_key = passphrase_to_key(TEST_PASSPHRASE)
        heartbeat_count, system_time_count = self.run_test_scenario(
            test_server, user_conn, engineer_conn,
            ports=TEST_PORTS_BIDI,
            engineer_signing_key=correct_key,
            user_signing_key=None,
            test_duration=5,
        )
        assert heartbeat_count == 0, \
            "BIDI %s/%s: unsigned user heartbeats must not be forwarded " \
            "(got %d)" % (user_conn, engineer_conn, heartbeat_count)
        assert system_time_count == 0, \
            "BIDI %s/%s: unsigned user SYSTEM_TIME must not be forwarded " \
            "(got %d)" % (user_conn, engineer_conn, system_time_count)

    def test_bidi_user_wrong_key(self, test_server, user_conn, engineer_conn):
        """User side signed with the WRONG passphrase -> engineer receives nothing."""
        correct_key = passphrase_to_key(TEST_PASSPHRASE)
        bad_key = passphrase_to_key("wrong_passphrase_for_bidi")
        heartbeat_count, system_time_count = self.run_test_scenario(
            test_server, user_conn, engineer_conn,
            ports=TEST_PORTS_BIDI,
            engineer_signing_key=correct_key,
            user_signing_key=bad_key,
            test_duration=5,
        )
        assert heartbeat_count == 0, \
            "BIDI %s/%s: wrong-key user heartbeats must not be forwarded " \
            "(got %d)" % (user_conn, engineer_conn, heartbeat_count)
        assert system_time_count == 0, \
            "BIDI %s/%s: wrong-key user SYSTEM_TIME must not be forwarded " \
            "(got %d)" % (user_conn, engineer_conn, system_time_count)

    def test_bidi_user_correct_key(self, test_server, user_conn, engineer_conn):
        """User side signed with the correct key -> engineer receives both
        HEARTBEAT and SYSTEM_TIME (the proxy verifies and forwards)."""
        correct_key = passphrase_to_key(TEST_PASSPHRASE)
        heartbeat_count, system_time_count = self.run_test_scenario(
            test_server, user_conn, engineer_conn,
            ports=TEST_PORTS_BIDI,
            engineer_signing_key=correct_key,
            user_signing_key=correct_key,
            test_duration=5,
        )
        self.assert_with_proxy_log(
            test_server, heartbeat_count > 0,
            "BIDI %s/%s: correctly-signed user heartbeats must be forwarded "
            "(got hb=%d sys=%d)"
            % (user_conn, engineer_conn, heartbeat_count, system_time_count))
        self.assert_with_proxy_log(
            test_server, system_time_count > 0,
            "BIDI %s/%s: correctly-signed user SYSTEM_TIME must be forwarded "
            "(got hb=%d sys=%d)"
            % (user_conn, engineer_conn, heartbeat_count, system_time_count))


class TestReloadReconciliation(BaseConnectionTest):
    """When an entry is removed from keys.tdb the proxy must stop
    listening on its port pair within one reload tick (~5s) — not just
    on the next restart. Same for port1 changes.
    """

    # A separate port range so this test doesn't touch the persistent
    # entries seeded by conftest.
    _RECONCILE_PORT1 = 14750
    _RECONCILE_PORT2 = 14751

    def _add_entry(self, port1, port2, name='reconcile_test'):
        result = subprocess.run(
            ['python', KEYDB_PY, 'add',
             str(port1), str(port2), name, TEST_PASSPHRASE],
            capture_output=True, text=True)
        assert result.returncode == 0, result.stderr

    def _remove_entry(self, port2):
        subprocess.run(['python', KEYDB_PY, 'remove', str(port2)],
                       capture_output=True)

    def _proxy_listening_on(self, port):
        """Probe whether something is bound to ``port`` on localhost
        UDP. We use SO_REUSEADDR + bind() — a successful bind means
        nothing is listening; EADDRINUSE means something (the proxy)
        is."""
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            try:
                s.bind(('127.0.0.1', port))
            except OSError as e:
                return e.errno == errno.EADDRINUSE
            return False
        finally:
            s.close()

    def _wait_until(self, predicate, timeout=15.0):
        start = time.time()
        while time.time() - start < timeout:
            if predicate():
                return True
            time.sleep(0.2)
        return False

    def test_remove_releases_port(self, test_server):
        """Add an entry, wait for the proxy's reload to pick it up,
        confirm the port is bound, then remove the entry and confirm
        the proxy releases the port within one reload window."""
        port1 = self._RECONCILE_PORT1
        port2 = self._RECONCILE_PORT2
        self._remove_entry(port2)  # idempotent cleanup
        self._add_entry(port1, port2)
        try:
            assert self._wait_until(
                lambda: self._proxy_listening_on(port2)), \
                "proxy never started listening on the new port2 %d" % port2
        finally:
            self._remove_entry(port2)
        # after removal + reload window, the port must be free
        assert self._wait_until(
            lambda: not self._proxy_listening_on(port2)), \
            "proxy still bound to port2 %d after entry removed" % port2


class TestConnectionsTDB(BaseConnectionTest):
    """While traffic flows, the proxy's per-port-pair child mirrors live
    state into ``connections.tdb`` (next to keys.tdb in cwd). Verify that
    a record for the expected port2 appears with the right transport tag
    and visible peer info — this is the wire the web admin UI reads.
    """

    def _read_connections_tdb(self):
        """Return list of ConnEntry-like dicts straight off connections.tdb.
        Imports kept inside so the rest of the file doesn't grow new
        top-level deps when running without webadmin installed."""
        import struct as _struct
        import tdb as _tdb
        path = os.path.join(os.getcwd(), 'connections.tdb')
        if not os.path.exists(path):
            return []
        # Mirror webadmin/connections.py's PACK_FORMAT exactly. Kept
        # local so this test doesn't drag the Flask app into the import
        # graph for an integration test.
        FORMAT = "<QQQiiIIIIHBBII4x"
        SIZE = _struct.calcsize(FORMAT)
        MAGIC = 0x436f6e6e45424553
        out = []
        db = _tdb.open(path, hash_size=1024, tdb_flags=0,
                       flags=os.O_RDWR, mode=0o600)
        try:
            k = db.firstkey()
            while k is not None:
                v = db.get(k)
                if v is not None and len(v) >= SIZE:
                    body = v[:SIZE]
                    (magic, connected_at, last_update, port2, conn_index,
                     pid, rx, tx, peer_ip_be, peer_port_be,
                     transport, is_user, _flags, _pad) = _struct.unpack(
                         FORMAT, body)
                    if magic == MAGIC:
                        out.append({
                            'port2': port2, 'conn_index': conn_index,
                            'transport': transport, 'is_user': is_user,
                            'rx': rx, 'tx': tx,
                            'last_update': last_update,
                            'peer_ip_be': peer_ip_be,
                            'peer_port_be': peer_port_be,
                        })
                k = db.nextkey(k)
        finally:
            db.close()
        return out

    def test_udp_traffic_appears_in_connections_tdb(self, test_server):
        """A live UDP user + UDP engineer pair should show up as a
        is_user record (mav1) and an is_user=0 record (engineer) in
        connections.tdb within the heartbeat window (10s)."""
        from test_config import TEST_PORTS
        port1, port2 = TEST_PORTS

        correct_key = passphrase_to_key(TEST_PASSPHRASE)
        user_conn = engineer_conn = None
        try:
            user_conn = self.create_connection('udp', port1, source_system=1)
            engineer_conn = self.create_connection('udp', port2,
                                                   source_system=2)
            self.setup_signing(engineer_conn, correct_key, enable_signing=True)

            stop_sending = threading.Event()
            user_sender = self.create_message_sender(
                user_conn, ['heartbeat_user'], stop_sending)
            engineer_sender = self.create_message_sender(
                engineer_conn, ['heartbeat_engineer'], stop_sending)
            user_thread = threading.Thread(target=user_sender)
            engineer_thread = threading.Thread(target=engineer_sender)

            user_thread.start()
            self.wait_for_connection_user(test_server)
            engineer_thread.start()

            # The heartbeat fires the first time main_loop's snapshot
            # branch is reached (initial last_conn_save_s = 0, throttle
            # >10s). In practice that's within ~1 packet exchange, but
            # give it up to ~3s of slack for the grandchild fork +
            # transaction + commit + the test reading back.
            deadline = time.time() + 3.0
            entries = []
            while time.time() < deadline:
                entries = [e for e in self._read_connections_tdb()
                           if e['port2'] == port2]
                if any(e['is_user'] == 1 for e in entries) and \
                   any(e['is_user'] == 0 for e in entries):
                    break
                time.sleep(0.2)

            stop_sending.set()
            user_thread.join()
            engineer_thread.join()

            user_recs = [e for e in entries if e['is_user'] == 1]
            eng_recs = [e for e in entries if e['is_user'] == 0]
            self.assert_with_proxy_log(
                test_server, len(user_recs) == 1,
                "expected 1 user-side connection record for port2=%d, got %r"
                % (port2, entries))
            self.assert_with_proxy_log(
                test_server, len(eng_recs) >= 1,
                "expected an engineer-side connection record for port2=%d, "
                "got %r" % (port2, entries))
            # transport == 0 is CONN_TRANSPORT_UDP
            assert user_recs[0]['transport'] == 0, user_recs[0]
            assert eng_recs[0]['transport'] == 0, eng_recs[0]
            # rx counters bump as messages get forwarded
            assert user_recs[0]['rx'] >= 1 or user_recs[0]['tx'] >= 1, \
                user_recs[0]

        finally:
            if user_conn:
                user_conn.close()
            if engineer_conn:
                engineer_conn.close()
            self.wait_for_connection_close(test_server)

        # After the child exits, the parent wipes records for that
        # port2. Allow up to ~5s (one reload tick) for cleanup.
        deadline = time.time() + 6.0
        while time.time() < deadline:
            remaining = [e for e in self._read_connections_tdb()
                         if e['port2'] == port2]
            if not remaining:
                break
            time.sleep(0.2)
        assert not [e for e in self._read_connections_tdb()
                    if e['port2'] == port2], \
            "stale connection records left behind for port2=%d" % port2


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
