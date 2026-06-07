"""Regression test for Codex finding #3 (counter-leak half): the
engineer UDP idle-timeout close path did not decrement
conn2_count/max_conn2_count, so repeated unauthenticated UDP churn
across MAX_COMM2_LINKS+ tuples drove max_conn2_count past the cap and
triggered the proxy's BUG exit(1) at supportproxy.cpp:438.

The fix decrements both counters on idle close and (defence in depth)
clamps + warns instead of exiting if the BUG guard ever fires.
"""
import socket
import time

import pytest

from test_config import TEST_PORT_ENGINEER
from test_connections import BaseConnectionTest


def _churn(port, count):
    """Send one short UDP datagram from `count` distinct ephemeral
    source ports. Each new tuple consumes a fresh conn2 slot at the
    proxy."""
    for _ in range(count):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.sendto(b"\xff" * 8, ("127.0.0.1", port))
        finally:
            s.close()


class TestEngineerUdpChurn(BaseConnectionTest):

    def test_udp_churn_does_not_BUG_exit(self, test_server):
        # MAX_COMM2_LINKS is 100. Burst 50 unsigned tuples; wait past the
        # 10s idle close threshold; then burst 60 more. Pre-fix this drove
        # max_conn2_count to 110 and tripped the BUG exit.
        _churn(TEST_PORT_ENGINEER, 50)
        time.sleep(11)
        _churn(TEST_PORT_ENGINEER, 60)
        time.sleep(1)

        self.assert_with_proxy_log(
            test_server,
            test_server.proc.poll() is None,
            "supportproxy died after engineer UDP-tuple churn")
