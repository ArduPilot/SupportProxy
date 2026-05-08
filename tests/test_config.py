"""
Centralized test configuration constants for UDPProxy testing.
This module provides a single source of truth for all test configuration.
"""
import os

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
KEYDB_PY = os.path.join(REPO_ROOT, 'keydb.py')
UDPPROXY_BIN = os.path.join(REPO_ROOT, 'udpproxy')

# Test port configuration. When running under pytest-xdist, conftest.py
# assigns per-worker port pairs via these env vars before this module is
# imported, so workers don't collide on listening ports.
TEST_PORT_USER = int(os.environ.get('TEST_PORT_USER', '14552'))
TEST_PORT_ENGINEER = int(os.environ.get('TEST_PORT_ENGINEER', '14553'))
TEST_PORTS = (TEST_PORT_USER, TEST_PORT_ENGINEER)

# Authentication configuration
TEST_PASSPHRASE = "shared_test_auth"

# Test timeouts and timing
DEFAULT_TEST_DURATION = 3
CONNECTION_TIMEOUT = 10
INITIALIZATION_TIMEOUT = 10

# Multiple connections test configuration
MAX_TCP_ENGINEER_CONNECTIONS = 8
MULTIPLE_CONNECTIONS_TEST_DURATION = 5
