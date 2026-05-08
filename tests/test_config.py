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

# Second port pair for bi-directional signing tests, seeded with
# KEY_FLAG_BIDI_SIGN at startup. +100 keeps it clear of the non-bidi
# range across many xdist workers.
TEST_PORT_USER_BIDI = int(os.environ.get('TEST_PORT_USER_BIDI',
                                         str(TEST_PORT_USER + 100)))
TEST_PORT_ENGINEER_BIDI = int(os.environ.get('TEST_PORT_ENGINEER_BIDI',
                                             str(TEST_PORT_ENGINEER + 100)))
TEST_PORTS_BIDI = (TEST_PORT_USER_BIDI, TEST_PORT_ENGINEER_BIDI)

# Authentication configuration
TEST_PASSPHRASE = "shared_test_auth"

# Test timeouts and timing
DEFAULT_TEST_DURATION = 3
CONNECTION_TIMEOUT = 10
INITIALIZATION_TIMEOUT = 10

# Multiple connections test configuration
MAX_TCP_ENGINEER_CONNECTIONS = 8
MULTIPLE_CONNECTIONS_TEST_DURATION = 5
