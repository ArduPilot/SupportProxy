"""
Test configuration and shared utilities for UDPProxy testing.
"""
import os

# Resolve worker ID and per-worker port pair *before* importing test_config so
# its module-level constants pick up the right values. We assign directly
# (rather than os.environ.setdefault) because the pytest-xdist controller
# imports this module first and exports its env to workers; a setdefault would
# leave every worker stuck on worker 0's ports.
_worker = os.environ.get('PYTEST_XDIST_WORKER', 'gw0')
_WORKER_ID = int(_worker[2:]) if _worker.startswith('gw') else 0
os.environ['TEST_PORT_USER'] = str(14552 + _WORKER_ID * 2)
os.environ['TEST_PORT_ENGINEER'] = str(14553 + _WORKER_ID * 2)

import subprocess
import threading
import time
import pytest
from test_config import (TEST_PORT_USER, TEST_PORT_ENGINEER, TEST_PASSPHRASE,
                         KEYDB_PY, UDPPROXY_BIN)

os.environ['MAVLINK_DIALECT'] = 'ardupilotmega'
os.environ['MAVLINK20'] = '1'  # Ensure MAVLink2 is used


class UDPProxyProcess:
    def __init__(self, executable=UDPPROXY_BIN, cwd=None):
        self.proc = subprocess.Popen(
            [executable],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=1,
            universal_newlines=True,
            cwd=cwd,
        )
        self._stdout_lines = []
        self._stderr_lines = []
        self._stdout_thread = threading.Thread(
            target=self._read_stream, args=(self.proc.stdout, self._stdout_lines))
        self._stderr_thread = threading.Thread(
            target=self._read_stream, args=(self.proc.stderr, self._stderr_lines))
        self._stdout_thread.daemon = True
        self._stderr_thread.daemon = True
        self._stdout_thread.start()
        self._stderr_thread.start()
        self._stdout_last_idx = 0
        self._stderr_last_idx = 0

    def _read_stream(self, stream, lines):
        for line in iter(stream.readline, ''):
            lines.append(line)
        stream.close()

    def get_new_output_since_last_check(self):
        stdout_new = self._stdout_lines[self._stdout_last_idx:]
        stderr_new = self._stderr_lines[self._stderr_last_idx:]
        self._stdout_last_idx = len(self._stdout_lines)
        self._stderr_last_idx = len(self._stderr_lines)
        return ''.join(stdout_new), ''.join(stderr_new)

    def get_latest_output(self, num_lines=5):
        """Get the latest N lines from stdout/stderr combined."""
        if len(self._stdout_lines) >= num_lines:
            latest_stdout = self._stdout_lines[-num_lines:]
        else:
            latest_stdout = self._stdout_lines

        if len(self._stderr_lines) >= num_lines:
            latest_stderr = self._stderr_lines[-num_lines:]
        else:
            latest_stderr = self._stderr_lines

        return ''.join(latest_stdout), ''.join(latest_stderr)

    def terminate(self):
        self.proc.terminate()
        try:
            self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.proc.kill()


@pytest.fixture(scope="session", autouse=True)
def _worker_cwd(tmp_path_factory):
    """Each xdist worker runs in its own tmpdir so workers don't share a
    keys.tdb. cwd-relative paths in tests resolve to the per-worker dir."""
    workdir = tmp_path_factory.mktemp(f"udpproxy_w{_WORKER_ID}")
    os.chdir(workdir)
    yield workdir


@pytest.fixture(scope="session")
def test_server(_worker_cwd):
    """Pytest fixture to provide a test server instance."""
    workdir = _worker_cwd
    print(f"DEBUG: Setting up test_server (worker={_WORKER_ID}, cwd={workdir})")

    # Initialize the per-worker keys.tdb in the worker's cwd. We use the
    # absolute KEYDB_PY because cwd is no longer the repo root.
    subprocess.check_call(['python', KEYDB_PY, 'initialise'])

    port1, port2 = TEST_PORT_USER, TEST_PORT_ENGINEER

    # Idempotent: remove any prior entry, then add the test entry.
    subprocess.run(['python', KEYDB_PY, 'remove', str(port2)],
                   capture_output=True)

    result = subprocess.run([
        'python', KEYDB_PY, 'add', str(port1), str(port2),
        'test_user', TEST_PASSPHRASE
    ], capture_output=True, text=True)
    assert result.returncode == 0, f"Failed to setup database: {result.stderr}"

    # Verify database entry
    result = subprocess.run(['python', KEYDB_PY, 'list'],
                            capture_output=True, text=True)
    print(f"DEBUG: Database contents before starting UDPProxy:\n{result.stdout}")

    print("DEBUG: Starting UDPProxy with database ready...")
    server = UDPProxyProcess()  # cwd is already the worker's tmpdir

    # Wait for UDPProxy to load our port pair before yielding.
    expected_marker = f"Added port {port1}/{port2}"
    max_wait = 10
    start_time = time.time()

    while time.time() - start_time < max_wait:
        time.sleep(0.5)
        stdout, stderr = server.get_new_output_since_last_check()
        output = stdout + stderr

        if "Opening sockets" in output:
            print("DEBUG: UDPProxy has started opening sockets")
        if expected_marker in output:
            print(f"DEBUG: UDPProxy loaded port {port1}/{port2} - ready for testing!")
            break
    else:
        stdout, stderr = server.get_new_output_since_last_check()
        output = stdout + stderr
        print(f"DEBUG: UDPProxy initialization timeout. Output so far:\n{output}")
        server.terminate()
        raise RuntimeError(
            "UDPProxy failed to initialize properly within timeout")

    print("DEBUG: test_server fixture setup complete")
    yield server

    print("DEBUG: Tearing down test_server fixture")
    server.terminate()
    print("DEBUG: test_server fixture teardown complete")
