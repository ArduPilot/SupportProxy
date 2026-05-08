#!/usr/bin/env python3
"""
Test runner for UDPProxy.

Builds the udpproxy binary then runs the pytest suite. Pass -j N to run
tests in parallel via pytest-xdist; each worker gets its own tmpdir and
port pair so they don't collide.
"""
import argparse
import os
import subprocess
import sys

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))


def run(cmd, **kwargs):
    print('+', ' '.join(cmd), flush=True)
    subprocess.check_call(cmd, **kwargs)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('-j', type=int, default=1,
                    help='parallel pytest workers via pytest-xdist (default: 1)')
    ap.add_argument('--no-build', action='store_true',
                    help='skip the make step (use existing udpproxy binary)')
    args, extra = ap.parse_known_args()

    os.chdir(REPO_ROOT)

    if not args.no_build:
        print('=== Building UDPProxy ===')
        run(['make', 'clean'])
        run(['make', 'distclean'])
        run(['make', 'all'])

    if not os.path.isfile('udpproxy'):
        sys.exit('ERROR: udpproxy binary not found')
    print('udpproxy binary built successfully')

    pytest_base = [sys.executable, '-m', 'pytest', '-v']
    if args.j > 1:
        pytest_base += ['-n', str(args.j)]

    # Two pytest invocations: connection tests first (uses test_server with a
    # live udpproxy), then authentication tests (mutates keys.tdb directly,
    # would clobber test_server's view if combined). Each invocation
    # parallelizes internally.
    print('\n=== Running Connection Tests ===')
    run(pytest_base + ['tests/test_connections.py'] + extra)

    print('\n=== Running Authentication Tests ===')
    run(pytest_base + ['tests/test_authentication.py'] + extra)

    print('\nAll tests completed.')


if __name__ == '__main__':
    main()
