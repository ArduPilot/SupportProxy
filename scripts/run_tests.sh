#!/bin/bash
# Thin wrapper that activates the project venv (if present) and forwards to
# scripts/run_tests.py. The real logic lives in the Python runner so it can
# accept -j for pytest-xdist parallelism.

set -e
cd "$(dirname "$0")/.."
test -f venv/bin/activate && source venv/bin/activate
exec python3 scripts/run_tests.py "$@"
