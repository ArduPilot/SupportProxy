#!/usr/bin/env python3
"""
Test runner for UDPProxy.

Default behaviour: build udpproxy, then run three pytest invocations
(connection, authentication, webadmin tests) — each phase has different
cwd / keys.tdb / process expectations, so they stay isolated.

Pass -j N for parallel test execution via pytest-xdist; each worker gets
its own tmpdir and port pair. -j 0 picks one worker per test (so every
test gets its own worker), useful for the connection phase where the
slowest worker pins wall-clock time.

Pass --list to enumerate tests across all three phases without running.

Pass test selectors as positional args (any pytest selector works:
file path, dir, NodeID, -k expression). When selectors are present the
runner does ONE pytest invocation against exactly what you asked for,
skipping the three-phase split.
"""
import argparse
import os
import re
import subprocess
import sys

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))

# Phases run in this order when no selectors are given. Each is a single
# pytest target; the runner spawns one pytest invocation per phase.
PHASES = [
    ('Connection Tests',     'tests/test_connections.py'),
    ('Authentication Tests', 'tests/test_authentication.py'),
    ('Webadmin Tests',       'tests/webadmin/'),
]


def run(cmd, **kwargs):
    print('+', ' '.join(cmd), flush=True)
    subprocess.check_call(cmd, **kwargs)


def run_capture(cmd):
    """Run a command, echo its stdout/stderr live, and return what was
    captured. Raises CalledProcessError on non-zero exit just like
    subprocess.check_call so callers can keep failing fast."""
    print('+', ' '.join(cmd), flush=True)
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT,
                         text=True, bufsize=1)
    captured = []
    for line in p.stdout:
        sys.stdout.write(line)
        sys.stdout.flush()
        captured.append(line)
    p.wait()
    if p.returncode != 0:
        raise subprocess.CalledProcessError(p.returncode, cmd)
    return ''.join(captured)


_DURATION_RE = re.compile(
    r'^\s*(\d+(?:\.\d+)?)s\s+(setup|call|teardown)\s+(.+?)\s*$')


def extract_timings(output):
    """Pull the per-test phase durations out of pytest --durations=0 output.

    Returns a list of (seconds, nodeid, phase) tuples.
    """
    timings = []
    in_section = False
    for line in output.splitlines():
        if 'slowest durations' in line:
            in_section = True
            continue
        if in_section:
            if line.startswith('='):
                in_section = False
                continue
            m = _DURATION_RE.match(line)
            if m:
                timings.append((float(m.group(1)), m.group(3), m.group(2)))
    return timings


def print_combined_timings(timings):
    """Sum setup+call+teardown per test, print sorted ascending so the
    slowest tests are at the bottom of the output (closest to the next
    prompt)."""
    totals = {}
    for d, nid, _ph in timings:
        totals[nid] = totals.get(nid, 0.0) + d
    if not totals:
        return
    print('\n=== Test timings (slowest last) ===')
    for nid, t in sorted(totals.items(), key=lambda kv: kv[1]):
        print('  %7.2fs  %s' % (t, nid))


def count_tests(target_args):
    """Return how many tests pytest would collect for the given args."""
    out = subprocess.check_output(
        [sys.executable, '-m', 'pytest', '--collect-only', '-q',
         '--no-header'] + target_args,
        text=True, stderr=subprocess.STDOUT)
    m = re.search(r'(\d+)\s+tests?\s+collected', out)
    return int(m.group(1)) if m else 0


def workers_for(j, target_args):
    """Resolve the -n value pytest-xdist should get.

    j is None  -> sequential (no -n flag)
    j == 0    -> one worker per test (collect first, count, use that)
    j >= 1    -> j workers
    """
    if j is None:
        return None
    if j == 0:
        n = count_tests(target_args)
        return max(n, 1)
    return j


def build_pytest_cmd(j, extra_args, target_args, timing=False):
    """Build the full pytest command including -n N when j is set."""
    cmd = [sys.executable, '-m', 'pytest', '-v']
    n = workers_for(j, target_args)
    if n is not None:
        cmd += ['-n', str(n)]
    if timing:
        # We pipe pytest's output to capture it; pytest's --color=auto
        # then sees a non-TTY and turns colors off. Force them back on if
        # OUR own stdout is a TTY so the user still sees green PASSED /
        # red FAILED in interactive runs.
        cmd += ['--durations=0', '--durations-min=0']
        if sys.stdout.isatty():
            cmd += ['--color=yes']
    return cmd + extra_args + target_args


def cmd_list():
    """Run pytest --collect-only -q across the three phases."""
    for label, target in PHASES:
        print('\n=== %s ===' % label, flush=True)
        subprocess.call([sys.executable, '-m', 'pytest', '--collect-only',
                         '-q', '--no-header', target])


def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('-j', type=int, default=None, metavar='N',
                    help='parallel pytest workers via pytest-xdist. '
                         '"-j 0" uses one worker per test; "-j N" '
                         '(N>=1) uses N workers; omit for sequential.')
    ap.add_argument('--no-build', action='store_true',
                    help='skip the make step (use existing udpproxy binary)')
    ap.add_argument('--list', action='store_true',
                    help='list all tests across the three phases and exit')
    ap.add_argument('--timing', action='store_true',
                    help='print per-test timing at the end, sorted ascending '
                         '(slowest test last)')
    ap.add_argument('selectors', nargs='*',
                    help='pytest selectors. Tokens with "/", "::", or a '
                         '".py" suffix are treated as file paths / NodeIDs. '
                         'Bare words become a case-insensitive substring '
                         'filter via pytest -k (multiple bare words OR\'d '
                         'together). Mixing both is fine. With selectors '
                         'the runner does one pytest invocation instead '
                         'of the three default phases.')
    args = ap.parse_args()

    os.chdir(REPO_ROOT)

    # --list never needs the binary or test execution.
    if args.list:
        cmd_list()
        return 0

    if not args.no_build:
        print('=== Building UDPProxy ===')
        run(['make', 'clean'])
        run(['make', 'distclean'])
        run(['make', 'all'])

    if not os.path.isfile('udpproxy'):
        sys.exit('ERROR: udpproxy binary not found')

    all_timings = []

    def run_one(extra_args, target_args):
        cmd = build_pytest_cmd(args.j, extra_args, target_args, args.timing)
        if args.timing:
            output = run_capture(cmd)
            all_timings.extend(extract_timings(output))
        else:
            run(cmd)

    if args.selectors:
        # User asked for specific tests. One invocation, exactly what they want.
        # Split selectors into path-like (passed as-is) vs bare keywords
        # (collapsed into a single pytest -k expression). pytest -k is
        # already a case-insensitive substring match.
        paths = []
        keywords = []
        for s in args.selectors:
            if '/' in s or '::' in s or s.endswith('.py'):
                paths.append(s)
            else:
                keywords.append(s)
        extra = ['-k', ' or '.join(keywords)] if keywords else []
        if not paths:
            # No path given: search the whole tests/ tree so the keyword
            # filter applies across all three phases.
            paths = ['tests/']
        print('\n=== Running selected tests ===')
        run_one(extra, paths)
    else:
        # Default: three separate phases (kept apart so phase 2 can wipe
        # keys.tdb without disturbing phase 1's live udpproxy fixture).
        for label, target in PHASES:
            print('\n=== Running %s ===' % label)
            run_one([], [target])

    if args.timing:
        print_combined_timings(all_timings)

    print('\nAll tests completed.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
