"""Tiny in-memory login throttle.

Two layers:

1. record_failure(ip) appends a timestamp to a sliding 60s window per
   remote address. is_blocked(ip) returns True once that window has
   accumulated MAX_FAILURES_PER_WINDOW entries.

2. The login route also sleeps a constant ~0.5s on each failed
   attempt. That dominates raw throughput for an attacker on a single
   IP regardless of the counter — a brute-forcer is throttled to
   ~120 attempts/min before the counter even kicks in. The counter
   then hard-caps the burst.

State is per-process and lives in memory; a restart resets all
counters. For the small admin UI this is fine — anything bigger
should swap in flask-limiter with a redis backend.
"""
import threading
import time

WINDOW_SECONDS = 60.0
MAX_FAILURES_PER_WINDOW = 10

_lock = threading.Lock()
_failures = {}  # ip -> [monotonic timestamps]


def _prune(ts_list, now):
    cutoff = now - WINDOW_SECONDS
    return [t for t in ts_list if t >= cutoff]


def is_blocked(ip):
    """True if this IP has hit the failure ceiling within the window."""
    if not ip:
        return False
    now = time.monotonic()
    with _lock:
        ts_list = _prune(_failures.get(ip, []), now)
        _failures[ip] = ts_list
        return len(ts_list) >= MAX_FAILURES_PER_WINDOW


def record_failure(ip):
    if not ip:
        return
    now = time.monotonic()
    with _lock:
        ts_list = _prune(_failures.get(ip, []), now)
        ts_list.append(now)
        _failures[ip] = ts_list


def record_success(ip):
    """Clear an IP's failure history once it logs in successfully so
    a few user typos don't lock them out for a full minute."""
    if not ip:
        return
    with _lock:
        _failures.pop(ip, None)


def reset_for_tests():
    with _lock:
        _failures.clear()
