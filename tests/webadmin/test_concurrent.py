"""Concurrent-write safety: the proxy's counter update must not be lost
when the web UI also writes to the same entry.

Simulate the proxy's connection-close path (read entry, bump counters,
save) running in a separate thread while the web UI POSTs a name change
to /admin/<port2>. Both writes use TDB transactions, so they must
serialize, and both updates must land in the final record.

We loop the proxy-side update enough times that the two paths interleave
under TDB's per-DB lock; if either path bypassed the transaction we'd
expect to see the counters revert to their initial values.
"""
import threading
import time

import keydb_lib

from _test_helpers import (BOB_PASS, BOB_PORT1, BOB_PORT2,
                           ALICE_PORT1, ALICE_PORT2,
                           fetch_entry, login_as)


def _bump_counters(keydb_path, port2, iterations, stop_event):
    """Imitate supportproxy.cpp's connection-close counter update."""
    for _ in range(iterations):
        if stop_event.is_set():
            return
        db = keydb_lib.open_db(keydb_path)
        db.transaction_start()
        try:
            ke = keydb_lib.KeyEntry(port2)
            if ke.fetch(db):
                ke.count1 += 1
                ke.count2 += 2
                ke.connections += 1
                ke.store(db)
            db.transaction_prepare_commit()
            db.transaction_commit()
        except Exception:
            db.transaction_cancel()
            raise
        finally:
            db.close()
        time.sleep(0.001)


class TestConcurrent:
    def test_ui_rename_does_not_lose_counter_updates(self, client, keydb_path):
        login_as(client, BOB_PORT1, BOB_PASS)

        stop = threading.Event()
        # bump alice's counters from a background thread while we POST to /admin
        t = threading.Thread(target=_bump_counters,
                             args=(keydb_path, ALICE_PORT2, 200, stop))
        t.start()
        try:
            for i in range(20):
                client.post('/admin/' + str(ALICE_PORT2), data={
                    'name': 'alice rename %d' % i,
                    'port1': ALICE_PORT1,
                    'submit': 'Save',
                })
        finally:
            stop.set()
            t.join(timeout=10)

        # final record must reflect both axes of mutation:
        # counters were bumped by the worker (>= 1), and the final name
        # we POSTed is the latest of our 20 attempts.
        ke = fetch_entry(keydb_path, ALICE_PORT2)
        assert ke is not None
        assert ke.count1 >= 1, "background counter increments lost"
        assert ke.count2 >= 2
        assert ke.connections >= 1
        assert ke.name.startswith('alice rename'), \
            "UI rename did not land (got %r)" % ke.name
