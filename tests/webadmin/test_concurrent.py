"""Concurrent-write safety: the proxy's counter update must not be lost
when the web UI also writes to the same entry.

Simulate the proxy's connection-close path (read entry, bump counters,
save) running in a separate process while the web UI POSTs a name change
to /admin/<port2>. Both writes use TDB transactions, so they must
serialize, and both updates must land in the final record.

We loop the proxy-side update enough times that the two paths interleave
under TDB's per-DB lock; if either path bypassed the transaction we'd
expect to see the counters revert to their initial values.
"""
import multiprocessing
import time

import keydb_lib

from _test_helpers import (BOB_PASS, BOB_PORT1, BOB_PORT2,
                           ALICE_PORT1, ALICE_PORT2,
                           fetch_entry, login_as)


def _bump_counters(keydb_path, port2, iterations, stop_event, ready, completed):
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
        completed.value += 1
        ready.set()
        time.sleep(0.001)


class TestConcurrent:
    def test_ui_rename_does_not_lose_counter_updates(self, client, keydb_path):
        login_as(client, BOB_PORT1, BOB_PASS)

        # TDB rejects two handles for the same database in one process with
        # EBUSY. Match the separate proxy/web workers and avoid inheriting any
        # TDB state from the test runner.
        ctx = multiprocessing.get_context('spawn')
        stop, ready = ctx.Event(), ctx.Event()
        completed = ctx.Value('I', 0)
        worker = ctx.Process(target=_bump_counters,
                             args=(keydb_path, ALICE_PORT2, 200, stop,
                                   ready, completed))
        worker.start()
        try:
            assert ready.wait(10), "counter worker did not start"
            for i in range(20):
                response = client.post('/admin/' + str(ALICE_PORT2), data={
                    'name': 'alice rename %d' % i,
                    'port1': ALICE_PORT1,
                    'submit': 'Save',
                })
                assert response.status_code == 302
        finally:
            stop.set()
            worker.join(timeout=10)
            if worker.is_alive():
                worker.terminate()
                worker.join(timeout=10)
        assert worker.exitcode == 0, "counter worker failed or timed out"

        # final record must reflect both axes of mutation:
        # counters were bumped by the worker (>= 1), and the final name
        # we POSTed is the latest of our 20 attempts.
        ke = fetch_entry(keydb_path, ALICE_PORT2)
        assert ke is not None
        assert completed.value >= 1, "counter worker made no updates"
        assert ke.count1 == completed.value, "background counter increments lost"
        assert ke.count2 == 2 * completed.value
        assert ke.connections == completed.value
        assert ke.name == 'alice rename 19', \
            "UI rename did not land (got %r)" % ke.name
