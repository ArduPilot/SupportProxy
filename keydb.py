#!/usr/bin/env python3
"""
SupportProxy key database management.
"""

import argparse
import sys

import conntdb_lib
import keydb_lib
from keydb_lib import CLIError, FLAG_NAMES


def _expect(args, n, usage):
    if len(args) != n:
        raise CLIError("Usage: %s" % usage)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--keydb", default="keys.tdb",
                        help="key database tdb filename")
    parser.add_argument("action", default=None,
                        choices=['list', 'convert', 'add', 'remove',
                                 'setname', 'setpass', 'setport1',
                                 'initialise', 'resettimestamp',
                                 'setflag', 'clearflag', 'flags',
                                 'setretention',
                                 'stats'],
                        help="action to perform")
    parser.add_argument("args", default=[], nargs=argparse.REMAINDER)
    args = parser.parse_args()

    if args.action == "initialise":
        keydb_lib.init_db(args.keydb)
        print("Database %s initialised" % args.keydb)
        return 0

    try:
        db = keydb_lib.open_db(args.keydb)
    except FileNotFoundError:
        print("%s not found, you need to use 'keydb.py initialise' "
              "to initialise the database" % args.keydb)
        return 1

    db.transaction_start()
    try:
        if args.action == "convert":
            count = keydb_lib.convert_db(db)
            print("Converted %u records" % count)

        elif args.action == "list":
            for ke in keydb_lib.list_entries(db):
                print(str(ke))

        elif args.action == "add":
            _expect(args.args, 4, "keydb.py add PORT1 PORT2 NAME PASSPHRASE")
            ke = keydb_lib.add_entry(db, int(args.args[0]), int(args.args[1]),
                                     args.args[2], args.args[3])
            print("Added %s" % ke)

        elif args.action == "remove":
            _expect(args.args, 1, "keydb.py remove PORT2")
            ke = keydb_lib.remove_entry(db, int(args.args[0]))
            print("Removed %s" % ke)

        elif args.action == "setname":
            _expect(args.args, 2, "keydb.py setname PORT2 NAME")
            ke = keydb_lib.set_name(db, int(args.args[0]), args.args[1])
            print("Set name for %s" % ke)

        elif args.action == "setpass":
            _expect(args.args, 2, "keydb.py setpass PORT2 PASSPHRASE")
            ke = keydb_lib.set_pass(db, int(args.args[0]), args.args[1])
            print("Set passphrase for %s" % ke)

        elif args.action == "setport1":
            _expect(args.args, 2, "keydb.py setport1 PORT2 PORT1")
            ke = keydb_lib.set_port1(db, int(args.args[0]), int(args.args[1]))
            print("Set port1 for %s" % ke)

        elif args.action == "resettimestamp":
            _expect(args.args, 1, "keydb.py resettimestamp PORT2")
            ke = keydb_lib.reset_timestamp(db, int(args.args[0]))
            print("Reset timestamp for %s" % ke)

        elif args.action == "setflag":
            _expect(args.args, 2, "keydb.py setflag PORT2 FLAG (known: %s)"
                    % ', '.join(sorted(FLAG_NAMES)))
            ke = keydb_lib.set_flag(db, int(args.args[0]), args.args[1])
            print("Set flag %s for %s" % (args.args[1], ke))

        elif args.action == "clearflag":
            _expect(args.args, 2, "keydb.py clearflag PORT2 FLAG")
            ke = keydb_lib.clear_flag(db, int(args.args[0]), args.args[1])
            print("Cleared flag %s for %s" % (args.args[1], ke))

        elif args.action == "flags":
            _expect(args.args, 1, "keydb.py flags PORT2")
            port2 = int(args.args[0])
            ke = keydb_lib.KeyEntry(port2)
            if not ke.fetch(db):
                raise CLIError("No entry for port2 %d" % port2)
            on = ke.flag_names()
            print("flags=0x%x %s" % (ke.flags, ','.join(on) if on else '(none)'))

        elif args.action == "setretention":
            _expect(args.args, 2,
                    "keydb.py setretention PORT2 DAYS  "
                    "(float; 0 = keep forever)")
            try:
                days = float(args.args[1])
            except ValueError:
                raise CLIError("retention DAYS must be a number, got %r"
                               % args.args[1])
            ke = keydb_lib.set_tlog_retention(db, int(args.args[0]), days)
            if days == 0.0:
                print("Set tlog retention=0 (keep forever) for %s" % ke)
            else:
                print("Set tlog retention=%.4g days for %s" % (days, ke))

        elif args.action == "stats":
            # Live-connection stats from connections.tdb (sibling of
            # keys.tdb), joined with each entry's name from this DB.
            entries = {ke.port2: ke for ke in keydb_lib.list_entries(db)}
            conn_path = conntdb_lib.conn_path_for(args.keydb)
            active = conntdb_lib.list_active(conn_path)
            if not active:
                print("(no active connections)")
            else:
                for c in active:
                    ke = entries.get(c.port2)
                    if ke is not None:
                        label = "%d/%d '%s'" % (ke.port1, ke.port2, ke.name)
                    else:
                        label = "?/%d" % c.port2
                    side = 'user' if c.is_user else 'eng#%d' % c.conn_index
                    print("%s %s %s peer=%s uptime=%ds rx=%u tx=%u"
                          % (label, side, c.transport_name, c.peer,
                             c.uptime_s(), c.rx_msgs, c.tx_msgs))

        else:
            raise CLIError("Unknown action: %s" % args.action)

    except CLIError as e:
        print(str(e))
        db.transaction_cancel()
        return 1

    db.transaction_prepare_commit()
    db.transaction_commit()
    return 0


if __name__ == '__main__':
    sys.exit(main())
