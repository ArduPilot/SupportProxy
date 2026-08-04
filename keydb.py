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
                                 'setsysid',
                                 'settz',
                                 'setvideo', 'videoflag', 'videoopt', 'setrtmp',
                                 'setviewerpass', 'setpublishpass',
                                 'setvideoquota', 'setvideograce',
                                 'video',
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
            ke = keydb_lib.set_log_retention(db, int(args.args[0]), days)
            if days == 0.0:
                print("Set log retention=0 (keep forever) for %s" % ke)
            else:
                print("Set log retention=%.4g days for %s" % (days, ke))

        elif args.action == "setvideo":
            if not args.args:
                raise CLIError(
                    "Usage: keydb.py setvideo PORT2 [VPORT ...]  "
                    "(up to %d ports; none clears them all)"
                    % keydb_lib.MAX_VIDEO_PORTS)
            port2 = int(args.args[0])
            try:
                vports = [int(a) for a in args.args[1:]]
            except ValueError:
                raise CLIError("video ports must be integers, got %r"
                               % (args.args[1:],))
            ke = keydb_lib.set_video_ports(db, port2, vports)
            if any(ke.video_ports):
                print("Set video ports %s for %s"
                      % (','.join(str(p) for p in ke.video_ports if p), ke))
            else:
                print("Cleared video ports for %s" % ke)

        elif args.action == "setrtmp":
            # setrtmp PORT2 SLOT [app/stream]   -- omit to clear
            if len(args.args) not in (2, 3):
                raise CLIError(
                    "Usage: keydb.py setrtmp PORT2 SLOT [app/stream]  "
                    "(omit the path to clear)")
            port2 = int(args.args[0])
            slot = int(args.args[1])
            path = args.args[2] if len(args.args) == 3 else ''
            ke = keydb_lib.set_video_rtmp_path(db, port2, slot, path)
            got = ke.rtmp_path(slot)
            print("Set slot %d RTMP path to %s for %s"
                  % (slot, repr(got) if got else "(cleared)", ke))

        elif args.action in ("videoflag", "videoopt"):
            # videoflag PORT2 SLOT NAME [on|off]   -- per-slot option
            # videoopt  PORT2 NAME [on|off]        -- entry-wide option
            per_slot = args.action == "videoflag"
            usage = ("keydb.py videoflag PORT2 SLOT NAME [on|off]  (NAME: %s)"
                     % ', '.join(sorted(keydb_lib.VIDEO_SLOT_FLAG_NAMES))
                     if per_slot else
                     "keydb.py videoopt PORT2 NAME [on|off]  (NAME: %s)"
                     % ', '.join(sorted(keydb_lib.VIDEO_OPT_FLAG_NAMES)))
            nargs = 3 if per_slot else 2
            if len(args.args) not in (nargs, nargs + 1):
                raise CLIError("Usage: %s" % usage)
            state = args.args[nargs].lower() if len(args.args) > nargs else "on"
            if state not in ("on", "off"):
                raise CLIError("state must be 'on' or 'off', got %r" % state)
            on = state == "on"
            port2 = int(args.args[0])
            if per_slot:
                slot = int(args.args[1])
                ke = keydb_lib.set_video_slot_flag(db, port2, slot,
                                                   args.args[2], on)
                print("Set slot %d %s=%s for %s"
                      % (slot, args.args[2], state, ke))
            else:
                ke = keydb_lib.set_video_entry_flag(db, port2,
                                                    args.args[1], on)
                print("Set video %s=%s for %s" % (args.args[1], state, ke))

        elif args.action in ("setviewerpass", "setpublishpass"):
            which = ("viewer" if args.action == "setviewerpass" else "publish")
            if len(args.args) not in (1, 2):
                raise CLIError(
                    "Usage: keydb.py %s PORT2 [PASSPHRASE]  "
                    "(omit PASSPHRASE to clear)" % args.action)
            port2 = int(args.args[0])
            phrase = args.args[1] if len(args.args) == 2 else ''
            fn = (keydb_lib.set_video_viewer_pass
                  if which == "viewer" else keydb_lib.set_video_publish_pass)
            ke = fn(db, port2, phrase)
            if phrase:
                print("Set video %s password for %s" % (which, ke))
            else:
                print("Cleared video %s password for %s" % (which, ke))

        elif args.action == "setvideoquota":
            _expect(args.args, 2,
                    "keydb.py setvideoquota PORT2 MB  (0 = server default)")
            try:
                mb = int(args.args[1])
            except ValueError:
                raise CLIError("MB must be an integer, got %r" % args.args[1])
            ke = keydb_lib.set_video_quota(db, int(args.args[0]), mb)
            if mb == 0:
                print("Cleared video quota (server default) for %s" % ke)
            else:
                print("Set video quota=%d MB for %s" % (mb, ke))

        elif args.action == "setvideograce":
            _expect(args.args, 2,
                    "keydb.py setvideograce PORT2 SECONDS  (0 = default %d)"
                    % keydb_lib.VIDEO_MAV_GRACE_DEFAULT_S)
            try:
                secs = int(args.args[1])
            except ValueError:
                raise CLIError("SECONDS must be an integer, got %r"
                               % args.args[1])
            ke = keydb_lib.set_video_grace(db, int(args.args[0]), secs)
            print("Set video MAVLink grace=%ds for %s"
                  % (ke.mav_grace_seconds(), ke))

        elif args.action == "video":
            _expect(args.args, 1, "keydb.py video PORT2")
            port2 = int(args.args[0])
            ke = keydb_lib.KeyEntry(port2)
            if not ke.fetch(db):
                raise CLIError("No entry for port2 %d" % port2)
            print("video: %s" % ("enabled" if ke.video_enabled()
                                 else "disabled (set the 'video' flag)"))
            active = ke.active_video_ports()
            if not active:
                print("  no video ports configured")
            for slot, port in active:
                opts = ke.slot_opt_names(slot)
                print("  slot %d: port %d  %s%s"
                      % (slot, port,
                         "srt" if 'srt' in opts else "mpegts",
                         ''.join(' +' + o for o in sorted(opts)
                                 if o != 'srt')))
                rp = ke.rtmp_path(slot)
                print("           RTMP path: %s"
                      % (rp if rp else "(any)"))
            eopts = ke.entry_opt_names()
            print("  options: %s" % (','.join(sorted(eopts)) if eopts
                                     else '(none)'))
            print("  viewer password: %s"
                  % ("set" if ke.video_viewer_pass_set() else "not set (open)"))
            print("  publish password: %s"
                  % ("set" if ke.video_publish_pass_set()
                     else "not set (MAVLink session required)"))
            print("  mavlink grace: %ds" % ke.mav_grace_seconds())
            print("  quota: %s" % ("%d MB" % ke.video_quota_mb
                                   if ke.video_quota_mb else "server default"))

        elif args.action == "setsysid":
            _expect(args.args, 2,
                    "keydb.py setsysid PORT2 SYSID  "
                    "(0 = match any, 1..255 = filter to that MAVLink sysid)")
            try:
                sysid = int(args.args[1])
            except ValueError:
                raise CLIError("SYSID must be an integer, got %r"
                               % args.args[1])
            ke = keydb_lib.set_fc_sysid(db, int(args.args[0]), sysid)
            if sysid == 0:
                print("Cleared fc_sysid (match any) for %s" % ke)
            else:
                print("Set fc_sysid=%u for %s" % (sysid, ke))

        elif args.action == "settz":
            _expect(args.args, 2,
                    "keydb.py settz PORT2 HOURS  "
                    "(GMT offset in hours, fractional ok; enables use_tz. "
                    "Clear the use_tz flag to revert to server-local naming.)")
            try:
                hours = float(args.args[1])
            except ValueError:
                raise CLIError("HOURS must be a number, got %r"
                               % args.args[1])
            ke = keydb_lib.set_timezone(db, int(args.args[0]), hours)
            print("Set log timezone=%s for %s"
                  % (keydb_lib.format_tz_offset(hours), ke))

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
