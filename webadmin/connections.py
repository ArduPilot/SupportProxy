"""Flask glue around conntdb_lib — resolves connections.tdb's path
from the app's KEYDB_PATH config and delegates to the generic reader.
The CLI uses conntdb_lib directly; only the web app needs this shim.
"""
import os

from flask import current_app

import conntdb_lib

# Re-export for tests and templates that imported from this module
# before the conntdb_lib split.
ConnEntry = conntdb_lib.ConnEntry
PACK_FORMAT = conntdb_lib.PACK_FORMAT
KEY_FORMAT = conntdb_lib.KEY_FORMAT
CONN_MAGIC = conntdb_lib.CONN_MAGIC
CONN_FILE = conntdb_lib.CONN_FILE
CONNENTRY_MIN_SIZE = conntdb_lib.CONNENTRY_MIN_SIZE


def _conn_path():
    return conntdb_lib.conn_path_for(current_app.config['KEYDB_PATH'])


def iter_active(now=None, max_age_s=30):
    return conntdb_lib.iter_active(_conn_path(), now=now, max_age_s=max_age_s)


def list_active(**kw):
    return conntdb_lib.list_active(_conn_path(), **kw)


def list_for_port2(port2, **kw):
    return [c for c in list_active(**kw) if c.port2 == port2]
