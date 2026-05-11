"""Default configuration for the webadmin app.

All settings can be overridden via environment variables; the test suite
overrides them programmatically via create_app(test_config=...).
"""
import os
import secrets


def _bool_env(name, default=False):
    v = os.environ.get(name)
    if v is None:
        return default
    return v.lower() in ('1', 'true', 'yes', 'on')


class DefaultConfig:
    # WTF_CSRF + Flask session cookie use this. In production, set
    # WEBADMIN_SECRET_KEY to a stable random value (so sessions survive
    # restarts). For dev, generate ephemeral.
    SECRET_KEY = os.environ.get('WEBADMIN_SECRET_KEY') or secrets.token_hex(32)

    # Path to keys.tdb. Resolved relative to the working directory at startup
    # unless absolute. The supportproxy binary uses cwd-relative 'keys.tdb'
    # so the web admin should typically be started from the same directory.
    KEYDB_PATH = os.environ.get('WEBADMIN_KEYDB_PATH', 'keys.tdb')

    # Root directory for per-port-pair session logs written by the
    # supportproxy binary — both sessionN.tlog (raw MAVLink frames)
    # and sessionN.bin (ArduPilot dataflash) under
    # logs/<port2>/<YYYY-MM-DD>/. Must match the cwd supportproxy was
    # started from. Tests override this to a tmpdir.
    LOGS_DIR = os.environ.get('WEBADMIN_LOGS_DIR', 'logs')

    # Cookie hardening. Set WEBADMIN_INSECURE_COOKIES=1 only for local HTTP dev.
    SESSION_COOKIE_SECURE = not _bool_env('WEBADMIN_INSECURE_COOKIES')
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'

    # CSRF token validity (seconds). Forms older than this require a refresh.
    WTF_CSRF_TIME_LIMIT = 3600

    # Set true when running behind Apache so we honour X-Forwarded-Prefix /
    # X-Forwarded-Proto for URL building.
    BEHIND_PROXY = _bool_env('WEBADMIN_BEHIND_PROXY')

    # Site-name shown in templates. Overridden by webui.json's "title"
    # field if that file exists in the keys.tdb directory.
    WEBUI_TITLE = 'SupportProxy admin'

    # Browser-cache static assets (logo, CSS, JS). Without this Flask
    # emits no Cache-Control header, so the meta-refresh flow refetches
    # the logo every 5 s and you see a blank header flash mid-paint.
    # Set to 1 day; bust by renaming files or appending a query string
    # if you change one.
    SEND_FILE_MAX_AGE_DEFAULT = 86400
