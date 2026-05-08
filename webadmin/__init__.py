"""
UDPProxy web admin UI.

A Flask app that lets owners (port + passphrase) manage their own keys.tdb
entry and lets users with the KEY_FLAG_ADMIN bit set manage every entry.

Run standalone:
    gunicorn -w 2 -b 127.0.0.1:8080 webadmin.wsgi:application

or behind Apache via:
    ProxyPass        /admin/ http://127.0.0.1:8080/
    ProxyPassReverse /admin/ http://127.0.0.1:8080/

Site-specific options live in a JSON file alongside keys.tdb. If
$WEBADMIN_KEYDB_PATH is /home/proxy/keys.tdb then create_app() reads
/home/proxy/webui.json on startup. Recognised keys (all optional):

    {
        "title": "Support Proxy",   # site name shown in nav + <title>
        "mode":  "standalone",      # or "apache" — sets BEHIND_PROXY
        "host":  "127.0.0.1",       # used by start_proxy.sh, not the app
        "port":  8080               # used by start_proxy.sh, not the app
    }
"""
import json
import os

from flask import Flask, redirect, url_for
from flask_wtf.csrf import CSRFProtect
from werkzeug.middleware.proxy_fix import ProxyFix

from . import config

WEBUI_JSON_NAME = 'webui.json'


def _load_webui_json(app):
    """Apply settings from webui.json (next to keys.tdb) to the Flask
    app config. Quiet no-op if the file is missing or unreadable."""
    keydb_path = os.path.abspath(app.config['KEYDB_PATH'])
    json_path = os.path.join(os.path.dirname(keydb_path), WEBUI_JSON_NAME)
    if not os.path.isfile(json_path):
        return
    try:
        with open(json_path) as f:
            cfg = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        app.logger.warning("ignoring %s: %s", json_path, e)
        return
    if isinstance(cfg, dict):
        if isinstance(cfg.get('title'), str):
            app.config['WEBUI_TITLE'] = cfg['title']
        if cfg.get('mode') == 'apache':
            app.config['BEHIND_PROXY'] = True


def create_app(test_config=None):
    app = Flask(__name__)
    app.config.from_object(config.DefaultConfig)
    # test_config (when present) typically sets KEYDB_PATH to a fresh
    # tmpdir; apply it before reading webui.json so the json lookup
    # uses the final keys.tdb path rather than the default.
    if test_config is not None:
        app.config.update(test_config)
    _load_webui_json(app)

    if app.config.get('BEHIND_PROXY'):
        # honour X-Forwarded-* set by Apache so url_for and request.is_secure
        # behave correctly when mounted under a path prefix.
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

    CSRFProtect(app)

    from .auth import bp as auth_bp
    from .routes_owner import bp as owner_bp
    from .routes_admin import bp as admin_bp
    app.register_blueprint(auth_bp)
    app.register_blueprint(owner_bp)
    app.register_blueprint(admin_bp)

    @app.route('/')
    def index():
        from .auth import is_admin, current_owner
        if is_admin():
            return redirect(url_for('admin.list_entries'))
        if current_owner() is not None:
            return redirect(url_for('owner.me'))
        return redirect(url_for('auth.login'))

    return app
