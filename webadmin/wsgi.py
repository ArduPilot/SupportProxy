"""WSGI entry point for gunicorn.

Run with:
    gunicorn -w 2 -b 127.0.0.1:8080 webadmin.wsgi:application

The keydb_lib module lives at the project root; we add it to sys.path so
gunicorn can find it regardless of how it was launched.
"""
import os
import sys

_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from webadmin import create_app  # noqa: E402

application = create_app()
