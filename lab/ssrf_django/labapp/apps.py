import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

from django.apps import AppConfig

CANARY = "SENTINELAI-SSRF-CANARY-9d21ab6f"
INTERNAL_HOST = "127.0.0.1"
INTERNAL_PORT = 6000


class _InternalAdminHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/admin-metadata":
            body = json.dumps({"role": "admin", "notes": CANARY}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):  # noqa: A002 - silence default stderr logging
        pass


def _run_internal_server() -> None:
    HTTPServer((INTERNAL_HOST, INTERNAL_PORT), _InternalAdminHandler).serve_forever()


class LabappConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "labapp"

    def ready(self) -> None:
        # Internal-only admin API - bound to loopback, never published by
        # docker-compose, only reachable from the main app's own
        # server-side fetch (Step 5, matching lab/ssrf/app.py exactly).
        threading.Thread(target=_run_internal_server, daemon=True).start()
