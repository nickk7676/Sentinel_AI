"""
Deliberately vulnerable link-preview service for SentinelAI Step 3.

Real, exploitable SSRF on POST /preview: the server fetches whatever URL
the client supplies with no host/IP allowlist, so an attacker can point it
at internal-only infrastructure (do not copy this pattern anywhere else).

To make the SSRF genuine (not just "another route on the same app"), a
second, internal-only Flask app runs in a background thread bound to
127.0.0.1:6000 - a port that is NEVER published by docker-compose, so it is
truly unreachable from outside the container. Only the main app's own
server-side fetch (loopback) can reach it, exactly like a real internal
admin API or cloud metadata endpoint that SSRF is used to pivot into.

Every request to the public app is logged, and GET /logs exposes that log
over HTTP so blue team can read real telemetry, matching lab/target's
contract exactly.
"""

import logging
import threading
from io import StringIO

import requests
from flask import Flask, jsonify, request

app = Flask(__name__)
internal_app = Flask("internal")

CANARY = "SENTINELAI-SSRF-CANARY-9d21ab6f"
INTERNAL_HOST = "127.0.0.1"
INTERNAL_PORT = 6000

log_stream = StringIO()
handler = logging.StreamHandler(log_stream)
handler.setFormatter(logging.Formatter("%(asctime)s %(message)s"))
logger = logging.getLogger("lab_target")
logger.setLevel(logging.INFO)
logger.addHandler(handler)


@internal_app.route("/admin-metadata", methods=["GET"])
def admin_metadata():
    return jsonify({"role": "admin", "notes": CANARY})


@app.route("/welcome", methods=["GET"])
def welcome():
    return jsonify({"message": "Welcome to the link-preview service."})


@app.route("/preview", methods=["POST"])
def preview():
    data = request.get_json(silent=True) or {}
    url = data.get("url", request.form.get("url", ""))

    try:
        # Deliberately vulnerable: no host/IP allowlist on the server-side
        # fetch, so an attacker-supplied URL can reach internal-only
        # services (e.g. the loopback-only internal app on port 6000).
        resp = requests.get(url, timeout=5)
        content = resp.text[:2000]
        status_code = resp.status_code
        error = None
    except requests.RequestException as exc:
        content = ""
        status_code = None
        error = str(exc)

    logger.info("PREVIEW_REQUEST url=%r status=%s error=%r canary_leaked=%s", url, status_code, error, CANARY in content)

    return jsonify({"url": url, "status_code": status_code, "content": content, "error": error}), 200


@app.route("/logs", methods=["GET"])
def logs():
    since = request.args.get("since", default=0, type=int)
    contents = log_stream.getvalue()
    new_content = contents[since:]
    return jsonify({"lines": new_content, "offset": len(contents)})


@app.route("/healthz", methods=["GET"])
def healthz():
    return "ok", 200


def _run_internal_app():
    internal_app.run(host=INTERNAL_HOST, port=INTERNAL_PORT)


if __name__ == "__main__":
    threading.Thread(target=_run_internal_app, daemon=True).start()
    app.run(host="0.0.0.0", port=5000)
