"""
Deliberately vulnerable account service for SentinelAI Step 3.

Real, exploitable broken authentication via predictable session tokens:
POST /login issues tokens as a plain sequential counter (SESS-1000,
SESS-1001, ...) instead of cryptographically random values, and GET
/account accepts any token that matches an issued session with no binding
to the client that originally received it (do not copy this pattern
anywhere else). An admin session is pre-issued at startup with a low
counter value, before any client has logged in - a real-world pattern where
predictable sessions let an attacker guess earlier (often higher-privilege)
sessions. Every request is logged, and GET /logs exposes that log over HTTP
so blue team can read real telemetry, matching lab/target's contract
exactly.
"""

import logging
from io import StringIO

from flask import Flask, jsonify, request

app = Flask(__name__)

CANARY = "SENTINELAI-BROKENAUTH-CANARY-e2f7a1d9"

_COUNTER_START = 1000
ACTIVE_SESSIONS: dict[str, dict] = {}
_next_counter = _COUNTER_START

log_stream = StringIO()
handler = logging.StreamHandler(log_stream)
handler.setFormatter(logging.Formatter("%(asctime)s %(message)s"))
logger = logging.getLogger("lab_target")
logger.setLevel(logging.INFO)
logger.addHandler(handler)


def _issue_session(username: str, is_admin: bool, notes: str) -> str:
    global _next_counter
    token = f"SESS-{_next_counter}"
    _next_counter += 1
    ACTIVE_SESSIONS[token] = {"username": username, "is_admin": is_admin, "notes": notes}
    return token


def init_admin_session():
    """Simulates an administrator logging in during application startup,
    before any external client connects - the vulnerable part is that the
    resulting token is just the next sequential counter value."""
    _issue_session("admin", True, f"Admin private notes: {CANARY}")


@app.route("/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    username = str(data.get("username") or request.form.get("username") or "guest")
    token = _issue_session(username, False, "No notes.")
    logger.info("LOGIN username=%r issued_token=%r", username, token)
    return jsonify({"status": "success", "session_token": token}), 200


@app.route("/account", methods=["GET"])
def account():
    auth_header = request.headers.get("Authorization", "")
    token = auth_header.removeprefix("Bearer ").strip() or request.args.get("session_token", "")

    # Deliberately vulnerable: any token matching an issued session is
    # accepted, with no check that it was issued to this requester.
    session = ACTIVE_SESSIONS.get(token)
    logger.info("ACCOUNT_ACCESS token=%r found=%s is_admin=%s", token, bool(session), bool(session and session["is_admin"]))

    if session is None:
        return jsonify({"status": "fail", "message": "invalid session"}), 401

    return jsonify({
        "status": "success",
        "username": session["username"],
        "is_admin": session["is_admin"],
        "notes": session["notes"],
    }), 200


@app.route("/logs", methods=["GET"])
def logs():
    since = request.args.get("since", default=0, type=int)
    contents = log_stream.getvalue()
    new_content = contents[since:]
    return jsonify({"lines": new_content, "offset": len(contents)})


@app.route("/healthz", methods=["GET"])
def healthz():
    return "ok", 200


if __name__ == "__main__":
    init_admin_session()
    app.run(host="0.0.0.0", port=5000)
