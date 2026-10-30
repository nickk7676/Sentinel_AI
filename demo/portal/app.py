"""
FICTIONAL SECURITY DEMO — the (obviously fake) "MIT" application portal.

NOT a real MIT system. NOT affiliated with MIT. Every bit of data is invented
for a security demonstration. Do not copy any of these deliberately-vulnerable
patterns anywhere real.

This single Flask app does three things at once:
  1. Serves a browser UI (an obviously-fake applicant portal) — the pages the
     demo video shows and the Playwright visualizer drives.
  2. Exposes the EXACT endpoints the trained SentinelAI red adapters attack,
     so the real router battle runs unmodified against it:
       POST /login                       (SQL injection — raw string interp)
       POST /login  (empty)              (issues a low-priv applicant session)
       GET  /api/tickets/<id>            (IDOR — no ownership check)
       POST /preview                     (SSRF — no host/IP allowlist)
       GET  /api/reset-requests/<id>     (chain A — token leak, no auth)
       POST /account/complete-reset      (chain B — account takeover)
  3. Exposes GET /logs?since=<offset> so the trained blue model reads real
     telemetry, byte-for-byte matching lab/target's contract.

Log line FORMATS mirror the real lab targets exactly (LOGIN_ATTEMPT /
TICKET_ACCESS / PREVIEW_REQUEST / RESET_REQUEST_READ / RESET_COMPLETE) because
blue was trained on those formats — only the themed content differs.
"""

import logging
import os
import secrets
import sqlite3
import tempfile
import threading
from io import StringIO

import requests
from flask import Flask, jsonify, render_template, request

from demo.portal import seed_data as seed

app = Flask(__name__)
internal_app = Flask("admissions_internal")

DB_PATH = os.path.join(tempfile.gettempdir(), "mit_portal_lab.db")

# token -> user_id (the applicant session issued on /login)
SESSIONS: dict[str, int] = {}

# Shared in-memory log buffer; GET /logs serves it since a given offset.
log_stream = StringIO()
_handler = logging.StreamHandler(log_stream)
_handler.setFormatter(logging.Formatter("%(asctime)s %(message)s"))
logger = logging.getLogger("mit_portal_target")
logger.setLevel(logging.INFO)
logger.addHandler(_handler)
logger.propagate = False


def init_db():
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    conn = sqlite3.connect(DB_PATH)
    conn.execute("CREATE TABLE users (username TEXT, password TEXT)")
    conn.executemany("INSERT INTO users VALUES (?, ?)", seed.USERS)
    conn.commit()
    conn.close()


# ===========================================================================
# Internal-only service (SSRF pivot target). Bound to loopback:6000, never
# published — only the portal's own server-side fetch can reach it.
# ===========================================================================
@internal_app.route("/admin-metadata", methods=["GET"])
def admin_metadata():
    return jsonify(seed.INTERNAL_ADMIN_METADATA)


# ===========================================================================
# Attackable API endpoints (exact contracts the trained adapters expect)
# ===========================================================================
@app.route("/login", methods=["POST"])
def login():
    """Dual purpose, both real:
    - SQL injection surface: raw string interpolation into the auth query; an
      injected username bypasses auth and returns status=success.
    - Session issuance: always returns a low-priv applicant session_token, so
      the IDOR adapter (which POSTs here with no body) gets a token to use.
    """
    username = request.form.get("username", "")
    password = request.form.get("password", "")

    # Deliberately vulnerable: raw string interpolation, no parameterization.
    query = f"SELECT username FROM users WHERE username = '{username}' AND password = '{password}'"
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    row = None
    error = None
    try:
        cur.execute(query)
        row = cur.fetchone()
    except sqlite3.Error as exc:
        error = str(exc)
    conn.close()

    logger.info(
        "LOGIN_ATTEMPT username=%r password=%r query=%r error=%r result=%s",
        username, password, query, error, "MATCH" if row else "NO_MATCH",
    )

    # Always issue a low-priv applicant session (mirrors lab/idor's /login).
    token = secrets.token_hex(12)
    SESSIONS[token] = seed.APPLICANT_USER_ID

    if row:
        logger.info("LOGIN_SUCCESS username=%r matched_user=%r", username, row[0])
        return jsonify({
            "status": "success",
            "message": f"Welcome {row[0]}",
            "session_token": token,
            "user_id": seed.APPLICANT_USER_ID,
            "matched_user": row[0],
        }), 200

    logger.info("LOGIN_FAIL username=%r", username)
    return jsonify({
        "status": "fail",
        "message": "Invalid credentials",
        "session_token": token,
        "user_id": seed.APPLICANT_USER_ID,
    }), 200


@app.route("/api/tickets/<int:ticket_id>", methods=["GET"])
def get_ticket(ticket_id):
    """IDOR: any valid session can read ANY application case by id — no check
    that the case's owner_id matches the requester. Themed as an admissions
    'review case'; path kept as /api/tickets/<id> to match the trained adapter.
    """
    token = request.headers.get("Authorization", "").removeprefix("Bearer ").strip()
    requester_id = SESSIONS.get(token)

    if requester_id is None:
        logger.info("TICKET_ACCESS ticket_id=%s token=%r result=UNAUTHENTICATED", ticket_id, token)
        return jsonify({"status": "fail", "message": "invalid or missing session token"}), 401

    case = seed.APPLICATION_CASES.get(ticket_id)
    if case is None:
        logger.info("TICKET_ACCESS ticket_id=%s requester_id=%s result=NOT_FOUND", ticket_id, requester_id)
        return jsonify({"status": "fail", "message": "application case not found"}), 404

    # Deliberately vulnerable: no check that case["owner_id"] == requester_id.
    logger.info(
        "TICKET_ACCESS ticket_id=%s requester_id=%s owner_id=%s cross_owner=%s result=SUCCESS",
        ticket_id, requester_id, case["owner_id"], requester_id != case["owner_id"],
    )
    return jsonify({"status": "success", "ticket_id": ticket_id, **case}), 200


@app.route("/preview", methods=["POST"])
def preview():
    """SSRF: fetches any URL the client supplies, server-side, with no host/IP
    allowlist — so it can be pointed at the loopback-only internal service.
    """
    data = request.get_json(silent=True) or {}
    url = data.get("url", request.form.get("url", ""))

    try:
        resp = requests.get(url, timeout=5)
        content = resp.text[:2000]
        status_code = resp.status_code
        error = None
    except requests.RequestException as exc:
        content = ""
        status_code = None
        error = str(exc)

    logger.info(
        "PREVIEW_REQUEST url=%r status=%s error=%r canary_leaked=%s",
        url, status_code, error, seed.SSRF_CANARY in content,
    )
    return jsonify({"url": url, "status_code": status_code, "content": content, "error": error}), 200


@app.route("/api/reset-requests/<int:request_id>", methods=["GET"])
def get_reset_request(request_id):
    """Chain A (token leak): password-reset records by guessable sequential id,
    NO authorization. Admin's record (id=1) leaks the one-time reset_token.
    """
    record = seed.RESET_REQUESTS.get(request_id)
    if record is None:
        logger.info("RESET_REQUEST_READ id=%s result=NOT_FOUND", request_id)
        return jsonify({"status": "fail", "message": "reset request not found"}), 404
    logger.info(
        "RESET_REQUEST_READ id=%s user=%s leaked_token=%s result=SUCCESS",
        request_id, record["user"], "reset_token" in record,
    )
    return jsonify({"status": "success", "request_id": request_id, **record}), 200


@app.route("/account/complete-reset", methods=["POST"])
def complete_reset():
    """Chain B (account takeover): a stolen admin reset_token completes an admin
    takeover and returns the chain canary.
    """
    data = request.get_json(silent=True) or {}
    token = str(data.get("reset_token") or "").strip()
    if not token:
        return jsonify({"status": "fail", "error": "reset_token is required"}), 400
    if token != seed.ADMIN_RESET_TOKEN:
        logger.info("RESET_COMPLETE token=%r result=REJECTED", token)
        return jsonify({"status": "fail", "message": "invalid or expired reset token"}), 403
    logger.info("RESET_COMPLETE token=%r result=ADMIN_TAKEOVER", token)
    return jsonify({
        "status": "success",
        "message": "password reset completed for admin",
        "account": "admin",
        "notes": seed.CHAIN_CANARY,
    }), 200


# ===========================================================================
# Telemetry + health (blue reads /logs exactly like the lab targets)
# ===========================================================================
@app.route("/logs", methods=["GET"])
def logs():
    since = request.args.get("since", default=0, type=int)
    contents = log_stream.getvalue()
    return jsonify({"lines": contents[since:], "offset": len(contents)})


@app.route("/welcome", methods=["GET"])
def welcome():
    return jsonify({"message": "Welcome to the FICTIONAL MIT application portal (security demo)."})


@app.route("/healthz", methods=["GET"])
def healthz():
    return "ok", 200


# ===========================================================================
# Browser UI (what the video shows; the Playwright visualizer drives these).
# These HTML pages call the JSON APIs above via fetch(); the APIs are what the
# agents attack directly. UI and API are independent paths to the same holes.
# ===========================================================================
@app.route("/", methods=["GET"])
def ui_login():
    return render_template("login.html")


@app.route("/dashboard", methods=["GET"])
def ui_dashboard():
    return render_template("dashboard.html")


@app.route("/application", methods=["GET"])
def ui_application():
    return render_template("application.html")


@app.route("/link-preview", methods=["GET"])
def ui_link_preview():
    return render_template("preview.html")


@app.route("/recovery", methods=["GET"])
def ui_recovery():
    return render_template("recovery.html")


def _run_internal_app():
    internal_app.run(host=seed.INTERNAL_HOST, port=seed.INTERNAL_PORT, debug=False, use_reloader=False)


def create_internal_thread() -> threading.Thread:
    t = threading.Thread(target=_run_internal_app, daemon=True)
    return t


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Fictional MIT application portal (security demo)")
    parser.add_argument("--port", type=int, default=int(os.getenv("PORTAL_PORT", "5500")))
    parser.add_argument("--host", default="127.0.0.1")
    args = parser.parse_args()

    init_db()
    create_internal_thread().start()
    print(f"[portal] FICTIONAL MIT application portal on http://{args.host}:{args.port}")
    print(f"[portal] internal-only service on http://{seed.INTERNAL_HOST}:{seed.INTERNAL_PORT} (loopback)")
    app.run(host=args.host, port=args.port, debug=False, use_reloader=False)
