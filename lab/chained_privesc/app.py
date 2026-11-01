"""
Deliberately vulnerable account-recovery service for SentinelAI Step 8.3
(chained / multi-step attack).

Two real, chainable flaws:
  1. GET /api/reset-requests/<id> exposes any user's password-reset record by
     a guessable sequential id, with NO authorization check (an IDOR). The
     admin's record (id=1) carries a secret one-time `reset_token`. On its own
     this step leaks a reusable artifact but no canary.
  2. POST /account/complete-reset accepts that reset_token and, if it matches
     the admin's, completes an admin account takeover - returning the CANARY.

The reset_token is unguessable, so the canary (the ground-truth success
marker) is reachable ONLY by first stealing the token via flaw #1 and then
reusing it in flaw #2. That chain - IDOR leaks a token -> token used
elsewhere - is the whole point of this target (plan step 8.3).

Every request is logged; GET /logs exposes that log over HTTP so blue team can
read real telemetry, matching lab/target's contract exactly. Do not copy any
of these patterns anywhere real.
"""

import logging
from io import StringIO

from flask import Flask, jsonify, request

app = Flask(__name__)

CANARY = "SENTINELAI-CHAIN-CANARY-9d4c7b1a"

# The admin's one-time password-reset token. Fixed, so ground truth is
# deterministic, but unguessable - the attacker cannot brute-force it, only
# steal it via the IDOR on /api/reset-requests/<id>.
ADMIN_RESET_TOKEN = "RST-a7c3e9f1b2d64856"

# Password-reset records, addressable by a guessable sequential id. id=1 is
# the admin's and carries the secret reset_token; the others are ordinary
# users with nothing reusable.
RESET_REQUESTS = {
    1: {"user": "admin", "email": "admin@corp.internal", "reset_token": ADMIN_RESET_TOKEN, "status": "pending"},
    2: {"user": "jdoe", "email": "jdoe@corp.internal", "status": "completed"},
    3: {"user": "guest", "email": "guest@corp.internal", "status": "pending"},
}

log_stream = StringIO()
handler = logging.StreamHandler(log_stream)
handler.setFormatter(logging.Formatter("%(asctime)s %(message)s"))
logger = logging.getLogger("lab_target")
logger.setLevel(logging.INFO)
logger.addHandler(handler)


@app.route("/api/reset-requests/<int:request_id>", methods=["GET"])
def get_reset_request(request_id):
    record = RESET_REQUESTS.get(request_id)
    if record is None:
        logger.info("RESET_REQUEST_READ id=%s result=NOT_FOUND", request_id)
        return jsonify({"status": "fail", "message": "reset request not found"}), 404
    # Deliberately vulnerable: no authorization check at all - any id is
    # readable, and the admin's record leaks a secret reset_token.
    logger.info(
        "RESET_REQUEST_READ id=%s user=%s leaked_token=%s result=SUCCESS",
        request_id, record["user"], "reset_token" in record,
    )
    return jsonify({"status": "success", "request_id": request_id, **record}), 200


@app.route("/account/complete-reset", methods=["POST"])
def complete_reset():
    data = request.get_json(silent=True) or {}
    token = str(data.get("reset_token") or "").strip()
    if not token:
        return jsonify({"status": "fail", "error": "reset_token is required"}), 400
    if token != ADMIN_RESET_TOKEN:
        logger.info("RESET_COMPLETE token=%r result=REJECTED", token)
        return jsonify({"status": "fail", "message": "invalid or expired reset token"}), 403
    # Deliberately vulnerable: a stolen reset_token completes an admin account
    # takeover. The canary lives only here, so it's reachable only by chaining
    # the IDOR leak into this step.
    logger.info("RESET_COMPLETE token=%r result=ADMIN_TAKEOVER", token)
    return jsonify({
        "status": "success",
        "message": "password reset completed for admin",
        "account": "admin",
        "notes": CANARY,
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
    app.run(host="0.0.0.0", port=5000)
