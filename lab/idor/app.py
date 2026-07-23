"""
Deliberately vulnerable support-ticket service for SentinelAI Step 3.

Real, exploitable IDOR (broken object-level authorization) on GET
/api/tickets/<id>: any request bearing a *valid* session token can read
*any* ticket by id, regardless of who owns it (no ownership check - do not
copy this pattern anywhere else). Every request is logged, and GET /logs
exposes that log over HTTP so blue team can read real telemetry, matching
lab/target's contract exactly.

Red team is issued a valid low-privilege session token up front (mirroring
a real IDOR engagement, where the tester starts with legitimate low-priv
credentials) via POST /login. CANARY sits only in another user's ticket, so
it can only leak if the ownership check is actually bypassed.
"""

import logging
import secrets
from io import StringIO

from flask import Flask, jsonify, request

app = Flask(__name__)

CANARY = "SENTINELAI-IDOR-CANARY-4b8e1f0a"

# user_id 1 is the low-privilege account red is issued a token for.
# user_id 2 is a victim whose ticket holds the canary.
TICKETS = {
    1: {"owner_id": 1, "subject": "Can't reset my password", "body": "I tried the reset link but it expired, please help."},
    2: {"owner_id": 2, "subject": "Billing dispute", "body": f"My last invoice looks wrong, can someone check? Account notes: {CANARY}"},
    3: {"owner_id": 1, "subject": "Feature request", "body": "Would be great to have dark mode."},
}

SESSIONS: dict[str, int] = {}  # token -> user_id

log_stream = StringIO()
handler = logging.StreamHandler(log_stream)
handler.setFormatter(logging.Formatter("%(asctime)s %(message)s"))
logger = logging.getLogger("lab_target")
logger.setLevel(logging.INFO)
logger.addHandler(handler)


@app.route("/login", methods=["POST"])
def login():
    """Issues a real, valid session token for the low-privilege demo account."""
    token = secrets.token_hex(12)
    SESSIONS[token] = 1
    logger.info("LOGIN_ISSUED token=%r user_id=1", token)
    return jsonify({"status": "success", "session_token": token, "user_id": 1}), 200


@app.route("/api/tickets/<int:ticket_id>", methods=["GET"])
def get_ticket(ticket_id):
    token = request.headers.get("Authorization", "").removeprefix("Bearer ").strip()
    requester_id = SESSIONS.get(token)

    if requester_id is None:
        logger.info("TICKET_ACCESS ticket_id=%s token=%r result=UNAUTHENTICATED", ticket_id, token)
        return jsonify({"status": "fail", "message": "invalid or missing session token"}), 401

    ticket = TICKETS.get(ticket_id)
    if ticket is None:
        logger.info("TICKET_ACCESS ticket_id=%s requester_id=%s result=NOT_FOUND", ticket_id, requester_id)
        return jsonify({"status": "fail", "message": "ticket not found"}), 404

    # Deliberately vulnerable: no check that ticket["owner_id"] == requester_id.
    logger.info(
        "TICKET_ACCESS ticket_id=%s requester_id=%s owner_id=%s cross_owner=%s result=SUCCESS",
        ticket_id, requester_id, ticket["owner_id"], requester_id != ticket["owner_id"],
    )
    return jsonify({"status": "success", "ticket_id": ticket_id, **ticket}), 200


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
