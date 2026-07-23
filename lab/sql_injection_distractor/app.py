"""
Distractor login service for SentinelAI Step 5 (5.3).

Looks exactly like lab/target's SQL-injection-vulnerable login (same
/login contract, same verbose per-attempt logging that echoes the raw
attempted query including any injection syntax) but the query is actually
parameterized - injection payloads can never bypass auth here. The point is
NOT to be a clean, quiet app: the logs still say things like "query="...
OR '1'='1'..."" for a failed attempt, so blue must learn to tell a real
bypass (status=success) apart from alarming-looking-but-harmless traffic
instead of keyword-matching on the log text.
"""

import logging
import os
import secrets
import sqlite3
from io import StringIO

from flask import Flask, jsonify, request

app = Flask(__name__)

DB_PATH = "/tmp/lab_sqli_distractor.db"
SEEDED_USER = "admin"
SEEDED_PASSWORD = secrets.token_urlsafe(12)

log_stream = StringIO()
handler = logging.StreamHandler(log_stream)
handler.setFormatter(logging.Formatter("%(asctime)s %(message)s"))
logger = logging.getLogger("lab_target")
logger.setLevel(logging.INFO)
logger.addHandler(handler)


def init_db():
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    conn = sqlite3.connect(DB_PATH)
    conn.execute("CREATE TABLE users (username TEXT, password TEXT)")
    conn.execute("INSERT INTO users VALUES (?, ?)", (SEEDED_USER, SEEDED_PASSWORD))
    conn.commit()
    conn.close()


@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")

    # Fixed: parameterized query - injection syntax in username/password is
    # just literal string data here, never breaks out of the query. The
    # log line below still records the *would-be* raw interpolated string
    # (for audit purposes) so it reads exactly as alarming as a real
    # vulnerable attempt, even though nothing was actually bypassed.
    display_query = f"SELECT username FROM users WHERE username = '{username}' AND password = '{password}'"

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    row = None
    error = None
    try:
        cur.execute("SELECT username FROM users WHERE username = ? AND password = ?", (username, password))
        row = cur.fetchone()
    except sqlite3.Error as exc:
        error = str(exc)
    conn.close()

    logger.info(
        "LOGIN_ATTEMPT username=%r password=%r query=%r error=%r result=%s",
        username, password, display_query, error, "MATCH" if row else "NO_MATCH",
    )

    if row:
        logger.info("LOGIN_SUCCESS username=%r matched_user=%r", username, row[0])
        return jsonify({"status": "success", "message": f"Welcome {row[0]}"}), 200

    logger.info("LOGIN_FAIL username=%r", username)
    return jsonify({"status": "fail", "message": "Invalid credentials"}), 401


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
    init_db()
    app.run(host="0.0.0.0", port=5000)
