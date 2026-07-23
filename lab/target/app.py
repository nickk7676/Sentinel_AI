"""
Deliberately vulnerable login service for SentinelAI Milestone 1.

Real, exploitable SQL injection on POST /login (raw string interpolation into
the query - do not copy this pattern anywhere else). Every attempt is logged,
and GET /logs exposes that log over HTTP so blue team can read real telemetry
without needing a shared volume/filesystem.
"""

import logging
import os
import secrets
import sqlite3
from io import StringIO

from flask import Flask, jsonify, request

app = Flask(__name__)

DB_PATH = "/tmp/lab.db"
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
