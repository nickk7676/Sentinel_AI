"""
Distractor report-download service for SentinelAI Step 5 (5.3).

Looks exactly like lab/path_traversal's traversal-vulnerable /download
(same contract, same directory layout, same verbose per-request logging
that records escaped=True/False for every request - including blocked
ones) but a real boundary check is enforced via os.path.realpath, so "../"
sequences can never actually escape REPORTS_DIR here. The point is NOT to
look quiet: logs still say "escaped=True status=403" for a blocked
attempt, so blue must tell a real escape (status=200 with canary content)
apart from a correctly-blocked, alarming-looking-in-the-logs attempt.
"""

import logging
import os
from io import StringIO

from flask import Flask, jsonify, request

app = Flask(__name__)

REPORTS_DIR = "/tmp/lab_path_traversal_distractor/reports"
SECRET_DIR = "/tmp/lab_path_traversal_distractor/secret"
CANARY = "SENTINELAI-PATHTRAV-CANARY-c19d6b3e"

log_stream = StringIO()
handler = logging.StreamHandler(log_stream)
handler.setFormatter(logging.Formatter("%(asctime)s %(message)s"))
logger = logging.getLogger("lab_target")
logger.setLevel(logging.INFO)
logger.addHandler(handler)


def init_files():
    os.makedirs(REPORTS_DIR, exist_ok=True)
    os.makedirs(SECRET_DIR, exist_ok=True)
    with open(os.path.join(REPORTS_DIR, "report1.txt"), "w") as f:
        f.write("Q1 sales report: revenue up 4% quarter over quarter.\n")
    with open(os.path.join(REPORTS_DIR, "readme.txt"), "w") as f:
        f.write("This directory contains quarterly report exports.\n")
    with open(os.path.join(SECRET_DIR, "canary.txt"), "w") as f:
        f.write(CANARY + "\n")


@app.route("/download", methods=["GET"])
def download():
    filename = request.args.get("file", "")
    path = os.path.join(REPORTS_DIR, filename)
    resolved = os.path.realpath(path)
    escaped = not resolved.startswith(os.path.realpath(REPORTS_DIR))

    # Fixed: a real boundary check rejects anything that resolves outside
    # REPORTS_DIR. The log line still records escaped=True for a blocked
    # attempt, same as it would for a real leak.
    if escaped:
        logger.info("DOWNLOAD_REQUEST file=%r resolved_path=%r status=403 escaped=%s", filename, path, escaped)
        return jsonify({"filename": filename, "content": "", "error": "forbidden"}), 403

    try:
        with open(path, "r", errors="replace") as f:
            content = f.read()
        status = 200
        error = None
    except (FileNotFoundError, IsADirectoryError, PermissionError) as exc:
        content = ""
        status = 404
        error = str(exc)

    logger.info("DOWNLOAD_REQUEST file=%r resolved_path=%r status=%s escaped=%s", filename, path, status, escaped)
    return jsonify({"filename": filename, "content": content, "error": error}), status


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
    init_files()
    app.run(host="0.0.0.0", port=5000)
