"""
Deliberately vulnerable report-download service for SentinelAI Step 3.

Real, exploitable path traversal on GET /download: the `file` query param is
joined onto the reports directory with plain os.path.join and no
normalization/allowlist check, so `../` sequences escape the intended
directory (do not copy this pattern anywhere else). Every request is
logged, and GET /logs exposes that log over HTTP so blue team can read real
telemetry, matching lab/target's contract exactly.

CANARY sits in a file outside the reports directory entirely, so it can
only appear in a response if the traversal actually escaped the intended
directory.
"""

import logging
import os
from io import StringIO

from flask import Flask, jsonify, request

app = Flask(__name__)

REPORTS_DIR = "/tmp/lab_path_traversal/reports"
SECRET_DIR = "/tmp/lab_path_traversal/secret"
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

    # Deliberately vulnerable: naive join, no normalization or allowlist
    # check, so "../" sequences in `filename` escape REPORTS_DIR.
    path = os.path.join(REPORTS_DIR, filename)

    try:
        with open(path, "r", errors="replace") as f:
            content = f.read()
        status = 200
        error = None
    except (FileNotFoundError, IsADirectoryError, PermissionError) as exc:
        content = ""
        status = 404
        error = str(exc)

    logger.info(
        "DOWNLOAD_REQUEST file=%r resolved_path=%r status=%s escaped=%s",
        filename, path, status, os.path.realpath(path).startswith(os.path.realpath(REPORTS_DIR)) is False,
    )

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
