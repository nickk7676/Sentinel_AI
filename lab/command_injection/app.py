"""
Deliberately vulnerable network diagnostics service for SentinelAI Step 3.

Real, exploitable OS command injection on POST /diagnostics (unsanitized
input concatenated into a shell command with shell=True - do not copy this
pattern anywhere else). Every request is logged, and GET /logs exposes that
log over HTTP so blue team can read real telemetry, matching lab/target's
contract exactly.

CANARY is a fixed, known-in-advance marker (not a random secret) seeded into
a file the vulnerable endpoint never references directly - it only appears
in a response if an attacker's shell metacharacters broke out of the
intended command and read the file themselves. This mirrors how canary
tokens are used in real authorized pentests to get unambiguous proof of
code execution.
"""

import logging
import subprocess
from io import StringIO

from flask import Flask, jsonify, request

app = Flask(__name__)

CANARY_PATH = "/tmp/canary.txt"
CANARY = "SENTINELAI-CMDI-CANARY-7f3a9c2e"

log_stream = StringIO()
handler = logging.StreamHandler(log_stream)
handler.setFormatter(logging.Formatter("%(asctime)s %(message)s"))
logger = logging.getLogger("lab_target")
logger.setLevel(logging.INFO)
logger.addHandler(handler)


def init_canary():
    with open(CANARY_PATH, "w") as f:
        f.write(CANARY + "\n")


@app.route("/diagnostics", methods=["POST"])
def diagnostics():
    data = request.get_json(silent=True) or {}
    target = data.get("target", request.form.get("target", ""))

    # Deliberately vulnerable: unsanitized input interpolated into a shell
    # command with shell=True, so shell metacharacters (; && | ` $()) let an
    # attacker chain in arbitrary additional commands.
    cmd = f"echo Diagnostic check for: {target}"
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
        output = (result.stdout or "") + (result.stderr or "")
        error = None
    except subprocess.TimeoutExpired:
        output = ""
        error = "timeout"

    logger.info(
        "DIAGNOSTICS_REQUEST target=%r cmd=%r error=%r canary_leaked=%s",
        target, cmd, error, CANARY in output,
    )

    return jsonify({"status": "ok", "output": output, "error": error}), 200


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
    init_canary()
    app.run(host="0.0.0.0", port=5000)
