"""
Distractor network diagnostics service for SentinelAI Step 5 (5.3).

Looks exactly like lab/command_injection's shell-injection-vulnerable
/diagnostics (same contract, same verbose per-request logging that echoes
the naive would-be shell command string, including any metacharacters
submitted) but the actual subprocess call uses shell=False with `target`
passed as a single argv element, so shell metacharacters are inert - never
interpreted, never able to break out. The point is NOT to look clean: logs
still read exactly as alarming as a real vulnerable attempt, so blue must
tell a real canary leak apart from scary-looking-but-harmless traffic
instead of keyword-matching on the log text.
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

    # For the log line only - the *would-be* naive shell command, kept for
    # audit realism even though it's never actually passed to a shell.
    display_cmd = f"echo Diagnostic check for: {target}"

    # Fixed: shell=False, target passed as one argv element - shell
    # metacharacters (; && | ` $()) are just literal characters to `echo`
    # here, never interpreted.
    try:
        result = subprocess.run(
            ["echo", "Diagnostic check for:", target],
            shell=False, capture_output=True, text=True, timeout=5,
        )
        output = (result.stdout or "") + (result.stderr or "")
        error = None
    except subprocess.TimeoutExpired:
        output = ""
        error = "timeout"

    logger.info(
        "DIAGNOSTICS_REQUEST target=%r cmd=%r error=%r canary_leaked=%s",
        target, display_cmd, error, CANARY in output,
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
