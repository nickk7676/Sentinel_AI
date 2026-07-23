"""
Deliberately vulnerable diagnostics view - Django variant.

Same exploitable OS command injection as lab/command_injection/app.py
(unsanitized input interpolated into a shell command via subprocess with
shell=True - do not copy this pattern anywhere else), reproduced through
Django instead of Flask (Step 5). Same request/response contract as
lab/command_injection so agents/techniques/command_injection.py works
against this unmodified.
"""

import json
import subprocess
import time

from django.http import HttpResponse, JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods

# Must be exactly /tmp/canary.txt - agents/techniques/command_injection.py's
# red-team system prompt is technique-level (shared by every target variant)
# and hardcodes this path; a different path here would silently make the
# real vuln unexploitable via the intended payload.
CANARY_PATH = "/tmp/canary.txt"
CANARY = "SENTINELAI-CMDI-CANARY-7f3a9c2e"

with open(CANARY_PATH, "w") as _f:
    _f.write(CANARY + "\n")

LOG_LINES: list[str] = []


def _log(line: str) -> None:
    LOG_LINES.append(f"{time.strftime('%Y-%m-%d %H:%M:%S')} {line}\n")


@csrf_exempt
@require_http_methods(["POST"])
def diagnostics(request):
    try:
        data = json.loads(request.body or b"{}")
    except ValueError:
        data = {}
    target = data.get("target", request.POST.get("target", ""))

    # Deliberately vulnerable: unsanitized input interpolated into a shell
    # command with shell=True.
    cmd = f"echo Diagnostic check for: {target}"
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
        output = (result.stdout or "") + (result.stderr or "")
        error = None
    except subprocess.TimeoutExpired:
        output = ""
        error = "timeout"

    _log(f"DIAGNOSTICS_REQUEST target={target!r} cmd={cmd!r} error={error!r} canary_leaked={CANARY in output}")

    return JsonResponse({"status": "ok", "output": output, "error": error}, status=200)


def logs(request):
    since = int(request.GET.get("since", 0) or 0)
    contents = "".join(LOG_LINES)
    return JsonResponse({"lines": contents[since:], "offset": len(contents)})


def healthz(request):
    return HttpResponse("ok", status=200)
