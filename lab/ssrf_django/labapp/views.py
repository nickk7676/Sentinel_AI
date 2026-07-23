"""
Deliberately vulnerable link-preview view - Django variant.

Same exploitable SSRF as lab/ssrf/app.py (no host/IP allowlist on the
server-side fetch on POST /preview - do not copy this pattern anywhere
else), reproduced through Django (Step 5). The internal-only admin API on
127.0.0.1:6000 (see apps.py) and this app's own /welcome are identical to
lab/ssrf/app.py's since agents/techniques/ssrf.py's red-team prompt
hardcodes both URLs.
"""

import time

import requests
from django.http import HttpResponse, JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods

from .apps import CANARY

LOG_LINES: list[str] = []


def _log(line: str) -> None:
    LOG_LINES.append(f"{time.strftime('%Y-%m-%d %H:%M:%S')} {line}\n")


def welcome(request):
    return JsonResponse({"message": "Welcome to the link-preview service."})


@csrf_exempt
@require_http_methods(["POST"])
def preview(request):
    import json as _json
    try:
        data = _json.loads(request.body or b"{}")
    except ValueError:
        data = {}
    url = data.get("url", request.POST.get("url", ""))

    content = ""
    status_code = None
    error = None
    try:
        # Deliberately vulnerable: no host/IP allowlist on the server-side
        # fetch, so an attacker-supplied URL can reach internal-only
        # services (e.g. the loopback-only internal app on port 6000).
        resp = requests.get(url, timeout=5)
        content = resp.text[:2000]
        status_code = resp.status_code
    except requests.RequestException as exc:
        error = str(exc)

    _log(f"PREVIEW_REQUEST url={url!r} status={status_code} error={error!r} canary_leaked={CANARY in content}")
    return JsonResponse({"url": url, "status_code": status_code, "content": content, "error": error}, status=200)


def logs(request):
    since = int(request.GET.get("since", 0) or 0)
    contents = "".join(LOG_LINES)
    return JsonResponse({"lines": contents[since:], "offset": len(contents)})


def healthz(request):
    return HttpResponse("ok", status=200)
