"""
Deliberately vulnerable account view - Django variant.

Same exploitable broken authentication as lab/broken_auth/app.py: session
tokens are issued as a plain sequential counter (SESS-1000, SESS-1001, ...)
and GET /account accepts any token matching an issued session with no
binding to the original recipient (do not copy this pattern anywhere
else), reproduced through Django (Step 5). Token format and startup
sequencing are identical to lab/broken_auth/app.py since
agents/techniques/broken_auth.py's red-team prompt hardcodes both.
"""

import json
import time

from django.http import HttpResponse, JsonResponse
from django.views.decorators.csrf import csrf_exempt

from .apps import ACTIVE_SESSIONS, issue_session

LOG_LINES: list[str] = []


def _log(line: str) -> None:
    LOG_LINES.append(f"{time.strftime('%Y-%m-%d %H:%M:%S')} {line}\n")


@csrf_exempt
def login(request):
    if request.method != "POST":
        return JsonResponse({"status": "fail"}, status=405)
    try:
        data = json.loads(request.body or b"{}")
    except ValueError:
        data = {}
    username = str(data.get("username") or request.POST.get("username") or "guest")
    token = issue_session(username, False, "No notes.")
    _log(f"LOGIN username={username!r} issued_token={token!r}")
    return JsonResponse({"status": "success", "session_token": token}, status=200)


def account(request):
    auth_header = request.headers.get("Authorization", "")
    token = auth_header.removeprefix("Bearer ").strip() or request.GET.get("session_token", "")

    # Deliberately vulnerable: any token matching an issued session is
    # accepted, with no check that it was issued to this requester.
    session = ACTIVE_SESSIONS.get(token)
    _log(f"ACCOUNT_ACCESS token={token!r} found={bool(session)} is_admin={bool(session and session['is_admin'])}")

    if session is None:
        return JsonResponse({"status": "fail", "message": "invalid session"}, status=401)

    return JsonResponse({
        "status": "success",
        "username": session["username"],
        "is_admin": session["is_admin"],
        "notes": session["notes"],
    }, status=200)


def logs(request):
    since = int(request.GET.get("since", 0) or 0)
    contents = "".join(LOG_LINES)
    return JsonResponse({"lines": contents[since:], "offset": len(contents)})


def healthz(request):
    return HttpResponse("ok", status=200)
