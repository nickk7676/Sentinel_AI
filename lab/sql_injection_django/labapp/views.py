"""
Deliberately vulnerable login view - Django variant.

Same exploitable SQL injection as lab/target/app.py (raw string
interpolation into the query - do not copy this pattern anywhere else),
reproduced through Django's own DB layer (a raw cursor, deliberately
bypassing the ORM's parameterized queryset API - the same class of
real-world bug as misuse of Django's `.raw()`/`.extra()`) so red/blue must
generalize past one specific framework (Step 5). Same request/response
contract as lab/target so agents/techniques/sql_injection.py works against
this unmodified.
"""

import json
import sqlite3
import time

from django.http import HttpResponse, JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods

from .apps import DB_PATH

LOG_LINES: list[str] = []


def _log(line: str) -> None:
    LOG_LINES.append(f"{time.strftime('%Y-%m-%d %H:%M:%S')} {line}\n")


def _log_text() -> str:
    return "".join(LOG_LINES)


@csrf_exempt
@require_http_methods(["POST"])
def login(request):
    username = request.POST.get("username", "")
    password = request.POST.get("password", "")
    if not username and not password and request.body:
        try:
            body = json.loads(request.body)
        except ValueError:
            body = {}
        username = body.get("username", username)
        password = body.get("password", password)

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

    _log(
        f"LOGIN_ATTEMPT username={username!r} password={password!r} query={query!r} "
        f"error={error!r} result={'MATCH' if row else 'NO_MATCH'}"
    )

    if row:
        request.session["username"] = row[0]
        _log(f"LOGIN_SUCCESS username={username!r} matched_user={row[0]!r}")
        return JsonResponse({"status": "success", "message": f"Welcome {row[0]}"}, status=200)

    _log(f"LOGIN_FAIL username={username!r}")
    return JsonResponse({"status": "fail", "message": "Invalid credentials"}, status=401)


def logs(request):
    since = int(request.GET.get("since", 0) or 0)
    contents = _log_text()
    return JsonResponse({"lines": contents[since:], "offset": len(contents)})


def healthz(request):
    return HttpResponse("ok", status=200)
