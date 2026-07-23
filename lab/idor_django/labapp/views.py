"""
Deliberately vulnerable support-ticket view - Django variant.

Same exploitable IDOR as lab/idor/app.py (no ownership check on GET
/api/tickets/<id> - do not copy this pattern anywhere else), reproduced
with Django's own stateless signed-token helper (django.core.signing)
instead of the Flask target's opaque server-side token map (Step 5). Ticket
ids/owners and CANARY placement are identical to lab/idor/app.py since
agents/techniques/idor.py's red-team prompt hardcodes "the account
legitimately owns tickets 1 and 3."
"""

import time

from django.core import signing
from django.http import HttpResponse, JsonResponse
from django.views.decorators.csrf import csrf_exempt

CANARY = "SENTINELAI-IDOR-CANARY-4b8e1f0a"
SIGNING_SALT = "sentinelai-idor-session"

TICKETS = {
    1: {"owner_id": 1, "subject": "Can't reset my password", "body": "I tried the reset link but it expired, please help."},
    2: {"owner_id": 2, "subject": "Billing dispute", "body": f"My last invoice looks wrong, can someone check? Account notes: {CANARY}"},
    3: {"owner_id": 1, "subject": "Feature request", "body": "Would be great to have dark mode."},
}

LOG_LINES: list[str] = []


def _log(line: str) -> None:
    LOG_LINES.append(f"{time.strftime('%Y-%m-%d %H:%M:%S')} {line}\n")


@csrf_exempt
def login(request):
    if request.method != "POST":
        return JsonResponse({"status": "fail", "message": "POST required"}, status=405)
    token = signing.dumps({"user_id": 1}, salt=SIGNING_SALT)
    _log(f"LOGIN_ISSUED token={token!r} user_id=1")
    return JsonResponse({"status": "success", "session_token": token, "user_id": 1}, status=200)


def get_ticket(request, ticket_id):
    ticket_id = int(ticket_id)
    auth_header = request.headers.get("Authorization", "")
    token = auth_header.removeprefix("Bearer ").strip()

    requester_id = None
    try:
        requester_id = signing.loads(token, salt=SIGNING_SALT, max_age=3600).get("user_id")
    except signing.BadSignature:
        requester_id = None

    if requester_id is None:
        _log(f"TICKET_ACCESS ticket_id={ticket_id} token={token!r} result=UNAUTHENTICATED")
        return JsonResponse({"status": "fail", "message": "invalid or missing session token"}, status=401)

    ticket = TICKETS.get(ticket_id)
    if ticket is None:
        _log(f"TICKET_ACCESS ticket_id={ticket_id} requester_id={requester_id} result=NOT_FOUND")
        return JsonResponse({"status": "fail", "message": "ticket not found"}, status=404)

    # Deliberately vulnerable: no check that ticket["owner_id"] == requester_id.
    _log(
        f"TICKET_ACCESS ticket_id={ticket_id} requester_id={requester_id} "
        f"owner_id={ticket['owner_id']} cross_owner={requester_id != ticket['owner_id']} result=SUCCESS"
    )
    return JsonResponse({"status": "success", "ticket_id": ticket_id, **ticket}, status=200)


def logs(request):
    since = int(request.GET.get("since", 0) or 0)
    contents = "".join(LOG_LINES)
    return JsonResponse({"lines": contents[since:], "offset": len(contents)})


def healthz(request):
    return HttpResponse("ok", status=200)
