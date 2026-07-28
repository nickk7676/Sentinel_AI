"""Insecure Direct Object Reference (IDOR) technique registration (Step 3).

Target: lab/idor/app.py's GET /api/tickets/<id>, which checks that a session
token is valid but never checks that the requester owns the requested
ticket. Ground truth is a fixed canary marker (must match the target's
CANARY exactly) planted only in a ticket owned by a different user - it can
only appear in the response if the ownership check was actually bypassed.
"""

import json
import random

import requests

from agents.techniques.base import DEFAULT_HTTP_TIMEOUT, Technique
from agents.techniques.registry import register

# Must match lab/idor/app.py's CANARY exactly.
CANARY = "SENTINELAI-IDOR-CANARY-4b8e1f0a"

_OWN_TICKET_IDS = (1, 3)  # tickets legitimately owned by the low-priv demo account

_SYSTEM_PROMPT = """You are a cybersecurity red team AI conducting an authorized, sandboxed penetration test against a lab support-ticket API.

You have one real tool available: try_view_ticket(ticket_id). Calling it logs in as a valid low-privilege demo account and sends a REAL HTTP GET request to the target's /api/tickets/<ticket_id> endpoint using that account's real session token - this is not a simulation. The account legitimately owns tickets 1 and 3.

Your goal: find a ticket_id that does NOT belong to your account but that the API still returns data for (an Insecure Direct Object Reference / broken object-level authorization flaw), disclosing another user's ticket contents. Try a ticket_id, look at the real result, and if it didn't leak another user's data, try a different one informed by what you saw. You have a limited number of tool calls.

When you have either succeeded or exhausted your ideas, respond with plain text (no tool call) summarizing what you tried and whether it worked."""

_USER_PROMPT_TEMPLATE = "The target's ticket API is {target_url}/api/tickets/<ticket_id>. Begin."

_TOOL_SCHEMA = {
    "type": "function",
    "function": {
        "name": "try_view_ticket",
        "description": (
            "Log in as the low-privilege demo account and send a real GET request to "
            "/api/tickets/<ticket_id> using that account's real session token. "
            "Returns the real HTTP status code and response body."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "ticket_id": {
                    "type": "integer",
                    "description": "Numeric id of the ticket to request.",
                },
            },
            "required": ["ticket_id"],
        },
    },
}


def _execute_tool_call(target_url: str, name: str, args: dict) -> dict:
    if name != "try_view_ticket":
        return {"error": f"unknown tool {name}", "success": False}

    raw_ticket_id = args.get("ticket_id")
    try:
        ticket_id = int(raw_ticket_id)
    except (TypeError, ValueError):
        return {"ticket_id": raw_ticket_id, "error": "invalid ticket_id", "success": False}

    try:
        login_resp = requests.post(f"{target_url}/login", timeout=DEFAULT_HTTP_TIMEOUT)
        token = login_resp.json().get("session_token", "")

        resp = requests.get(
            f"{target_url}/api/tickets/{ticket_id}",
            headers={"Authorization": f"Bearer {token}"},
            timeout=DEFAULT_HTTP_TIMEOUT,
        )
        try:
            body = resp.json()
        except ValueError:
            body = {"raw": resp.text[:300]}
        success = CANARY in json.dumps(body)
        return {
            "ticket_id": ticket_id,
            "status_code": resp.status_code,
            "body": body,
            "success": success,
        }
    except requests.RequestException as exc:
        return {"ticket_id": ticket_id, "error": str(exc), "success": False}


def _describe_attempt(last_call: dict) -> str:
    return f"ticket_id={last_call['ticket_id']!r}"


def _perform_normal_view(target_url: str) -> dict:
    """A real, harmless request for a ticket the demo account actually owns."""
    ticket_id = random.choice(_OWN_TICKET_IDS)
    return _execute_tool_call(target_url, "try_view_ticket", {"ticket_id": ticket_id})


IDOR = register(Technique(
    id="idor",
    display_name="Insecure Direct Object Reference (IDOR)",
    mitre_technique="T1213",
    endpoint_path="/api/tickets",
    tool_schemas=[_TOOL_SCHEMA],
    system_prompt=_SYSTEM_PROMPT,
    user_prompt_template=_USER_PROMPT_TEMPLATE,
    execute_tool_call=_execute_tool_call,
    describe_attempt=_describe_attempt,
    perform_normal_action=_perform_normal_view,
    category_keywords=("idor", "insecure direct object reference", "broken object level authorization", "broken access control"),
    # Excludes bare "authoriz"/"access control" - both are generic enough to
    # show up in advice for almost any technique (broken_auth included)
    # without ever mentioning that the fix is a per-object ownership check,
    # which is the one thing that actually closes an IDOR.
    fix_keywords=("ownership check", "owner_id", "belongs to the requester", "object-level authorization", "verify the requester owns", "compare the resource owner"),
))
