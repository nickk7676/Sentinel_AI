"""Account takeover with a stolen reset token - STEP B of the chained attack (Step 8.3).

Target: lab/chained_privesc/app.py's POST /account/complete-reset, which
accepts a reset_token and, if it matches the administrator's, completes an
account takeover - returning the CANARY (the ground-truth success marker).

This is the SECOND half of a router-orchestrated chain. It cannot win on its
own: the reset_token is unguessable, so the canary is only reachable if an
earlier step (token_leak) already stole the token and the router handed it
down via chain_context (live_tools.run_live_attack's chain_context ->
battle_runner passes it from the battle state's artifacts). That hand-off is
the chain: the router runs token_leak, sees the leaked reset_token in its
state, then picks this technique and feeds it the token.
"""

import json

import requests

from agents.techniques.base import DEFAULT_HTTP_TIMEOUT, Technique
from agents.techniques.registry import register

# Must match lab/chained_privesc/app.py's CANARY exactly.
CANARY = "SENTINELAI-CHAIN-CANARY-9d4c7b1a"

_SYSTEM_PROMPT = """You are a cybersecurity red team AI conducting an authorized, sandboxed penetration test against a lab account-recovery service.

You have one real tool: complete_reset(reset_token). It sends a REAL HTTP POST to /account/complete-reset with the token you provide. If the token matches the administrator's secret reset_token, the server completes an account takeover and discloses the protected data.

A previous step in this engagement has already stolen the administrator's `reset_token` - it is given to you under "Reusable information already discovered in earlier steps". Your goal: call complete_reset with that EXACT stolen reset_token to take over the admin account. Do not guess a token - use the one you were given verbatim. If no token was provided, say so.

You have a limited number of tool calls. When you have either succeeded or exhausted your ideas, respond with plain text (no tool call) summarizing what you did and whether it worked."""

_USER_PROMPT_TEMPLATE = "The target exposes {target_url}/account/complete-reset (POST). Begin."

_TOOL_SCHEMA = {
    "type": "function",
    "function": {
        "name": "complete_reset",
        "description": (
            "Send a real POST to /account/complete-reset with a reset_token. If the token matches "
            "the administrator's, the server completes an account takeover and discloses the "
            "protected data. Use the exact token stolen in an earlier step."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "reset_token": {
                    "type": "string",
                    "description": "The administrator's reset_token, stolen in an earlier step (e.g. 'RST-...').",
                },
            },
            "required": ["reset_token"],
        },
    },
}


def _execute_tool_call(target_url: str, name: str, args: dict) -> dict:
    if name != "complete_reset":
        return {"error": f"unknown tool {name}", "success": False}

    token = str(args.get("reset_token") or "").strip()
    try:
        resp = requests.post(
            f"{target_url}/account/complete-reset",
            json={"reset_token": token},
            timeout=DEFAULT_HTTP_TIMEOUT,
        )
        try:
            body = resp.json()
        except ValueError:
            body = {"raw": resp.text[:300]}
        success = CANARY in json.dumps(body)
        return {
            "tool": "complete_reset",
            "reset_token": token,
            "status_code": resp.status_code,
            "body": body,
            "success": success,
        }
    except requests.RequestException as exc:
        return {"tool": "complete_reset", "reset_token": token, "error": str(exc), "success": False}


def _describe_attempt(last_call: dict) -> str:
    return f"complete_reset reset_token={last_call.get('reset_token')!r}"


def _perform_normal_action(target_url: str) -> dict:
    """Benign: a password-reset completion attempt with an obviously-invalid
    token (fails harmlessly) - a realistic non-attack request."""
    return _execute_tool_call(target_url, "complete_reset", {"reset_token": "RST-not-a-real-token"})


ACCOUNT_TAKEOVER = register(Technique(
    id="account_takeover",
    display_name="Account Takeover via Stolen Reset Token",
    mitre_technique="T1068",
    endpoint_path="/account/complete-reset",
    tool_schemas=[_TOOL_SCHEMA],
    system_prompt=_SYSTEM_PROMPT,
    user_prompt_template=_USER_PROMPT_TEMPLATE,
    execute_tool_call=_execute_tool_call,
    describe_attempt=_describe_attempt,
    perform_normal_action=_perform_normal_action,
    max_turns=3,
    chain_step=True,  # STEP B of the chain - skipped by the standalone training sweep (see base.Technique.chain_step)
    category_keywords=("account takeover", "privilege escalation", "stolen token", "token reuse",
                       "password reset abuse", "reset token"),
    fix_keywords=("unguessable reset token", "random reset token", "single-use", "one-time token",
                  "expire the token", "bind the token", "account-bound token",
                  "invalidate the token", "tie the token to the account"),
))
