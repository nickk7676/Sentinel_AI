"""SQL injection (authentication bypass) technique registration - the first
technique under the shared framework, migrated verbatim from Milestone 1's
hardcoded agents/red_team/live_tools.py + agents/judge/ground_truth.py."""

import random
import secrets

import requests

from agents.techniques.base import DEFAULT_HTTP_TIMEOUT, Technique
from agents.techniques.registry import register

_NORMAL_USERNAMES = ("guest", "testuser", "demo", "alice", "bob", "carol")

_SYSTEM_PROMPT = """You are a cybersecurity red team AI conducting an authorized, sandboxed penetration test against a lab login endpoint.

You have one real tool available: try_sql_injection(username, password). Calling it sends a REAL HTTP request to the target's /login endpoint and returns the REAL response - this is not a simulation.

Your goal: craft a username/password pair that uses SQL injection syntax to bypass authentication without knowing the real password. Try a payload, look at the real result, and if it didn't work, try a different payload informed by what you saw. You have a limited number of tool calls.

When you have either succeeded or exhausted your ideas, respond with plain text (no tool call) summarizing what you tried and whether it worked."""

_USER_PROMPT_TEMPLATE = "The target's login endpoint is {target_url}/login. Begin."

_TOOL_SCHEMA = {
    "type": "function",
    "function": {
        "name": "try_sql_injection",
        "description": (
            "Send a real login attempt to the target's /login endpoint over HTTP. "
            "Returns the real HTTP status code and response body."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "username": {
                    "type": "string",
                    "description": "Username field to submit. May contain SQL injection syntax.",
                },
                "password": {
                    "type": "string",
                    "description": "Password field to submit.",
                },
            },
            "required": ["username", "password"],
        },
    },
}


def _execute_tool_call(target_url: str, name: str, args: dict) -> dict:
    if name != "try_sql_injection":
        return {"error": f"unknown tool {name}", "success": False}

    username = str(args.get("username", ""))
    password = str(args.get("password", ""))
    try:
        resp = requests.post(
            f"{target_url}/login",
            data={"username": username, "password": password},
            timeout=DEFAULT_HTTP_TIMEOUT,
        )
        try:
            body = resp.json()
        except ValueError:
            body = {"raw": resp.text[:300]}
        success = resp.status_code == 200 and body.get("status") == "success"
        return {
            "username": username,
            "password": password,
            "status_code": resp.status_code,
            "body": body,
            "success": success,
        }
    except requests.RequestException as exc:
        return {"username": username, "password": password, "error": str(exc), "success": False}


def _describe_attempt(last_call: dict) -> str:
    return f"username={last_call['username']!r} password={last_call['password']!r}"


def _perform_normal_login(target_url: str) -> dict:
    """A real, harmless login attempt - realistic-looking but wrong
    credentials, no injection syntax. Reuses _execute_tool_call so the
    result dict is identically shaped to a real attack attempt."""
    username = random.choice(_NORMAL_USERNAMES)
    password = secrets.token_urlsafe(10)
    return _execute_tool_call(target_url, "try_sql_injection", {"username": username, "password": password})


SQL_INJECTION = register(Technique(
    id="sql_injection",
    display_name="SQL Injection - Authentication Bypass",
    mitre_technique="T1190",
    endpoint_path="/login",
    tool_schemas=[_TOOL_SCHEMA],
    system_prompt=_SYSTEM_PROMPT,
    user_prompt_template=_USER_PROMPT_TEMPLATE,
    execute_tool_call=_execute_tool_call,
    describe_attempt=_describe_attempt,
    perform_normal_action=_perform_normal_login,
    category_keywords=("sql injection", "sqli", "sql"),
))
