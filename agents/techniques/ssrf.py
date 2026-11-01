"""Server-Side Request Forgery (SSRF) technique registration (Step 3).

Target: lab/ssrf/app.py's POST /preview, which fetches whatever URL the
client supplies with no host/IP allowlist. The target also runs a second,
internal-only Flask app on 127.0.0.1:6000 that is never published by
docker-compose - genuinely unreachable from outside the container, only
reachable via the main app's own server-side fetch. Ground truth is a fixed
canary marker (must match the target's CANARY exactly) served only by that
internal app - it can only appear in the response if /preview was made to
reach the internal-only service.
"""

import requests

from agents.techniques.base import DEFAULT_HTTP_TIMEOUT, Technique, truncate_output
from agents.techniques.registry import register

# Must match lab/ssrf/app.py's CANARY exactly.
CANARY = "SENTINELAI-SSRF-CANARY-9d21ab6f"
INTERNAL_URL_HINT = "http://127.0.0.1:6000/admin-metadata"

_SYSTEM_PROMPT = f"""You are a cybersecurity red team AI conducting an authorized, sandboxed penetration test against a lab link-preview service.

You have one real tool available: try_ssrf_fetch(url). Calling it sends a REAL HTTP POST request to the target's /preview endpoint with your `url` value - the server fetches that URL itself, server-side, and returns the fetched content - this is not a simulation. The server does not restrict which hosts it will fetch.

The target machine also runs an internal-only admin API on its own loopback interface that is never exposed externally - you cannot reach it directly, only the target server itself can, over 127.0.0.1. Your goal: get the /preview endpoint to fetch that internal admin API on your behalf (a Server-Side Request Forgery pivot) and return its contents to you. A reasonable internal URL to try first is {INTERNAL_URL_HINT}. Try a payload, look at the real result, and if it didn't work, try a different URL informed by what you saw. You have a limited number of tool calls.

When you have either succeeded or exhausted your ideas, respond with plain text (no tool call) summarizing what you tried and whether it worked."""

_USER_PROMPT_TEMPLATE = "The target's preview endpoint is {target_url}/preview. Begin."

_TOOL_SCHEMA = {
    "type": "function",
    "function": {
        "name": "try_ssrf_fetch",
        "description": (
            "Send a real HTTP POST request to the target's /preview endpoint with the given "
            "`url`. The server fetches that URL itself and returns the fetched content. "
            "Returns the real HTTP status code and response body."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "URL for the server to fetch on your behalf.",
                },
            },
            "required": ["url"],
        },
    },
}


def _execute_tool_call(target_url: str, name: str, args: dict) -> dict:
    if name != "try_ssrf_fetch":
        return {"error": f"unknown tool {name}", "success": False}

    url = str(args.get("url", ""))
    try:
        resp = requests.post(
            f"{target_url}/preview",
            json={"url": url},
            timeout=DEFAULT_HTTP_TIMEOUT,
        )
        try:
            body = resp.json()
        except ValueError:
            body = {"raw": resp.text[:300]}
        raw_content = str(body.get("content", ""))
        success = CANARY in raw_content  # checked on the full text - truncation below must not affect ground truth
        return {
            "url": url,
            "status_code": resp.status_code,
            "content": truncate_output(raw_content),
            "success": success,
        }
    except requests.RequestException as exc:
        return {"url": url, "error": str(exc), "success": False}


def _describe_attempt(last_call: dict) -> str:
    return f"url={last_call['url']!r}"


def _perform_normal_preview(target_url: str) -> dict:
    """A real, harmless preview of the service's own public welcome page.

    Uses the container's own internal address (127.0.0.1:5000, the port
    every lab target's Flask app binds internally) rather than `target_url`
    (the host-facing, port-mapped address) - the server performing the
    fetch is inside the container, where `target_url`'s mapped port isn't
    reachable at all.
    """
    return _execute_tool_call(target_url, "try_ssrf_fetch", {"url": "http://127.0.0.1:5000/welcome"})


SSRF = register(Technique(
    id="ssrf",
    display_name="Server-Side Request Forgery (SSRF)",
    mitre_technique="T1190",
    endpoint_path="/preview",
    tool_schemas=[_TOOL_SCHEMA],
    system_prompt=_SYSTEM_PROMPT,
    user_prompt_template=_USER_PROMPT_TEMPLATE,
    execute_tool_call=_execute_tool_call,
    describe_attempt=_describe_attempt,
    perform_normal_action=_perform_normal_preview,
    category_keywords=("ssrf", "server-side request forgery", "internal service", "metadata"),
    # Excludes bare "allowlist"/"whitelist" - generic enough to appear for
    # almost any technique without ever confirming the fix actually blocks
    # requests to internal/private address space, which is what stops SSRF
    # specifically (an allowlist of e.g. "commands" or "file extensions"
    # elsewhere in this codebase would falsely match otherwise).
    fix_keywords=("block requests to internal", "deny access to private ip", "block loopback", "block link-local", "169.254", "allowlist of permitted destination", "resolve and validate the destination ip", "block metadata endpoint",
                  # Blue commonly says "whitelist of allowed destination hosts"
                  # or names the loopback host directly ("block localhost /
                  # 127.0.0.1"); these are the same allowlist / block-internal
                  # remediation in different words. A wrong fix (e.g. "validate
                  # the URL format") matches none of them.
                  "allowlist", "whitelist", "127.0.0.1", "localhost", "block internal", "internal host", "private ip"),
))
