"""
Generic, technique-agnostic recon tools (Step 8.1).

Unlike the per-technique tool calls in agents/techniques/*.py, these are
plain deterministic HTTP probes - no model inference, no LoRA adapter. They
exist so the router (router.py) has something concrete to reason over
before it has to pick a technique.

Each public function is wrapped through agents.safety.guard.
guard_tool_executor at import time, the exact same wrapper every technique's
execute_tool_call already goes through (agents/techniques/registry.py's
register()) - it's already shaped as (target_url, name, args) -> dict, so
recon gets identical scope/kill-switch/audit-log coverage with no new safety
code. technique="recon" tags every audit record so these show up
distinguishable from real technique actions in logs/audit_log.jsonl.

target_url is threaded through every one of these calls, including
enumerate_forms (whose real input is already-fetched HTML, not a URL it
fetches itself) - so the scope/audit check never depends on a tool's
primary argument happening to be a URL.
"""

from __future__ import annotations

import re
from urllib.parse import urljoin, urlparse

import requests

import agents.techniques  # noqa: F401 - must fully import before agents.safety.guard
# below: agents.techniques.registry.register() lazily imports agents.safety.guard
# per technique at package-import time, so importing agents.techniques first (and
# fully) here avoids a circular partial-import if this module is the first thing in
# the process to touch agents.safety.guard directly, as guard.py itself imports
# agents.techniques.base.
from agents.safety.guard import guard_tool_executor
from agents.techniques.base import DEFAULT_HTTP_TIMEOUT, truncate_output
from agents.red_team.router.schema import ReconFinding

_HREF_RE = re.compile(r'href=["\']([^"\'#][^"\']*)["\']', re.IGNORECASE)
_FORM_RE = re.compile(r"<form\b[^>]*>.*?</form>", re.IGNORECASE | re.DOTALL)
_FORM_ATTR_RE = re.compile(r'<form\b[^>]*\baction=["\']([^"\']*)["\']', re.IGNORECASE)
_FORM_METHOD_RE = re.compile(r'<form\b[^>]*\bmethod=["\']([^"\']*)["\']', re.IGNORECASE)
_INPUT_RE = re.compile(r'<input\b([^>]*)>', re.IGNORECASE)
_INPUT_NAME_RE = re.compile(r'\bname=["\']([^"\']*)["\']', re.IGNORECASE)
_INPUT_TYPE_RE = re.compile(r'\btype=["\']([^"\']*)["\']', re.IGNORECASE)
_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE)
_HASHLIKE_RE = re.compile(r"^[0-9a-f]{16,}$", re.IGNORECASE)
_SEQUENTIAL_ID_RE = re.compile(r"^\d{1,6}$")


def _fetch(url: str, method: str = "GET") -> tuple[int | None, str, dict]:
    try:
        # Benign, body-less request - recon never sends a technique payload;
        # an empty-JSON POST exists only to read a POST-only endpoint's own
        # "missing field X" error, which is the cheapest signal for what that
        # endpoint is for (see _body_tell / _fingerprint_endpoint).
        kwargs = {"timeout": DEFAULT_HTTP_TIMEOUT}
        if method != "GET":
            kwargs["json"] = {}
        resp = requests.request(method, url, **kwargs)
        # Lowercase header keys: requests preserves the server's original case
        # (e.g. "Content-Type"), but every lookup in this module uses the
        # lowercase name, so normalize once here.
        headers = {k.lower(): v for k, v in resp.headers.items()}
        return resp.status_code, truncate_output(resp.text), headers
    except requests.RequestException as exc:
        return None, "", {"error": str(exc)}


def _body_tell(body: str, content_type: str) -> str:
    """A short, technique-discriminating snippet of a response body. For a
    JSON error, the message/error field is the richest cheap signal (e.g.
    path_traversal's '/download' leaks a filesystem path, broken_auth's
    '/account' says 'invalid session'); for anything else, a trimmed,
    boilerplate-free head of the body."""
    body = (body or "").strip()
    if not body:
        return ""
    if "json" in content_type.lower():
        try:
            import json as _json
            data = _json.loads(body)
            if isinstance(data, dict):
                for key in ("error", "message", "detail", "msg"):
                    if data.get(key):
                        return f"{key}={str(data[key])[:120]!r}"
                keys = list(data.keys())
                # An endpoint that hands back a session/token field in response
                # to a credential-less benign POST has authenticated us with NO
                # credentials - the textbook broken-authentication tell, and the
                # thing that tells it apart from a login that properly rejects
                # (SQL-injection's surface, which answers 'Invalid credentials').
                # Surface it explicitly rather than burying it in a key list, so
                # the router weighs it instead of anchoring on "/login -> SQLi".
                if any(any(w in k.lower() for w in ("session", "token", "jwt", "auth")) for k in keys):
                    return f"issued a session token to a request with no credentials (keys: {', '.join(keys[:6])})"
                # no known error key - surface the field names themselves,
                # which often name the parameter the endpoint expects
                return "json keys: " + ", ".join(keys[:6])
        except ValueError:
            pass
    # Non-JSON: drop the generic Werkzeug HTML error boilerplate
    if "<title>" in body:
        return ""
    return body[:120]


def _probe_root(target_url: str, name: str, args: dict) -> dict:
    status, body, headers = _fetch(target_url)
    success = status is not None
    tech_tells = [
        v for k, v in headers.items()
        if k.lower() in ("server", "x-powered-by") and v
    ]
    cookie_names = [c.split("=", 1)[0].strip() for c in headers.get("set-cookie", "").split(";") if "=" in c]
    return {
        "success": success,
        "status_code": status,
        "body": body,
        "headers": headers,
        "tech_tells": tech_tells,
        "cookie_names": cookie_names,
    }


def _crawl_links(target_url: str, name: str, args: dict) -> dict:
    depth = args.get("depth", 1)
    status, body, _ = _fetch(target_url)
    if status is None:
        return {"success": False, "links": []}

    base_host = urlparse(target_url).netloc
    links = []
    for href in _HREF_RE.findall(body):
        absolute = urljoin(target_url + "/", href)
        if urlparse(absolute).netloc == base_host and absolute not in links:
            links.append(absolute)
    return {"success": True, "links": links[:50], "depth": depth}


def _enumerate_forms(target_url: str, name: str, args: dict) -> dict:
    """args: {"page_html": <already-fetched HTML>}. target_url is not
    re-fetched here - it's still required and still passed through the
    guarded wrapper below so every recon call carries the same scope/audit
    trail, regardless of whether this particular tool touches the network
    itself."""
    page_html = args.get("page_html", "")
    forms = []
    for form_html in _FORM_RE.findall(page_html):
        action_match = _FORM_ATTR_RE.search(form_html)
        method_match = _FORM_METHOD_RE.search(form_html)
        fields = []
        for attrs in _INPUT_RE.findall(form_html):
            name_match = _INPUT_NAME_RE.search(attrs)
            type_match = _INPUT_TYPE_RE.search(attrs)
            if name_match:
                fields.append({
                    "name": name_match.group(1),
                    "type": type_match.group(1) if type_match else "text",
                })
        forms.append({
            "action": action_match.group(1) if action_match else target_url,
            "method": (method_match.group(1) if method_match else "GET").upper(),
            "fields": fields,
        })
    return {"success": True, "forms": forms}


def _id_shape(value: str) -> str:
    if _UUID_RE.match(value):
        return "uuid"
    if _SEQUENTIAL_ID_RE.match(value):
        return "sequential"
    if _HASHLIKE_RE.match(value):
        return "hash-like"
    return "opaque"


def _fingerprint_endpoint(target_url: str, name: str, args: dict) -> dict:
    """Hits an endpoint and, if its path contains an id-shaped segment,
    classifies it - direct, cheap signal for the router to weigh IDOR
    against other techniques (see agents/techniques/idor.py's own use of
    sequential ids)."""
    path = args.get("path", "")
    url = urljoin(target_url + "/", path.lstrip("/")) if path else target_url
    status, body, headers = _fetch(url)

    content_type = headers.get("content-type", "")
    allow = (headers.get("allow") or headers.get("Allow") or "").upper()
    allowed_methods = [m.strip() for m in allow.split(",") if m.strip() and m.strip() != "OPTIONS"]
    tell = _body_tell(body, content_type)

    # If GET isn't allowed but POST (or another verb) is, this is a write-style
    # endpoint (login, diagnostics, preview...). A single benign body-less
    # request with the allowed verb reads its "missing parameter" error, which
    # usually names what the endpoint is for - the discriminating signal GET
    # alone can't reach on a 405.
    if status == 405 and allowed_methods:
        m2 = "POST" if "POST" in allowed_methods else allowed_methods[0]
        s2, b2, h2 = _fetch(url, method=m2)
        tell2 = _body_tell(b2, h2.get("content-type", ""))
        if tell2:
            tell = f"{m2} {tell2}"
        if s2 is not None:
            content_type = h2.get("content-type", "") or content_type

    # Not every framework answers a wrong-method request with 405 + Allow:
    # Express (and others) return a bare 404 with no Allow header, so the 405
    # branch above never fires and a POST-only endpoint (login, diagnostics,
    # preview...) looks like a dead 404 - which is exactly why the three Express
    # lab targets exposed no clue at all and the router fell back to guessing.
    # When GET gave us nothing useful on a NAMED sub-path, try one benign POST:
    # a real POST-only endpoint answers with a "missing parameter" error that
    # names what it's for (the discriminating tell), while a path that truly
    # doesn't exist just 404s again with no tell, so this adds no noise.
    if path and status in (404, 405) and "POST" not in allowed_methods and not tell:
        sp, sb, sh = _fetch(url, method="POST")
        post_tell = _body_tell(sb, sh.get("content-type", ""))
        if post_tell and sp is not None and sp != 404:
            tell = f"POST {post_tell}"
            content_type = sh.get("content-type", "") or content_type
            allowed_methods.append("POST")

    # Numbered sub-resource probe: a collection that 404s on its own root
    # (e.g. /api/tickets) but responds at <path>/1 is an object addressed by a
    # guessable, sequential id - the hallmark of IDOR, and something a GET on
    # the bare collection can't reveal. One cheap extra request surfaces it,
    # plus whatever guards it (e.g. a session-token check).
    numbered_subresource = False
    last_seg = urlparse(url).path.rstrip("/").split("/")[-1]
    if status == 404 and not last_seg.isdigit():
        s3, b3, h3 = _fetch(url.rstrip("/") + "/1")
        if s3 is not None and s3 != 404:
            numbered_subresource = True
            status = s3
            content_type = h3.get("content-type", "") or content_type
            sub_tell = _body_tell(b3, h3.get("content-type", ""))
            tell = f"sub-resource /1 -> {sub_tell}" if sub_tell else "sub-resource /1 exists"

    segments = [s for s in urlparse(url).path.split("/") if s]
    id_segment = next((s for s in segments if any(c.isdigit() for c in s)), None)
    id_shape = _id_shape(id_segment) if id_segment else None
    if numbered_subresource and not id_shape:
        id_shape = "sequential"

    return {
        "success": status is not None,
        "status_code": status,
        "content_type": content_type,
        "allowed_methods": allowed_methods,
        "body_tell": tell,
        "id_segment": id_segment,
        "id_shape": id_shape,
        "numbered_subresource": numbered_subresource,
    }


_probe_root_guarded = guard_tool_executor("recon", _probe_root)
_crawl_links_guarded = guard_tool_executor("recon", _crawl_links)
_enumerate_forms_guarded = guard_tool_executor("recon", _enumerate_forms)
_fingerprint_endpoint_guarded = guard_tool_executor("recon", _fingerprint_endpoint)


def fetch_page_html(target_url: str) -> str:
    """Raw HTML for target_url's root page - feeds enumerate_forms, which
    needs already-fetched HTML rather than fetching its own. Reuses the same
    guarded probe_root fetch (so it's still scope/audit-covered) instead of
    making a second, unguarded network call."""
    result = _probe_root_guarded(target_url, "probe_root", {})
    return result.get("body", "")


def probe_root(target_url: str) -> ReconFinding:
    result = _probe_root_guarded(target_url, "probe_root", {})
    tells = ", ".join(result.get("tech_tells", [])) or "none observed"
    cookies = ", ".join(result.get("cookie_names", [])) or "none"
    notes = f"tech tells: {tells}; cookies: {cookies}"
    if not result.get("success"):
        notes = f"unreachable: {result.get('headers', {}).get('error', 'no response')}"
    return ReconFinding(
        endpoint=target_url,
        method="GET",
        response_shape=f"status={result.get('status_code')}",
        notes=notes,
    )


def crawl_links(target_url: str, depth: int = 1) -> list[ReconFinding]:
    result = _crawl_links_guarded(target_url, "crawl_links", {"depth": depth})
    links = result.get("links", [])
    if not links:
        return [ReconFinding(endpoint=target_url, method="GET", response_shape="no links", notes="no same-origin links found")]
    return [
        ReconFinding(endpoint=link, method="GET", response_shape="link", notes="discovered via crawl_links")
        for link in links
    ]


def enumerate_forms(target_url: str, page_html: str) -> list[ReconFinding]:
    result = _enumerate_forms_guarded(target_url, "enumerate_forms", {"page_html": page_html})
    forms = result.get("forms", [])
    if not forms:
        return [ReconFinding(endpoint=target_url, method="GET", response_shape="no forms", notes="no forms found on page")]
    findings = []
    for form in forms:
        field_names = ", ".join(f["name"] for f in form["fields"]) or "(no named fields)"
        findings.append(ReconFinding(
            endpoint=form["action"],
            method=form["method"],
            params=tuple(f["name"] for f in form["fields"]),
            response_shape="form",
            notes=f"fields: {field_names}",
        ))
    return findings


def fingerprint_endpoint(target_url: str, path: str = "") -> ReconFinding:
    result = _fingerprint_endpoint_guarded(target_url, "fingerprint_endpoint", {"path": path})
    parts = []
    methods = result.get("allowed_methods") or []
    if methods:
        parts.append("accepts " + "/".join(methods))
    id_shape = result.get("id_shape")
    if id_shape:
        parts.append(f"id_shape={id_shape}")
    tell = result.get("body_tell")
    if tell:
        parts.append(f"response: {tell}")
    notes = "; ".join(parts) if parts else "no distinguishing signal"
    return ReconFinding(
        endpoint=urljoin(target_url + "/", path.lstrip("/")) if path else target_url,
        method="GET",
        response_shape=f"status={result.get('status_code')} content-type={result.get('content_type')}",
        notes=notes,
    )
