"""Step 6.3 - redaction before anything is persisted or leaves the box.

Everything red/blue encounter during a live battle is real HTTP traffic
against a real target - training/battle_log.py, training/dataset.py, and
(when a remote LLM_PROVIDER is configured) agents/blue_team/agent.py all
persist or transmit that traffic verbatim today. This scrubs secret-*shaped*
values only (API keys, JWTs, AWS keys, card/SSN-shaped digit runs, private
key blocks) - deliberately not generic email/password fields, since those
are legitimate parts of several techniques' own payloads (e.g. broken_auth's
login body) and the lab fixtures never contain real secrets of the shapes
below, so this is pure defense-in-depth with no effect on today's training
signal.
"""

from __future__ import annotations

import re

_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("private_key_block", re.compile(
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.DOTALL)),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b")),
    ("aws_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("bearer_token", re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/-]+=*")),
    ("api_key", re.compile(r"\b(?:sk|pk|ghp|gho|ghu|ghs)-[A-Za-z0-9]{10,}\b")),
    ("credit_card", re.compile(r"\b(?:\d[ -]?){13,16}\b")),
    ("ssn", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
]


def redact_text(text: str) -> str:
    if not text:
        return text
    redacted = text
    for label, pattern in _PATTERNS:
        redacted = pattern.sub(f"[REDACTED:{label}]", redacted)
    return redacted


def redact_value(value):
    """Recursively redact strings inside dicts/lists - tool-call results,
    conversation transcripts, and log excerpts are all nested structures,
    not flat text."""
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, dict):
        return {k: redact_value(v) for k, v in value.items()}
    if isinstance(value, list):
        return [redact_value(v) for v in value]
    return value
