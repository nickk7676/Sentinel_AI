"""Step 6.1 - machine-enforced scope/allowlist.

Every technique's tool execution and telemetry fetch receives target_url as
a plain caller-supplied string, with nothing stopping it from being pointed
anywhere - "this is an authorized, sandboxed penetration test" is currently
only ever asserted to the model in prompt text (see agents/techniques/
ssrf.py), never enforced in code. This module makes the enforcement real:
assert_in_scope() is the one check every real HTTP action must pass
(wired in centrally by agents/safety/guard.py), so red/blue are technically
incapable of acting against a host outside the allowlist, regardless of
what the model decides to do.
"""

from __future__ import annotations

import logging
import os
from functools import lru_cache
from urllib.parse import urlparse

# Comma-separated list of extra "scheme://host:port" base URLs to allow
# beyond the lab target registry - e.g. for a future real client engagement
# where targets aren't in training/targets.py. Deliberately not silent: any
# non-empty value logs a warning (once per distinct value per process,
# below) since this is the one thing in agents/safety that can widen scope
# rather than enforce it - it should never take effect unnoticed.
_EXTRA_TARGETS_ENV = "SENTINELAI_ALLOWED_TARGETS"

_logger = logging.getLogger(__name__)
_last_warned_extra: str | None = None


class ScopeViolationError(Exception):
    """Raised when code attempts to act against a host/port outside the
    authorized scope allowlist."""


@lru_cache(maxsize=1)
def _lab_target_urls() -> frozenset[str]:
    """training/targets.py's LabTarget registry is the canonical source of
    truth for every lab target this codebase is allowed to touch - it's a
    leaf module (no imports back into agents/ or backend/), so importing it
    here doesn't create a layering cycle. Imported lazily (not at module
    load time) so agents/safety has no hard dependency on training/ being
    importable in every deployment."""
    try:
        from training.targets import TARGETS
        return frozenset(target.url for target in TARGETS)
    except ImportError:
        return frozenset()


def allowed_targets() -> frozenset[str]:
    """The full allowlist: every registered lab target's base URL, plus any
    extra base URLs from SENTINELAI_ALLOWED_TARGETS (comma-separated),
    re-read on every call so an operator can update the env var without a
    process restart."""
    global _last_warned_extra
    extra = os.environ.get(_EXTRA_TARGETS_ENV, "")
    if extra and extra != _last_warned_extra:
        _logger.warning(
            "SENTINELAI_ALLOWED_TARGETS is set (%r) - the scope allowlist is "
            "extended beyond the lab target registry. This is a deliberate "
            "escape hatch, not a default: if you didn't set this on purpose, "
            "unset it.",
            extra,
        )
        _last_warned_extra = extra
    extra_urls = frozenset(_base_url(u.strip()) for u in extra.split(",") if u.strip())
    return _lab_target_urls() | extra_urls


def _base_url(target_url: str) -> str:
    parsed = urlparse(target_url)
    if not parsed.scheme or not parsed.hostname:
        raise ScopeViolationError(f"cannot parse target URL {target_url!r}")
    default_port = 443 if parsed.scheme == "https" else 80
    return f"{parsed.scheme}://{parsed.hostname}:{parsed.port or default_port}"


def assert_in_scope(target_url: str) -> None:
    """Raises ScopeViolationError unless target_url's scheme+host+port
    exactly matches an entry in allowed_targets()."""
    base = _base_url(target_url)
    allowed = allowed_targets()
    if base not in allowed:
        raise ScopeViolationError(
            f"target {target_url!r} is outside the authorized scope allowlist "
            f"({len(allowed)} target(s) registered) - refusing to act"
        )
