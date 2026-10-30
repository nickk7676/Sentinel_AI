"""Real benign traffic against the portal.

Every function here issues a genuine, legitimate request that an ordinary
applicant would make. They produce real benign log lines (correct-credential
logins, viewing one's OWN application case, previewing an allowed external
link, checking one's own reset request). The demo interleaves these with the
attack so the log stream looks alive — and so blue can demonstrate that it
flags NONE of them (zero false positives).

Nothing here is an attack: no injection syntax, no cross-owner access, no
internal URLs, no token theft.
"""

from __future__ import annotations

import random

import requests

from demo.portal import seed_data as seed

TIMEOUT = 8

# Realistic benign applicants (no injection syntax anywhere).
_BENIGN_USERNAMES = ("guest", "testuser", "demo", "s.wu", "r.patel", "m.okafor")


def _login(url: str, username: str, password: str) -> str | None:
    """Real login; returns the issued applicant session token (or None)."""
    try:
        r = requests.post(f"{url}/login", data={"username": username, "password": password}, timeout=TIMEOUT)
        return r.json().get("session_token")
    except requests.RequestException:
        return None


def benign_legit_login(url: str) -> str:
    """The seeded applicant logging in with CORRECT credentials (succeeds, no injection)."""
    _login(url, seed.APPLICANT_USERNAME, seed.APPLICANT_PASSWORD)
    return f"legit login: {seed.APPLICANT_USERNAME} (correct password)"


def benign_failed_login(url: str) -> str:
    """An ordinary mistyped login — wrong password, NO injection syntax."""
    u = random.choice(_BENIGN_USERNAMES)
    _login(url, u, "".join(random.choice("abcdefghijklmnop0123456789") for _ in range(10)))
    return f"ordinary failed login: {u} (wrong password, no injection)"


def benign_view_own_case(url: str) -> str:
    """Applicant views their OWN application case (cross_owner=False)."""
    token = _login(url, seed.APPLICANT_USERNAME, seed.APPLICANT_PASSWORD)
    own_id = random.choice([1, 3])  # cases this applicant owns
    try:
        requests.get(f"{url}/api/tickets/{own_id}", headers={"Authorization": f"Bearer {token}"}, timeout=TIMEOUT)
    except requests.RequestException:
        pass
    return f"applicant views own application case #{own_id}"


def benign_preview(url: str) -> str:
    """A legitimate link preview of an ALLOWED external-style URL (not internal)."""
    # Preview the portal's own public welcome page — a benign, allowed fetch
    # (not the loopback internal admin service, so no canary leaks).
    allowed = f"{url}/welcome"
    try:
        requests.post(f"{url}/preview", json={"url": allowed}, timeout=TIMEOUT)
    except requests.RequestException:
        pass
    return "legit link preview of an allowed URL"


def benign_own_reset_lookup(url: str) -> str:
    """Guest checks their OWN pending reset request (no token leaked)."""
    try:
        requests.get(f"{url}/api/reset-requests/{seed.OWN_RESET_REQUEST_ID}", timeout=TIMEOUT)
    except requests.RequestException:
        pass
    return f"user checks own reset request #{seed.OWN_RESET_REQUEST_ID}"


# Ordered mix the orchestrator can fire to seed the log with life.
BENIGN_ACTIONS = [
    benign_legit_login,
    benign_view_own_case,
    benign_failed_login,
    benign_preview,
    benign_own_reset_lookup,
]


def generate_benign_burst(url: str, n: int = 5) -> list[str]:
    """Fire n benign actions (cycling through the mix). Returns descriptions."""
    out = []
    for i in range(n):
        action = BENIGN_ACTIONS[i % len(BENIGN_ACTIONS)]
        out.append(action(url))
    return out
