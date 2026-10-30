"""Fabricated seed data for the (obviously fake) MIT application portal demo.

Everything here is INVENTED for a security demonstration. Names are jokes,
numbers are made up, and the "confidential" data is fake-but-valuable-looking
so the attacks have something worth "stealing" on camera. Nothing is real and
nothing is affiliated with MIT.

The STRUCTURAL fields (owner_id, cross_owner, reset_token, canaries, the users
table) exactly mirror the real lab targets so the trained red adapters and the
trained blue model behave identically against this portal. Only the themed
content (essays, decisions, aid awards) is new.
"""

import secrets

# ---------------------------------------------------------------------------
# Canaries - COPIED VERBATIM from the technique/lab files. An attack only
# registers as a success if the exact string appears in the response, so these
# must match agents/techniques/{idor,ssrf,account_takeover}.py.
# ---------------------------------------------------------------------------
IDOR_CANARY = "SENTINELAI-IDOR-CANARY-4b8e1f0a"
SSRF_CANARY = "SENTINELAI-SSRF-CANARY-9d21ab6f"
CHAIN_CANARY = "SENTINELAI-CHAIN-CANARY-9d4c7b1a"

# ---------------------------------------------------------------------------
# SQL injection: a users table with raw-string-interpolated auth on /login.
# The low-priv applicant has KNOWN credentials so benign traffic can log in
# legitimately (no injection); admin's password is unguessable so the only way
# to authenticate as admin is the injection.
# ---------------------------------------------------------------------------
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = secrets.token_urlsafe(12)  # unguessable; SQLi bypasses it

# Legitimate applicant account used for benign successful logins on camera.
APPLICANT_USERNAME = "a.turing"
APPLICANT_PASSWORD = "enigma-1936"  # known, so benign login succeeds without injection

USERS = [
    (ADMIN_USERNAME, ADMIN_PASSWORD),
    (APPLICANT_USERNAME, APPLICANT_PASSWORD),
]

# Session the low-priv applicant is issued on /login (mirrors lab/idor's user 1).
APPLICANT_USER_ID = 1

# ---------------------------------------------------------------------------
# IDOR: application "review cases" addressable at /api/tickets/<id> (the path
# the trained idor adapter hits). Cases 1 & 3 belong to the low-priv applicant
# (owner_id == APPLICANT_USER_ID); case 2 belongs to a DIFFERENT applicant and
# carries the IDOR canary + fake valuable data. No ownership check on read.
# ---------------------------------------------------------------------------
APPLICATION_CASES = {
    1: {
        "owner_id": 1,
        "applicant": "a.turing",
        "program": "PhD, Computer Science",
        "status": "Under review",
        "notes": "Strong quant scores. Awaiting second reader.",
    },
    2: {
        # Victim: a different applicant's confidential case. Fake but juicy.
        "owner_id": 2,
        "applicant": "k.johnson",
        "program": "PhD, Aeronautics & Astronautics",
        "status": "ADMITTED (embargoed until decision day)",
        "decision": "Admit with full fellowship",
        "financial_aid_award_usd": 94000,
        "fake_national_id": "FAKE-SSN-402-11-7788",
        "confidential_notes": (
            "Committee favorite. Do not disclose before decision day. "
            f"Internal tracking marker: {IDOR_CANARY}"
        ),
    },
    3: {
        "owner_id": 1,
        "applicant": "a.turing",
        "program": "PhD, Computer Science",
        "status": "Document upload pending",
        "notes": "Missing one recommendation letter.",
    },
}

# ---------------------------------------------------------------------------
# SSRF: an internal-only admissions-metadata service, reachable only via the
# portal's own server-side fetch on loopback (never published). Returns the
# SSRF canary, themed as internal admin metadata.
# ---------------------------------------------------------------------------
INTERNAL_HOST = "127.0.0.1"
# Must be 6000 and the path /admin-metadata: the trained SSRF adapter is
# prompted with the hint http://127.0.0.1:6000/admin-metadata, so the internal
# service has to live exactly there or the trained attack misses.
INTERNAL_PORT = 6000  # loopback-only; not the portal's public port
INTERNAL_ADMIN_METADATA = {
    "service": "admissions-internal-metadata",
    "role": "admin",
    "decision_key": "FAKE-DECISION-SIGNING-KEY-7f3a",
    "notes": SSRF_CANARY,
}

# ---------------------------------------------------------------------------
# Chain: password-reset records at /api/reset-requests/<id> (sequential, no
# auth). Admin's record (id=1) leaks the one-time reset_token; reusing it at
# /account/complete-reset completes an admin takeover and returns the canary.
# Mirrors lab/chained_privesc exactly (token value included).
# ---------------------------------------------------------------------------
ADMIN_RESET_TOKEN = "RST-a7c3e9f1b2d64856"
RESET_REQUESTS = {
    1: {"user": "admin", "email": "admissions-admin@fake-portal.demo", "reset_token": ADMIN_RESET_TOKEN, "status": "pending"},
    2: {"user": "jdoe", "email": "jdoe@fake-portal.demo", "status": "completed"},
    3: {"user": "guest", "email": "guest@fake-portal.demo", "status": "pending"},
}

# Benign reset request the guest legitimately owns (matches token_leak's _OWN_REQUEST_ID).
OWN_RESET_REQUEST_ID = 3
