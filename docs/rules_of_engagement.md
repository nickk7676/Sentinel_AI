# SentinelAI — Rules of Engagement / Authorization Agreement (Draft Template)

> **Status: draft, not legal advice.** This is a starting template for Step 6.5
> of the project plan. It must be reviewed and finalized with a qualified
> lawyer before it is used to authorize any engagement against a real
> client's systems. Until then, the only "client" this system is authorized
> against is the lab target set described below.

## 1. Purpose

This document defines the scope, permitted actions, and safety controls
under which SentinelAI's red team agent may perform automated attack
simulations, and blue team agent may perform automated detection, against a
named set of target systems. It exists so authorization is an explicit,
written, mutually agreed fact — not an assumption embedded in a prompt.

## 2. Authorized scope

- **In scope:** only the target(s) explicitly listed in this section (base
  URL, host, and port). For the current lab environment, this is every
  target registered in `training/targets.py`'s `TARGETS` list (see
  `agents/safety/scope.py`'s `allowed_targets()` for the live, authoritative
  list the system actually enforces).
- **Out of scope:** everything else, including any system reachable from an
  in-scope target but not itself explicitly listed (e.g. a pivot target
  reached via SSRF must also be separately listed to be in scope for
  reporting purposes, even though the technical control in
  `agents/safety/scope.py` only ever restricts the *initial* target the
  harness is pointed at).
- Scope changes require updating the allowlist (`training/targets.py` for a
  lab target, or the `SENTINELAI_ALLOWED_TARGETS` environment variable for
  an ad hoc addition) and are only effective once reflected there — the
  system is technically incapable of acting outside this list regardless of
  what any prompt or model output claims (see `agents/safety/guard.py`).

## 3. Duration

Engagement window: **[start date] — [end date]**. Outside this window, no
battles should be run against the listed targets even though the technical
allowlist does not itself enforce a time boundary today — the safety
framework does not yet implement scheduled expiry.

## 4. Permitted techniques

Only the techniques listed in `agents/techniques/` at the time of
authorization, currently: SQL injection, command injection, IDOR, path
traversal, broken authentication, SSRF. Any new technique added to the
codebase after this agreement is signed is not automatically in scope for
an existing engagement.

## 5. Safety controls in effect

This system enforces the following technical controls for every action, not
merely as prompted behavior:

- **Scope allowlist** (`agents/safety/scope.py`) — every action is checked
  against the authorized target list before it is allowed to execute.
- **Kill-switch** (`agents/safety/killswitch.py`) — a target is
  automatically paused after repeated consecutive errors (default: 8 in a
  row), requiring a human to manually resume it after checking what
  happened.
- **Redaction** (`agents/safety/redact.py`) — secret-shaped values
  (API keys, tokens, credit-card/SSN-shaped numbers, private key material)
  are scrubbed before anything is persisted to disk or sent to a
  third-party LLM provider.
- **Hash-chained audit log** (`agents/safety/audit.py`) — every action taken
  is recorded in an append-only log (`logs/audit_log.jsonl`),
  verifiable after the fact with `verify_chain()`. Note the precise
  guarantee: this detects edited records, not a truncated/shortened log —
  see the module docstring before describing this as tamper-proof to a
  client.

## 6. Data handling

- No real client data should ever be exfiltrated or persisted verbatim; see
  Section 5's redaction control.
- Full battle transcripts and audit logs are retained locally for training
  and compliance analysis. Retention period and deletion policy: **[TBD —
  define before any real client engagement, see plan Step 11.2]**.

## 7. Human oversight

Per the project plan's Step 10.6, full autonomy against a real client's
production systems is a trust milestone earned later, not assumed. Until
then, a human must review and approve engagement scope before each
authorization period, and should periodically review the audit log
(`agents/safety/audit.py`'s `verify_chain()` plus manual spot-checks of
`logs/audit_log.jsonl`).

## 8. Signatures

| Role | Name | Signature | Date |
|---|---|---|---|
| Authorizing client representative | | | |
| SentinelAI engagement owner | | | |
