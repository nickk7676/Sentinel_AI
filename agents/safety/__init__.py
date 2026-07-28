"""Step 6 - safety & authorization framework.

Cross-cutting guardrails that sit between red/blue's tool-calling code and
any real target: a machine-enforced scope allowlist (scope.py), rate
limiting / auto-pause on error storms (killswitch.py), redaction before
anything is persisted or sent to a third-party LLM provider (redact.py),
and an immutable, hash-chained audit log of every action taken (audit.py).
guard.py wires all three around a Technique's execute_tool_call/
fetch_telemetry at registration time (agents/techniques/registry.py), so
no other call site in the codebase needs to change.
"""
