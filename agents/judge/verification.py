"""
Step 7.2 - blue-team remediation verification.

Blue only ever sees log/telemetry text (agents/blue_team/agent.py's
defend_live never receives target source code), so its recommended_fix
(Step 7.1) is freeform remediation advice, not applicable code - there is no
general-purpose engine here that turns that prose into a real patch and
rebuilds a container.

What this module verifies for real, over live HTTP, is narrower but still
concrete: whether blue named the actual correct remediation category for
this technique (matched the same way threat_category is matched against
Technique.category_keywords in agents/judge/ground_truth.py), and if so,
replays red's exact winning attack against that technique's distractor lab
target (training/targets.py's role="distractor" - the same app, same
contract, with the real fix already applied) to confirm the exploit that
just worked no longer does. A fix that didn't name the right category was
never applied anywhere, so the replay runs against the same still-vulnerable
target instead - "this fix would not have helped" is a real, confirmed HTTP
replay too, not just a keyword miss.

This is a real live-battle re-run every time it fires (a second live HTTP
call to a real target through the same guarded execute_tool_call as the
original attack), just against a fixed, already-patched counterpart instead
of a dynamically-patched one - see the module docstring above for why.
"""

from __future__ import annotations

from agents.techniques.base import Technique


def _extract_winning_call(attack: dict) -> tuple[str, dict] | None:
    """Recovers the (tool_name, arguments) pair for the tool_calls_made entry
    with success=True, by pairing attack["tool_calls"] positionally against
    every assistant turn's "tool_calls" in attack["_live_messages"] - both
    are built by agents/red_team/live_tools.py's run_live_attack() in the
    same call order (one flattened entry per real HTTP attempt across every
    turn), so index i in one is always index i in the other. Returns None if
    there's no recorded winning call (attack failed, or a normal-traffic
    round with no _live_messages at all)."""
    tool_calls_made = attack.get("tool_calls") or []
    flattened_calls: list[tuple[str, dict]] = []
    for msg in attack.get("_live_messages") or []:
        if msg.get("role") == "assistant" and msg.get("tool_calls"):
            for tc in msg["tool_calls"]:
                flattened_calls.append((tc.get("name", ""), tc.get("arguments") or {}))

    for i, result in enumerate(tool_calls_made):
        if result.get("success") and i < len(flattened_calls):
            return flattened_calls[i]
    return None


def _distractor_url(technique_id: str) -> str | None:
    """training/targets.py's role="distractor" target for this technique -
    same Flask app/contract as the vulnerable training target, with the real
    fix already applied (Step 5.3). Imported lazily, same as
    agents/safety/scope.py does for the same module, so agents/judge has no
    hard dependency on training/ being importable in every deployment."""
    try:
        from training.targets import targets_for
    except ImportError:
        return None
    candidates = targets_for(technique_id, role="distractor")
    return candidates[0].url if candidates else None


def verify_fix(technique: Technique, attack: dict, defense: dict, target_url: str) -> dict:
    """Returns a verification result dict, present on every battle's result
    but only meaningful (attempted=True) when there was a real successful
    attack and blue proposed some fix for it.

    Fields:
      attempted            - whether a live replay was actually made.
      fix_category_correct - did recommended_fix name the real remediation
                              for this technique (keyword match)? None if
                              never checked (nothing to verify).
      fix_verified         - did the replayed attack fail against the target
                              the fix maps to? None if never checked.
      verification_target  - which URL the replay was run against.
      reason                - short human-readable explanation, for logging.
    """
    result = {
        "attempted": False,
        "fix_category_correct": None,
        "fix_verified": None,
        "verification_target": None,
        "reason": "",
    }

    if not attack.get("success"):
        result["reason"] = "attack did not succeed - nothing to remediate"
        return result

    recommended_fix = str(defense.get("recommended_fix") or "").strip()
    if not recommended_fix:
        result["reason"] = "blue proposed no recommended_fix"
        return result

    winning_call = _extract_winning_call(attack)
    if winning_call is None:
        result["reason"] = "could not recover the winning attack call for replay"
        return result

    fix_text = recommended_fix.lower()
    fix_category_correct = any(kw in fix_text for kw in technique.fix_keywords)
    result["fix_category_correct"] = fix_category_correct

    replay_url = target_url
    if fix_category_correct:
        distractor_url = _distractor_url(technique.id)
        if distractor_url is not None:
            replay_url = distractor_url
    result["verification_target"] = replay_url

    name, args = winning_call
    try:
        replay_result = technique.execute_tool_call(replay_url, name, args)
    except Exception as exc:
        result["attempted"] = True
        result["reason"] = f"replay against {replay_url} raised an error: {exc}"
        return result

    result["attempted"] = True
    still_works = bool(replay_result.get("success"))
    result["fix_verified"] = fix_category_correct and not still_works
    target_desc = "the patched distractor target" if replay_url != target_url else "the original (still-vulnerable) target"
    result["reason"] = (
        f"replayed red's winning attack against {target_desc} - "
        f"attack {'still succeeded' if still_works else 'no longer succeeded'}"
    )
    return result
