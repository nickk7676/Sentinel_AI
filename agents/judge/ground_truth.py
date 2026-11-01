"""
Deterministic scorer for live battles - no LLM judging.

Red and blue are scored independently against ground truth, not against each
other, so neither side's training signal depends on the other side's
performance:
  - attack_success    - did red's attack actually work (real HTTP bypass)?
  - detection_correct - did blue's call match ground truth? On a real attack
    attempt (was_attack=True) that means flagging it AND categorizing it
    correctly; on a normal-traffic round (was_attack=False, Step 2.5) that
    means correctly staying quiet - any positive flag there is a false alarm
    regardless of category.

`winner` is still produced for display/console purposes only - it is not
used to decide which side gets a training example.
"""

def score_live_battle(attack: dict, defense: dict) -> dict:
    from agents.techniques import DEFAULT_TECHNIQUE_ID, get_technique

    technique = get_technique(attack.get("attack_type") or DEFAULT_TECHNIQUE_ID)
    was_attack = attack.get("was_attack", True)
    attack_success = bool(attack.get("success", False))

    detected = bool(defense.get("threat_detected"))
    category = str(defense.get("threat_category", "")).lower()
    correct_category = any(keyword in category for keyword in technique.category_keywords)

    if was_attack:
        detection_correct = detected and correct_category
        false_positive = detected and not correct_category
    else:
        # Nothing malicious happened - blue is right iff it stayed quiet.
        detection_correct = not detected
        false_positive = detected

    if attack_success and detection_correct:
        winner = "draw"  # both sides did their job
        defense_quality = 7.0
    elif attack_success and not detection_correct:
        winner = "red"
        defense_quality = 2.0
    elif not attack_success and detection_correct:
        winner = "blue"
        defense_quality = 9.0
    else:
        winner = "draw"
        defense_quality = 5.0

    # Step 9.2 - partial-credit rewards. The binary fields above
    # (attack_success / detection_correct) stay exactly as they were, but a
    # 0/1 win-loss throws away real signal: red that leaked something but
    # didn't finish, or blue that noticed the attack but mislabeled it, both
    # made genuine progress that a binary gate scores as a flat zero. These
    # graded 0.0-1.0 rewards capture that middle ground so training (and the
    # eval curves) can reward getting-closer, not just winning. They are
    # additive - nothing that already reads attack_success/detection_correct
    # changes behavior.
    red_reward = _red_partial_reward(attack, was_attack, attack_success)
    blue_reward = _blue_partial_reward(was_attack, detected, correct_category)

    reasoning = (
        f"Ground truth: was_attack={was_attack}, attack_success={attack_success}, "
        f"blue_detected={detected}, category_correct={correct_category}. "
        f"Partial rewards: red={red_reward:.2f}, blue={blue_reward:.2f}."
    )

    return {
        "winner": winner,
        "attack_success": attack_success,
        "detection_correct": detection_correct,
        "precision": 1.0 if correct_category else 0.0,
        "recall": 1.0 if detected else 0.0,
        "false_positives": 1 if false_positive else 0,
        "defense_quality": defense_quality,
        "red_reward": red_reward,
        "blue_reward": blue_reward,
        "reasoning": reasoning,
    }


def _red_partial_reward(attack: dict, was_attack: bool, attack_success: bool) -> float:
    """0.0-1.0 credit for how far red got (Step 9.2):
      1.0  - full success (the canary was reached).
      0.5  - no canary, but a reusable artifact leaked (e.g. a stolen token -
             a real foothold / the first half of a chain).
      0.25 - no canary and no artifact, but at least one request got a real
             2xx response back (reached live, exploitable-looking surface).
      0.0  - normal-traffic round, or nothing landed.
    """
    if not was_attack:
        return 0.0
    if attack_success:
        return 1.0
    tool_calls = attack.get("tool_calls", []) or []
    if any(isinstance(c, dict) and c.get("artifacts") for c in tool_calls):
        return 0.5
    reached = any(
        isinstance(c, dict) and isinstance(c.get("status_code"), int) and 200 <= c["status_code"] < 300
        for c in tool_calls
    )
    return 0.25 if reached else 0.0


def _blue_partial_reward(was_attack: bool, detected: bool, correct_category: bool) -> float:
    """0.0-1.0 credit for blue's call (Step 9.2):
      attack round:  1.0 detect+correct category | 0.5 detect but wrong
                     category (noticed the threat, mislabeled it) | 0.0 missed.
      normal round:  1.0 correctly stayed quiet | 0.0 false alarm.
    """
    if not was_attack:
        return 0.0 if detected else 1.0
    if not detected:
        return 0.0
    return 1.0 if correct_category else 0.5
