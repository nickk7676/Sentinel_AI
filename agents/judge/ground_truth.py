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

    reasoning = (
        f"Ground truth: was_attack={was_attack}, attack_success={attack_success}, "
        f"blue_detected={detected}, category_correct={correct_category}."
    )

    return {
        "winner": winner,
        "attack_success": attack_success,
        "detection_correct": detection_correct,
        "precision": 1.0 if correct_category else 0.0,
        "recall": 1.0 if detected else 0.0,
        "false_positives": 1 if false_positive else 0,
        "defense_quality": defense_quality,
        "reasoning": reasoning,
    }
