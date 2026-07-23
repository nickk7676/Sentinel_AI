"""
Quick data quality audit — run this before starting a long training loop.

Usage:
  python audit.py
"""

import json
import os
from collections import Counter
from pathlib import Path

from training.dataset import DATA_DIR, _examples_dir
STATS_FILE = DATA_DIR / "training_stats.jsonl"


def load_examples(agent_name):
    """Load all training examples for an agent from their individual JSON files."""
    d = _examples_dir(agent_name)
    if not d.exists():
        return []
    results = []
    for f in sorted(d.glob("*.json")):
        try:
            results.append(json.loads(f.read_text(encoding="utf-8")))
        except (json.JSONDecodeError, OSError) as e:
            print(f"  WARNING: could not read {f.name}: {e}")
    return results


def load_jsonl(path):
    """Legacy loader kept for training_stats.jsonl which is still a JSONL file."""
    if not path.exists():
        return []
    with open(path, encoding="utf-8") as f:
        lines = [l.strip() for l in f if l.strip()]
    results = []
    for line in lines:
        try:
            results.append(json.loads(line))
        except json.JSONDecodeError:
            print(f"  WARNING: corrupt line in {path.name}: {line[:80]}")
    return results


def check_messages(example, index, filename):
    msgs = example.get("messages", [])
    issues = []
    roles = [m.get("role") for m in msgs]

    if roles != ["system", "user", "assistant"]:
        issues.append(f"  BAD STRUCTURE at line {index+1}: roles={roles}")

    assistant_msg = msgs[-1].get("content", "") if msgs else ""
    try:
        parsed = json.loads(assistant_msg)
        if not isinstance(parsed, dict):
            issues.append(f"  BAD CONTENT at line {index+1}: assistant response is not a JSON object")
    except json.JSONDecodeError:
        issues.append(f"  BAD CONTENT at line {index+1}: assistant response is not valid JSON")
        issues.append(f"    Raw: {assistant_msg[:120]}")

    return issues, parsed if not issues else {}


def audit_blue(examples):
    print(f"\n{'='*55}")
    print(f"  BLUE WINS  ({len(examples)} examples)")
    print(f"{'='*55}")

    all_issues = []
    attack_types = Counter()
    risk_scores  = []
    has_mitigation = 0
    has_recommendations = 0

    for i, ex in enumerate(examples):
        issues, content = check_messages(ex, i, "blue_wins.jsonl")
        all_issues.extend(issues)
        if content:
            attack_types[content.get("threat_category", "unknown")] += 1
            score = content.get("risk_score")
            if score is not None:
                risk_scores.append(float(score))
            if content.get("mitigation", "").strip():
                has_mitigation += 1
            recs = content.get("recommendations", [])
            if isinstance(recs, list) and len(recs) > 0:
                has_recommendations += 1

    if all_issues:
        print(f"  ISSUES FOUND ({len(all_issues)}):")
        for issue in all_issues:
            print(issue)
    else:
        print("  Structure: OK — all examples have correct role order and valid JSON")

    if risk_scores:
        avg = sum(risk_scores) / len(risk_scores)
        print(f"  Avg risk score:       {avg:.1f}/10  (want 5+ for meaningful examples)")
    print(f"  Has mitigation:       {has_mitigation}/{len(examples)}")
    print(f"  Has recommendations:  {has_recommendations}/{len(examples)}")
    print(f"  Threat categories:")
    for cat, count in attack_types.most_common():
        print(f"    {cat:<30} {count}")

    # Sample one example
    if examples:
        print(f"\n  SAMPLE (line 1):")
        msgs = examples[0].get("messages", [])
        user_msg = msgs[1].get("content", "") if len(msgs) > 1 else ""
        asst_msg = msgs[2].get("content", "") if len(msgs) > 2 else ""
        print(f"  User input:  {user_msg[:200]}")
        print(f"  Response:    {asst_msg[:300]}")


def audit_red(examples):
    print(f"\n{'='*55}")
    print(f"  RED WINS  ({len(examples)} examples)")
    print(f"{'='*55}")

    all_issues = []
    attack_types = Counter()
    severities   = Counter()
    has_payload  = 0

    for i, ex in enumerate(examples):
        issues, content = check_messages(ex, i, "red_wins.jsonl")
        all_issues.extend(issues)
        if content:
            attack_types[content.get("attack_type", "unknown")] += 1
            severities[content.get("severity", "unknown")] += 1
            if content.get("payload", "").strip():
                has_payload += 1

    if all_issues:
        print(f"  ISSUES FOUND ({len(all_issues)}):")
        for issue in all_issues:
            print(issue)
    else:
        print("  Structure: OK — all examples have correct role order and valid JSON")

    print(f"  Has payload:  {has_payload}/{len(examples)}")
    print(f"  Attack types:")
    for t, count in attack_types.most_common():
        print(f"    {t:<30} {count}")
    print(f"  Severities:")
    for s, count in severities.most_common():
        print(f"    {s:<30} {count}")

    if examples:
        print(f"\n  SAMPLE (line 1):")
        msgs = examples[0].get("messages", [])
        asst_msg = msgs[2].get("content", "") if len(msgs) > 2 else ""
        try:
            parsed = json.loads(asst_msg)
            print(f"  Attack type: {parsed.get('attack_type')}")
            print(f"  Severity:    {parsed.get('severity')}")
            print(f"  Technique:   {parsed.get('technique')}")
            print(f"  Payload:     {str(parsed.get('payload', ''))[:200]}")
        except Exception:
            print(f"  Raw: {asst_msg[:300]}")


def audit_stats():
    stats = load_jsonl(STATS_FILE)
    if not stats:
        print(f"\n  No training_stats.jsonl yet.")
        return

    print(f"\n{'='*55}")
    print(f"  TRAINING STATS  ({len(stats)} rounds logged)")
    print(f"{'='*55}")
    print(f"  {'Round':<8} {'Red wins':<12} {'Blue wins':<12} {'Draws':<8} {'Blue win%':<12} {'Time(s)'}")
    for s in stats:
        print(
            f"  {s['round']:<8} {s['red_wins']:<12} {s['blue_wins']:<12} "
            f"{s['draws']:<8} {s['blue_win_rate']*100:.1f}%{'':<7} {s['elapsed_seconds']}"
        )

    if len(stats) >= 3:
        recent = stats[-3:]
        blue_rates = [s["blue_win_rate"] for s in recent]
        red_rates  = [s["red_wins"] / s["total_battles"] for s in recent]
        draw_rates = [s["draws"] / s["total_battles"] for s in recent]

        blue_dom = all(r > 0.70 for r in blue_rates)
        red_dom  = all(r > 0.70 for r in red_rates)
        all_draw = all(r > 0.50 for r in draw_rates)

        print(f"\n  Last 3 rounds breakdown:")
        if blue_dom:
            print("  WARNING: Blue winning 70%+ for 3+ rounds straight — red adapter may not be loading or training")
        elif red_dom:
            print("  WARNING: Red winning 70%+ for 3+ rounds straight — blue adapter may not be loading or training")
        elif all_draw:
            print("  WARNING: Mostly draws — judge thresholds may be too lenient, or both agents are producing generic output")
        else:
            print("  Healthy: win rates are oscillating — both agents are competing and adapting")


def main():
    print("\n" + "="*55)
    print("  SENTINEL AI — DATA QUALITY AUDIT")
    print("="*55)

    blue = load_examples("blue")
    red  = load_examples("red")

    if not blue and not red:
        print("\n  No training data found. Run at least one battle first.")
        return

    if blue:
        audit_blue(blue)
    else:
        print("\n  No blue wins yet.")

    if red:
        audit_red(red)
    else:
        print("\n  No red wins yet.")

    audit_stats()

    total = len(blue) + len(red)
    print(f"\n{'='*55}")
    print(f"  SUMMARY: {len(blue)} blue examples, {len(red)} red examples, {total} total")
    if total < 50:
        print(f"  NOTE: Run more battles before full training — 50+ examples per agent gives better results.")
    else:
        print(f"  Data volume looks good. Check the samples above to confirm quality before training.")
    print("="*55 + "\n")


if __name__ == "__main__":
    main()
