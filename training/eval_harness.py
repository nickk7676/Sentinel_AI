"""
Step 4 - evaluation harness.

Everything else in this codebase (battle_loop.py) trains on live battles.
This module runs a fixed, held-out suite of live battles that are NEVER
saved as training examples, purely to measure real skill:

  - "Frozen" here means the harness definition itself - which techniques,
    how many attack battles vs. normal-traffic battles per technique - is a
    fixed suite checked into git (EVAL_SUITE below), not regenerated ad hoc.
    There's no static input dataset to freeze: every battle is a real live
    HTTP exchange against a running lab target, so a battle can't be
    literally cached and replayed - "held out" means these battles are
    never fed into training/dataset.py's save_red_win/save_blue_win, so
    they can never leak into what red or blue actually trained on.
  - Each battle is scored with the same deterministic ground-truth scorer
    used everywhere else (agents/judge/ground_truth.score_live_battle), and
    logged in full via training/battle_log.py (source="eval") alongside the
    adapter version each side was running - so "is round 50 better than
    round 10" is a real number pulled from this file, not a vibe.
  - Attack battles and normal-traffic battles are run in a fixed,
    deterministic split per technique (normal_traffic_probability forced to
    0.0 or 1.0) rather than left to live_tools' random mix, so detection
    rate and false-positive rate are each measured on a known-size sample
    instead of an incidental one.

Requires every technique's lab targets running (see training/targets.py for the
full list, and docker/docker-compose.yml to bring up all of them at once).
Step 5 runs each technique against all of its targets (not just one) - the
original training target, a new-framework training target, a held-out
new-framework target never used in battle_loop.py, and a distractor whose
vuln is patched - so per_technique[tech]["by_role"] directly answers "does
this generalize to targets it never trained on."

Usage:
  python -m training.eval_harness                          # baseline (round 0), all techniques
  python -m training.eval_harness --round 10
  python -m training.eval_harness --techniques sql_injection,idor
  python -m training.eval_harness --attacks-per-technique 20 --normal-per-technique 10
"""

import argparse
import json
import os
import time
from pathlib import Path

from agents.techniques import list_techniques
from backend.services.simulation_service import run_simulation
from training.adapter_version import get_version
from training.battle_log import log_battle
from training.dataset import DATA_DIR
from training.process_lock import technique_lock
from training.targets import LabTarget, targets_for
from training.train_agent import adapter_path

EVAL_SUMMARY_FILE = DATA_DIR / "eval_summary.jsonl"
TENSORBOARD_EVAL_DIR = DATA_DIR / "tensorboard" / "eval"

# Fixed held-out suite: how many attack-mode and normal-traffic-mode battles
# to run per (technique, target). Deliberately the same for every technique
# so per-technique numbers are comparable to each other, not just to their
# own past. Step 5 runs this per technique against all 4 of that technique's
# targets (train x2, heldout, distractor - see training/targets.py), not
# just one, so total battle count is ~4x what it was pre-Step 5.
DEFAULT_ATTACKS_PER_TECHNIQUE = 10
DEFAULT_NORMAL_PER_TECHNIQUE = 5


def _target_url(target: LabTarget, overrides: dict[str, str]) -> str:
    return overrides.get(target.id, target.url)


def _run_batch(
    technique_id: str,
    target: LabTarget,
    target_url: str,
    round_num: int,
    normal_traffic_probability: float,
    n: int,
    red_version: int,
    blue_version: int,
) -> tuple[list[dict], list[dict]]:
    verdicts = []
    remediations = []
    for i in range(1, n + 1):
        result = run_simulation(
            target_url=target_url,
            technique=technique_id,
            normal_traffic_probability=normal_traffic_probability,
        )
        attack, defense, verdict = result["attack"], result["defense"], result["evaluation"]
        remediation = result.get("remediation", {})
        log_battle(
            source="eval",
            technique=technique_id,
            round_num=round_num,
            battle_num=i,
            target_url=target_url,
            attack=attack,
            defense=defense,
            verdict=verdict,
            red_adapter_version=red_version,
            blue_adapter_version=blue_version,
            target_id=target.id,
            target_role=target.role,
            target_framework=target.framework,
            remediation=remediation,
        )
        verdicts.append(verdict)
        remediations.append(remediation)
    return verdicts, remediations


def _summarize(attack_verdicts: list[dict], normal_verdicts: list[dict], attack_remediations: list[dict] | None = None) -> dict:
    n_attack = len(attack_verdicts)
    n_normal = len(normal_verdicts)
    attack_remediations = attack_remediations or []

    detection_rate = (
        sum(1 for v in attack_verdicts if v.get("detection_correct")) / n_attack if n_attack else 0.0
    )
    attack_success_rate = (
        sum(1 for v in attack_verdicts if v.get("attack_success")) / n_attack if n_attack else 0.0
    )
    false_positive_rate = (
        sum(1 for v in normal_verdicts if v.get("false_positives")) / n_normal if n_normal else 0.0
    )
    precision = (
        sum(v.get("precision", 0.0) for v in attack_verdicts) / n_attack if n_attack else 0.0
    )
    recall = (
        sum(v.get("recall", 0.0) for v in attack_verdicts) / n_attack if n_attack else 0.0
    )
    # Step 7: fraction of battles where blue's recommended_fix was actually
    # checked (a real attack succeeded and blue proposed something) and, of
    # those, the fraction confirmed (via a live replay - see
    # agents/judge/verification.py) to actually close the hole.
    n_fix_proposed = sum(1 for r in attack_remediations if r.get("attempted"))
    n_fix_verified = sum(1 for r in attack_remediations if r.get("fix_verified"))
    fix_verified_rate = n_fix_verified / n_fix_proposed if n_fix_proposed else 0.0

    return {
        "attack_battles": n_attack,
        "normal_battles": n_normal,
        "red_attack_success_rate": round(attack_success_rate, 3),
        "blue_detection_rate": round(detection_rate, 3),
        "blue_false_positive_rate": round(false_positive_rate, 3),
        "blue_precision": round(precision, 3),
        "blue_recall": round(recall, 3),
        "fix_proposed": n_fix_proposed,
        "fix_verified": n_fix_verified,
        "blue_fix_verified_rate": round(fix_verified_rate, 3),
    }


def _rollup(summaries: list[dict]) -> dict:
    """Weighted-average several _summarize() dicts into one - used both for
    a technique's per-role rollup (train vs heldout vs distractor) and for
    the run-wide overall numbers. Step 5.4: comparing the "train" rollup
    against "heldout" is what answers "does this generalize, or did it just
    memorize the training targets."""
    n_attack_total = sum(s["attack_battles"] for s in summaries)
    n_normal_total = sum(s["normal_battles"] for s in summaries)
    n_fix_proposed_total = sum(s.get("fix_proposed", 0) for s in summaries)
    return {
        "attack_battles": n_attack_total,
        "normal_battles": n_normal_total,
        "red_attack_success_rate": round(
            sum(s["red_attack_success_rate"] * s["attack_battles"] for s in summaries) / n_attack_total, 3
        ) if n_attack_total else 0.0,
        "blue_detection_rate": round(
            sum(s["blue_detection_rate"] * s["attack_battles"] for s in summaries) / n_attack_total, 3
        ) if n_attack_total else 0.0,
        "blue_false_positive_rate": round(
            sum(s["blue_false_positive_rate"] * s["normal_battles"] for s in summaries) / n_normal_total, 3
        ) if n_normal_total else 0.0,
        "fix_proposed": n_fix_proposed_total,
        "fix_verified": sum(s.get("fix_verified", 0) for s in summaries),
        "blue_fix_verified_rate": round(
            sum(s.get("blue_fix_verified_rate", 0.0) * s.get("fix_proposed", 0) for s in summaries) / n_fix_proposed_total, 3
        ) if n_fix_proposed_total else 0.0,
    }


def run_eval(
    round_num: int = 0,
    technique_ids: list[str] | None = None,
    attacks_per_technique: int = DEFAULT_ATTACKS_PER_TECHNIQUE,
    normal_per_technique: int = DEFAULT_NORMAL_PER_TECHNIQUE,
    target_url_overrides: dict[str, str] | None = None,
) -> dict:
    target_url_overrides = target_url_overrides or {}
    techniques = (
        [t for t in list_techniques() if t.id in technique_ids]
        if technique_ids
        else list_techniques()
    )

    print("=" * 60)
    print("  SENTINEL AI — EVAL HARNESS (Step 4)")
    print(f"  Round label:            {round_num}")
    print(f"  Techniques:             {', '.join(t.id for t in techniques)}")
    print(f"  Attacks/technique:      {attacks_per_technique}")
    print(f"  Normal-traffic/technique:{normal_per_technique}")
    print("=" * 60)

    per_technique = {}
    all_target_summaries = []  # every (technique, target) summary, for the run-wide by_role rollup
    blue_version = get_version(adapter_path("blue"))

    for tech in techniques:
        targets = targets_for(tech.id)
        red_version = get_version(adapter_path("red", tech.id))
        print(f"\n[{tech.id}] targets={[t.id for t in targets]}  red_v={red_version}  blue_v={blue_version}")

        # Refuses to run this technique's battles if a training run
        # (battle_loop.py) or another eval run is already battling it -
        # concurrent processes against the same lab target corrupt each
        # other's log-reading windows (see training/process_lock.py). One
        # lock covers all of this technique's targets since battle_loop.py
        # also locks per-technique, not per-target.
        with technique_lock(tech.id):
            target_summaries = {}
            for target in targets:
                target_url = _target_url(target, target_url_overrides)
                print(f"  [{target.id}] ({target.role}/{target.framework}) target={target_url}")
                attack_verdicts, attack_remediations = _run_batch(
                    tech.id, target, target_url, round_num, normal_traffic_probability=0.0,
                    n=attacks_per_technique, red_version=red_version, blue_version=blue_version,
                )
                normal_verdicts, _ = _run_batch(
                    tech.id, target, target_url, round_num, normal_traffic_probability=1.0,
                    n=normal_per_technique, red_version=red_version, blue_version=blue_version,
                )
                summary = _summarize(attack_verdicts, normal_verdicts, attack_remediations)
                summary["role"] = target.role
                summary["framework"] = target.framework
                target_summaries[target.id] = summary
                all_target_summaries.append(summary)
                print(f"  [{target.id}] {summary}")

        by_role = {}
        for role in ("train", "heldout", "distractor"):
            role_summaries = [s for s in target_summaries.values() if s["role"] == role]
            if role_summaries:
                by_role[role] = _rollup(role_summaries)

        per_technique[tech.id] = {
            "red_adapter_version": red_version,
            "targets": target_summaries,
            "by_role": by_role,
        }
        print(f"[{tech.id}] by_role={by_role}")

        # Red's model cache is keyed per technique's own adapter path
        # (agents/red_team/agent.py), and this loop loads a different
        # technique's adapter every iteration - without unloading, every
        # technique's weights stay resident and can exceed available VRAM
        # by the time all 6 have been visited. Blue is a single shared
        # adapter regardless of technique, so it's left cached across the
        # whole run instead of being reloaded every iteration.
        _unload_red_adapter()

    # Blue is left cached for the whole run (see comment above), but that
    # means whatever it was actually served through (Ollama, if
    # LLM_PROVIDER isn't overridden to "local" the way battle_loop.py does)
    # is still resident once this function returns - unload it now rather
    # than leaving it sitting in VRAM until Ollama's own idle timeout.
    _unload_ollama_judge()

    overall = _rollup(all_target_summaries)
    # The headline Step 5 number: train-target performance vs. the entirely
    # unseen (never-trained-on) heldout/distractor targets, pooled across
    # every technique. "Meaningfully above chance" here (5.4's exit
    # criterion) means overall["by_role"]["heldout"] isn't dramatically
    # worse than overall["by_role"]["train"].
    overall["by_role"] = {
        role: _rollup([s for s in all_target_summaries if s["role"] == role])
        for role in ("train", "heldout", "distractor")
        if any(s["role"] == role for s in all_target_summaries)
    }

    result = {
        "timestamp": time.time(),
        "round": round_num,
        "blue_adapter_version": blue_version,
        "per_technique": per_technique,
        "overall": overall,
    }

    EVAL_SUMMARY_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(EVAL_SUMMARY_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(result) + "\n")

    _log_tensorboard(round_num, per_technique, overall)

    print("\n" + "=" * 60)
    print(f"  Overall: {overall}")
    print(f"  Summary appended to: {EVAL_SUMMARY_FILE}")
    print("=" * 60)
    return result


def _unload_red_adapter() -> None:
    """Free whichever technique's red adapter is currently loaded, so the
    next technique's adapter isn't stacking VRAM on top of it."""
    import gc
    import sys

    import torch

    module_name = "agents.red_team.agent"
    if module_name in sys.modules:
        mod = sys.modules[module_name]
        if hasattr(mod, "_model_cache"):
            for key in list(mod._model_cache.keys()):
                model, tokenizer = mod._model_cache.pop(key)
                del model, tokenizer

    gc.collect()
    gc.collect()  # second pass catches circular refs in quantized models
    if torch.cuda.is_available():
        torch.cuda.synchronize()
        torch.cuda.empty_cache()
        used = torch.cuda.memory_allocated() / 1024**3
        print(f"  Red adapter unloaded. VRAM in use: {used:.2f} GB")


def _unload_ollama_judge() -> None:
    """Tell Ollama to evict whatever model blue was served through (see
    JUDGE_MODEL below) from VRAM now that this run is done - mirrors
    training/battle_loop.py's helper of the same name. Without this, the
    model stays resident in Ollama until its own idle keep_alive timeout."""
    import requests

    model = os.getenv("JUDGE_MODEL", "llama3.2")
    try:
        requests.post(
            "http://localhost:11434/api/chat",
            json={"model": model, "messages": [], "keep_alive": 0},
            timeout=10,
        )
        print(f"  Ollama judge model ({model}) unloaded from VRAM.")
    except Exception:
        pass  # Ollama not running or not in use — safe to ignore


def _log_tensorboard(round_num: int, per_technique: dict, overall: dict) -> None:
    try:
        from torch.utils.tensorboard import SummaryWriter
    except ImportError:
        print("  (tensorboard not installed - skipping scalar logging; `pip install tensorboard`)")
        return

    writer = SummaryWriter(log_dir=str(TENSORBOARD_EVAL_DIR))
    for metric, value in overall.items():
        if isinstance(value, (int, float)):
            writer.add_scalar(f"eval/overall/{metric}", value, round_num)
    for role, role_summary in overall.get("by_role", {}).items():
        for metric, value in role_summary.items():
            if isinstance(value, (int, float)):
                writer.add_scalar(f"eval/overall/by_role/{role}/{metric}", value, round_num)

    for tech_id, tech_result in per_technique.items():
        for target_id, summary in tech_result.get("targets", {}).items():
            for metric, value in summary.items():
                if isinstance(value, (int, float)):
                    writer.add_scalar(f"eval/{tech_id}/targets/{target_id}/{metric}", value, round_num)
        for role, role_summary in tech_result.get("by_role", {}).items():
            for metric, value in role_summary.items():
                if isinstance(value, (int, float)):
                    writer.add_scalar(f"eval/{tech_id}/by_role/{role}/{metric}", value, round_num)
    writer.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Step 4 held-out evaluation harness for SentinelAI")
    parser.add_argument("--round", type=int, default=0,
                        help="Training round label this eval corresponds to (0 = pre-training baseline).")
    parser.add_argument("--techniques", type=str, default=None,
                        help="Comma-separated technique ids to evaluate (default: all registered).")
    parser.add_argument("--attacks-per-technique", type=int, default=DEFAULT_ATTACKS_PER_TECHNIQUE)
    parser.add_argument("--normal-per-technique", type=int, default=DEFAULT_NORMAL_PER_TECHNIQUE)
    parser.add_argument("--target-url-override", action="append", default=[],
                        help="target_id=http://host:port (e.g. sql_injection_django=http://host:port), "
                             "repeatable, overrides one specific target's default port (see training/targets.py).")
    args = parser.parse_args()

    overrides = dict(kv.split("=", 1) for kv in args.target_url_override)
    ids = [t.strip() for t in args.techniques.split(",")] if args.techniques else None

    run_eval(
        round_num=args.round,
        technique_ids=ids,
        attacks_per_technique=args.attacks_per_technique,
        normal_per_technique=args.normal_per_technique,
        target_url_overrides=overrides,
    )
