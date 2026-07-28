"""
Saves battle results as training examples.

Each example is written as its own .json file, scoped by technique:
  red_wins/<technique_id>/  -> red team live tool-calling transcripts
                                (multi-turn, with a "tool" role message)
  blue_wins/<technique_id>/ -> blue team live defenses (built from a real
                                log excerpt)

Red trains one technique at a time, so its helpers (get_data_path,
count_examples) stay scoped to a single technique_id - a given training run
never mixes in another technique's examples.

Blue's actual skill is discriminating between categories from raw log
evidence, not acting out one specific technique, so it trains jointly on a
mix of every technique's saved examples at once (get_data_path_all,
count_examples_all) rather than one technique in isolation - the per-agent
"technique" tag on each saved example is still kept regardless, since it's
what lets these joint helpers exist and lets blue's performance later be
broken down by technique even though training itself is joint.

Individual files avoid append-mode locking issues on Windows (OneDrive / Defender).
"""

import json
import os
import uuid
from pathlib import Path

from agents.safety.redact import redact_value

# Store training data outside OneDrive to avoid sync lock conflicts.
# Override with SENTINEL_DATA_DIR env var if you want a different location.
DATA_DIR = Path(
    os.getenv("SENTINEL_DATA_DIR") or
    Path(os.environ["LOCALAPPDATA"]) / "sentinelai" / "data"
)


def _examples_dir(agent_name: str, technique_id: str) -> Path:
    return DATA_DIR / f"{agent_name}_wins" / technique_id


def save_red_win(messages: list, technique_id: str) -> None:
    """Save a real live-battle tool-calling transcript verbatim, so fine-tuning
    reproduces the exact successful <tool_call> sequence."""
    d = _examples_dir("red", technique_id)
    d.mkdir(parents=True, exist_ok=True)
    # Step 6.3 - scrub secret-shaped values before this training example is
    # ever written to disk.
    example = {"technique": technique_id, "messages": redact_value(messages)}
    (d / f"{uuid.uuid4().hex}.json").write_text(json.dumps(example), encoding="utf-8")


def save_blue_win(attack: dict, defense: dict, system_prompt: str, user_prompt: str, technique_id: str) -> str:
    """Returns the saved file's path (as str) so callers (battle_loop.py)
    can force this exact example past get_data_path_all's per-technique cap
    - see that function's always_include param."""
    d = _examples_dir("blue", technique_id)
    d.mkdir(parents=True, exist_ok=True)
    response_payload = {k: v for k, v in defense.items() if k != "latency"}
    # Step 6.3 - scrub secret-shaped values before this training example is
    # ever written to disk.
    example = {
        "technique": technique_id,
        "messages": [
            {"role": "system", "content": redact_value(system_prompt)},
            {"role": "user", "content": redact_value(user_prompt)},
            {"role": "assistant", "content": redact_value(json.dumps(response_payload))},
        ]
    }
    path = d / f"{uuid.uuid4().hex}.json"
    path.write_text(json.dumps(example), encoding="utf-8")
    return str(path)


def count_examples(agent_name: str, technique_id: str) -> int:
    d = _examples_dir(agent_name, technique_id)
    if not d.exists():
        return 0
    return len(list(d.glob("*.json")))


def get_data_path(agent_name: str, technique_id: str, max_examples: int = None) -> list[str]:
    """Return example file paths for this agent+technique, newest first, capped at max_examples."""
    d = _examples_dir(agent_name, technique_id)
    if not d.exists():
        return []
    files = sorted(d.glob("*.json"), key=lambda f: f.stat().st_mtime, reverse=True)
    if max_examples is not None:
        files = files[:max_examples]
    return [str(f) for f in files]


def _all_technique_dirs(agent_name: str) -> list[Path]:
    base = DATA_DIR / f"{agent_name}_wins"
    if not base.exists():
        return []
    return [d for d in base.iterdir() if d.is_dir()]


def count_examples_all(agent_name: str) -> int:
    """Total example count across every technique's saved examples for this
    agent - blue's training trigger uses this instead of count_examples,
    since blue trains jointly rather than one technique at a time."""
    return sum(len(list(d.glob("*.json"))) for d in _all_technique_dirs(agent_name))


def get_data_path_all(
    agent_name: str,
    max_examples: int = None,
    always_include: list[str] = None,
) -> list[str]:
    """Return example file paths across every technique for this agent,
    newest first within each technique - blue's training batch uses this
    instead of get_data_path, so it sees a mix of techniques together
    rather than one in isolation.

    max_examples is a per-technique cap (max_examples // number of
    techniques), not a flat global cap - a technique that's been battled
    far more than the others (e.g. sql_injection/idor racking up hundreds
    of examples while command_injection/ssrf/broken_auth/path_traversal
    have few) would otherwise crowd every other technique out of blue's
    training batch entirely, since a flat "newest N overall" cap is
    dominated by whichever technique produces examples fastest. A technique
    with fewer examples than its cap just contributes all of them - no
    padding, no redistributing its unused quota to other techniques - so the
    returned batch can land well under max_examples when most techniques are
    thin, which is the intended, safer failure mode (a smaller balanced
    batch beats a large lopsided one).

    always_include: paths (as returned by save_blue_win) to keep in the
    batch even if they'd fall outside their technique's per-technique cap -
    used to guarantee the current round's own fresh wins are never excluded
    just because that technique has a large backlog, without permanently
    inflating that technique's normal share.
    """
    dirs = _all_technique_dirs(agent_name)
    if not dirs:
        return []

    always_include = set(always_include or [])
    per_technique_cap = max(1, max_examples // len(dirs)) if max_examples is not None else None

    selected: list[str] = []
    for d in dirs:
        files = sorted(d.glob("*.json"), key=lambda f: f.stat().st_mtime, reverse=True)
        paths = [str(f) for f in files]
        if per_technique_cap is None:
            selected.extend(paths)
            continue
        kept = paths[:per_technique_cap]
        forced = [p for p in paths[per_technique_cap:] if p in always_include]
        selected.extend(kept + forced)
    return selected
