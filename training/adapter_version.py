"""
Tracks a monotonic version number per adapter directory.

train_agent.py overwrites each adapter's weights in place on every training
call, so there's nothing on disk that identifies *which* version of an
adapter produced a given battle. That's fine for training (Step 9.3's
checkpoint league is a later concern), but Step 4.2 needs every logged
battle to record which adapter version played it, so eval results and
training-data battles can later be lined up against "adapter version at
the time."

A version is just an integer bumped once per completed train() call,
stored as a sidecar JSON file next to the adapter weights - it does not
replace or interact with the adapter files themselves.
"""

import json
import time
from pathlib import Path


def _version_file(adapter_dir: Path) -> Path:
    return adapter_dir / "version.json"


def get_version(adapter_dir: Path) -> int:
    """Current version of the adapter at this path. 0 if never trained (base model)."""
    f = _version_file(adapter_dir)
    if not f.exists():
        return 0
    try:
        return json.loads(f.read_text(encoding="utf-8")).get("version", 0)
    except (json.JSONDecodeError, OSError):
        return 0


def bump_version(adapter_dir: Path) -> int:
    """Increment and persist this adapter's version. Call once per completed
    training run, after the adapter weights themselves are saved."""
    new_version = get_version(adapter_dir) + 1
    adapter_dir.mkdir(parents=True, exist_ok=True)
    _version_file(adapter_dir).write_text(
        json.dumps({"version": new_version, "updated_at": time.time()}),
        encoding="utf-8",
    )
    return new_version
