from dataclasses import replace

from agents.techniques.base import Technique

_REGISTRY: dict[str, Technique] = {}


def register(technique: Technique) -> Technique:
    if technique.id in _REGISTRY:
        raise ValueError(f"technique {technique.id!r} already registered")

    # Step 6.1/6.2/6.4 - every technique's real HTTP actions go through a
    # scope allowlist check, kill-switch check, and immutable audit log,
    # wired in once here rather than in each technique module (see
    # agents/safety/guard.py for why registration time is the one place
    # both execute_tool_call and fetch_telemetry are ever assigned).
    from agents.safety.guard import guard_telemetry_fetcher, guard_tool_executor

    guarded = replace(
        technique,
        execute_tool_call=guard_tool_executor(technique.id, technique.execute_tool_call),
        fetch_telemetry=guard_telemetry_fetcher(technique.id, technique.fetch_telemetry),
    )
    _REGISTRY[technique.id] = guarded
    return guarded


def get_technique(technique_id: str) -> Technique:
    try:
        return _REGISTRY[technique_id]
    except KeyError:
        available = ", ".join(sorted(_REGISTRY)) or "(none registered)"
        raise KeyError(f"Unknown technique {technique_id!r}. Available: {available}") from None


def list_techniques() -> list[Technique]:
    return list(_REGISTRY.values())
