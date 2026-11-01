"""Wires scope.py + killswitch.py + audit.py around a Technique's
execute_tool_call/fetch_telemetry, at the one place both are ever assigned:
agents/techniques/registry.py's register(). Every real call site in the
system - agents/red_team/live_tools.py's per-turn tool dispatch, blue's
telemetry fetch (backend/services/simulation_service.py, training/
battle_loop.py's pre-flight snapshot) - obtains its Technique via
get_technique(), so wrapping here covers all of them without editing
live_tools.py, simulation_service.py, battle_loop.py, or any of the
individual technique modules.
"""

from __future__ import annotations

import functools
import time

from agents.safety import audit, killswitch, scope
from agents.techniques.base import TelemetryFetcher, ToolExecutor

_DENIAL_EXCEPTIONS = (scope.ScopeViolationError, killswitch.KillSwitchTripped)


def guard_tool_executor(technique_id: str, fn: ToolExecutor) -> ToolExecutor:
    """Red's execute_tool_call is model-facing: a denial must not raise (the
    tool-calling loop in agents/red_team/live_tools.py has no exception
    handling around this call) - it returns the same {"error", "success":
    False} shape every technique already returns for a bad call, so the
    model simply sees the action fail."""

    @functools.wraps(fn)
    def wrapper(target_url: str, name: str, args: dict) -> dict:
        try:
            scope.assert_in_scope(target_url)
            killswitch.check(target_url)
        except _DENIAL_EXCEPTIONS as exc:
            audit.record_action(
                "red", name, target_url, technique=technique_id, args=args,
                outcome=type(exc).__name__, detail={"error": str(exc)},
            )
            return {"error": str(exc), "success": False}

        start = time.time()
        result = fn(target_url, name, args)
        errored = bool(result.get("error")) and not result.get("success")
        killswitch.record(target_url, errored=errored)
        audit.record_action(
            "red", name, target_url, technique=technique_id, args=args,
            outcome="ok",
            detail={"success": result.get("success"), "latency": round(time.time() - start, 3)},
        )
        return result

    return wrapper


def guard_telemetry_fetcher(technique_id: str, fn: TelemetryFetcher) -> TelemetryFetcher:
    """Blue's fetch_telemetry isn't part of the model-facing tool-calling
    turn loop, so a denial here raises - it means the harness itself picked
    an out-of-scope target or a target is paused, which should hard-fail
    the battle rather than silently return blank telemetry."""

    @functools.wraps(fn)
    def wrapper(target_url: str, since_offset: int = 0) -> tuple[str, int]:
        try:
            scope.assert_in_scope(target_url)
            killswitch.check(target_url)
        except _DENIAL_EXCEPTIONS as exc:
            audit.record_action(
                "blue", "fetch_telemetry", target_url, technique=technique_id,
                outcome=type(exc).__name__, detail={"error": str(exc)},
            )
            raise

        try:
            result = fn(target_url, since_offset)
        except Exception as exc:
            killswitch.record(target_url, errored=True)
            audit.record_action(
                "blue", "fetch_telemetry", target_url, technique=technique_id,
                outcome="error", detail={"error": str(exc)},
            )
            raise

        killswitch.record(target_url, errored=False)
        audit.record_action("blue", "fetch_telemetry", target_url, technique=technique_id, outcome="ok")
        return result

    return wrapper
