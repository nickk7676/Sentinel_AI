"""
Shared "technique" abstraction (Step 2 of the project plan).

A Technique bundles everything red, blue, and the judge need for one attack
type: red's tool schema(s) + execution + prompts, blue's telemetry fetch, and
the judge's category-matching rule. Adding a new technique means creating a
new module under agents/techniques/ that builds and registers one of these -
nothing in live_tools.py, simulation_service.py, or battle_loop.py changes.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from agents.blue_team.live_tools import fetch_new_logs
from agents.tool_output import MAX_TOOL_RESULT_CHARS, truncate_output  # noqa: F401 - re-exported for technique modules

DEFAULT_HTTP_TIMEOUT = 10

# (target_url, since_offset) -> (new_evidence_text, new_offset)
TelemetryFetcher = Callable[[str, int], tuple[str, int]]
# (target_url, tool_name, args) -> result dict, must include "success": bool
ToolExecutor = Callable[[str, str, dict], dict]
# last successful/attempted tool-call result dict -> human-readable payload string
AttemptDescriber = Callable[[dict], str]
# target_url -> result dict, shaped exactly like ToolExecutor's result (must include "success": bool)
NormalActionPerformer = Callable[[str], dict]


@dataclass(frozen=True, kw_only=True)
class Technique:
    id: str
    display_name: str
    mitre_technique: str
    endpoint_path: str

    # Red side
    tool_schemas: list[dict]
    system_prompt: str
    user_prompt_template: str
    execute_tool_call: ToolExecutor
    describe_attempt: AttemptDescriber
    # Performs a real, harmless action against the live target (Step 2.5:
    # randomized normal-traffic rounds) - not an attack attempt.
    perform_normal_action: NormalActionPerformer
    severity_success: str = "critical"
    severity_failure: str = "medium"
    # Max tool-calling turns per live battle (agents/red_team/live_tools.py).
    # Override per-technique when trial-and-error needs more room to work -
    # e.g. a technique whose real bypass requires guessing an unknown value
    # (a directory name, an id) benefits from more attempts per battle to
    # react to real HTTP responses, independent of how well-trained it is.
    max_turns: int = 5

    # Blue/judge side
    category_keywords: tuple[str, ...] = ()
    # Step 7.1/7.2 - keywords that, if present in blue's freeform
    # recommended_fix text, indicate it named the actual correct remediation
    # category for this technique (same substring-match pattern as
    # category_keywords, just applied to the fix field instead of the
    # threat_category field). Used by agents/judge/verification.py to decide
    # whether blue's proposed fix is even worth verifying against a real
    # patched target, since there's no code-patching engine that turns
    # arbitrary fix prose into an applicable diff.
    fix_keywords: tuple[str, ...] = ()

    # Telemetry (2.2) - override only if a target doesn't expose the generic /logs shape
    fetch_telemetry: TelemetryFetcher = fetch_new_logs
