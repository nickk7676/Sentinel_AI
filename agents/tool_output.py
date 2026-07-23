"""
Shared tool-result truncation.

Lives outside agents/techniques/ and agents/blue_team/ specifically to avoid
a circular import: agents/techniques/base.py imports from
agents/blue_team/live_tools.py (for the default telemetry fetcher), and
live_tools.py also needs this truncation helper - a leaf module with no
dependencies on either package lets both import it directly.

Some techniques let an attacker payload coerce the target into returning far
more data than any tool result needs (command_injection's shell command can
run anything up to its timeout; path_traversal/ssrf can reach arbitrarily
large files or pages), and blue's log fetch could in principle grow large if
offset tracking ever falls behind. Left uncapped, one such response balloons
the next turn's prompt - this is what caused a live CUDA OOM: an unbounded
shell dump pushed a single battle to 382k tokens against the model's
131k-token limit. Truncating here, on the way back from the target, keeps
every tool result bounded by construction regardless of what a payload
manages to coerce out of the target.
"""

MAX_TOOL_RESULT_CHARS = 4000


def truncate_output(text: str, max_chars: int = MAX_TOOL_RESULT_CHARS) -> str:
    if len(text) <= max_chars:
        return text
    return text[:max_chars] + f"...[truncated, {len(text) - max_chars} more chars]"
