"""
Real telemetry fetch for SentinelAI Milestone 1.

Instead of reading a self-reported attack summary, blue team pulls the
target's own real access log over HTTP - the same kind of evidence a real
security team would look at.
"""

import requests

from agents.tool_output import truncate_output

TARGET_TIMEOUT = 10


def fetch_new_logs(target_url: str, since_offset: int = 0) -> tuple[str, int]:
    """Fetch log content appended since `since_offset`.

    Returns (new_log_text, new_offset) so the caller can track its position
    across multiple battles against the same long-running target. Normally
    this is a handful of lines, but if offset tracking ever falls behind
    (a skipped battle, a reset), the delta could grow unbounded - truncate
    defensively so a bad offset can't blow up the next prompt the same way
    an uncapped tool result did on red's side.
    """
    resp = requests.get(
        f"{target_url}/logs",
        params={"since": since_offset},
        timeout=TARGET_TIMEOUT,
    )
    resp.raise_for_status()
    data = resp.json()
    return truncate_output(data.get("lines", "")), data.get("offset", since_offset)
