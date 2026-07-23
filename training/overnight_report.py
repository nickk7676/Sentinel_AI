"""
Generates a single self-contained HTML summary at the end of a
--technique all overnight run (training/battle_loop.py:run_loop_all), so
the results of a multi-hour unattended session can be read at a glance in
the morning instead of scrolled for in the console log.

Deliberately a plain HTML/CSS file with no external requests (no CDN, no
JS framework) - it has to open correctly from disk, offline, on whatever
machine the run happened on.
"""

import html
import json
import time
from pathlib import Path

from training.dataset import DATA_DIR

SUMMARY_DIR = DATA_DIR / "overnight_summaries"

# Reference palette (see dataviz skill, references/palette.md) - sequential
# blue for magnitude bars, fixed status colors for technique outcome badges.
_SEQ_LIGHT = "#2a78d6"
_SEQ_DARK = "#3987e5"
_STATUS = {
    "complete":  {"color": "#0ca30c", "dark": "#0ca30c", "icon": "✓", "label": "Complete"},
    "skipped":   {"color": "#fab219", "dark": "#fab219", "icon": "⚠", "label": "Skipped"},
    "crashed":   {"color": "#d03b3b", "dark": "#d03b3b", "icon": "✕", "label": "Crashed"},
}
_DELTA_GOOD = "#0ca30c"
_DELTA_BAD = "#d03b3b"
_DELTA_NEUTRAL = "#898781"


def _status_kind(status: str) -> str:
    if status.startswith("skipped"):
        return "skipped"
    if status == "crashed":
        return "crashed"
    return "complete"


def _fmt_pct(rate: float | None) -> str:
    return "—" if rate is None else f"{round(rate * 100)}%"


def _bar_row(label: str, rate: float | None, detail: str) -> str:
    """One horizontal bar: a technique's rate for a single metric. rate=None
    (technique didn't run) renders as an empty, hatched, non-numeric bar
    rather than a misleading 0%."""
    safe_label = html.escape(label)
    safe_detail = html.escape(detail)
    if rate is None:
        return f"""
        <div class="bar-row" title="{safe_detail}">
          <span class="bar-label">{safe_label}</span>
          <div class="bar-track bar-track--empty"></div>
          <span class="bar-value bar-value--muted">—</span>
        </div>"""
    pct = max(0.0, min(1.0, rate)) * 100
    return f"""
        <div class="bar-row" title="{safe_detail}">
          <span class="bar-label">{safe_label}</span>
          <div class="bar-track"><div class="bar-fill" style="width:{pct:.1f}%"></div></div>
          <span class="bar-value">{round(pct)}%</span>
        </div>"""


def _stat_tile(value: str, label: str) -> str:
    return f"""
      <div class="stat-tile">
        <div class="stat-value">{html.escape(value)}</div>
        <div class="stat-label">{html.escape(label)}</div>
      </div>"""


def _status_badge(status: str) -> str:
    kind = _status_kind(status)
    s = _STATUS[kind]
    return (f'<span class="badge badge--{kind}">'
            f'<span class="badge-icon">{s["icon"]}</span>{html.escape(s["label"])}</span>')


def _delta_row(scope: str, metric: str, before: float | None, after: float | None, lower_is_better: bool = False) -> str:
    """One row of the before/after comparison table. Color follows whether
    the change is actually an improvement for THAT metric - false-positive
    rate flips the sign (a drop is good) relative to success/detection
    rate (a rise is good), per the palette's "delta good/bad" ink roles."""
    if before is None or after is None:
        return f"""
        <tr><td>{html.escape(scope)}</td><td>{html.escape(metric)}</td>
          <td>—</td><td>—</td><td class="delta-muted">no data</td></tr>"""
    delta_pts = (after - before) * 100
    improved = delta_pts <= 0 if lower_is_better else delta_pts >= 0
    color_class = "delta-neutral" if abs(delta_pts) < 0.5 else ("delta-good" if improved else "delta-bad")
    arrow = "→" if abs(delta_pts) < 0.5 else ("↑" if delta_pts > 0 else "↓")
    return f"""
        <tr><td>{html.escape(scope)}</td><td>{html.escape(metric)}</td>
          <td>{round(before * 100)}%</td><td>{round(after * 100)}%</td>
          <td class="{color_class}">{arrow} {abs(round(delta_pts))} pts</td></tr>"""


def _eval_scope_rates(eval_result: dict | None, role: str | None) -> dict:
    """Pulls red/blue rates out of an eval_harness.run_eval() result dict -
    either the run-wide "overall" numbers (role=None) or one role's rollup
    (role="heldout") from overall["by_role"]. Missing/crashed snapshot or an
    empty role bucket (e.g. no heldout targets were reachable) -> all None,
    which _delta_row renders as "no data" instead of a fake 0%."""
    empty = {"red_attack_success_rate": None, "blue_detection_rate": None, "blue_false_positive_rate": None}
    if eval_result is None:
        return empty
    overall = eval_result.get("overall", {})
    if role is None:
        source = overall
    else:
        source = overall.get("by_role", {}).get(role, {})
    return {
        "red_attack_success_rate": source.get("red_attack_success_rate"),
        "blue_detection_rate": source.get("blue_detection_rate"),
        "blue_false_positive_rate": source.get("blue_false_positive_rate"),
    }


def write_summary(
    session_stats: list[dict],
    rounds: int,
    battles_per_round: int,
    overall_started: float,
    overall_elapsed: float,
    baseline_eval: dict | None = None,
    after_eval: dict | None = None,
) -> Path:
    """session_stats: one dict per technique, in run order:
        id, display_name, status, elapsed_seconds,
        attack_battles, attack_successes, detections,
        normal_battles, false_positives,
        red_attack_success_rate, blue_detection_rate, blue_false_positive_rate
      (the three rates are None for a technique that never ran a battle -
      skipped or crashed before its first result came back).

    baseline_eval/after_eval: raw dicts returned by
    eval_harness.run_eval(), taken right before and right after this run's
    training (training/battle_loop.py:run_loop_all) - a real before/after
    comparison on frozen, held-out battles rather than this run's own live
    in-training numbers. Either or both may be None if that snapshot was
    skipped or crashed; the comparison section renders "no data" rather
    than guessing."""
    started_str = time.strftime("%Y-%m-%d %H:%M", time.localtime(overall_started))
    n_complete = sum(1 for s in session_stats if _status_kind(s["status"]) == "complete")
    n_total = len(session_stats)

    total_attack_battles = sum(s["attack_battles"] for s in session_stats)
    total_attack_successes = sum(s["attack_successes"] for s in session_stats)
    total_detections = sum(s["detections"] for s in session_stats)
    total_normal_battles = sum(s["normal_battles"] for s in session_stats)
    total_false_positives = sum(s["false_positives"] for s in session_stats)
    total_battles = total_attack_battles + total_normal_battles

    overall_success = total_attack_successes / total_attack_battles if total_attack_battles else None
    overall_detect = total_detections / total_attack_battles if total_attack_battles else None
    overall_fp = total_false_positives / total_normal_battles if total_normal_battles else None

    stat_tiles = "".join([
        _stat_tile(f"{n_complete}/{n_total}", "Techniques completed"),
        _stat_tile(str(total_battles), "Battles run"),
        _stat_tile(_fmt_pct(overall_success), "Red attack success"),
        _stat_tile(_fmt_pct(overall_detect), "Blue detection rate"),
        _stat_tile(_fmt_pct(overall_fp), "Blue false-positive rate"),
        _stat_tile(f"{overall_elapsed / 3600:.1f}h", "Total run time"),
    ])

    red_bars = "".join(
        _bar_row(s["display_name"], s["red_attack_success_rate"],
                 f"{s['attack_successes']}/{s['attack_battles']} attacks succeeded" if s["attack_battles"] else "no attack battles ran")
        for s in session_stats
    )
    detect_bars = "".join(
        _bar_row(s["display_name"], s["blue_detection_rate"],
                 f"{s['detections']}/{s['attack_battles']} attacks detected" if s["attack_battles"] else "no attack battles ran")
        for s in session_stats
    )
    fp_bars = "".join(
        _bar_row(s["display_name"], s["blue_false_positive_rate"],
                 f"{s['false_positives']}/{s['normal_battles']} normal battles flagged" if s["normal_battles"] else "no normal-traffic battles ran")
        for s in session_stats
    )

    table_rows = "".join(f"""
        <tr>
          <td>{html.escape(s["display_name"])}</td>
          <td>{_status_badge(s["status"])}</td>
          <td>{round(s["elapsed_seconds"])}s</td>
          <td>{s["attack_battles"]}</td>
          <td>{s["normal_battles"]}</td>
          <td>{_fmt_pct(s["red_attack_success_rate"])}</td>
          <td>{_fmt_pct(s["blue_detection_rate"])}</td>
          <td>{_fmt_pct(s["blue_false_positive_rate"])}</td>
        </tr>""" for s in session_stats)

    before_all = _eval_scope_rates(baseline_eval, None)
    after_all = _eval_scope_rates(after_eval, None)
    before_heldout = _eval_scope_rates(baseline_eval, "heldout")
    after_heldout = _eval_scope_rates(after_eval, "heldout")

    comparison_rows = "".join([
        _delta_row("All targets", "Red attack success", before_all["red_attack_success_rate"], after_all["red_attack_success_rate"]),
        _delta_row("All targets", "Blue detection rate", before_all["blue_detection_rate"], after_all["blue_detection_rate"]),
        _delta_row("All targets", "Blue false-positive rate", before_all["blue_false_positive_rate"], after_all["blue_false_positive_rate"], lower_is_better=True),
        _delta_row("Held-out targets (never trained on)", "Red attack success", before_heldout["red_attack_success_rate"], after_heldout["red_attack_success_rate"]),
        _delta_row("Held-out targets (never trained on)", "Blue detection rate", before_heldout["blue_detection_rate"], after_heldout["blue_detection_rate"]),
        _delta_row("Held-out targets (never trained on)", "Blue false-positive rate", before_heldout["blue_false_positive_rate"], after_heldout["blue_false_positive_rate"], lower_is_better=True),
    ])
    if baseline_eval is None and after_eval is None:
        comparison_note = "Eval snapshots were skipped or unavailable for this run."
    elif baseline_eval is None:
        comparison_note = 'Baseline (before) snapshot unavailable - only "after" numbers below, no delta.'
    elif after_eval is None:
        comparison_note = 'Comparison (after) snapshot unavailable - only "before" numbers below, no delta.'
    else:
        comparison_note = "Frozen, held-out battles (eval_harness.py) run once before and once after tonight's training - not this run's own live in-training numbers."

    html_doc = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>SentinelAI — Overnight Run Summary</title>
<style>
  :root {{
    --surface-1: #fcfcfb; --page: #f9f9f7; --text-primary: #0b0b0b;
    --text-secondary: #52514e; --text-muted: #898781; --gridline: #e1e0d9;
    --border: rgba(11,11,11,0.10); --seq: {_SEQ_LIGHT}; --seq-track: #e1e0d9;
    --delta-good: {_DELTA_GOOD}; --delta-bad: {_DELTA_BAD}; --delta-neutral: {_DELTA_NEUTRAL};
  }}
  @media (prefers-color-scheme: dark) {{
    :root {{
      --surface-1: #1a1a19; --page: #0d0d0d; --text-primary: #ffffff;
      --text-secondary: #c3c2b7; --text-muted: #898781; --gridline: #2c2c2a;
      --border: rgba(255,255,255,0.10); --seq: {_SEQ_DARK}; --seq-track: #2c2c2a;
    }}
  }}
  * {{ box-sizing: border-box; }}
  body {{
    margin: 0; padding: 32px 24px 64px; background: var(--page); color: var(--text-primary);
    font-family: system-ui, -apple-system, "Segoe UI", sans-serif;
  }}
  .wrap {{ max-width: 960px; margin: 0 auto; }}
  h1 {{ font-size: 22px; margin: 0 0 4px; }}
  .subtitle {{ color: var(--text-secondary); font-size: 14px; margin: 0 0 32px; }}
  .card {{
    background: var(--surface-1); border: 1px solid var(--border); border-radius: 12px;
    padding: 20px 24px; margin-bottom: 20px;
  }}
  .card h2 {{ font-size: 15px; margin: 0 0 16px; color: var(--text-primary); }}
  .stat-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(130px, 1fr)); gap: 16px; }}
  .stat-tile {{ text-align: left; }}
  .stat-value {{ font-size: 26px; font-weight: 600; font-variant-numeric: tabular-nums; }}
  .stat-label {{ font-size: 12px; color: var(--text-secondary); margin-top: 2px; }}
  .bar-row {{ display: grid; grid-template-columns: 150px 1fr 44px; align-items: center; gap: 12px; margin-bottom: 10px; }}
  .bar-label {{ font-size: 13px; color: var(--text-secondary); }}
  .bar-track {{ height: 10px; background: var(--gridline); border-radius: 4px; overflow: hidden; }}
  .bar-track--empty {{
    background-image: repeating-linear-gradient(135deg, var(--gridline) 0 4px, transparent 4px 8px);
  }}
  .bar-fill {{ height: 100%; background: var(--seq); border-radius: 4px; }}
  .bar-value {{ font-size: 12px; font-variant-numeric: tabular-nums; color: var(--text-primary); text-align: right; }}
  .bar-value--muted {{ color: var(--text-muted); }}
  table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
  th, td {{ text-align: left; padding: 8px 10px; border-bottom: 1px solid var(--gridline); font-variant-numeric: tabular-nums; }}
  th {{ color: var(--text-muted); font-weight: 500; font-size: 11px; text-transform: uppercase; letter-spacing: 0.03em; }}
  .badge {{ display: inline-flex; align-items: center; gap: 5px; font-size: 12px; font-weight: 600; }}
  .badge-icon {{ display: inline-block; width: 16px; height: 16px; line-height: 16px; text-align: center;
                 border-radius: 50%; font-size: 10px; color: #fff; }}
  .badge--complete .badge-icon {{ background: {_STATUS['complete']['color']}; }}
  .badge--skipped  .badge-icon {{ background: {_STATUS['skipped']['color']}; color: #1a1a19; }}
  .badge--crashed  .badge-icon {{ background: {_STATUS['crashed']['color']}; }}
  .badge--complete {{ color: {_STATUS['complete']['color']}; }}
  .badge--skipped  {{ color: #a56a00; }}
  .badge--crashed  {{ color: {_STATUS['crashed']['color']}; }}
  @media (prefers-color-scheme: dark) {{
    .badge--skipped {{ color: {_STATUS['skipped']['color']}; }}
  }}
  .delta-good {{ color: var(--delta-good); font-weight: 600; }}
  .delta-bad {{ color: var(--delta-bad); font-weight: 600; }}
  .delta-neutral {{ color: var(--delta-neutral); font-weight: 600; }}
  .delta-muted {{ color: var(--text-muted); }}
  .card-note {{ color: var(--text-secondary); font-size: 12px; margin: -8px 0 16px; }}
</style>
</head>
<body>
<div class="wrap">
  <h1>SentinelAI — Overnight Run Summary</h1>
  <p class="subtitle">Started {html.escape(started_str)} &middot; {rounds} round{"s" if rounds != 1 else ""} &times; {battles_per_round} battles per technique &middot; {n_total} techniques</p>

  <div class="card">
    <h2>Overall</h2>
    <div class="stat-grid">{stat_tiles}</div>
  </div>

  <div class="card">
    <h2>Did tonight actually help? (before &rarr; after)</h2>
    <p class="card-note">{html.escape(comparison_note)}</p>
    <table>
      <thead>
        <tr><th>Scope</th><th>Metric</th><th>Before</th><th>After</th><th>Change</th></tr>
      </thead>
      <tbody>{comparison_rows}</tbody>
    </table>
  </div>

  <div class="card">
    <h2>Red — attack success rate</h2>
    {red_bars}
  </div>

  <div class="card">
    <h2>Blue — detection rate</h2>
    {detect_bars}
  </div>

  <div class="card">
    <h2>Blue — false-positive rate (lower is better)</h2>
    {fp_bars}
  </div>

  <div class="card">
    <h2>Per-technique detail</h2>
    <table>
      <thead>
        <tr><th>Technique</th><th>Status</th><th>Elapsed</th><th>Attacks</th><th>Normal</th>
            <th>Red success</th><th>Blue detect</th><th>Blue FP</th></tr>
      </thead>
      <tbody>{table_rows}</tbody>
    </table>
  </div>
</div>
</body>
</html>
"""

    SUMMARY_DIR.mkdir(parents=True, exist_ok=True)
    out_path = SUMMARY_DIR / f"summary_{time.strftime('%Y%m%d_%H%M%S', time.localtime(overall_started))}.html"
    out_path.write_text(html_doc, encoding="utf-8")

    # Also drop the raw numbers as JSON next to it, for anything that wants
    # to chart trend-over-time across multiple overnight runs later.
    out_path.with_suffix(".json").write_text(
        json.dumps({"rounds": rounds, "battles_per_round": battles_per_round,
                    "started": overall_started, "elapsed_seconds": overall_elapsed,
                    "techniques": session_stats}, indent=2),
        encoding="utf-8",
    )

    return out_path
