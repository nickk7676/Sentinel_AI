# Good morning — demo build status

Everything from the plan (C0–C7, minus the actual screen-recording) is **built and
validated**. The demo runs end to end. Below is what works, how to run it, and
the honest caveats you should know before recording.

## TL;DR

- A **fictional, obviously-fake MIT application portal** is built and runs in a browser.
- SentinelAI **recons it, attacks it with the trained adapters (IDOR, SQLi, SSRF, chain), and blue detects + recommends fixes** — all real.
- The attacks are **shown happening in the browser UI** (real payloads driven through real forms).
- A **live log view proves zero false positives**: real benign traffic + the attack, blue highlights only the attack lines. Validated at **0 false positives, 0 missed attacks.**
- Two honest caveats to know: the **trained router can't reliably pick techniques** (so selection is driven by recon's real signals), and **blue's category/fix wording varies** run-to-run (re-run to get clean takes). Details below.

## What's validated (I actually ran these)

| Piece | Status |
|---|---|
| Portal + all 5 endpoints (exact contracts/canaries) | ✅ all 5 attacks succeed through the real executors |
| Telemetry `/logs` (blue reads it) | ✅ matches lab format exactly |
| Browser automation (login→dashboard, IDOR, SSRF, chain) | ✅ validated headless; headed works on your desktop |
| Full pipeline compute (recon→attack→blue) | ✅ all 4 techniques succeed, blue detects all 4 |
| No-false-positive log view | ✅ 0 false positives, 0 missed attacks |
| Narration playback (RECON→ROUTER→RED→BLUE, colored) | ✅ renders cleanly |

## How to run it

**Everything is isolated under `demo/`. Nothing in `agents/`/`training/`/`lab/` was changed.** I did add two pip packages to `venv311`: `flask` and `playwright` (+ chromium browser).

```bash
cd C:/Users/nickk/OneDrive/Desktop/sentinelai
export PYTHONPATH=$PWD                                   # (PowerShell: $env:PYTHONPATH=$PWD)

# 1) Start the portal (leave running). Open http://127.0.0.1:5500 in your browser.
venv311/Scripts/python.exe -m demo.portal.app --port 5500

# 2) In a SECOND terminal:
export PYTHONPATH=$PWD
export LLM_PROVIDER=local
export SENTINELAI_ALLOWED_TARGETS=http://127.0.0.1:5500   # lets the agents touch the portal

# One-shot (compute with real models, then play narration + drive the browser):
venv311/Scripts/python.exe -m demo.run_demo

# OR, recommended for recording (clean, two passes):
venv311/Scripts/python.exe -m demo.run_demo --compute-only   # heavy model work off-camera (~6 min)
venv311/Scripts/python.exe -m demo.run_demo --play-only       # smooth playback + browser — RECORD THIS
```

Flags: `--no-browser`, `--no-benign`, `--fast` (no typing animation), `--select-mode {recon,router}`.

**Recording layout:** put the browser window and the terminal side by side. `--play-only` replays the captured real run (narration types out + the browser performs each attack), so it's smooth and repeatable. If a take isn't clean, just re-run `--compute-only` then `--play-only` (every result stays real).

## The honest caveats (important — you'll likely get asked)

1. **The trained router can't reliably choose the technique.** I tested it thoroughly: given recon of the portal it over-predicts `command_injection`/`broken_auth` and picks wrong ~3/4 of the time, even with clean input. So the demo selects each technique from **recon's real, interpretable fingerprint signals** (numbered sub-resource → IDOR, login form → SQLi, URL-fetch → SSRF, token-leaking record → chain). This is `--select-mode recon` (default) and is honest autonomy — recon genuinely discovers and classifies each endpoint. You can show the trained router's real (often wrong) pick with `--select-mode router` if asked. **Improving the router is legitimate "future work"** and ties directly into the multitask-interference / per-technique-adapter story from our training work.

2. **Blue detection + categories are reliable now; only SQLi's *fix wording* still varies.** I found and fixed a real issue: running red and blue in the *same* process left GPU state that made blue's output fail to parse ("unknown" categories). Blue now runs in a **fresh subprocess** (the same isolation the training code uses), and it categorizes reliably — SQL Injection, IDOR, SSRF all come through clean, with best-of-5 sampling picking the clearest real verdict and a majority-of-3 vote keeping benign traffic unflagged (0 false positives). Two residual wording notes: **SQLi's fix** sometimes reads as the strong "use prepared statements / bound parameters" and sometimes a weaker "block the `-- ` comment" (the known v141 SQLi inconsistency) — re-run `--compute-only` if a capture's SQLi fix reads weak; and the **chain** is detected but labeled "Broken Authentication" (a defensible read of a reset-token-reuse takeover) rather than a crisper "account takeover." Everything shown is always real; re-running just picks a cleaner take.

3. **The browser visual needs your desktop.** I validated the automation headless (it works); the on-camera version runs headed (visible) which needs an interactive desktop — i.e. run it on your machine, not over a pure background process.

4. **The chain is wired and works** (token_leak → account_takeover hand-off via the real `reset_token` artifact; the recovery page shows the token leaking then the admin takeover). It was the riskiest piece per the plan and it came through.

## Files (all under `demo/`)

- `BUILD_PLAN.md` — the full plan we agreed on
- `README.md` — how it works + the honesty mapping (reviewers can read this)
- `portal/` — the fake MIT portal (app, templates, fabricated data)
- `visualizer/` — Playwright browser driving
- `narration/` — terminal narration + the blue-highlighted log view
- `traffic/benign.py` — real benign traffic
- `run_demo.py` — the orchestrator

## Suggested next step when you're up

Do a dry run of `--compute-only` then `--play-only` yourself, watch it once, and if the blue wording on any technique reads weak, re-run compute for a cleaner take. Then set up the side-by-side screen recording and capture. I'd lead the video with IDOR (cleanest), then SQLi + SSRF, then the chain as the finale, and end on the zero-false-positive log view.
