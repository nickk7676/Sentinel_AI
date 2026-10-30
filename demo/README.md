# SentinelAI Demo — Autonomous Attack & Defense on a (Fictional) MIT Application Portal

> **⚠ FICTIONAL SECURITY DEMO.** The "MIT application portal" in `demo/portal/` is
> an invented, deliberately-vulnerable stand-in built solely for this
> demonstration. It is **not** a real MIT system, uses **no** real MIT branding,
> and every applicant, decision, award, and identifier in it is **fake**. Do not
> deploy any of its intentionally-insecure code.

This directory is **fully additive** — it does not modify anything in `agents/`,
`training/`, or `lab/`. It reuses those read-only (the real trained adapters, the
real router battle, the real blue model).

## What it shows

Given **only the portal URL and no hints**, SentinelAI:
1. **Recons** the portal (real deterministic HTTP fingerprinting).
2. **Selects** an attack per endpoint from recon's real signals.
3. **Attacks** with the matching **trained red adapter** — and the attack is shown
   happening in the **browser UI** (the agent's real payload is typed into the
   real form; the page really changes).
4. **Blue** reads the portal's `/logs` telemetry, **detects** the attack, and
   prints a **recommended fix**.
5. A **live log view** interleaves real **benign** traffic with the attack and
   highlights **only** the lines blue itself flags — demonstrating blue's
   **zero false positives**.

Featured techniques: **IDOR, SQL injection, SSRF, and the token-leak → account-takeover chain.**

## Honesty (this goes to MIT — read this)

- Every **attack, payload, canary, log line, and blue verdict is real**, produced
  by the real trained models against the real portal.
- The **browser** re-enacts the agent's **real winning payload** through the real
  UI. Nothing on screen is a pre-recorded animation.
- **Technique selection** is driven by **recon's real fingerprint signals** (a
  transparent triage: numbered sub-resource → IDOR, login form → SQLi, URL-fetch
  endpoint → SSRF, token-leaking record → chain). This is `--select-mode recon`
  (the default).
  - The project also has a **trained router LLM** meant to make this selection.
    In testing it **underperforms** at mapping recon findings to the right
    technique (it over-predicts a couple of categories). You can show its real
    (often wrong) decision with `--select-mode router`. The recon-signal triage
    is used by default so the demo is reliable and honest about what's real.
    Improving the router (or per-technique routing) is documented future work.

## Run it

```bash
# 1) deps (into the project venv311, which already has torch for the agents)
venv311/Scripts/python.exe -m pip install -r demo/requirements-demo.txt
venv311/Scripts/python.exe -m playwright install chromium

# 2) start the portal (serves UI + attackable endpoints + /logs; internal SSRF svc on :6000)
export PYTHONPATH=$PWD
venv311/Scripts/python.exe -m demo.portal.app --port 5500
#   open http://127.0.0.1:5500 in a browser to see the portal

# 3) in another shell: allow the portal in the agents' safety scope, then run
export PYTHONPATH=$PWD
export LLM_PROVIDER=local
export SENTINELAI_ALLOWED_TARGETS=http://127.0.0.1:5500
venv311/Scripts/python.exe -m demo.run_demo                 # compute (real models) then play
# or, for recording in two clean passes:
venv311/Scripts/python.exe -m demo.run_demo --compute-only  # heavy model work off-camera
venv311/Scripts/python.exe -m demo.run_demo --play-only     # smooth playback + browser (record this)
```

Flags: `--no-browser`, `--no-benign`, `--fast` (no typing delay),
`--select-mode {recon,router}`.

## How it fits together

| File | Role |
|---|---|
| `portal/app.py` | the fake MIT portal: UI pages + the exact attackable endpoints + `/logs` + loopback SSRF service |
| `portal/seed_data.py` | fabricated applicants/decisions/aid + the exact canaries the adapters check |
| `traffic/benign.py` | real benign traffic (legit logins, own-case views, allowed previews) |
| `visualizer/browser.py`, `visualizer/mapping.py` | Playwright drives the agent's real payloads through the UI |
| `narration/demo_mode.py` | clean typed terminal narration of the real events |
| `narration/log_view.py` | blue-driven red/benign log highlighting (zero-false-positive view) |
| `run_demo.py` | orchestrator: compute (real models) → play (narration + browser) |

## Notes / limits

- Needs the project `venv311` (torch/transformers/peft) + Flask + Playwright.
- GPU: one model resident at a time (compute unloads red before loading blue).
- It's an **edited** 2-minute video: capture longer real runs, cut to highlights.
  Retries are free — if a run flakes, re-run it (we never fake a result).
