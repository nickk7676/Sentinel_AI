# SentinelAI — MIT Demo Video Build Plan

**Audience:** the people building this demo (you + Claude). This is an implementation
spec, not marketing copy. Followed exactly, it produces a ~2-minute edited video
showing SentinelAI autonomously reconning, attacking, and defending a fictional
application portal — with the attacks visibly playing out in the browser UI.

**Status:** plan only. No demo code written yet. Build happens in the order in §7.

---

## 1. Goal & success criteria

A 2-minute, text-on-screen (no voiceover) video in which:

1. A fictional, obviously-fake "MIT" application portal is open in a browser.
2. SentinelAI is given **only the portal URL** — no hints about its vulnerabilities.
3. The **recon + router** survey the portal and **autonomously choose** which attack to run.
4. The matching **trained red adapter** attacks, and the attack **visibly happens in the portal UI** (payload typed into a form, page changes, "stolen" fake data shown).
5. The **blue team** reads the portal's telemetry, **detects** the attack, and prints a **correct recommended fix**.
6. Four techniques are featured: **IDOR, SQL injection, SSRF, and the token-leak→account-takeover chain.**
7. **A live log view shows real BENIGN traffic interleaved with the attack.** Every log line is classified by blue; blue-flagged attack lines are **highlighted red**, benign lines stay normal — visibly demonstrating blue's **zero false positives** (benign never flagged) alongside full detection (attacks always flagged). The red/benign split reflects blue's REAL per-event verdict, never a pre-labeled list.

**Done = success** when, in captured footage: the router selects each technique correctly with no hints, each attack succeeds and is shown in the UI, and blue detects + fixes each — all from real runs (see §4).

---

## 2. Hard constraints (do not violate)

### 2.1 Isolation — no changes to existing code
- **Everything new lives under `demo/`.** Do **not** edit anything in `agents/`, `training/`, or `lab/`.
- The demo **imports** existing modules read-only (router, blue agent, live_tools). Reuse, never modify.
- The featured attacks must use the **existing trained adapters** (`training/adapters/red_team/<technique>`), keyed by the real technique ids — so we reuse the real router battle, we don't re-register techniques.

### 2.2 Integrity — everything shown is real (this goes to MIT)
- The browser visualization is driven by the agent's **real chosen payloads** from a **real run**. Nothing is hardcoded, faked, or pre-animated.
- Terminal narration pretty-prints **real** router decisions, red payloads, and blue output — formatting only, never fabricated outcomes.
- If a run flakes, we **re-run** it. We never stage a result that didn't happen.
- `demo/README.md` will state plainly how the visualization maps to the real run, so a reviewer reading the code sees exactly what is real.

### 2.3 The portal is OBVIOUSLY fake (personality, but harmless & non-deceptive)
- Parody branding, **not** the real MIT seal/logo/domain. A made-up crest is fine.
- A persistent on-screen banner: **"⚠ FICTIONAL SECURITY DEMO — NOT A REAL MIT SYSTEM."**
- All applicant data is **obviously fabricated** (joke names, absurd-but-plausible fields). The "valuable stolen info" is fake (e.g. a fake admission decision, fake financial-aid award, fake internal admin notes) — valuable-looking, clearly invented.
- `demo/README.md` carries a disclaimer: fictional, built as a security-demo stand-in.

---

## 3. Directory layout (all additive)

```
demo/
  BUILD_PLAN.md            # this file
  README.md                # disclaimer + how the visualization maps to the real run
  requirements-demo.txt    # playwright (+ its browser install step)
  portal/
    app.py                 # the fake MIT portal (one Flask app; serves UI + endpoints + /logs)
    templates/             # login, dashboard, application view, link-preview, reset pages
    static/                # parody crest, CSS (obviously-fake banner styling)
    seed_data.py           # fabricated applicants, admin record, canaries
  visualizer/
    browser.py             # Playwright wrapper: types a given payload into a given page, screenshots
    mapping.py             # technique -> which page/form/field + how to render the "stolen data"
  narration/
    demo_mode.py           # formats real router/red/blue events into the clean terminal blocks
    log_view.py            # live log view: feeds each line through blue, highlights blue-flagged attack lines red, benign normal
  traffic/
    benign.py              # generates real benign traffic (perform_normal_action + seeded legit logins)
  run_demo.py              # orchestrator: real router battle -> capture -> narrate + drive browser -> blue
```

---

## 4. The portal (`demo/portal/app.py`) — exact contracts

One Flask app, themed as the fake MIT portal, that **simultaneously**:
- serves the **HTML UI** (what the browser shows), and
- exposes the **endpoints the trained agents already attack**, and
- exposes **`GET /logs?since=<offset>`** returning `{"lines": "...", "offset": N}` (blue reads telemetry this way — matches `agents/blue_team/live_tools.py:fetch_new_logs`).

Logging must mirror the existing lab targets: a `logging.StreamHandler` into an in-memory buffer, every request logged, `/logs` returns new lines since `since`. Copy the pattern from `lab/idor/app.py` (do not import it — re-implement inside `demo/portal/app.py`).

### 4.1 Canaries (COPY EXACTLY — success is gated on these)
Each technique's executor checks for a specific marker in the response. The portal MUST plant the exact string from each technique file, or the attack will never register as a success:

| Technique | Endpoint(s) the portal must expose | Canary source (copy verbatim) |
|---|---|---|
| SQL injection | `POST /login` (username/password form; string-built SQL; `' OR '1'='1' -- ` logs in) | `agents/techniques/sql_injection.py` CANARY |
| IDOR | `GET /api/applications/<id>` (sequential ids, **no ownership check**) themed as "view application" | `agents/techniques/idor.py` CANARY (`SENTINELAI-IDOR-CANARY-4b8e1f0a`) |
| SSRF | `POST /preview` ("preview an application link"; server fetches any URL; internal-only admin service on loopback) | `agents/techniques/ssrf.py` CANARY (`SENTINELAI-SSRF-CANARY-9d21ab6f`) + internal URL hint |
| Chain A: token_leak | `GET /api/reset-requests/<id>` (sequential, no auth; admin's low-id record contains `reset_token`) | n/a (leak surfaces `reset_token` artifact) |
| Chain B: account_takeover | `POST /account/complete-reset` (accepts `reset_token`; admin token → returns canary) | `agents/techniques/account_takeover.py` CANARY (`SENTINELAI-CHAIN-CANARY-9d4c7b1a`) |

> Build note: treat `lab/sql_injection`, `lab/idor`, `lab/ssrf`, `lab/chained_privesc` as **reference implementations** for endpoint behavior. Re-create the same request/response/canary behavior inside the portal with MIT-portal theming. Verify each technique's exact tool contract (param names, methods) against its file in `agents/techniques/` during build.

### 4.2 Recon tells (so the router picks correctly with no hints)
The router keys off signals from `agents/red_team/router/recon.py`. The portal must expose them:
- IDOR → `/api/applications/<id>` is a **numbered sub-resource** returning another applicant's record.
- SSRF → `/preview` is a POST-only endpoint whose "missing field" error names a URL/link parameter.
- SQLi → `/login` is a POST-only form endpoint whose error reveals it builds SQL from input.
- Chain → `/api/reset-requests/<id>` is another numbered sub-resource leaking a token field.
- Real HTML pages with links/forms help `crawl_links` / `enumerate_forms` find the surface.

### 4.3 Fabricated portal content (what the browser shows)
- **Login page:** parody crest + fake-demo banner, username/password form.
- **Applicant dashboard (after login):** the logged-in applicant's fake profile — application status, a fake admission decision, a fake financial-aid award, uploaded "documents."
- **Application view (`/api/applications/<id>` rendered):** another applicant's record — the IDOR "stolen data" (fake PII, fake essay, fake decision).
- **Link-preview page:** a field to "preview an application link" (SSRF surface); the internal admin service returns fake internal admin notes.
- **Password-reset pages:** backs the chain (reset-request records + complete-reset).
- All data from `seed_data.py`, all obviously fake.

### 4.4 Benign traffic (for the no-false-positive demonstration)
- The portal must behave correctly for **legitimate** use so benign traffic produces benign log lines: correct-credential logins succeed; an applicant viewing **their own** application id logs `cross_owner=False result=SUCCESS`; a normal (external, allowed) link preview; reading one's own reset request.
- Benign traffic is generated by calling each featured technique's existing `perform_normal_action(target_url)` (real requests, real benign log lines) — plus a few portal-specific legit flows (a real successful login with seeded correct creds). The orchestrator interleaves these with the attack so the log stream looks alive.
- **Honesty:** benign lines are real benign requests; attack lines are real attack requests; blue classifies them blind. We never pre-label which is which for the highlight.

---

## 5. The visualizer (`demo/visualizer/`) — honest browser rendering

**Model:** the real agent run (HTTP, iterative) determines the real winning payload and real outcome. The visualizer then **re-enacts the agent's real payload through the portal UI** so it's visible. Because the portal's forms post to the same endpoints the agent hit, the UI action produces the identical real result. (Documented in `demo/README.md`.)

- `browser.py`: Playwright wrapper — open page, type a given string into a given field, submit, wait, screenshot. One generic "type payload → submit → show result" primitive.
- `mapping.py`: per technique, which page/field the winning payload goes into and what "stolen data" view to surface:
  - **SQLi** → `/login`, type payload into username → admin dashboard loads.
  - **IDOR** → application view, change the id → another applicant's record loads.
  - **SSRF** → preview field, paste internal URL → internal admin notes render.
  - **Chain** → reset-requests page shows the leaked admin token appearing, then complete-reset page shows the takeover + the fake protected data.

> Integrity: the payload the visualizer types is the agent's real one, read from the run (§6). Optionally show one or two of red's real failed attempts before the winning one, for authenticity.

---

## 6. The orchestrator (`demo/run_demo.py`)

1. Start `demo/portal/app.py`; confirm it's reachable + `/logs` works.
2. Run the **real, unmodified router battle** against the portal URL
   (`agents.red_team.router.battle_runner.run_router_battle(target_url, blue_analysis=True)`).
3. Capture, per decision: the router's chosen technique, red's real tool calls/payloads + results, the chain artifacts, and blue's assessment (detection + recommended_fix).
4. Feed captured events to `narration/demo_mode.py` (clean terminal blocks, §just like the agreed format) **and** to `visualizer/` (drive the browser with the real winning payload).
5. Blue's `defend_live_window` output (already produced by the battle with `blue_analysis=True`) is printed as the blue block.

> Verify during build: whether `run_router_battle` returns red's per-step payloads and chain artifacts in its result dict; if not, capture them from the portal's `/logs` (which records every request) rather than modifying agent code.

---

## 7. Build order (incremental — this is the deadline insurance)

Each checkpoint is a **shippable subset**. If time runs out, cut the video from the last completed checkpoint — never a broken state.

- **C0 — Portal skeleton:** Flask app, parody theme + banner, login/dashboard pages, `/logs` endpoint, `seed_data.py`. Verify in a browser.
- **C1 — Endpoints + canaries:** wire SQLi, IDOR, SSRF, chain endpoints with exact canaries (§4.1). Verify each with a raw `curl`/`requests` reproduction of the known winning payload.
- **C2 — Router picks right:** run `run_router_battle` (no visualizer yet). Confirm recon + router select IDOR/SQLi/SSRF correctly against the portal with no hints. Fix recon tells (§4.2) until it does. **Checkpoint: autonomy proven.**
- **C3 — SQLi browser-visual:** build `browser.py` + SQLi mapping. Watch the payload type into the login form and the admin dashboard load, driven by the real run. **First shippable video.**
- **C4 — SSRF + IDOR visual:** replicate the C3 pattern. **Three-technique shippable video.**
- **C5 — Chain:** wire the chain end-to-end (token_leak artifact → account_takeover) and its two-step visual. **Riskiest — see §8.**
- **C6 — Narration + log view:** `demo_mode.py` clean blocks; `log_view.py` live benign+attack log with blue-driven red highlighting (§4.4); `traffic/benign.py` interleaving real benign traffic. Verify benign lines stay unflagged (0 false positives) and attack lines light up red.
- **C7 — Reliability check + capture:** §9.
- **C8 — Edit to 2:00:** §10.

---

## 8. The chain (C5) — special handling

Mechanics (verified from code): `token_leak` reads `/api/reset-requests/<id>` (sequential, no auth), finds the admin record's `reset_token`, and surfaces it as `artifacts["reset_token"]`. The router folds that into `chain_context` and picks `account_takeover`, which POSTs the stolen token to `/account/complete-reset` → returns the chain canary.

- Chain steps were excluded from the training sweep and **can't win standalone** — they only work through the router's artifact hand-off. So the chain must be exercised via the **router battle**, not a pinned technique.
- **C5 is the one checkpoint allowed to fail.** If, after reasonable effort, the chain won't run reliably end-to-end, fall back: feature IDOR/SQLi/SSRF fully, and present the chain as a short "concept" beat (still real token_leak, shown surfacing the token) rather than the full takeover. Decide at C5, not on recording day.

---

## 9. Reliability check protocol (C7)

- Run the full `run_demo.py` flow **N≥10 times** per technique offline.
- Record: did the router pick correctly? did the attack succeed? did blue detect + give a correct fix? did the browser render cleanly?
- IDOR is the safe lead (blue ~100% fix). SQLi fix is ~75% — expect to re-roll some takes to catch a clean "parameterized queries" fix; that's fine (real, just selected).
- Only after a technique passes reliably do we capture its final footage.

---

## 10. Recording & edit (C8) — 2:00 structure

| time | beat |
|---|---|
| 0:00–0:15 | Portal in browser; fake-demo banner; "given only the URL, no hints" |
| 0:15–0:45 | **IDOR** full: recon → router reason → attack visible in UI → blue detect + fix |
| 0:45–1:10 | **SQLi + SSRF**, faster cuts |
| 1:10–1:45 | **Chain** climax (token leak → takeover) |
| 1:45–2:00 | Blue's correlated summary + takeaway: *autonomous triage & exploitation over a trained technique library* |

- Capture: browser window + terminal (demo-mode) side by side.
- Edit: time-lapse the model-inference waits so streams read as fast/confident; keep every decision + result beat.
- Retries are free (edited video, not livestream).

---

## 11. Dependencies & setup

- `demo/requirements-demo.txt`: `playwright` (+ `playwright install chromium`).
- Portal runs on a free local port (e.g. 5500) — not colliding with the 5001–5306 lab targets.
- Reuse the project venv (`venv311`) + `PYTHONPATH` to the repo root (so `agents`/`training` import).

---

## 12. Open items to verify DURING build (not blockers now)

1. Exact tool-call param names/methods per technique (read each `agents/techniques/*.py` at C1).
2. Whether `run_router_battle`'s return value exposes red's per-step payloads + chain artifacts, or whether we read them from `/logs` (C2/C6).
3. Whether the router reliably selects all four against the portal (C2) — the main autonomy risk.
4. Chain end-to-end reliability (C5/§8).
5. Blue fix-quality variance on SQLi live (C7 — mitigated by re-rolls).
```
```

---

*Fictional security demo. Not affiliated with, endorsed by, or representative of MIT.*
