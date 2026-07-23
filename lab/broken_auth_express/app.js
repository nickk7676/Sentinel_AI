/*
 * Deliberately vulnerable account service - Express/Node variant.
 *
 * Same exploitable broken authentication as lab/broken_auth/app.py:
 * session tokens are issued as a plain sequential counter (SESS-1000,
 * SESS-1001, ...) and GET /account accepts any token matching an issued
 * session with no binding to the original recipient (do not copy this
 * pattern anywhere else), reproduced on Express (Step 5). Token format and
 * startup sequencing (admin session pre-issued before any client logs in,
 * so it holds a lower counter value) are identical to
 * lab/broken_auth/app.py since agents/techniques/broken_auth.py's
 * red-team prompt hardcodes both.
 */

const express = require("express");

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const CANARY = "SENTINELAI-BROKENAUTH-CANARY-e2f7a1d9";
const COUNTER_START = 1000;
let nextCounter = COUNTER_START;
const ACTIVE_SESSIONS = new Map(); // token -> {username, isAdmin, notes}

let logBuffer = "";
function log(line) {
  logBuffer += `${new Date().toISOString()} ${line}\n`;
}

function issueSession(username, isAdmin, notes) {
  const token = `SESS-${nextCounter}`;
  nextCounter += 1;
  ACTIVE_SESSIONS.set(token, { username, isAdmin, notes });
  return token;
}

// Simulates an administrator logging in during application startup, before
// any external client connects - the vulnerable part is that the resulting
// token is just the next sequential counter value.
issueSession("admin", true, `Admin private notes: ${CANARY}`);

app.post("/login", (req, res) => {
  const username = (req.body && req.body.username) || "guest";
  const token = issueSession(username, false, "No notes.");
  log(`LOGIN username=${JSON.stringify(username)} issued_token=${JSON.stringify(token)}`);
  res.status(200).json({ status: "success", session_token: token });
});

app.get("/account", (req, res) => {
  const authHeader = req.headers["authorization"] || "";
  const token = authHeader.replace(/^Bearer\s+/i, "").trim() || req.query.session_token || "";

  // Deliberately vulnerable: any token matching an issued session is
  // accepted, with no check that it was issued to this requester.
  const session = ACTIVE_SESSIONS.get(token);
  log(`ACCOUNT_ACCESS token=${JSON.stringify(token)} found=${!!session} is_admin=${!!(session && session.isAdmin)}`);

  if (!session) {
    return res.status(401).json({ status: "fail", message: "invalid session" });
  }

  res.status(200).json({
    status: "success",
    username: session.username,
    is_admin: session.isAdmin,
    notes: session.notes,
  });
});

app.get("/logs", (req, res) => {
  const since = parseInt(req.query.since || "0", 10);
  res.json({ lines: logBuffer.slice(since), offset: logBuffer.length });
});

app.get("/healthz", (req, res) => {
  res.status(200).send("ok");
});

app.listen(5000, "0.0.0.0", () => {
  console.log("broken_auth express target listening on 5000");
});
