/*
 * Deliberately vulnerable support-ticket service - Express/Node variant.
 *
 * Same exploitable IDOR (broken object-level authorization) on GET
 * /api/tickets/:id as lab/idor/app.py (no ownership check - do not copy
 * this pattern anywhere else), reproduced with a stateless signed JWT
 * session instead of the Flask target's opaque server-side token map, to
 * prove red/blue generalize past one specific auth mechanism (Step 5).
 * Ticket ids/owners and CANARY placement are identical to lab/idor/app.py
 * since agents/techniques/idor.py's red-team prompt hardcodes "the account
 * legitimately owns tickets 1 and 3."
 */

const express = require("express");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const CANARY = "SENTINELAI-IDOR-CANARY-4b8e1f0a";
const JWT_SECRET = crypto.randomBytes(32).toString("hex");

const TICKETS = {
  1: { owner_id: 1, subject: "Can't reset my password", body: "I tried the reset link but it expired, please help." },
  2: { owner_id: 2, subject: "Billing dispute", body: `My last invoice looks wrong, can someone check? Account notes: ${CANARY}` },
  3: { owner_id: 1, subject: "Feature request", body: "Would be great to have dark mode." },
};

let logBuffer = "";
function log(line) {
  logBuffer += `${new Date().toISOString()} ${line}\n`;
}

app.post("/login", (req, res) => {
  const token = jwt.sign({ user_id: 1 }, JWT_SECRET, { expiresIn: "1h" });
  log(`LOGIN_ISSUED token=${JSON.stringify(token)} user_id=1`);
  res.status(200).json({ status: "success", session_token: token, user_id: 1 });
});

app.get("/api/tickets/:id", (req, res) => {
  const ticketId = parseInt(req.params.id, 10);
  const authHeader = req.headers["authorization"] || "";
  const token = authHeader.replace(/^Bearer\s+/i, "").trim();

  let requesterId = null;
  try {
    requesterId = jwt.verify(token, JWT_SECRET).user_id;
  } catch (e) {
    requesterId = null;
  }

  if (requesterId === null) {
    log(`TICKET_ACCESS ticket_id=${ticketId} token=${JSON.stringify(token)} result=UNAUTHENTICATED`);
    return res.status(401).json({ status: "fail", message: "invalid or missing session token" });
  }

  const ticket = TICKETS[ticketId];
  if (!ticket) {
    log(`TICKET_ACCESS ticket_id=${ticketId} requester_id=${requesterId} result=NOT_FOUND`);
    return res.status(404).json({ status: "fail", message: "ticket not found" });
  }

  // Deliberately vulnerable: no check that ticket.owner_id === requesterId.
  log(`TICKET_ACCESS ticket_id=${ticketId} requester_id=${requesterId} owner_id=${ticket.owner_id} cross_owner=${requesterId !== ticket.owner_id} result=SUCCESS`);
  res.status(200).json({ status: "success", ticket_id: ticketId, ...ticket });
});

app.get("/logs", (req, res) => {
  const since = parseInt(req.query.since || "0", 10);
  res.json({ lines: logBuffer.slice(since), offset: logBuffer.length });
});

app.get("/healthz", (req, res) => {
  res.status(200).send("ok");
});

app.listen(5000, "0.0.0.0", () => {
  console.log("idor express target listening on 5000");
});
