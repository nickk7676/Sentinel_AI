/*
 * Deliberately vulnerable login service - Express/Node + SQLite variant.
 *
 * Same exploitable SQL injection on POST /login as lab/target/app.py (raw
 * string interpolation into the query, no parameterization - do not copy
 * this pattern anywhere else), reproduced on a different framework/DB/auth
 * stack (Express + better-sqlite3, express-session cookies instead of the
 * Flask target's stateless login) to prove red/blue generalize past one
 * specific app (Step 5). Same request/response contract as lab/target so
 * agents/techniques/sql_injection.py works against this unmodified.
 */

const express = require("express");
const session = require("express-session");
const Database = require("better-sqlite3");
const crypto = require("crypto");

const app = express();
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(session({ secret: crypto.randomBytes(16).toString("hex"), resave: false, saveUninitialized: true }));

const SEEDED_USER = "admin";
const SEEDED_PASSWORD = crypto.randomBytes(9).toString("base64url");

const db = new Database(":memory:");
db.exec("CREATE TABLE users (username TEXT, password TEXT)");
db.prepare("INSERT INTO users VALUES (?, ?)").run(SEEDED_USER, SEEDED_PASSWORD);

let logBuffer = "";
function log(line) {
  logBuffer += `${new Date().toISOString()} ${line}\n`;
}

app.post("/login", (req, res) => {
  const username = req.body.username || "";
  const password = req.body.password || "";

  // Deliberately vulnerable: raw string interpolation, no parameterization.
  const query = `SELECT username FROM users WHERE username = '${username}' AND password = '${password}'`;

  let row = null;
  let error = null;
  try {
    row = db.prepare(query).get();
  } catch (exc) {
    error = String(exc.message || exc);
  }

  log(`LOGIN_ATTEMPT username=${JSON.stringify(username)} password=${JSON.stringify(password)} query=${JSON.stringify(query)} error=${JSON.stringify(error)} result=${row ? "MATCH" : "NO_MATCH"}`);

  if (row) {
    req.session.username = row.username;
    log(`LOGIN_SUCCESS username=${JSON.stringify(username)} matched_user=${JSON.stringify(row.username)}`);
    return res.status(200).json({ status: "success", message: `Welcome ${row.username}` });
  }

  log(`LOGIN_FAIL username=${JSON.stringify(username)}`);
  return res.status(401).json({ status: "fail", message: "Invalid credentials" });
});

app.get("/logs", (req, res) => {
  const since = parseInt(req.query.since || "0", 10);
  const newContent = logBuffer.slice(since);
  res.json({ lines: newContent, offset: logBuffer.length });
});

app.get("/healthz", (req, res) => {
  res.status(200).send("ok");
});

app.listen(5000, "0.0.0.0", () => {
  console.log("sql_injection express target listening on 5000");
});
