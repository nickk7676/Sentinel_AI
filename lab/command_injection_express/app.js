/*
 * Deliberately vulnerable network diagnostics service - Express/Node variant.
 *
 * Same exploitable OS command injection on POST /diagnostics as
 * lab/command_injection/app.py (unsanitized input concatenated into a
 * shell command - do not copy this pattern anywhere else), reproduced on
 * Node's child_process instead of Python's subprocess, to prove red/blue
 * generalize past one specific runtime (Step 5). Same request/response
 * contract as lab/command_injection so
 * agents/techniques/command_injection.py works against this unmodified.
 */

const express = require("express");
const { exec } = require("child_process");
const fs = require("fs");

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const CANARY_PATH = "/tmp/canary.txt";
const CANARY = "SENTINELAI-CMDI-CANARY-7f3a9c2e";
fs.writeFileSync(CANARY_PATH, CANARY + "\n");

let logBuffer = "";
function log(line) {
  logBuffer += `${new Date().toISOString()} ${line}\n`;
}

app.post("/diagnostics", (req, res) => {
  const target = (req.body && req.body.target) || "";

  // Deliberately vulnerable: unsanitized input interpolated into a shell
  // command, so shell metacharacters (; && | ` $()) let an attacker chain
  // in arbitrary additional commands.
  const cmd = `echo Diagnostic check for: ${target}`;

  exec(cmd, { timeout: 5000 }, (error, stdout, stderr) => {
    const output = (stdout || "") + (stderr || "");
    log(`DIAGNOSTICS_REQUEST target=${JSON.stringify(target)} cmd=${JSON.stringify(cmd)} error=${JSON.stringify(error && error.message)} canary_leaked=${output.includes(CANARY)}`);
    res.status(200).json({ status: "ok", output, error: error ? error.message : null });
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
  console.log("command_injection express target listening on 5000");
});
