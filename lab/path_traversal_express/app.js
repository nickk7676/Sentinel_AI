/*
 * Deliberately vulnerable report-download service - Express/Node variant.
 *
 * Same exploitable path traversal on GET /download as
 * lab/path_traversal/app.py (the `file` query param is joined onto the
 * reports directory with no normalization/allowlist check - do not copy
 * this pattern anywhere else), reproduced on Node's fs/path modules
 * instead of Python's os.path (Step 5). Directory layout (a sibling
 * "secret" dir next to "reports", holding canary.txt) is identical to
 * lab/path_traversal/app.py since agents/techniques/path_traversal.py's
 * red-team prompt hardcodes the exact payload shape "../<dir>/<canary
 * filename>" against a short list of candidate directory names that
 * includes "secret".
 */

const express = require("express");
const fs = require("fs");
const path = require("path");

const app = express();

const BASE_DIR = "/tmp/lab_path_traversal_express";
const REPORTS_DIR = path.join(BASE_DIR, "reports");
const SECRET_DIR = path.join(BASE_DIR, "secret");
const CANARY = "SENTINELAI-PATHTRAV-CANARY-c19d6b3e";

fs.mkdirSync(REPORTS_DIR, { recursive: true });
fs.mkdirSync(SECRET_DIR, { recursive: true });
fs.writeFileSync(path.join(REPORTS_DIR, "report1.txt"), "Q1 sales report: revenue up 4% quarter over quarter.\n");
fs.writeFileSync(path.join(REPORTS_DIR, "readme.txt"), "This directory contains quarterly report exports.\n");
fs.writeFileSync(path.join(SECRET_DIR, "canary.txt"), CANARY + "\n");

let logBuffer = "";
function log(line) {
  logBuffer += `${new Date().toISOString()} ${line}\n`;
}

app.get("/download", (req, res) => {
  const filename = req.query.file || "";

  // Deliberately vulnerable: naive join, no normalization or allowlist
  // check, so "../" sequences in `filename` escape REPORTS_DIR.
  const resolvedPath = path.join(REPORTS_DIR, filename);

  let content = "";
  let status = 200;
  let error = null;
  try {
    content = fs.readFileSync(resolvedPath, "utf8");
  } catch (exc) {
    content = "";
    status = 404;
    error = exc.message;
  }

  const escaped = !path.resolve(resolvedPath).startsWith(path.resolve(REPORTS_DIR));
  log(`DOWNLOAD_REQUEST file=${JSON.stringify(filename)} resolved_path=${JSON.stringify(resolvedPath)} status=${status} escaped=${escaped}`);

  res.status(status).json({ filename, content, error });
});

app.get("/logs", (req, res) => {
  const since = parseInt(req.query.since || "0", 10);
  res.json({ lines: logBuffer.slice(since), offset: logBuffer.length });
});

app.get("/healthz", (req, res) => {
  res.status(200).send("ok");
});

app.listen(5000, "0.0.0.0", () => {
  console.log("path_traversal express target listening on 5000");
});
