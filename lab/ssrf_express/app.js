/*
 * Deliberately vulnerable link-preview service - Express/Node variant.
 *
 * Same exploitable SSRF on POST /preview as lab/ssrf/app.py (no host/IP
 * allowlist on the server-side fetch - do not copy this pattern anywhere
 * else), reproduced on Express/Node's http/https core modules instead of
 * Python's requests (Step 5) - NOT Node's global fetch(), which silently
 * rejects port 6000 as a spec-mandated "forbidden port" (historically
 * reserved for X11) regardless of any application logic, which would mask
 * the very vulnerability this target exists to demonstrate. A second,
 * internal-only HTTP server on 127.0.0.1:6000 (never published) is
 * identical to lab/ssrf/app.py's, since agents/techniques/ssrf.py's
 * red-team prompt hardcodes the exact internal URL
 * "http://127.0.0.1:6000/admin-metadata", and normal-traffic battles
 * hardcode "http://127.0.0.1:5000/welcome" on the main app.
 */

const express = require("express");
const http = require("http");
const https = require("https");

const CANARY = "SENTINELAI-SSRF-CANARY-9d21ab6f";
const INTERNAL_HOST = "127.0.0.1";
const INTERNAL_PORT = 6000;

let logBuffer = "";
function log(line) {
  logBuffer += `${new Date().toISOString()} ${line}\n`;
}

// Internal-only admin API - bound to loopback, never published by
// docker-compose, only reachable from the main app's own server-side fetch.
const internalServer = http.createServer((req, res) => {
  if (req.url === "/admin-metadata") {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ role: "admin", notes: CANARY }));
  } else {
    res.writeHead(404);
    res.end();
  }
});
internalServer.listen(INTERNAL_PORT, INTERNAL_HOST, () => {
  console.log(`internal admin API listening on ${INTERNAL_HOST}:${INTERNAL_PORT}`);
});

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.get("/welcome", (req, res) => {
  res.json({ message: "Welcome to the link-preview service." });
});

function fetchUrl(url) {
  return new Promise((resolve) => {
    try {
      const client = url.startsWith("https:") ? https : http;
      const req = client.get(url, { timeout: 5000 }, (resp) => {
        let body = "";
        resp.on("data", (chunk) => {
          if (body.length < 2000) body += chunk.toString();
        });
        resp.on("end", () => resolve({ statusCode: resp.statusCode, content: body.slice(0, 2000), error: null }));
      });
      req.on("timeout", () => req.destroy(new Error("timeout")));
      req.on("error", (exc) => resolve({ statusCode: null, content: "", error: String(exc.message || exc) }));
    } catch (exc) {
      resolve({ statusCode: null, content: "", error: String(exc.message || exc) });
    }
  });
}

app.post("/preview", async (req, res) => {
  const url = (req.body && req.body.url) || "";

  // Deliberately vulnerable: no host/IP allowlist on the server-side
  // fetch, so an attacker-supplied URL can reach internal-only services.
  const { statusCode, content, error } = await fetchUrl(url);

  log(`PREVIEW_REQUEST url=${JSON.stringify(url)} status=${statusCode} error=${JSON.stringify(error)} canary_leaked=${content.includes(CANARY)}`);
  res.status(200).json({ url, status_code: statusCode, content, error });
});

app.get("/logs", (req, res) => {
  const since = parseInt(req.query.since || "0", 10);
  res.json({ lines: logBuffer.slice(since), offset: logBuffer.length });
});

app.get("/healthz", (req, res) => {
  res.status(200).send("ok");
});

app.listen(5000, "0.0.0.0", () => {
  console.log("ssrf express target listening on 5000");
});
