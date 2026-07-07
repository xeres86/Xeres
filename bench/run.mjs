// Xeres performance harness (spec 30) — makes "we are fast" a tracked number.
//
// Two always-on, deterministic, cross-platform metrics over every example:
//   1. Compiler throughput  — `xeres build` wall-time + lines/sec
//   2. Client bundle size   — gzipped `client.js` (the zero-framework proof)
//
// Plus an opt-in `--server` mode (spawns the real server on bench/app.xrs):
//   3. Server cold start    — spawn -> first 200 (ms)
//   4. Request throughput   — req/s on an RPC + an `api` route
//   (+ best-effort resident memory of the serve process)
//
// No runtime deps — Node stdlib only (esbuild is already the client bundler).
//
// Usage:
//   node bench/run.mjs                  compile + bundle metrics, diff vs baseline
//   node bench/run.mjs --server         also run the live-server metrics
//   node bench/run.mjs --update-baseline   write current results as the baseline
//
// Exit code is 0 even on a regression (advisory gate, per spec) — a run only
// fails on a real error (a build that won't compile, a server that won't boot).

import { execFileSync, execSync, spawn } from "node:child_process";
import { gzipSync } from "node:zlib";
import http from "node:http";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const BENCH = path.join(ROOT, "bench");
const XERES = path.join(ROOT, "target", "release", process.platform === "win32" ? "xeres.exe" : "xeres");
const BASELINE = path.join(BENCH, "baseline.json");

// Per-metric regression thresholds (advisory — never fails CI). Bundle size is
// deterministic (esbuild output is byte-stable), so a tight gate is meaningful.
// Compile time is startup-dominated (~40ms process floor) and jittery on a
// shared/Windows runner, so it needs a looser gate to avoid crying wolf.
const REGRESS_BUNDLE_PCT = 10;
const REGRESS_COMPILE_PCT = 40;

// The example apps we track. Order = report order.
const EXAMPLES = [
  "examples/counter.xrs",
  "examples/todo.xrs",
  "examples/router.xrs",
  "examples/dashboard.xrs",
  "examples/acme.xrs",
  "examples/weather.xrs",
  "examples/theme_demo.xrs",
];

const args = process.argv.slice(2);
const WITH_SERVER = args.includes("--server");
const UPDATE_BASELINE = args.includes("--update-baseline");

function ensureBinary() {
  if (!fs.existsSync(XERES)) {
    console.error(`error: ${path.relative(ROOT, XERES)} not found — run \`cargo build --release\` first.`);
    process.exit(1);
  }
}

// Non-blank source lines of an .xrs file (the throughput denominator).
function locOf(file) {
  const src = fs.readFileSync(path.join(ROOT, file), "utf8");
  return src.split("\n").filter((l) => l.trim().length > 0).length;
}

// Compile `file` a few times, returning the best (least-noisy) wall-time in ms.
function compileMs(file, iters = 5) {
  let best = Infinity;
  for (let i = 0; i < iters; i++) {
    const t0 = process.hrtime.bigint();
    execFileSync(XERES, ["build", file], { cwd: ROOT, stdio: "ignore" });
    const ms = Number(process.hrtime.bigint() - t0) / 1e6;
    if (ms < best) best = ms;
  }
  return best;
}

// Bundle the just-built client.ts exactly as `xeres serve` does (esbuild,
// --bundle --format=esm, no minify) and return { raw, gz } byte sizes. Returns
// null when a build produced no client (e.g. a screen-less app).
function bundleBytes() {
  const clientTs = path.join(ROOT, "out", "server", "static", "client.ts");
  if (!fs.existsSync(clientTs)) return null;
  const out = path.join(os.tmpdir(), `xeres-bench-${process.pid}.js`);
  // Single command string (not execFile + args + shell) so Node doesn't warn
  // about un-escaped args under shell:true. Paths are quoted; the compiler's
  // own bundler uses this exact esbuild invocation (main.rs `bundle()`).
  execSync(`npx --yes esbuild "${clientTs}" --bundle --format=esm --outfile="${out}"`, {
    cwd: ROOT,
    stdio: "ignore",
  });
  const js = fs.readFileSync(out);
  fs.rmSync(out, { force: true });
  return { raw: js.length, gz: gzipSync(js).length };
}

function measureExamples() {
  const results = {};
  for (const ex of EXAMPLES) {
    process.stdout.write(`  building ${ex} ... `);
    const loc = locOf(ex);
    const ms = compileMs(ex);
    const bundle = bundleBytes();
    results[ex] = {
      loc,
      compile_ms: round(ms),
      lines_per_sec: Math.round((loc / ms) * 1000),
      bundle_raw: bundle?.raw ?? null,
      bundle_gz: bundle?.gz ?? null,
    };
    console.log(`${round(ms)}ms  bundle ${bundle ? fmtBytes(bundle.gz) + " gz" : "—"}`);
  }
  return results;
}

// ---- live-server metrics (--server) ---------------------------------------

function get(port, { method = "GET", path: p = "/", body = null, headers = {} }) {
  return new Promise((resolve) => {
    const t0 = process.hrtime.bigint();
    const req = http.request({ host: "127.0.0.1", port, path: p, method, headers, agent }, (res) => {
      let n = 0;
      res.on("data", (c) => (n += c.length));
      res.on("end", () =>
        resolve({ ms: Number(process.hrtime.bigint() - t0) / 1e6, status: res.statusCode, bytes: n, headers: res.headers })
      );
    });
    req.on("error", () => resolve({ ms: 0, status: 0, bytes: 0, headers: {} }));
    if (body != null) req.write(body);
    req.end();
  });
}
const agent = new http.Agent({ keepAlive: true, maxSockets: 64, maxFreeSockets: 64 });

async function waitForBoot(port, timeoutMs = 60000) {
  const t0 = Date.now();
  for (;;) {
    const r = await get(port, { path: "/" }).catch(() => ({ status: 0 }));
    if (r.status === 200) return Date.now() - t0;
    if (Date.now() - t0 > timeoutMs) return null;
    await sleep(50);
  }
}

// Best-effort resident set size (KB) of a pid — platform-specific, advisory.
function residentKb(pid) {
  try {
    if (process.platform === "win32") {
      const out = execFileSync("tasklist", ["/FI", `PID eq ${pid}`, "/FO", "CSV", "/NH"], { encoding: "utf8" });
      const m = out.match(/"([\d.,]+) K"/);
      return m ? Math.round(Number(m[1].replace(/[.,]/g, "")) ) : null;
    }
    const out = execFileSync("ps", ["-o", "rss=", "-p", String(pid)], { encoding: "utf8" });
    return Number(out.trim()) || null;
  } catch {
    return null;
  }
}

async function throughput(port, make, durMs = 5000, conc = 32) {
  const lat = [];
  let ok = 0;
  const deadline = Date.now() + durMs;
  const worker = async () => {
    while (Date.now() < deadline) {
      const r = await get(port, make());
      if (r.status === 200) { ok++; lat.push(r.ms); }
    }
  };
  const t0 = Date.now();
  await Promise.all(Array.from({ length: conc }, worker));
  const secs = (Date.now() - t0) / 1000;
  lat.sort((a, b) => a - b);
  return {
    req_per_sec: Math.round(ok / secs),
    p50_ms: round(pct(lat, 50)),
    p99_ms: round(pct(lat, 99)),
  };
}

async function measureServer() {
  const port = 8079;
  console.log(`\n  spawning \`xeres serve bench/app.xrs\` on :${port} ...`);
  const proc = spawn(XERES, ["serve", "bench/app.xrs"], {
    cwd: ROOT,
    env: { ...process.env, PORT: String(port) },
    stdio: "ignore",
  });
  try {
    const coldMs = await waitForBoot(port);
    if (coldMs == null) throw new Error("server did not become ready within 60s");
    const rss = residentKb(proc.pid);

    // Warm one request to grab the CSRF token for the RPC path.
    const warm = await get(port, { path: "/" });
    const csrf = ((warm.headers["set-cookie"] || []).join(";").match(/xeres_csrf=([^;]+)/) || [])[1] || "";
    const rpcHeaders = (json) => ({
      "Content-Type": "application/json",
      "Content-Length": Buffer.byteLength(json),
      Cookie: `xeres_csrf=${csrf}`,
      "X-CSRF-Token": csrf,
    });

    const rpc = await throughput(port, () => ({ method: "POST", path: "/__xeres/ping", body: "[]", headers: rpcHeaders("[]") }));
    const api = await throughput(port, () => ({ path: "/api/bench/ping" }));

    return {
      cold_start_ms: round(coldMs),
      resident_kb: rss,
      rpc_ping: rpc,
      api_ping: api,
    };
  } finally {
    proc.kill();
  }
}

// ---- helpers ---------------------------------------------------------------

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const round = (n) => Math.round(n * 100) / 100;
function pct(sorted, p) {
  if (!sorted.length) return 0;
  return sorted[Math.min(sorted.length - 1, Math.floor((p / 100) * sorted.length))];
}
function fmtBytes(n) {
  if (n == null) return "—";
  return n < 1024 ? `${n}B` : `${(n / 1024).toFixed(1)}kb`;
}
function pctDelta(now, base) {
  if (base == null || now == null || base === 0) return null;
  return ((now - base) / base) * 100;
}

// Compare vs baseline; print a per-metric delta and flag regressions.
function diffBaseline(results) {
  if (!fs.existsSync(BASELINE)) {
    console.log("\nno baseline — run `node bench/run.mjs --update-baseline` to record one.");
    return;
  }
  const base = JSON.parse(fs.readFileSync(BASELINE, "utf8"));
  console.log("\n  vs baseline (compile time / gz bundle — + is worse):");
  let regressions = 0;
  for (const ex of EXAMPLES) {
    const b = base.examples?.[ex];
    const r = results.examples[ex];
    if (!b || !r) continue;
    const dMs = pctDelta(r.compile_ms, b.compile_ms);
    const dGz = pctDelta(r.bundle_gz, b.bundle_gz);
    const flags = [];
    if (dMs != null && dMs > REGRESS_COMPILE_PCT) { flags.push("compile"); regressions++; }
    if (dGz != null && dGz > REGRESS_BUNDLE_PCT) { flags.push("bundle"); regressions++; }
    console.log(
      `    ${ex.padEnd(28)} compile ${fmtPct(dMs)}   bundle ${fmtPct(dGz)}` +
      (flags.length ? `   ⚠ ${flags.join(", ")}` : "")
    );
  }
  console.log(
    regressions
      ? `\n  ⚠ ${regressions} metric(s) regressed (>${REGRESS_BUNDLE_PCT}% bundle / >${REGRESS_COMPILE_PCT}% compile — advisory, not a build failure).`
      : `\n  ✓ no regression (>${REGRESS_BUNDLE_PCT}% bundle / >${REGRESS_COMPILE_PCT}% compile).`
  );
}
function fmtPct(d) {
  if (d == null) return "  n/a ";
  const s = `${d >= 0 ? "+" : ""}${d.toFixed(1)}%`;
  return s.padStart(7);
}

// ---- main ------------------------------------------------------------------

ensureBinary();
console.log(`Xeres perf harness — ${new Date().toISOString()}`);
console.log(`  compiler: ${path.relative(ROOT, XERES)}\n`);

const results = { generated: new Date().toISOString(), platform: `${process.platform}-${process.arch}`, examples: measureExamples() };

if (WITH_SERVER) {
  results.server = await measureServer();
  const s = results.server;
  console.log(
    `\n  cold start ${s.cold_start_ms}ms   resident ${s.resident_kb ? (s.resident_kb / 1024).toFixed(1) + "MB" : "—"}\n` +
    `  RPC ping()          ${String(s.rpc_ping.req_per_sec).padStart(7)} req/s  p50 ${s.rpc_ping.p50_ms}ms  p99 ${s.rpc_ping.p99_ms}ms\n` +
    `  api GET /ping       ${String(s.api_ping.req_per_sec).padStart(7)} req/s  p50 ${s.api_ping.p50_ms}ms  p99 ${s.api_ping.p99_ms}ms`
  );
}

diffBaseline(results);

const stamp = results.generated.replace(/[:.]/g, "-");
const outFile = path.join(BENCH, `results-${stamp}.json`);
fs.writeFileSync(outFile, JSON.stringify(results, null, 2) + "\n");
console.log(`\nwrote ${path.relative(ROOT, outFile)}`);

if (UPDATE_BASELINE) {
  fs.writeFileSync(BASELINE, JSON.stringify(results, null, 2) + "\n");
  console.log(`updated ${path.relative(ROOT, BASELINE)}`);
}
