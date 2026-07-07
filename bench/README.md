# Xeres performance harness (spec 30)

Makes "we are fast" a tracked number. Run it from the repo root after a
`cargo build --release`.

```
node bench/run.mjs                    # compile-time + gzipped bundle size, diffed vs baseline
node bench/run.mjs --server           # + live cold-start / throughput / resident memory
node bench/run.mjs --update-baseline  # record the current run as the new baseline
```

## What it measures

| Metric | How | Determinism |
|---|---|---|
| **Compile throughput** | `xeres build <example>` wall-time (best of 5) + lines/sec | noisy — ~40 ms process-startup floor dominates the small apps |
| **Client bundle size** | esbuild the generated `client.ts` (same flags the compiler uses), gzip it | deterministic — byte-stable |
| **Server cold start** | spawn `xeres serve bench/app.xrs`, time spawn → first `200` | machine-dependent |
| **Request throughput** | keep-alive load on an RPC (`/__xeres/ping`) + an `api` route (`GET /api/bench/ping`) | machine-dependent |
| **Resident memory** | best-effort RSS of the serve process (`tasklist`/`ps`) | machine-dependent |

## Files

- `run.mjs` — the harness (Node stdlib only; esbuild via `npx`, the compiler's own bundler).
- `app.xrs` — the throughput workload (a `ping()` RPC + a `GET /api/bench/ping` route).
- `baseline.json` — the committed regression baseline (**compile-time + bundle only** — the
  deterministic metrics). Server numbers are machine-specific and reported in the run output /
  README, not gated.
- `results-*.json` — per-run output (gitignored).

## The regression gate

Advisory, never fails a build. It flags a bundle regression **>10 %** (bundle size is
deterministic, so a real change is meaningful) or a compile regression **>40 %** (compile time
is startup-jittery, so the gate is loose to avoid false alarms). Update the baseline deliberately
with `--update-baseline` when a change legitimately moves the numbers.
