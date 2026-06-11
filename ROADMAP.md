# Xeres — Roadmap

## Vision
A tier-safe web language. One `.xrs` file compiles to two tiers — a Rust server
and a browser bundle — under one type system. The server/client boundary is
enforced by the **compiler**, not by convention: secrets and server
capabilities physically cannot reach the browser. Local-first by default. Zero
framework runtime in the browser.

## v0.1.0 — shipped
See [CHANGELOG.md](CHANGELOG.md) for the full list. Highlights:
- Compiler (lexer, parser, checker **R1–R16**, codegen) with a 35-fixture suite
  wired into `cargo test` + CI.
- The boundary: `secret` containment at type *and* wire level, `declassify`,
  `await` RPC, server-only `db` capability.
- Views (`state`, `bind`, `for`, `if/else`, handlers), local-first synced
  collections with a real sync round-trip, `try/catch`, `List<T>`/`Optional<T>`,
  model-typed RPC args, Postgres (`query_one`/`query`/`exec`, TLS-capable).
- `create-xeres` scaffolder; generated apps are zero-dependency unless `db`
  is used.

## v0.2 — next
1. ~~**`xeres dev`** — watch + rebuild + serve in one command.~~ ✅ done
   (also: `.env` config loaded into the server; `create-xeres` scaffolds it).
2. **Verify the db path end-to-end** — full toolchain (binutils/MSVC) + a live
   Postgres; `Optional<Model>` return for `query_one` misses.
3. **Sync hardening** — field-level merge (CRDT / cr-sqlite) instead of
   row-level last-write-wins.
4. **`for` over `List<T>`** in views (not just synced collections).
5. **List/Optional inside RPC arguments** (currently default server-side).
6. **Auth primitives** — session tokens (a `declassify`d secret), TLS story
   for the app server.
7. **Distribution** — machinery built (npm `xeres` wrapper + per-platform
   release workflow, see [RELEASING.md](RELEASING.md)); remaining: actually
   publish to npm + cut a tagged release, then the self-contained runtime so
   generated apps don't need `cargo`.

## Later
- `enum`s; the `Tainted`/information-flow layer (the `declassify` keyword
  already reserves the surface).
- LSP (inline R-rule diagnostics in editors), `xeres fmt`.
- More databases behind the same `db` API (MySQL, SQL Server, Oracle).
- Real SQLite (cr-sqlite) for the on-device store.

## Dogfooding (alongside, not after)
Build one real reference app in Xeres — an auth'd notes/todo — as the proof and
the gap-finder. Real screens drive feature priorities (every one so far has).
