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
2. **Verify the db path end-to-end** — `Optional<Model>` return for `query_one`
   misses ✅ done; the db-feature build compiles (Windows uses `schannel`, no
   OpenSSL); `uid()` now works in `server fn`s (server-side builtin) ✅.
   ✅ **Proven against a live Neon Postgres** with the compiled `xeres` binary
   (`--features full`): `examples/login_db.xrs` register (insert + Argon2 hash),
   login (typed-`let` fetch + `verify`), wrong-password and no-user paths all
   correct. Also fixed `return db.exec(...)` routing in the interpreter. (Local
   db builds need MinGW `dlltool` or MSVC; CI release binaries bundle it.) See
   [`examples/users.xrs`](examples/users.xrs), [`examples/login_db.xrs`](examples/login_db.xrs).
3. **Sync hardening** — field-level merge (CRDT / cr-sqlite) instead of
   row-level last-write-wins.
4. ~~**`for` over `List<T>`** in views (not just synced collections).~~ ✅ done
   (array loops key per-item handlers by index; synced collections by `id`).
5. ~~**List/Optional inside RPC arguments**~~ ✅ done — a recursive JSON decoder
   handles `List<T>`, `Optional<T>`, nested models and any nesting, in both the
   generated Rust and the `xeres serve` interpreter.
6. **Auth primitives** — server-only `hash()` / `verify()` (Argon2id) ✅ done
   (rule R19; `examples/login_db.xrs`). Remaining: session tokens (a
   `declassify`d secret), TLS story for the app server.
7. **Distribution** — npm `xeres` wrapper + per-platform release workflow built
   (see [RELEASING.md](RELEASING.md)); remaining: actually publish to npm + cut
   a tagged release.
8. ~~**Self-contained runtime**~~ ✅ done — `xeres serve` runs apps via an
   interpreter + in-process server, no `cargo`. (`xeres build` remains for
   eject/max-perf.) Together with (7), a dev needs only Node + the `xeres`
   binary — no git, no Rust.
10. ~~**Control flow in functions**~~ ✅ done — statement `if`/`else`, `for x in
   list`, `for i in 0..n`, `while`, `break`/`continue` in `fn` bodies + ui
   handlers (Rust + TS + interpreter). Functions can finally express algorithms
   (a fn body previously had no loops or statement branching). Next language
   foundations: extended primitives (`Date`/`Decimal`/`Enum`), then a stdlib.
9. ~~**View & component layer**~~ ✅ done — inline `style "<css>"` (full-bleed
   when a screen styles its root), conditional expression `cond ? a : b`,
   layout/text primitives (`grid`, `box`, `subheading`, `title`, `paragraph`),
   and reusable **`ui component`s** invoked by a Capitalized tag. New
   compiler-enforced rules: **R17** (component) and **R18** (conditional-branch
   type agreement); **R2** broadened to screen/component names. Components are
   browser-tier only and the secret/scope rules apply inside their views, so
   they don't widen the tier boundary. Drove the `dashboard` + `acme` reference
   apps (dogfooding).

## Later
- `enum`s; the `Tainted`/information-flow layer (the `declassify` keyword
  already reserves the surface).
- LSP (inline R-rule diagnostics in editors), `xeres fmt`.
- More databases behind the same `db` API (MySQL, SQL Server, Oracle).
- Real SQLite (cr-sqlite) for the on-device store.

## Dogfooding (alongside, not after)
Build one real reference app in Xeres — an auth'd notes/todo — as the proof and
the gap-finder. Real screens drive feature priorities (every one so far has).
