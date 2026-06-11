# Xeres — Roadmap to v0.1

## Vision
A tier-safe web language. One `.xrs` file compiles to two tiers — a Rust server
and a browser bundle — under one type system. The server/client boundary is
enforced by the **compiler**, not by convention: secrets and server
capabilities physically cannot reach the browser. Local-first by default. Zero
framework runtime in the browser.

## Done
- **Compiler** (Rust): lexer, parser, checker (rules R1–R14), codegen.
- **Boundary**: `server`/`ui`/`shared`, `secret` fields, `declassify`, `await`
  for UI→server RPC, wire-level secret stripping.
- **Data**: `model`, record construction, client `state`, `synced state`
  collections + a real sync round-trip (server merge + reactive pull).
- **Views**: `column`/`row`/`heading`/`text`/`button`/`input`/`password`,
  `bind`, `for`, `if`/`else`.
- **Interactivity**: handlers, collection `add`/`remove`, per-item delete,
  reactive rendering.
- **Tooling**: global `xeres` compiler, `create-xeres` scaffolder, clean
  default page, 27 passing fixtures, `COMPARISON.md`.

## v0.1 — the finish line
1. **Persistence / `Db` layer** — a server-only `Db` capability (a `Located`,
   non-`Wire` type that cannot cross to the client). Typed CRUD over models,
   persisted to disk. Turns `login`/todo stubs into real apps. *(keystone)*
2. **Model-typed RPC args** — allow `save(user: User)` (decoder is scalar-only).
3. **Error handling across RPC** — `try`/`Result` so a failed `await` is handled
   in the UI instead of throwing silently.
4. **More types** — `List<T>`, `Optional<T>`/nullable.
5. **`xeres dev`** — watch + rebuild + serve (one command).

## Deferred to v0.2+
- CRDT / cr-sqlite sync hardening (v0.1 ships last-write-wins).
- Real SQLite/Postgres adapter (if v0.1 uses an on-disk store).
- `enum`s; the `Tainted`/information-flow layer; TLS + session tokens.
- LSP (editor diagnostics), formatter.
- Self-contained runtime so generated apps need no `cargo`.

## Publication checklist
- License: `MIT OR Apache-2.0` (Rust-ecosystem norm).
- README, a docs page, `CHANGELOG.md`, the `COMPARISON.md`.
- Wire the fixtures into `cargo test` + CI.
- Publish `create-xeres` to npm; ship prebuilt `xeres` binaries via GitHub
  Releases (the esbuild model).
- **Distribution model A** for v0.1 (the generated app needs `cargo`; documented).
  **Model B** (self-contained runtime, no `cargo`) is a v0.2 goal.
- Tag `v0.1.0`.

## Dogfooding (alongside, not after)
Build one real reference app in Xeres — an auth'd notes/todo — as the proof and
the gap-finder. Real screens drive feature priorities (every one so far has).
