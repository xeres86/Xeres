# Changelog

## 0.1.0 — 2026-06-11

First versioned release of the Xeres language and compiler.

### Language
- Tier placement: `server fn`, `ui fn` / `ui screen`, unscoped (shared) `fn`.
- Boundary rules **R1–R16**, compiler-enforced. Headline guarantees:
  - `secret` model fields cannot be read in browser code (R3), cannot be
    returned by non-server functions (R5), and are stripped from the RPC wire
    payload by construction.
  - `declassify(...)` is the single audited release point, server-only (R6).
  - browser → server calls are typed async RPC and must be `await`-ed (R4).
  - the `db` capability is server-only; the connection can never reach the
    browser (R15).
- Data: `model` declarations, record construction (R9), `List<T>`,
  `Optional<T>` (`none`, `T` coercion, `.or(default)`), `uid()` builtin.
- Views: `view { column/row/heading/text/button/input/password }`,
  two-way `bind` (R13), `for x in collection`, `if/else` (R14),
  inline `-> { ... }` handlers, per-item handlers inside `for`.
- Client state: reactive `state` cells (R11); re-render on change.
- Local-first: `synced state x: Collection<M>` — offline-capable local store,
  background sync (last-write-wins by Lamport counter), reactive pull.
- Error handling: `try { ... } catch { ... }` in browser code (R16) — covers
  failed RPC (network or server error) with one mechanism.
- Database: `db.query_one(sql, ...) -> Model`, `db.query(sql, ...) -> List<Model>`,
  `db.exec(sql, ...) -> Int` against hosted PostgreSQL (`DATABASE_URL`),
  TLS-capable connector.

### Compiler & output
- `xeres build app.xrs` emits a self-contained server crate (`out/server/`):
  a std-only HTTP server (thread-per-connection) with a generated router,
  JSON codec, secret-stripping wire serialization, sync endpoint, and static
  hosting — plus `static/client.ts` (screens, RPC stubs, sync runtime, DOM
  mount; ~1 kb bundled) and a generated `index.html`.
- Zero dependencies in the browser; zero server dependencies unless `db` is
  used (then `postgres` + TLS crates).
- Model-typed RPC arguments decoded server-side.
- Fixture suite (35 programs) wired into `cargo test`; CI via GitHub Actions.

### Tooling
- `create-xeres` scaffolder (`tooling/create-xeres`).
- VS Code syntax highlighting (TextMate grammar).

### Known limitations (v0.1)
- Generated apps require a Rust toolchain (`cargo`) to build; db apps
  additionally need a full linker/binutils for the Postgres driver.
- Sync is last-write-wins (field-level CRDT planned).
- `for` in views iterates synced collections only (not `List<T>` values).
- List/Optional values inside *RPC arguments* default server-side.
- No TLS on the app server itself (terminate TLS in front, or v0.2).
