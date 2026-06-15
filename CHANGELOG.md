# Changelog

## 0.4.0 (unreleased) — security hardening, wave 2

Finishing the secure-by-default posture and the remaining capability gaps.

- **CSRF, HSTS & tighter CORS (Default S1/S2)** — every state-changing RPC fn
  call now requires a double-submit CSRF token: the server issues a JS-readable
  `xeres_csrf` cookie and the generated client resends it as the `X-CSRF-Token`
  header on every call (a mismatch/absent token is a `403`). The developer never
  writes any of it. `Strict-Transport-Security` is now always sent (honored once
  TLS is terminated in front), and the blanket `Access-Control-Allow-Origin: *`
  is removed — the app is same-origin. Enforced in both the `xeres serve` runtime
  and the ejected server; sync replication is exempt. Proven live (403 with no /
  mismatched token, 200 on a match).
- **`log` primitive + log-no-secret (R27, A09)** — a server-only structured
  logger: `log.info` / `log.warn` / `log.error` emit one JSON line per call
  (`{"level":…,"msg":…}`) to stderr — the web-appropriate output primitive (the
  replacement for a stray `print`). Rule **R27**: a secret/Located value cannot be
  passed to `log`, so leaking a credential through logs is a compile error (use
  `declassify(...)` to release something deliberately). Dependency-free, in both
  the interpreter and the ejected server. Fixtures: pass_log, fail_log_secret.
- **`endpoint` egress allowlist (R26, A10 SSRF)** — outbound HTTP is expressible
  *only* through a declared `endpoint` whose host is fixed at declaration
  (`endpoint Notify { base "https://…" secret key: String }`). Call sites append
  a **literal** path (`Notify.post("/path", body) -> Int`, `Notify.get("/path")
  -> String`) but can never change the host — so `http.get(arbitraryUrl)` doesn't
  exist, and the program's entire egress surface is the set of `endpoint`
  declarations (statically auditable). Server-only (Located): calling an endpoint
  from the browser is a compile error, and its secret (env-loaded as
  `<NAME>_<FIELD>`, sent as a bearer token) never crosses the wire. Behaviour in
  both backends via `ureq` behind a new optional `http` feature (in `full`).
  Fixtures: pass_endpoint, fail_endpoint_in_ui, fail_endpoint_path.
- **`on load` lifecycle hook (P1)** — a screen-level `on load { … }` block that
  runs once on mount and may `await` server fns, so a screen fetches its own data
  on open (`on load { users = await list_users() }`), then redraws. It's a
  browser handler context, so the await discipline (R4) and `try` rule (R16)
  apply — a non-awaited server call in `on load` does not compile. The
  most-requested missing piece. Fixtures: pass_on_load, fail_on_load_sync.

## 0.3.0 — 2026-06-15 — language foundations + security hardening (R20–R25)

Rounding out the core language so it can express real business logic. Same
tier-safe boundary; new constructs go through the same checker.

- **`DateTime` primitive + `now()`** — a timestamp type (epoch milliseconds,
  carried as `i64`/`number` over the wire and DB) and a `now()` builtin in both
  tiers. Temporal arithmetic: `DateTime - DateTime` is the elapsed `Int` (ms),
  `DateTime ± Int` shifts a timestamp; comparisons work. Dependency-free.
- **`enum` + `match`** — `enum Status { Active Inactive Pending }` (unit
  variants), values via `Status.Active`, and a `match` statement
  (`match s { Active -> { … } _ -> { … } }`) in fn bodies + handlers. Enums are
  **string-backed** end to end: a Rust `type X = String` alias, a TS string
  union (`"Active" | …`), `Value::Str` in the interpreter, and the variant name
  on the wire/DB. `==` works. New rule **R20**: a `match` scrutinee must be an
  enum, every arm is a real variant, and the arms are **exhaustive** (cover all
  variants or include `_`); an unknown `Enum.Variant` is also R20.
- **String stdlib + math builtins** — String methods `trim` / `upper` / `lower`
  / `length` / `contains` / `split` / `replace`, and numeric `abs` / `min` /
  `max`, each spelled for its tier (Rust on the server, TS on the client) and
  run in the interpreter. New rule **R21**: a String method's receiver must be a
  `String` and its argument count must match (`contains`/`split` take 1,
  `replace` 2, the rest 0). `abs`/`min`/`max` stay `Int` when all arguments are
  `Int`, else `Float`.
- **View XSS escaping (R22) + secure-by-default headers** — every value
  interpolated into a view is HTML-escaped before it reaches the DOM (text
  content, `value="…"` attributes, and per-item `data-key`s), so `text userInput`
  can never inject markup: *escaping is the default, not a thing the developer has
  to remember*. The single audited opt-out is **`raw(html)`** — a keyword in the
  spirit of `declassify` (greppable, reviewable) for the rare trusted-HTML case.
  Backstopped by a strict **Content-Security-Policy** (no inline/external script
  except `'self'`; inline style allowed for the language's `<style>`/`style=""`),
  shipped with `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`
  and `X-Frame-Options: DENY` on **every** response from both the `xeres serve`
  runtime and the ejected server — no opt-in. The client bootstrap moved out of an
  inline `<script>` (`client.js` now self-starts) so the CSP needs no script
  exceptions.
- **SQL injection made inexpressible (R23)** — the query argument to
  `db.query` / `db.query_one` / `db.exec` must be a **string literal**. A
  variable, concatenation, or interpolation in query position is a compile error;
  user values may flow only through the trailing `$1`, `$2`, … parameters. So
  `"… where name='" + name + "'"` simply does not compile — the unsafe form is
  gone, not merely discouraged.
- **Server-only `session` capability + authn-required (R24)** — a Located,
  server-only `session` (the same machinery as `db`): `session.actor` reads the
  authenticated actor id (`Optional<String>`) from a verified cookie, and
  `session.login(id)` / `session.logout()` mint and clear it. The cookie is
  **HMAC-SHA256-signed** over a server secret (`SESSION_SECRET`) and set
  `HttpOnly; Secure; SameSite=Strict`, so it can't be read by JS, forged, or
  sent cross-site. New modifier **`auth server fn`** and rule **R24**: an `auth`
  fn must be server-side and must consult `session` — a protected fn that never
  reads `session.actor` (the "I forgot the auth check" bug) does not compile, and
  touching `session` from the browser is rejected (Located). Proven live on the
  `xeres serve` interpreter: login mints the signed cookie, the actor populates on
  the next request, and a tampered cookie is rejected. Signing uses `hmac`/`sha2`
  behind the existing `auth` feature. Eject (`xeres build`) guards a session app
  with a `compile_error!` for now — the interpreter is the supported session
  runtime. Fixtures: pass_session, fail_protected_no_auth, fail_session_in_ui.
- **Actor-scope, anti-IDOR (R25)** — in an `auth` fn, a `db` query that binds any
  parameter must also bind `session.actor` as an ownership predicate. A protected
  fetch or mutation scoped only by a caller-supplied id (`… where id = $1`,
  note_id) is a probable IDOR and does not compile; the actor-scoped form
  (`… where id = $1 and owner = $2`, note_id, session.actor) is required. This
  makes the common "forgot the ownership check" omission non-compiling. Fixtures:
  pass_owner_scope, fail_idor_no_owner.

## 0.2.0 — view & component layer

A larger, still tier-safe view vocabulary. The server/client boundary is
unchanged: every new construct is browser-tier and goes through the same
checker, so secrets and `db` still physically cannot reach the client.

- **Control flow in functions** — statement-level `if`/`else`, `for x in list`,
  `for i in 0..n` (ranges), `while`, and `break`/`continue` in `fn` bodies and
  ui handlers (previously a fn body had only `let`/assign/`return`/`expr`/`try`,
  so it couldn't loop or branch with statements — only the ternary). Compiles to
  Rust (server), TypeScript (client), and runs in the interpreter (a `Flow`
  control-signal). Server bindings are `let mut` so reassignment in loops works.
  `if`/`while` conditions must be `Bool` (R14).
- **View & component layer** — a bigger, still tier-safe view vocabulary:
  - **`style "<css>"`** on any element. `row`/`column` stay flex containers (the
    compiler prepends `display:flex`); your CSS wins otherwise. A screen that
    styles its **root** renders **full-bleed** on a neutral page (no card, logo,
    or gradient); unstyled screens keep the branded shell.
  - **`for` over a plain `List<T>` state** (not just synced `Collection<T>`) —
    *lifts a v0.1 limitation*. Array loops key per-item handlers by index;
    synced collections still key by `id`.
  - **Conditional expression `cond ? a : b`** (TS `?:` / Rust `if-else` /
    interpreted), with **R14** extended to ternary conditions and a new
    **R18 conditional-branch** rule: both branches must share one type (no
    silent `String`/`Int` mixing).
  - **Layout & text primitives** — `grid` (CSS grid), `box` (neutral container),
    `subheading`, `title`, `paragraph`.
  - **Reusable `ui component`s** — presentational, parameterized views invoked by
    a Capitalized tag (`StatCard { title: … }`). Browser-tier only; args checked
    against params and the secret/scope rules (R3/R8) apply inside the view, so a
    component never widens the tier boundary. New **R17 component** rule
    (Capitalized name + known component + matching args); **R2** broadened to
    screen/component names.
  - Reference apps: [`examples/dashboard.xrs`](examples/dashboard.xrs) and a full
    admin dashboard [`examples/acme.xrs`](examples/acme.xrs).
- **Full-grammar RPC arguments** — `List<T>`, `Optional<T>`, nested models, and
  any nesting now decode correctly server-side (both the generated Rust and the
  `xeres serve` interpreter), *lifting a v0.1 limitation* where they defaulted.
  A recursive JSON→value decoder replaces the flat scalar/model one.
- **Database** — `db.query_one` may return **`Optional<Model>`**: a no-row result
  is `none` instead of an error (the graceful "miss" form; a bare `Model` return
  still requires the row). `uid()` is now also a **server-side** builtin, so it
  works inside a `server fn` (e.g. minting a row id on `db.exec` insert) — it
  previously only existed client-side. Fixed: `return db.exec(...)` in the
  interpreter ran the query path (mapping rows) instead of executing; it now
  routes to exec. Verified end-to-end against a live Postgres (read/lookup/write).
  See [`examples/users.xrs`](examples/users.xrs).
- **Auth primitives** — server-only **`hash()` / `verify()`** builtins (Argon2id),
  enforced by new rule **R19** (no client-side hashing; the secret hash is
  compared server-side). The `argon2` dep is added to the generated server only
  when used; in `xeres serve` they're behind an `auth` feature (released binaries
  build `--features full`). **Typed `let`** (`let u: User = db.query_one(...)`)
  lets a server fn bind a query row and compute on it — the piece that makes a
  salted-hash login (fetch row → `verify`) expressible. Full tier-safe login:
  [`examples/login_db.xrs`](examples/login_db.xrs), proven against live Neon
  Postgres (register hashes, login fetch+verify, wrong-password + no-user paths).

## 0.1.1 — distribution & self-contained runtime

First release with prebuilt binaries + the no-toolchain run path:

- **Self-contained runtime (`xeres serve`)** — the compiler binary can now run
  an app directly: an interpreter executes `server` functions and an in-process
  HTTP server handles static, RPC (secret-stripped responses) and sync. **No
  cargo, no generated-Rust compile.** `xeres dev` now (re)spawns `xeres serve`,
  so the dev loop needs no Rust toolchain. The Postgres driver is feature-gated
  (`--features db`); released binaries are built with it, so DB apps work with
  no toolchain on the user's machine. `xeres build` still emits a standalone
  Rust crate for an eject / max-performance path.
- **Distribution (no-git install)** — an npm `xeres` package (`tooling/npm/xeres`)
  whose `postinstall` downloads a prebuilt compiler binary for the platform, and
  a `release.yml` workflow that builds those binaries per-platform on a tag.
  Goal: `npm i -g xeres` + `npm create xeres@latest` with no repo clone. See
  [RELEASING.md](RELEASING.md). (Publishing requires npm/GitHub accounts.)
- **`xeres dev`** — one command to compile, bundle the client, serve on
  `http://127.0.0.1:8080`, and rebuild + restart on every source change.
- **`.env` config** — `xeres dev` loads a dotenv-style `.env` into the server
  (e.g. `DATABASE_URL` for the `db` capability). Connection strings stay
  server-only.
- **`create-xeres`** now scaffolds a db-ready project: `npm run dev` uses
  `xeres dev`, with a `.env.example` and `.env` gitignored.

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
