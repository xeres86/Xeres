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
3. ~~**Sync hardening** — field-level merge instead of row-level
   last-write-wins.~~ ✅ done (v0.5.6) — synced rows merge **LWW per field** by a
   Lamport stamp (ties broken by a stable site id), so concurrent edits to
   different fields of a row both survive; deletes are tombstones a late write
   can't resurrect. It's LWW-per-field, **not** a full CRDT — true CRDTs
   (RGA/LSEQ text) and cr-sqlite stay under "Later" below.
4. ~~**`for` over `List<T>`** in views (not just synced collections).~~ ✅ done
   (array loops key per-item handlers by index; synced collections by `id`).
5. ~~**List/Optional inside RPC arguments**~~ ✅ done — a recursive JSON decoder
   handles `List<T>`, `Optional<T>`, nested models and any nesting, in both the
   generated Rust and the `xeres serve` interpreter.
6. **Auth primitives** — server-only `hash()` / `verify()` (Argon2id) ✅ done
   (rule R19; `examples/login_db.xrs`); signed `session` cookies ✅ (R24/R25);
   **auth-gated routes** ✅ done (v0.5.9, **R31**) — `auth ui screen` protected
   both tiers (client redirect + server shell guard). Remaining: roles/RBAC
   (spec 15), TLS follow-ups (below).
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

## v0.3 — language foundations + security hardening
Rounding out the core language *and* moving web-app security from developer
discipline into compiler-enforced impossibility (see `SECURITY-HARDENING.md`).
Rules now span **R1–R25**.

Landed:
- **Primitives & stdlib** — `DateTime` + `now()`; `enum` + exhaustive `match`
  (R20); a String stdlib (`trim`/`upper`/`lower`/`length`/`contains`/`split`/
  `replace`) + math (`abs`/`min`/`max`) (R21).
- **XSS escaping (R22)** — every interpolated view value is HTML-escaped by
  default; `raw(html)` is the single audited opt-out. Backstopped by a strict
  CSP + `nosniff`/`Referrer-Policy`/`X-Frame-Options` on every response (no
  opt-in); the client bootstrap is external so the CSP forbids all inline script.
- **SQL injection inexpressible (R23)** — `db.*` queries must be string literals;
  user values flow only through `$1`,`$2`,… params.
- **Session + authn (R24)** — server-only Located `session` capability
  (`session.actor`, `session.login`/`logout`) backed by an HMAC-signed
  `HttpOnly; Secure; SameSite=Strict` cookie; the `auth server fn` modifier must
  consult `session` or it won't compile. Works in **both run modes** — the
  ejected server (`xeres build`) threads the same signed cookie as `xeres serve`,
  so a cookie minted by one verifies under the other.
- **R25 actor-scope** (anti-IDOR) — in an `auth` fn, a parameterized `db` query
  must bind `session.actor` (an ownership predicate); a fetch/mutation scoped
  only by a caller-supplied id doesn't compile.

## v0.4 — security hardening, wave 2
Completes the OWASP-class rule set; rules now span **R1–R27**. Shipped:
- **CSRF + HSTS + tighter CORS** (Default S1/S2) — a double-submit token on every
  RPC fn call (the generated client attaches it automatically); HSTS always set;
  the blanket `Access-Control-Allow-Origin: *` removed.
- **R26 `endpoint` egress** (anti-SSRF) — outbound HTTP only through a declared,
  host-fixed `endpoint`; server-only (Located); secret env-loaded as a bearer.
  `ureq` behind a new optional `http` feature.
- **R27 `log` + log-no-secret** — server-only structured logging; a secret/Located
  value can't be passed to `log`.
- **P1 `on load`** — screen lifecycle hook that fetches its own data on mount
  (may `await`; R4/R16 apply).

## v0.5 — view & navigation primitives (next)
- ~~**P3 form controls** — `select`, `checkbox`, `radio`, `textarea`, `link`,
  `image` (each escaped + bind-aware).~~ ✅ done (`link` landed with the router).
- ~~**P2 client router** — `navigate(Screen)` + URL sync (`link` depends on
  it).~~ ✅ done — `navigate(Screen)` + `link "…" -> Screen` over a path-per-screen
  route map; `pushState`/`popstate` URL sync; SPA fallback so deep links survive a
  reload; a screen's `on load` runs on each navigation. New rule **R28**
  (navigation target must be a prop-less, non-component screen; browser-only).
  **Typed route params** ✅ done (v0.5.10, **R32**) — `ui screen Post(id: String)
  route "/post/:id"` binds `:name` segments to props (the one relaxation of R28);
  deep-link + `navigate(Post { id })`, params are R30-tainted. Pending: declarative
  `link -> Post { id }`, query strings, param routes that are also `auth`.
- ~~Lift the ejected-server `session` `compile_error!` guard.~~ ✅ done — the
  generated server now threads the HMAC-signed cookie, so `build` ≡ `serve` for
  session apps.
- ~~Real TLS for the app server (HSTS already set).~~ ✅ done — `xeres serve
  --tls` (and the ejected server behind a `tls` cargo feature) terminates HTTPS
  directly via pure-Rust `rustls`/`ring`, reading `TLS_CERT`/`TLS_KEY`; no proxy
  needed, so the always-on HSTS header is now truthful.
- ~~**`Decimal` money primitive (R29)**~~ ✅ done (v0.5.3) — exact, string-backed
  money via `decimal("19.99")`, type-distinct from `Float` so binary-float error
  can't leak into money math. Cut 1: construct, display (string concat), and
  `==`/`!=`; usable in model fields, RPC args, DB columns; both run modes
  (`Decimal` ⇒ a `String` on the wire/DB). **Cut 2 (below) adds arithmetic +
  ordered comparison.** Rules now span **R1–R29**.
- ~~**Typed numeric inputs (`number`)**~~ ✅ done (v0.5.4) — a `number` control
  binds an `Int`/`Float` `state` cell directly (`<input type="number">`; runtime
  coerces via `valueAsNumber`, empty → `0`), so a numeric field yields a number,
  not a string. Extends **R13** to three-way (checkbox→Bool, number→Int/Float,
  rest→String); a `number` can't bind a `Decimal` (it yields a float). No new
  rule, no parser change.
- ~~**`xeres fmt`** (canonical formatter)~~ ✅ done (v0.5.5) — a token-stream
  pretty-printer (`xeres fmt <file>`, `--check` for CI): canonical indentation/
  spacing, members one-per-line, blank-line policy, comment-preserving and
  idempotent. Lexer gained an opt-in `keep_comments` (compile path unchanged).
- Light touch: `cargo audit` in CI.

## Later
- **Inbound API (the addressable boundary)** — **Cut 1 shipped (spec 23, R36):**
  an `api Name { base "…" GET/POST "path" [body x: Model] -> Ret { … } }` block
  exposes the server/client boundary as a public HTTP/JSON surface (mobile,
  webhooks, server-to-server) — the dual of `endpoint` (R26 outbound vs R36
  inbound). Typed JSON object bodies → models, wire-projected responses (a
  `secret` can't leak — R5), `Optional<T>` → 404, capability-gated in imported
  modules (R34), no CSRF / no client stub. Runs identically under `xeres serve`
  and the ejected server (curl-verified). **Next cuts:** auth via bearer tokens;
  path params (`/posts/:id`) + query strings; request headers (webhook
  signatures); PUT/PATCH/DELETE + custom status codes / typed error bodies; CORS;
  and **OpenAPI/Swagger generation** (the `api` block is the natural source of
  truth). The big remaining production-web items beyond this: **migrations**
  (versioned SQL on boot), **form validation**, **file uploads**, **connection
  pooling**, **background jobs**, **RBAC**.
- **Modules & capability-secure packages** — **Cut 1 shipped (spec 20):** local
  multi-file modules with a pre-checker **loader** ([`src/loader.rs`](src/loader.rs))
  that resolves `import "…"` edges (relative paths), detects cycles, and merges
  every file into one program — so the tier/secret rules compose across the
  boundary for free. Only `pub` declarations cross a boundary (**R35**), and an
  imported module that uses a `Located` capability (`db`/`session`/`endpoint`)
  must `requires` it *and* be `grant`ed it by the app (**R34**) — the
  supply-chain guarantee that makes a left-pad/xz-style attack inexpressible. One
  merged server crate + client bundle; import-free apps unchanged. This is the
  keystone for the **two-layer trust model** ([ARCHITECTURE.md](ARCHITECTURE.md)):
  a tiny audited native-core TCB + a stdlib/packages written in Xeres with no
  ambient authority. **Cut 1.5 shipped (the Layer-2 proof):** the first
  self-hosted stdlib — `std/math.xrs` + `std/text.xrs`, written in Xeres and
  compiled into the binary (`include_str!`), imported via the embedded `std:`
  scheme (`import "std:math"`), zero ambient authority, verified across all three
  backends. **Cut 2 shipped (multi-file types):** `pub` + import discipline now
  applies to **all** decl kinds — `pub model` / `pub enum` / `pub ui component`
  / `pub ui screen`. The "import a Badge into the dashboard" / "import a
  UserProfile model" feature (the C#-namespace / JS-component-file feel).
  Cross-module type names are unqualified (JSX-style); functions keep the
  qualified `mod.fn(...)` from Cut 1 — *functions are called, types are named*.
  A type-visibility pass in the loader walks every type-reference site (model
  fields, fn params/returns, screen props, state decls, record literals,
  component invocations, enum-variant access, bare `link`/`navigate` idents);
  4 new pass + 3 new fail fixtures + their siblings; ejected `cargo build` of
  `pass_import_component` proves the cross-module `Badge` lands in both server
  and client output. Closes the type-level R35 gap from the codebase review.
  **Next cuts:** a package **registry** + `xeres.toml` **manifest** +
  **semver**/remote/cached packages + signing; `module__name` **mangling**
  (private-name reuse); a codegen **clone/borrow pass** so a `List`/`String` arg
  can be reused after a call (dogfooding found the Rust backend moves it);
  re-exports/glob imports/nested namespaces; capability **attenuation** (a
  narrowed `db`); and growing `std/*.xrs` (more modules; migrate the
  Xeres-expressible String/List builtins).
- ~~**`Decimal` Cut 2** — arithmetic (`+ - *`) and ordered comparison (`< > <=
  >=`)~~ ✅ done (spec 18) — a typed-desugaring pass rewrites Decimal
  `+ - * < > <= >=` into `__dec_*` builtin calls that every backend emits exactly:
  server via `rust_decimal` behind a new `decimal` cargo feature, browser via a
  zero-dep BigInt fixed-point runtime, interpreter via a scaled-`i128` core — all
  three verified to agree to the cent. `Decimal × Int → Decimal`,
  `Decimal ± Decimal → Decimal`; `Decimal` with `Float`, `Decimal ± Int`, and `/`
  stay compile errors (**R29**, no new rule). **Still deferred:** division +
  rounding modes (half-up/banker's), a `9.99d` literal, currency/locale formatting.
- TLS follow-ups: HTTP→HTTPS redirect listener, ACME/Let's Encrypt automation,
  and HTTP/2 (v0.5.2 ships TLS termination; these were explicitly out of scope).
- ~~`enum`s~~ ✅ (R20); the `Tainted`/information-flow layer — **cut 1 shipped as
  R30** (v0.5.7): `raw(...)` can't wrap untrusted *inbound* data (props /
  input-bound `state`), the inbound mirror of secret-out (R5). Remaining cuts
  (deferred): a dedicated in-view `sanitize(...)` launder, untrusted-in → outbound
  `endpoint` body/path, and a fuller multi-level taint lattice.
- **Collections** — `List<T>` stdlib **cut 1 shipped** (v0.5.8): `length`/`first`/
  `last`/`at`/`reverse` (safe, `Optional`-returning). **Cut 2 done (spec 19):**
  `map`/`filter`/`reduce` with **argument-only** expression closures (`x -> expr`,
  `(acc, x) -> expr`), `xs[i]` index sugar (→ `Optional<T>`), and list `.contains`
  (element equality — models derive `PartialEq`, lowered to `__list_contains` so the
  type-blind backends don't confuse it with `String.contains`). Tier/secret rules
  propagate into the closure body for free (no new rule — reuses R21/R3/R5).
  **Still pending:** first-class closures (stored/returned/passed), block-bodied
  closures, `sort_by`/`flatMap`/`zip`/slicing, and a `Map<K,V>` type.
- LSP (inline R-rule diagnostics in editors), format-on-save / editor integration.
- **DB transactions** ✅ done (v0.5.11, **R33**) — `transaction { … }` groups
  `db` writes atomically (commit/rollback on one shared connection), both
  backends. Pending (next cut): **migrations** (versioned SQL on boot), and
  transaction return-mapping for a typed `let` nested in control flow.
- More databases behind the same `db` API (MySQL, SQL Server, Oracle).
- Real SQLite (cr-sqlite) for the on-device store.

## Dogfooding (alongside, not after)
Build one real reference app in Xeres — an auth'd notes/todo — as the proof and
the gap-finder. Real screens drive feature priorities (every one so far has).
