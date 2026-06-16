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
  Rules now span **R1–R28**.
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
  (`Decimal` ⇒ a `String` on the wire/DB). **Arithmetic + ordered comparison are
  a deliberate Cut-2 follow-up** (see Later). Rules now span **R1–R29**.
- ~~**Typed numeric inputs (`number`)**~~ ✅ done (v0.5.4) — a `number` control
  binds an `Int`/`Float` `state` cell directly (`<input type="number">`; runtime
  coerces via `valueAsNumber`, empty → `0`), so a numeric field yields a number,
  not a string. Extends **R13** to three-way (checkbox→Bool, number→Int/Float,
  rest→String); a `number` can't bind a `Decimal` (it yields a float). No new
  rule, no parser change.
- Light touch: `cargo audit` in CI.

## Later
- **`Decimal` Cut 2** — arithmetic (`+ - *`) and ordered comparison (`< > <=
  >=`): server-side via the `rust_decimal` crate behind a new `decimal` cargo
  feature, browser-side a tiny fixed-point helper. `Decimal × Int → Decimal`,
  `Decimal ± Decimal → Decimal`; `Decimal` with `Float` stays a compile error.
  Plus a `9.99d` literal, currency/locale formatting, and rounding modes.
- TLS follow-ups: HTTP→HTTPS redirect listener, ACME/Let's Encrypt automation,
  and HTTP/2 (v0.5.2 ships TLS termination; these were explicitly out of scope).
- `enum`s; the `Tainted`/information-flow layer (the `declassify` keyword
  already reserves the surface).
- LSP (inline R-rule diagnostics in editors), `xeres fmt`.
- More databases behind the same `db` API (MySQL, SQL Server, Oracle).
- Real SQLite (cr-sqlite) for the on-device store.

## Dogfooding (alongside, not after)
Build one real reference app in Xeres — an auth'd notes/todo — as the proof and
the gap-finder. Real screens drive feature priorities (every one so far has).
