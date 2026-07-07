# Changelog

## Unreleased — performance harness (spec 30)

"Fast" is now a tracked number, not a vibe. A Node-stdlib harness (`bench/`)
measures four metrics over the example apps and gates regressions against a
committed baseline:

- **Compiler throughput** — `xeres build` wall-time (best of 5) + lines/sec.
- **Client bundle size** — gzipped `client.js` (the zero-framework proof:
  1.5–3.7 kb across the examples).
- **Server cold start + resident memory** — spawn → first `200`; ~10.6 MB RSS
  flat under load.
- **Request throughput** — keep-alive load on an RPC (`/__xeres/ping`) and an
  `api` route (`GET /api/bench/ping`): **10k+ req/s** each, p50 ~2.5 ms.

`bench/baseline.json` holds the deterministic metrics (compile-time + bundle);
`bench/run.mjs` diffs against it and flags a regression (advisory — >10 % bundle
/ >40 % compile, never fails the build). Server numbers are machine-specific, so
they're reported, not gated. A manual/nightly `perf.yml` CI job runs it. New
README "Performance" section.

Also: **`xeres serve` now honors a `PORT` env var** (was hardcoded 8080) — lets
the harness pick a free port and lets `xeres dev` run several apps side by side.

## 0.7.1 — 2026-07-02 — global CSS, the security pass & serve-path hardening

Three themes: a new **compile-time styling layer** (spec 26), the owed
**security pass** (spec 29 — which turned up and closed a real secret-on-wire
hole), and **panic-hardening** the `xeres serve` request path (spec 28).

> ⚠️ **Behavior change (R5).** A `server fn` that returns a **bare scalar** built
> from a `secret` field now requires `declassify(...)` — see the security-pass
> section. This rejects code that previously compiled (and leaked); the fix is a
> one-word `declassify(...)`, exactly what R5's error message always recommended.

### Global CSS — design tokens, named styles, dark mode (spec 26, R37)

A compile-time styling layer, still zero browser framework runtime:

```xeres
theme {
  color primary "#2563eb"
  space lg "24px"
}
theme dark { color primary "#7c3aed" }

style Card { "padding:token(lg); background:token(primary)" }

ui screen Home {
  view {
    column style Card { button "Toggle" -> { toggle_theme() } }
  }
}
```

- **`theme { … }` / `theme dark { … }`** — design tokens, compiled to CSS
  variables (`:root`, plus a `@media (prefers-color-scheme: dark)` block and a
  `[data-theme="dark"]` block for a manual toggle). `token(name)` inside any
  `style` string resolves to `var(--name)` at compile time.
- **`style Name { "…" }`** — a top-level named style, compiled to a generated
  `.x-name` class; an element's `style Name` modifier emits `class=` instead of
  inline CSS (sugar over the same generated sheet — inline `style "…"` keeps
  working unchanged, side by side).
- **`toggle_theme()`** — a browser-only builtin that flips `data-theme` on
  `<html>` and persists the choice to `localStorage`; tiny inline JS, no
  framework, only emitted when a `theme dark` block exists.
- Everything compiles to one generated `static/app.css`, linked from
  `index.html` only when the app actually declares a `theme`/`style` — a plain
  app's output is untouched (no `<link>`, no file).
- **New rule R37 unknown-token** — `token(x)` / `style Name` must reference a
  declared token/style, the same discipline as an unknown type. Next free rule
  → **R38**.
- Codegen-only feature: the interpreter has no `style` handling at all (`xeres
  serve` already serves codegen's client bundle), so this touches
  parser/checker/codegen — not `interp.rs`.

### The security pass — cargo-audit CI, an R1–R37 sweep, a secret-on-wire hole (spec 29)

The three artifacts owed since the original security pass, plus a genuine
finding from doing the sweep seriously instead of re-reading old comments:

- **`cargo audit` in CI** — a new `security` job (`.github/workflows/ci.yml`)
  fails the build on a RUSTSEC vulnerability in the dependency tree. Currently
  clean (2 known, triaged, non-blocking maintenance-status warnings — see
  `SECURITY.md`).
- **A written, verified R1–R37 coverage matrix** — `SECURITY.md`. Every rule's
  enforcement site and fail/pass fixture pair, checked against the compiler's
  actual output while writing it (not just trusted from old comments).
- **R5, closed for real:** a `server fn` could return a bare secret-derived
  **scalar** (`server fn get_hash(u: User) -> String { return u.password_hash
  }`) with **zero compiler errors** — R5 only ever restricted *non*-server
  functions, on the assumption wire-projection strips secrets automatically.
  True for a Model return (field-level stripping); **not** true for a scalar,
  which carries no field marker once extracted. Confirmed live: `xeres serve`
  + a valid-CSRF `curl` to `/__xeres/get_hash` returned the raw secret value.
  R5 now also rejects this; `declassify(...)` is the deliberate opt-out. New
  fixtures: `fail_secret_scalar_leak.xrs`, `pass_secret_scalar_declassified.xrs`,
  `fail_secret_return_via_call.xrs` (the call-graph composition path, distinct
  from a direct field read).
- **The secret-on-wire property, asserted mechanically:**
  `interp::tests::secret_never_crosses_the_wire` builds an app and calls it
  through both client-reachable wire surfaces (RPC, `api` route), asserting the
  secret value never appears in the serialized JSON on either — then
  mutation-tested (temporarily broke the stripping filter, confirmed the test
  goes red with the leaked value in the failure message) to prove it isn't a
  tautology.

### Panic-hardening the serve request path (spec 28)

A review flagged 49 `unwrap`/`panic!` sites in `interp.rs` as a robustness gap.
Triaging them found the count was mostly test code (only 3 real runtime sites,
all legitimate invariants — now documented in place) — but turned up two
*actual* crash bugs the grep count missed, since neither is a `.unwrap()`/
`panic!()` call:

- **`content_length()` (serve.rs)** — parsed `Content-Length` via a fixed
  byte-offset slice (`line[..15]`) guarded only by a length check; a request
  with a multi-byte UTF-8 character positioned so byte 15 falls mid-character
  panics the connection thread on ANY header line. Fixed with the `.get(..15)`
  pattern already used by `cookie_value`/`header_value` in the same file.
- **`dec_parse()` (interp.rs)** — a Decimal string with a huge leading-zero
  fractional part parses to a tiny i128 magnitude but an unbounded scale;
  combining it with a differently-scaled Decimal overflow-panics `dec_rescale`'s
  `10i128.pow(scale diff)`. Reachable from a single crafted `api`/RPC body.
  Fixed by capping the fractional scale (30 digits) and rejecting the rest as
  `"invalid Decimal"` — the graceful path every invalid Decimal already takes.
- **Sync store lock (serve.rs)** — `sync_store().lock().unwrap()` propagated
  poisoning forever after any one panic (a CRDT merge store, safe to keep
  merging into); now recovers via `.unwrap_or_else(|e| e.into_inner())`.

All three are regression-tested and confirmed live against a running
`xeres serve` with crafted raw requests.

## 0.7.0 — 2026-06-30 — multi-file, the addressable boundary & typed external data

Three themes: the multi-file story (modules Cut 2 + a multi-file scaffold), the
**addressable tier boundary** (the inbound `api` primitive), and **typed
external data** (typed `endpoint` responses + safe dynamic query paths + display
string-concat — spec 24, the "live weather app" wave).

### Inbound API — the addressable boundary (spec 23, Cut 1)

Until now the server/client boundary was real but only the bundled SPA could call
it (`server fn` → `/__xeres/<fn>` RPC). The new `api` block makes the boundary a
**first-class HTTP/JSON surface** for everyone else — mobile clients, webhooks,
server-to-server, third parties:

```xeres
api Public {
  base "/api/v1"
  GET "/posts" -> List<PostSummary> { return db.query("select id, title from posts") }
  POST "/waitlist" body signup: Signup -> Confirmation {
    let id = db.exec("insert into waitlist (id, email) values ($1, $2)", uid(), signup.email)
    return Confirmation { ok: true }
  }
}
```

- **Declared routes** (`GET`/`POST`) at real paths under `base`, JSON **object**
  bodies decoded into models, typed responses serialized as JSON. The dual of
  `endpoint` (R26 outbound): `api` is the inbound surface, statically auditable.
- **Same tier-safety, now public.** Responses are wire-projected — a `secret`
  field **cannot** appear in the JSON (R5). Bodies are untrusted; SQL-injection
  stays blocked by R23's literal-query rule. An `api` in an imported module is
  R34-capability-gated like any module code.
- **`Optional<T>` return ⇒ `None` is a 404**; an unknown path under a declared
  `base` is a JSON 404 (not the SPA shell). **No CSRF** (external callers have no
  cookie) and **no client stub** (the api is not for the bundled SPA).
- **New rule R36 api-route** (literal path, valid method, unique routes, `body`
  only on POST). Next free rule → **R37**.
- Runs identically under `xeres serve` (interpreter) and the ejected Rust server
  — verified with a live `curl` of every route (incl. secret-stripping + 404).
- Deferred to later cuts: auth via **bearer tokens**, path params (`/posts/:id`),
  request headers (webhook signatures), PUT/PATCH/DELETE, custom status codes,
  OpenAPI generation.

### Typed external data — typed endpoints, safe dynamic paths & string-concat (spec 24)

The outbound complement to `api`: consuming third-party JSON in a fully typed,
SSRF-safe way. Three features that together make a real "search a city → call a
public weather API → render typed cards" app expressible (see
[`examples/weather.xrs`](examples/weather.xrs)):

```xeres
endpoint Geocode { base "https://geocoding-api.open-meteo.com" }

server fn lookup(city: String) -> WeatherCard {
  let geo: GeoResponse = Geocode.get("/v1/search?count=1&name=" + city.replace(" ", "+"))
  let fc: Forecast = Weather.get("/v1/forecast?...&latitude=" + g.latitude + "&longitude=" + g.longitude)
  return WeatherCard { city: g.name, temp: fc.current.temperature_2m, ... }
}
```

- **Typed endpoint responses** — `endpoint.get(path) -> Model` decodes the JSON
  response straight into a declared `model` (mirrors `db.query_one`-onto-model).
  The shared JSON parser was hoisted out of `serve.rs` into a new `src/json.rs`
  so both runtimes — the interpreter and the ejected Rust server — decode through
  **one** implementation (also chips at the serve/interp duplication the codebase
  review flagged).
- **Safe dynamic query paths (R26 relaxed)** — a path may now be built at runtime
  (`"/v1/search?name=" + city`) **provided it begins with a literal `/…` segment**.
  That keeps the host pinned by `base` and blocks the `base + "@evil.com"`
  userinfo-host-injection trick — anti-SSRF by construction. Static `base` +
  literal-prefixed path = the egress allowlist still holds.
- **`String + scalar` display-concat** — `"lat=" + 51.5` now lowers to a
  `__str_concat` builtin (like the Decimal lowering) so building a URL or a label
  from an `Int`/`Float`/`Decimal`/`Bool` works on every backend. Also fixes a
  pre-existing latent bug: server-side `String + String` previously emitted Rust
  that didn't compile (`E0308`), never caught because concat had only run in TS
  views.
- Verified live end-to-end against Open-Meteo (London/Tokyo/NYC/Cape Town) under
  both `xeres serve` and the ejected Rust server, plus the not-found path.
- New demos: [`examples/weather.xrs`](examples/weather.xrs) (typed live API) and
  [`crm_demo.xrs`](crm_demo.xrs) (client router + `on load` page fetch, existing
  primitives only).

### Modules Cut 2 — cross-module types, components & screens (spec 20)

The "import a Badge into the dashboard" / "import a UserProfile model" feature.
Cut 1 shipped cross-module `pub fn`; Cut 2 extends the same `pub` + import
discipline to **all** declaration kinds — types, components, screens — so a real
multi-file app can break out shared models, enums, UI components, and even
whole pages into their own files (the C#-namespace / JS-component-file feel).
This also closes the F7 type-level R35 gap (the codebase review's biggest
remaining soundness loose end on spec 20).

### Modules Cut 2

- **`pub model` / `pub enum` / `pub ui component` / `pub ui screen`** now cross
  a module boundary. Same R35 rule as functions: only `pub` declarations are
  visible to importing modules; a reference to a non-`pub` decl from another
  module is a compile error. Names stay globally unique (R2 catches collisions).
- **Cross-module type names are UNQUALIFIED** — `import "card.xrs"; ui screen
  S { view { Badge { ... } } }` reads like a JSX/Python import. The asymmetry
  with functions (which keep the `mod.fn(...)` qualified form from Cut 1) is
  intentional: *functions are called, types are named*.
- A type-visibility pass in the loader walks the merged program, checking every
  type reference site — model field types, fn params/returns, screen props,
  state declarations, `let` annotations, record literals (`Model { ... }` /
  `navigate(Screen { ... })`), bare `navigate(Screen)` / `link "..." -> Screen`
  identifiers, component invocations (`Badge { ... }`), and enum-variant access
  (`Status.Active`). Unknown names fall through to R1 (unknown-type).
- New fixtures: `pass_import_component` + `card.xrs`, `pass_import_model` +
  `userprofile.xrs`, `pass_import_enum` + `status.xrs`, `pass_import_screen`
  + `profile_page.xrs`, plus `fail_component_not_pub` / `fail_model_not_pub` /
  `fail_enum_not_pub` with non-`pub` siblings. Verified end-to-end: the
  component fixture ejects + `cargo build`s, and the cross-module `Badge`
  shows up in both server and client output.
- No new rule (R35 itself was reserved for visibility from day one); next free
  rule remains **R36**.

### Scaffold v2 — `create-xeres` 0.6.1

- `npm create xeres@latest my-app` now scaffolds a **multi-file** project that
  demonstrates Cut 2 out of the box:
  ```
  my-app/
    app.xrs              # entry: imports + Home screen
    models/note.xrs      # pub model Note { ... }      (documented stub)
    components/welcome.xrs   # pub ui component Welcome — used by Home
    pages/about.xrs      # pub ui screen About — linked from Home
  ```
- Lowercase JS-style folders (matches Next.js / SvelteKit / Vite). New users
  see the multi-file pattern from minute one rather than discovering it in
  the docs.
- README rewritten with a project-layout section + the type-vs-fn import
  asymmetry (`Badge { ... }` unqualified vs `utils.fn(...)` qualified).

## 0.6.0 — 2026-06-26 — modules, capability-secure packages & a self-hosted stdlib (spec 20)

> **Bundles 0.5.13.** The 0.5.13 changes below (the postgres DoS CVE fix, Decimal
> Cut 2, closures) were prepared but never published as released binaries, so
> 0.6.0 is the release that ships them to users — upgrading from 0.5.12 gets
> everything in both entries.

The architectural keystone: local multi-file **modules** with explicit exports
and **capability discipline**. This is what makes the project principle real —
*the stdlib and packages are written in Xeres itself, with no ambient authority*
— so a dependency **cannot** leak a secret, do egress, or touch the database
unless the app explicitly grants it. See the new [ARCHITECTURE.md](ARCHITECTURE.md)
for the two-layer trust model this establishes.

### Modules (spec 20)

- **`import "relative/path.xrs"`** — a file can import another (relative paths in
  Cut 1). The loader resolves the import graph, detects cycles, and merges every
  file into one program *before* the checker runs — so the existing tier/secret
  rules (R3/R5/R6, R15/R24/R26, …) compose across the boundary automatically. A
  module **cannot widen the boundary**: a `secret` still can't cross it, a `server
  fn` stays server-tier.
- **`pub`** — declarations are module-private by default; only `pub fn` (and,
  reserved for the next cut, `pub model` / `pub enum` / `pub ui component`) cross
  a boundary. Call an exported function as `module.fn(...)`.
- **R35 module-visibility** — referencing a non-`pub` declaration in another
  module is a compile error.
- **R34 module-capability** — *the supply-chain guarantee.* An imported module
  that uses a `Located` capability (`db` / `session` / `endpoint`) must **declare**
  it (`requires db` at the module head) **and** the importing app must **grant**
  it (`import "m.xrs" grant db`). A dependency reaching for undeclared or
  ungranted authority does not compile — a left-pad / event-stream / xz-style
  attack becomes *inexpressible*. The entry app is the root of authority and is
  never gated (it uses `db` directly, as before).
- **Single output, no regression.** Modules flatten into the same single server
  crate + single client bundle. Import-free apps take an unchanged fast path
  (byte-identical output to before). Verified across all three backends — the
  interpreter (`xeres serve`), the ejected Rust crate (`xeres build` + `cargo
  build`), and the esbuild client bundle — for a two-file app.
- New rules **R34** and **R35**; next free rule is **R36**. New fixtures:
  `pass_import_basic`, `pass_module_grant`, `fail_import_private`,
  `fail_module_undeclared_cap`, `fail_module_secret_cross` (+ sibling modules).

### Self-hosted stdlib (spec 20, Cut 1.5 — the Layer-2 proof)

- The first standard-library modules — **`std/math.xrs`** (`clamp`, `in_range`,
  `pow`, `sum`, `average`) and **`std/text.xrs`** (`is_blank`, `word_count`,
  `slugify`) — are written **in Xeres** and compiled into the compiler binary via
  `include_str!`. `import "std:math"` resolves to that embedded source (no file on
  disk, no parser change — the `std:` scheme is purely loader resolution).
- This is **Layer 2 made real**: the stdlib is ordinary Xeres checked under the
  same R1–R33 rules as your app, and declares **no `requires`** — zero ambient
  authority. The functions are pure (tier-`None`), so they run on both tiers.
- Verified end-to-end: a new interp test runs the embedded modules
  (`stdlib_runs_end_to_end`), a build-time test asserts every shipped module
  parses + analyzes clean (`stdlib_modules_are_valid_xeres`), and `pass_import_std`
  ejects + `cargo build`s + bundles. Dogfooding finding: the Rust backend moves a
  non-`Copy` argument (`List`/`String`) into a call, so the stdlib is written to
  pass a value as its last use (a codegen clone/borrow pass is the proper fix).

**Deferred to later cuts:** a package registry, an `xeres.toml` manifest, semver /
remote / cached packages, signing; `module__name` mangling (private-name reuse);
re-exports / glob imports; capability attenuation; and growing the self-hosted
`std/*.xrs` library. Cut 1 imports are local files + the embedded `std:` scheme.

## 0.5.13 — 2026-06-24 — postgres DoS CVE fix · `Decimal` Cut 2 · closures + higher-order list ops

A security fix plus two language-completeness features, released together. The
published 0.5.12 binaries predate the security fix, so this is the release that
ships it.

### Security
- **Postgres dependency chain bumped for RUSTSEC-2026-0178 / -0179 / -0180**
  (denial-of-service). These affect only builds that use the `db` capability (the
  `postgres` / `postgres-native-tls` / `native-tls` chain). `cargo audit` reports
  no known vulnerabilities on 0.5.13.

### Closures + higher-order list ops (spec 19)

A `List<T>` was iterate-only (`for x in xs` + the safe accessors). This cut closes
the gap with every language you'd migrate from: expression-level closures and the
three core higher-order ops, plus index sugar and membership.

- **`map` / `filter` / `reduce`** with **argument-only** closures (`x -> expr`,
  `(acc, x) -> expr`): `users.map(u -> u.name)` → `List<String>`,
  `users.filter(u -> u.age >= 18)` → `List<User>`,
  `items.reduce(0, (acc, x) -> acc + x.qty)` → `Int`. Pipelines chain
  (`xs.filter(…).map(…)`). The closure body is type-checked with its param bound to
  the element/accumulator type — **no first-class function type** is introduced
  (closures can't be stored, returned, or passed around; that's a later cut).
- **`xs[i]` index sugar** → `Optional<T>` (lowers to `.at(i)`; out-of-bounds or
  negative is `none`, never a panic) — unwrap with `.or(default)`.
- **`List.contains(x)`** — element equality (models derive `PartialEq`; the interp
  does a deep value-compare). Lowered to a distinct `__list_contains` builtin so the
  type-blind backends don't confuse it with `String.contains` (different spelling
  per tier).
- **Tier & secret safety propagate into the closure for free — no new rule.** The
  body is checked in the enclosing fn's environment, so a `ui` closure still can't
  read a `secret` (R3) or surface one to the wire (R5), and R30 still trips on
  `raw(x)` over an element of a tainted list. Reuses **R21** for the closure/arity
  diagnostics. (Confirmed by `fail_closure_secret_leak`, which R3 rejects.)
- **Exact on every backend, verified to agree.** Interpreter evaluates the closure
  body per element in a child env; the ejected server lowers to
  `iter()/into_iter().map/filter().collect()` + `fold` (cloning the receiver so the
  source list survives); the browser uses `Array.map/filter/reduce` (reduce's
  `(callback, init)` order) and a structural `.some(JSON.stringify)` for
  `contains`. All three are checked against the same pipeline (interp unit + e2e
  tests, an ejected-crate parity test, and a bundled-in-node parity test).
- A closure over a `List<Decimal>` keeps spec-18 exact math (the lowering binds the
  param type before desugaring Decimal ops in the body).
- Fixtures `pass_map_filter_reduce` / `pass_index_contains` /
  `fail_filter_nonbool` / `fail_reduce_type` / `fail_closure_secret_leak`. Parser
  gains `Expr::Closure`/`Expr::Index` + a lexer save/restore for `(a, b) ->`
  backtracking; `xeres fmt` stays idempotent over the new syntax.

### `Decimal` Cut 2 — exact arithmetic + ordered comparison (spec 18)

`Decimal` (v0.5.3) could be constructed, displayed, and `==`-compared, but not
*computed* — `price * qty` and `subtotal + line` didn't type-check. This cut makes
`Decimal` a usable money type with **exact** arithmetic and ordered comparison,
never routed through binary `f64`.

- **Arithmetic + ordered comparison** — `Decimal + Decimal`, `Decimal - Decimal`,
  `Decimal * Decimal`, and `Decimal * Int` / `Int * Decimal` (exact integer
  scaling) now type-check and compute exactly, as do the ordered compares
  `< > <= >=`. Extends **R29** — no new rule.
- **Typed desugaring (the mechanism)** — both the interpreter's binary-op site and
  codegen's expression emitters are type-blind (a `Decimal` is a `String`, so a
  bare `+` would *concatenate* and `<` compare *lexicographically*). After
  type-checking, a new pass in the checker rewrites Decimal `+ - * < > <= >=` into
  explicit `__dec_*` builtin calls that every backend emits directly — no new
  value/AST shape, and the pattern generalizes to any future typed operator.
- **Exact on every backend, verified to the cent** — interpreter: a scaled-`i128`
  core (never `f64`); server (ejected): `rust_decimal` helpers behind a new,
  default-on `decimal` cargo feature; browser: a zero-dependency BigInt
  fixed-point runtime. All three are unit/parity-tested against the same cases
  (e.g. `0.1 + 0.2 == 0.3`, `19.99 * 2 == 39.98`, `10.00 > 9.99`).
- **Still a compile error (R29):** mixing `Decimal` with `Float`, `Decimal ± Int`
  (ambiguous — only `*` scales a Decimal by an Int), and `Decimal` *division* (it
  needs an explicit rounding mode — deferred to a later cut). `Decimal == Decimal`
  and `String + Decimal` display concatenation are unchanged (Cut 1).
- Fixtures `pass_decimal_arith` / `fail_decimal_float_add` / `fail_decimal_div`,
  interpreter unit + end-to-end tests, and `examples/cart.xrs` now computes a
  running subtotal.

## 0.5.12 — 2026-06-18 — fix: interpreter `.or` on a present Optional; dev RPC error logging

- **Fix (interpreter):** `optional.or(default)` on a *present* `Optional<String>`
  — which is a `Value::Str` at runtime — was matched against the String-method
  dispatch before `.or` was recognized, so it failed with "unknown String method
  `or`". `.or` is now resolved *before* the String/List dispatch, so
  `session.actor.or("")` (and any `Optional<String>.or(...)`) works in
  `xeres dev`/`serve`. The generated/ejected server was already correct (it checks
  `.or` first). Regression tests added in `src/interp.rs`.
- **DX:** `xeres dev`/`serve` now logs a failing server fn to the terminal
  (`xeres: rpc <name> failed: <error>`); previously a 500's cause only travelled in
  the HTTP response body, making it invisible in the dev console.

## 0.5.11 — 2026-06-17 — R33 db transactions (`transaction { … }`)

`db` was single statements (`query_one`/`query`/`exec`); a multi-statement write
couldn't be made atomic. `transaction { … }` now groups its `db` operations into
one all-or-nothing unit — the first half of the "db transactions + migrations"
work (migrations land next).

- **R33 transaction** — `transaction { db.exec(...) db.exec(...) }` runs the body
  as a single transaction: **commit on normal completion, roll back on any
  failure**. Server-only (it wraps `db`, R15) and not nestable. The rule is
  enforced in `server fn` bodies, `on load`, and ui handlers (where it's rejected).
- **One shared connection** — the db layer opened a fresh connection per call, so
  a transaction couldn't span calls. A `transaction` now parks one connection in a
  per-request slot for its duration; the body's `db.exec`/`query` reuse it (so
  they're part of the transaction), and a failure flips it to roll back. Outside a
  transaction, each call opens its own connection as before. Implemented
  identically in the `xeres serve` interpreter and the generated server.
- **Verified** — R33 fires on the fail fixtures (ui handler, nesting); both
  backends compile the transaction code (`cargo check` on the generated db server
  + `cargo check --features db` on the compiler). The emitted body is
  `{ tx_begin(); …; tx_end(); }` with the calls routed to the shared connection.
  (Live runtime against a Postgres needs DB access — the configured dev DB was
  unreachable from this build environment; the mechanism is standard
  BEGIN/COMMIT/ROLLBACK.)
- **Fixtures** — `pass_db_transaction` (a two-`exec` transfer), `fail_transaction_client`
  (`transaction` in a ui handler → R33), `fail_transaction_nested` (a nested
  transaction → R33).

Deferred to the next cut (still spec 11): **migrations** — versioned SQL applied
idempotently on boot. Plus, from the roadmap: transaction return-mapping for a
typed `let` nested inside control flow, and other DB engines.

## 0.5.10 — 2026-06-17 — R32 typed route params (`/post/:id`)

Routes were prop-less (R28: "a route can't supply props — fetch in `on load`").
Detail pages need a path segment bound to a typed prop. `ui screen Post(id: String)
route "/post/:id"` now does that, and the param is untrusted (R30) for free.

- **R32 route-param** — a `route "/post/:id"` clause binds each `:name` segment to
  a `String`/`Int` prop. The rule checks every `:name` names a prop, every prop is
  bound, param props are `String`/`Int` (parsed from a URL segment), the pattern
  has ≥1 param, and `route` is on a screen (not a component).
- **Deep-linking + in-app nav** — a reload or direct hit of `/post/123` boots
  `Post` with `id = "123"` (the client router matches the pattern and the screen
  reads the captured params, coerced by type). In-app you navigate with the params:
  `navigate(Post { id: x })`, which builds the URL from the pattern. This is the
  one relaxation of R28 — a route takes props *only* through a `route` pattern; a
  bare `navigate(Post)` to a param route is an R32 error.
- **Taint join is free** — a route param is a prop, so it's already in R30's
  untrusted set: `raw(id)` on a param is rejected with no new code.
- **Bugfix (deep-link assets)** — the generated `index.html` now loads the bundle
  from an absolute `/client.js`. A relative `./client.js` 404'd as
  `/post/client.js` on a nested deep link, leaving the app blank; this surfaced
  once multi-segment routes existed.
- **Fixtures** — `pass_route_param` (a `/post/:id` route + `navigate(Post { id })`),
  `fail_route_param_missing` (bare `navigate(Post)` → R32), `fail_route_param_raw`
  (`raw(id)` on a param → R30). Verified in a real browser: deep-link `/post/123`
  and in-app nav both render `id=123`/`id=42`.

Codegen/checker only — the router lives in the generated client (shared by both
run modes), so there's no interpreter change. Deferred (ROADMAP): declarative
`link -> Post { id }` (ambiguous in views today), query strings, and combining
param routes with `auth`.

## 0.5.9 — 2026-06-17 — R31 auth-gated routes (non-bypassable protected pages)

A screen could gate its *data* (an `auth server fn` consults `session`, R24/R25),
but the *page* rendered for anyone. `auth ui screen X { … }` now marks a protected
route, enforced on **both** tiers so it can't be reached without a session.

- **R31 auth-route** — `auth` before `ui screen` marks the route protected. The
  rule requires: the app establishes a session (some fn calls `session.login`),
  the screen is a prop-less route (not a component), and the **default route stays
  public** so unauthenticated users always have a landing/login page.
- **Two-tier enforcement** — the server **refuses to serve the protected route's
  shell** without a valid session cookie (a `302` redirect to `/`), so a deep link
  or hand-crafted request can't reach it; the client router does the same for
  in-app navigation, reading a non-secret `xeres_auth` flag cookie set alongside
  the signed session on `session.login`. The flag is only a UX hint — forging it
  reveals an empty shell, since protected *data* still needs the signed session
  (R24). Implemented identically in the `xeres serve` interpreter and the ejected
  server; verified live (unauthed `GET /dashboard` → 302 → `/`; authed → 200).
- **Plumbing** — `session.login`/`logout` now also set/clear the readable
  `xeres_auth` flag (both backends); `write_response` learned `302`/`Location`;
  the generated server gained an `is_protected_path` guard spliced into `dispatch`.
- **Fixtures** — `pass_auth_route` (public root + session + an `auth` dashboard),
  `fail_auth_route_no_session` (an `auth` screen with no session → R31),
  `fail_auth_on_component` (`auth ui component` → R31).

Deferred (ROADMAP): roles/permissions (RBAC, spec 15), an explicit login-screen
designation (Cut 1 redirects to the default route), per-route data prefetch.

## 0.5.8 — 2026-06-17 — List stdlib (length / first / last / at / reverse)

`List<T>` was iterate-only — `for x in xs` was the *only* way to touch a list, with
no count, no element access. This adds a small, closure-free List stdlib, mirroring
the String stdlib.

- **Methods** — `xs.length() -> Int`, `xs.first() -> Optional<T>`,
  `xs.last() -> Optional<T>`, `xs.at(i) -> Optional<T>`, `xs.reverse() -> List<T>`.
  All three backends (generated Rust, generated TS, and the `xeres serve`
  interpreter) implement them identically; verified by a live RPC round-trip.
- **Safe by default** — `first`/`last`/`at` return `Optional<T>`: an empty or
  out-of-bounds (or negative) read is `none`, never a panic or `undefined`. Unwrap
  with `.or(default)` (the same Optional discipline as `db.query_one`). So
  `xs.at(0)` can't be used where a plain `T` is required (R7/R11 catch it).
- **`.at(i)`, not `xs[i]`** — indexing is a method, reusing `Expr::MethodCall`, so
  Cut 1 adds **no new AST node and no new rule**. Argument discipline rides the
  existing R21 "stdlib" rule (`at` takes one `Int`; the rest take none). `xs[i]`
  sugar is a possible later nicety.
- **Type-blind codegen** — `.length()` lowers to a tiny `XLen` trait
  (`impl XLen for str` / `impl<T> XLen for [T]`) so the Rust backend needs no
  receiver-type info at the call site; TS uses the native `.length`/`Array.at`.
- **Fixtures** — `pass_list_methods` (all five methods, server + view),
  `fail_list_at_unwrapped` (returning `.at(0)` where `Int` is declared → R7).

Deferred (ROADMAP): `map`/`filter`/`reduce` (need expression-level closures),
`.contains` on lists (needs element equality / a `PartialEq` derive), `xs[i]`
sugar, slicing, in-place `push`/`pop`.

## 0.5.7 — 2026-06-17 — R30 inbound taint (`raw()` can't take request data)

The first cut of the reserved **information-flow layer** — the inbound mirror of
the existing secret-*out* flow (R5). Xeres already makes SQLi (R23), SSRF (R26),
and stored/secret-in-log (R27) inexpressible, and escapes all view output by
default (R22). The one remaining reflected-XSS hole was the audited un-escape
sink, `raw(...)`: nothing stopped `raw(userInput)`. **R30** closes it.

- **R30 raw-taint** — `raw(...)` may not wrap **untrusted inbound data**. The
  untrusted sources of a view are deliberately small and explicit (over-tainting
  erodes trust): a screen/component's **props** (they arrive from the caller /
  over the wire) and any **`state` cell bound to an input** (`bind cell` — the
  user types into it). Taint propagates structurally — field access, operators,
  records, ternaries, string methods (`.upper()` doesn't launder), and a `for`
  binding over a tainted source. A `raw()` wrapping such a value is a compile
  error.
- **The escape hatch is the secure one** — values that aren't request-derived
  stay clean: string literals, and a `state` cell populated from an `await`ed
  `server fn` (`state safe = ""` filled in `on load` from `await render(...)`,
  then `raw(safe)`). So rendering genuinely-trusted HTML is expressible, but the
  trust has to come from the server, not from raw client input.
- **Local + conservative** — each screen/component is checked against its *own*
  untrusted sources (a component's props are untrusted inside it), so no
  interprocedural flow is needed, and like R7/R18 the rule only fires on provable
  taint. Implemented as a self-contained checker pass (`check_raw_taint` in
  `src/checker.rs`) — no new syntax, no codegen/runtime change, so both run modes
  are unaffected.
- **Fixtures** — `pass_raw_trusted` (literal + server-`await`ed state compile),
  `fail_raw_tainted` (a `raw()` of an input-bound `state`), `fail_raw_prop` (a
  component `raw()`-ing a prop). The existing `pass_raw_sink` (a `raw()` of a
  non-bound literal state) stays green.

Deferred (noted in ROADMAP): a dedicated in-view `sanitize(...)` launder, taint
into the outbound `endpoint` body/path, and a fuller multi-level taint lattice.
`declassify` stays secret-out / server-only (R6) — untrusted-in is a separate
dimension on purpose.

## 0.5.6 — 2026-06-17 — field-level sync merge

Synced collections now merge **last-write-wins per field** instead of per row,
closing the headline correctness gap called out since v0.1 ("sync is
last-write-wins; field-level CRDT planned"). Two clients editing *different*
fields of the same row both keep their edit — neither clobbers the other.

- **Per-field stamps** — a synced row is stored as a map of `field -> cell`,
  where each cell carries the field's value plus its own Lamport stamp and a
  stable per-client **site id**. The merge is field-by-field: the higher Lamport
  wins; equal Lamports are broken deterministically by the greater site id, so
  every replica converges regardless of arrival order. Only the fields a write
  actually changed get a fresh stamp, so a concurrent edit to a *different* field
  survives (the old whole-row LWW lost it).
- **Tombstone deletes** — a delete is a row-level tombstone with its own stamp.
  A row stays visible unless its tombstone dominates every field stamp, so a late
  (lower-stamped) write can't resurrect a deleted row, while a genuinely-later
  re-add (a strictly higher stamp) cleanly revives it.
- **Identical merge in both run modes** — the new merge is implemented twice from
  one design: the `xeres serve` interpreter path (`src/serve.rs`) and the ejected
  Rust server (`SYNC_SERVER` in `src/codegen.rs`). The client store
  (`SyncedCollection` in the generated `client.ts`) tracks the same per-field
  cells, sends only changed cells, and applies pulled cells with the same total
  order. A new Rust test module (`src/serve.rs` `sync_tests`) drives
  `sync_dispatch` with crafted concurrent payloads and asserts convergence:
  different-field edits both survive, same-field is LWW by Lamport, ties break by
  site, and delete tombstones resist late writes.
- **The API is unchanged** — `synced state x: Collection<M>`, `x.add/remove/get/
  all`, `for x in xs`, and the subscribe→redraw path are all the same. Only the
  collection's internal representation and the sync wire shape changed.
- **⚠ Breaking sync-protocol bump** — the on-the-wire and on-disk (localStorage)
  sync format changed from whole-row `put`/`del` blobs to field-level `set`/`del`
  cells (`{kind, id, field, value, lamport, site}`). The in-memory dev store has
  no migration; the browser store is namespaced under a new key
  (`xeres:<name>:v2`), so stale v1 snapshots are ignored rather than mis-parsed.
  No persisted production data exists yet, so this is a clean break. Still
  last-write-wins per field, **not** a full CRDT — true CRDTs (RGA/LSEQ text,
  cr-sqlite) remain on the roadmap under "Later".

## 0.5.5 — 2026-06-16 — `xeres fmt` (canonical formatter)

A `xeres fmt <file.xrs>` subcommand that reprints a program in one canonical
style (in place, or `--check` for CI). One style ⇒ no bikeshedding, clean diffs.

- **Token-stream formatter** — `fmt` lexes the source (it doesn't go through the
  AST, which buckets declarations by kind and carries no statement/expression line
  numbers — so an AST printer couldn't preserve declaration **order** or
  **comments**). Working from the token stream keeps both for free. It's a pure
  function of the source text, so it formats files that don't type-check
  (format-on-error) and is decoupled from the checker/codegen.
- **Comment-preserving, with zero compile-path risk** — the lexer gained a
  `keep_comments` builder (off by default, so the parser/compile path is
  byte-for-byte unchanged) and a `Token::Comment`; only `fmt` turns it on. Leading
  comment blocks stay attached to the declaration they document.
- **What it normalizes** — 2-space indentation by `{}`/`[]`/`()` nesting; one
  space around binary operators / after `:` and `,`; no space inside `()`/`[]`,
  around `.`, or inside `List<…>`/`Optional<…>` generics; `model`/`enum`/
  `endpoint` members one per line; one blank line between top-level declarations
  (runs collapsed); no trailing whitespace; a single trailing newline. `style
  "…css…"` strings are left verbatim (CSS isn't reflowed). It preserves your line
  breaks for statements and view nodes (it won't join or force-split them).
- **Idempotence is the correctness bar** — `fmt(fmt(x)) == fmt(x)`, verified by a
  new `tests/fmt.rs` over the entire `tests/*.xrs` corpus; the existing examples
  were reformatted in place to dogfood it. No new dependency, no parser change.

## 0.5.4 — 2026-06-16 — typed numeric inputs (`number`)

A `number` form control that binds an `Int`/`Float` state cell directly — closing
the last papercut in the v0.5 form-controls work, on the same "a typed field
yields a typed value" theme as `Decimal`.

- **`number` input (extends R13)** — `number bind qty` binds a numeric `state`
  cell straight across, instead of forcing the dev to bind a `String` and parse
  by hand. `number` lowers to `<input type="number">`; the runtime coerces the
  DOM value back to a real JS number on write (`valueAsNumber`, with empty → `0`),
  so a `state qty: Int = 1` stays an `Int` and `qty * price` in the view is real
  arithmetic. Value reflection (`value="${qty}"`) and the `data-bind` wiring reuse
  the existing control machinery.
- **R13 is now three-way** — `checkbox` binds a `Bool`, `number` binds an `Int`
  or `Float`, and every other control (`input`/`password`/`textarea`/`select`/
  `radio`) binds a `String`. Binding a `number` to a non-numeric cell is a compile
  error (symmetric to the existing checkbox rule).
- **Deliberately not `Decimal`** — a `number` input yields a binary float
  (`valueAsNumber`), so it is *not* allowed to bind a `Decimal`; that would
  reintroduce exactly the float error `Decimal` (R29) exists to prevent. Money
  stays text-entry + `decimal("..")`. `input` also stays `String`-only — numeric
  binding is opt-in via the `number` tag, keeping the type obvious from the tag.
- Verified: `examples/order.xrs` builds, `xeres serve` bundles via esbuild and
  serves `<input type="number">` bound to numeric state with live `valueAsNumber`
  coercion. No new dependency, no parser change.

## 0.5.3 — 2026-06-16 — `Decimal` money primitive

The last missing "extended primitive": an exact, string-backed `Decimal` for
money and other exact fractions, kept type-distinct from `Float` so the two can
never silently mix.

- **`Decimal` type + `decimal("..")` constructor** — `decimal("19.99")` builds a
  string-backed exact value (carried as a decimal *string* over the wire / DB /
  interpreter, mirroring how enums are string-backed), so the browser tier stays
  zero-dependency and money values never pass through binary floating point.
  Following the `DateTime` playbook, it needs **no lexer/parser change** — the
  constructor is an ordinary builtin (like `now()`). `Decimal` is usable in model
  fields, RPC args, and DB columns, and is implemented identically in **both run
  modes** (the generated Rust server and the `xeres serve` interpreter): a
  `Decimal` field maps to a Rust `String` / TS `string` and serializes as a JSON
  string.
- **Type-safe by construction (R29)** — `decimal(...)` takes exactly one
  `String`; a `Float`/`Int` argument is a compile error. And because assignability
  never widens into `Decimal`, assigning a `Float` (or `Int`) to a `Decimal` — or
  passing one where a `Decimal` is expected — is rejected (R11/R7). This is the
  whole point: no silent float error in money math.
- **Cut 1 scope** — construct, display (string concatenation, e.g. `"Total: $" +
  total`), and `==`/`!=`. **Arithmetic (`+ - *`) and ordered comparison (`< > <=
  >=`) are a deliberate follow-up** (Cut 2 — server-side `rust_decimal`,
  browser-side fixed-point) noted in ROADMAP. Verified: `examples/cart.xrs` builds
  and `xeres serve` renders `Total: $19.99`, bundles via esbuild, and ejects to a
  Rust crate where the field is a `String`.

## 0.5.2 — 2026-06-16 — app-server TLS

Optional, first-class HTTPS — the always-on HSTS header and `Secure` cookies both
servers already promise stop being aspirational, with no TLS proxy in front.
(Also ships the previously-unreleased ejected-`session` run-mode parity, below.)

- **App-server TLS (`xeres serve --tls`)** — the `serve` runtime can now
  terminate HTTPS directly. With `TLS_CERT`/`TLS_KEY` pointing at PEM files,
  `xeres serve --tls <app>.xrs` listens on TLS and serves `https://`; the
  always-on `Strict-Transport-Security` header finally becomes truthful. Built on
  **pure-Rust `rustls`** (the `ring` backend — no OpenSSL/system deps; the app
  listener's TLS is independent of the `native-tls` the `db` Postgres client
  pulls in). The connection handler was generalized over `Read + Write`, so one
  code path serves either a raw `TcpStream` (plain HTTP — the default, unchanged)
  or a `rustls` stream; `xeres serve` with no flag is byte-for-byte as before. The
  **ejected server** gains the same HTTPS behind an opt-in `tls` cargo feature
  (`cargo build --features tls`, reading the same env), with `rustls` an optional
  dep so a default build of the emitted crate stays HTTP-only and lean. Verified
  end-to-end on both run modes: `curl -k https://127.0.0.1:8080/` → `200` carrying
  `Strict-Transport-Security`. HTTP→HTTPS redirect, ACME/Let's Encrypt, and HTTP/2
  are deferred (see ROADMAP "Later").

- **Ejected `session` support (R24, run-mode parity)** — `xeres build` no longer
  emits a `compile_error!` for a program that touches `session`; the generated
  std-only server now threads the same HMAC-SHA256–signed `xeres_session` cookie
  the interpreter does. The signer/verifier is a verbatim port of `src/interp.rs`,
  so the cookie is **byte-identical across run modes** — one minted by `xeres
  serve` verifies under `xeres build` and vice-versa. The actor is recovered from
  a verified cookie into a per-request store and read by `session.actor`;
  `session.login(id)` / `session.logout()` record a pending `Set-Cookie`
  (`HttpOnly; Secure; SameSite=Strict`) emitted after the call. Crypto rides the
  existing `auth` feature (the generated `Cargo.toml` gains `hmac`/`sha2` as
  optional `auth`-feature deps; a non-`auth` build gets the same inert stubs as
  the interpreter). Proven live: built the emitted crate with `--features auth`,
  logged in, confirmed the signed cookie round-trips (`session.actor` returns the
  actor) and a tampered cookie is rejected. No language-surface or checker change
  (R24/R25 already cover the failure modes); reuses the `pass_session` fixture.

## 0.5.1 — 2026-06-16 — client router (P2)

Multi-screen apps with real URLs and zero framework runtime.

- **Client router (P2)** — multi-screen apps with real URLs, no framework
  runtime. `navigate(Screen)` switches the mounted screen from a handler /
  `on load`; `link "Label" -> Screen` renders an `<a href>` that navigates with
  **no full reload** (the click is intercepted, `pushState` syncs the URL). Each
  prop-less, non-component screen is a route — the first is `/`, the rest
  `/<name>` — so Back/Forward (`popstate`) and deep-linking / reload both land on
  the right screen, and a screen's `on load` now runs whenever it's navigated to
  (generalizing P1's mount hook). Deep links survive a reload via an
  **SPA fallback**: an extension-less path that isn't a real file serves
  `index.html` (in both the `xeres serve` runtime and the ejected server), while
  a missing asset stays a `404`. New rule **R28**: a navigation target must be a
  known, *prop-less, non-component* screen (a route can't supply props), and the
  imperative `navigate(...)` is browser-only. Browser-tier only — no new server
  surface, the boundary is unchanged. Fixtures: pass_router, fail_nav_unknown,
  fail_nav_props; example [`examples/router.xrs`](examples/router.xrs).

## 0.5.0 — view & navigation primitives (P3 form controls)

The remaining capability gaps for line-of-business apps.

- **Form controls (P3)** — `textarea` (bind `String`, multiline; value is the
  element content), `checkbox` (bind `Bool`, reflected via `checked`, read from
  `node.checked`), `image` (escaped `src`), `select` (renders `<option>`s from a
  list arg; the bound `String` is the selected one), and `radio` (a grouped set
  from a list arg). All route through the R22 escape path; **R13 is type-aware**
  (`checkbox` needs `Bool`, the rest `String`); list-literal args are now allowed
  in views. Fixtures: pass_form_controls, pass_select, pass_radio,
  fail_checkbox_string. (`link` shipped with the **client router**, above.)

## 0.4.0 — 2026-06-15 — security wave 2 (CSRF, R26 SSRF, R27 logging) + on-load

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
