# Xeres security model

Xeres's central claim is that the server/client tier boundary is **compiler-enforced**:
a secret can't reach the browser, an untrusted value can't reach a raw SQL string or
an unescaped HTML sink, and a dependency can't reach for authority it wasn't granted.
This document is the mechanically-checked evidence for that claim, not a promise —
every row below is validated by a fixture, unit test, or CI job, verified by re-running
them (spec 29's security pass, `_specs/29-security-pass.md`).

## Reporting a vulnerability

Open a GitHub issue or contact the maintainer directly for anything sensitive. There
is no bug bounty; a clear repro (ideally a minimal `.xrs` fixture) is the fastest path
to a fix.

## Supply chain: `cargo audit` in CI

Every push/PR runs a `security` job (`.github/workflows/ci.yml`) that installs
`cargo-audit` and runs it against the committed `Cargo.lock`. Plain `cargo audit`
(no `--deny warnings`) fails the build on a real RUSTSEC **vulnerability**;
maintenance-status **warnings** (unmaintained, notice) print but don't block —
advisory-gating, not version-pinning. `cargo-deny` (license/duplicate-version
checks) is deliberately out of scope for this pass.

**Known, triaged, non-blocking warnings** (re-check when bumping dependencies):
- `RUSTSEC-2025-0134` — `rustls-pemfile` is unmaintained. Used once, at startup,
  to parse a `--tls` cert/key pair from disk (`src/serve.rs::load_tls`); not on
  the request path.
- `RUSTSEC-2026-0190` — unsoundness in `anyhow::Error::downcast_mut()`. `anyhow`
  is not a direct dependency of this crate at all (`cargo tree -i anyhow` finds
  nothing in the default or `full` feature sets) — it's pulled in transitively
  by WASM component-model tooling several layers down, unrelated to any code
  path this binary executes.

## The R1–R37 rule coverage matrix

Every rule is enforced in `src/middle/checker.rs` unless noted, pushed as a
`Diagnostic { rule: "Rxx name", .. }`. Fixture columns are ground truth — each
`fail_*.xrs` was re-run against the compiler while writing this table (`xeres
build tests/fail_*.xrs`, checking the rule actually printed, not just the
filename/comment). `pass_*.xrs` shows one representative fixture that exercises
the rule's non-violating path; most fixtures/examples exercise several rules at
once (they're small realistic apps, not one-rule-per-file), so this is
illustrative, not exhaustive, for the pass side.

| Rule | What it stops | Enforced at | Fail fixture | Pass fixture |
|------|----------------|-------------|---------------|---------------|
| R1 unknown-type | a field/param/return names a type that doesn't exist | checker.rs:625 | fail_unknown_type.xrs | pass_basic.xrs |
| R2 duplicate-decl | two decls (model/screen/enum/style/token/…) share a name | checker.rs:571 | fail_dup_screen.xrs | pass_basic.xrs |
| R3 secret-containment | a `secret` model field is read outside `server` code | checker.rs:1725 | fail_screen_secret.xrs | pass_db.xrs |
| R4 async-call-discipline | a `server fn` is called from the browser without `await` | checker.rs:2675 | fail_await_missing.xrs | pass_await.xrs |
| R5 secret-leak-via-return | a fn's return is secret-tainted with no safe path to the wire — **two branches**: (a) a non-`server` fn returns tainted data at all; (b) *(spec 29 finding)* a `server` fn returns a **bare scalar** built from a secret field with no `declassify(...)` — a Model return is exempt (field-level wire-stripping already covers it) | checker.rs:3219 | (a) fail_secret_in_ui.xrs, fail_secret_return_via_call.xrs · (b) fail_secret_scalar_leak.xrs | pass_wire_strip.xrs (a, Model) · pass_secret_scalar_declassified.xrs (b, scalar+declassify) |
| R6 declassify-context | `declassify(...)` used outside `server` code | checker.rs:1844 | fail_declassify_client.xrs | pass_declassify.xrs |
| R7 return-type | a `return` doesn't match the declared return type | checker.rs:804 | fail_return_type.xrs | pass_basic.xrs |
| R8 unknown-binding | a view references an identifier that isn't in scope | checker.rs:1481 | fail_screen_unknown.xrs | pass_basic.xrs |
| R9 record-construction | a record literal is missing/mistypes/misnames a field | checker.rs:1906 | fail_record_missing.xrs | pass_construct.xrs |
| R10 sync-key | a `synced state` collection's model has no `id: String` | checker.rs:3011 | fail_sync_nokey.xrs | pass_synced_screen.xrs |
| R11 state-init | a `state` cell's init expression doesn't match its declared type | checker.rs:879 | fail_decimal_float.xrs | pass_basic.xrs |
| R12 collection-method | a synced-collection method (`.all()`/`.get()`/…) misused server-side | checker.rs:2597 | fail_collection_server.xrs | pass_collection_write.xrs |
| R13 input-binding | `bind x` without a matching, correctly-typed `state` cell | checker.rs:1174 | fail_bind_nonstate.xrs | pass_input_bind.xrs |
| R14 if-condition | an `if`/`while`/ternary condition isn't `Bool` | checker.rs:710 | fail_if_type.xrs | pass_if.xrs |
| R15 db-capability | `db` used outside `server` code (a `Located` capability) | checker.rs:2041 | fail_db_in_ui.xrs | pass_db.xrs |
| R16 try-context | `try`/`catch` used outside `server` code | checker.rs:689 | fail_try_server.xrs | pass_try.xrs |
| R17 component | a component invocation is malformed (unknown, lowercase, bad args) | checker.rs:1274 | fail_component_unknown.xrs | pass_component.xrs |
| R18 conditional-branch | a ternary's two branches have incompatible types | checker.rs:1961 | fail_ternary_branch.xrs | pass_ternary.xrs |
| R19 auth-builtin | `hash`/`verify` used outside `server` code | checker.rs:1800 | fail_hash_in_ui.xrs | pass_auth.xrs |
| R20 match | a `match` scrutinee/arm references an unknown enum variant, or isn't exhaustive | checker.rs:85 | fail_match_nonexhaustive.xrs | pass_enum_match.xrs |
| R21 stdlib | a List/String stdlib method is misused (arity, receiver, non-bool predicate) | checker.rs:1987 | fail_filter_nonbool.xrs | pass_list_methods.xrs |
| R22 view-escaping | every interpolated view value is HTML-escaped by default | codegen.rs (structural — see below) | *(no fail fixture: unconditional, not a rejection)* | pass_escape.xrs |
| R23 sql-literal | a `db` query string isn't a literal (blocks SQL injection by construction) | checker.rs:2062 | fail_sql_concat.xrs | pass_db.xrs |
| R24 authn-required | an `auth fn` doesn't run server-side or never reads `session` | checker.rs:2213 | fail_session_in_ui.xrs | pass_session.xrs |
| R25 actor-scope | a protected `auth` fn's `db` query doesn't bind the actor (anti-IDOR) | checker.rs:2301 | fail_idor_no_owner.xrs | pass_owner_scope.xrs |
| R26 egress-allowlist | outbound HTTP used outside a declared `endpoint` (anti-SSRF) | checker.rs:2087 | fail_endpoint_path.xrs | pass_endpoint.xrs |
| R27 log | a secret value is passed to `log.*` | checker.rs:2159 | fail_log_secret.xrs | pass_log.xrs |
| R28 navigation | `navigate(...)`/`link` targets an invalid or non-navigable screen | checker.rs:1192 | fail_nav_unknown.xrs | pass_router.xrs |
| R29 decimal | `Decimal` arithmetic mixes with `Float`, or `/` (no rounding mode) | checker.rs:1773 | fail_decimal_float_add.xrs | pass_decimal_arith.xrs |
| R30 raw-taint | `raw(...)` wraps untrusted (prop/bound-input) data — closes the reflected-XSS hole R22 leaves open by design | checker.rs:1031 | fail_raw_tainted.xrs | pass_raw_trusted.xrs |
| R31 auth-route | an `auth ui screen` is a component, takes props, has no session source, or is the default route | checker.rs:3103 | fail_auth_route_no_session.xrs | pass_auth_route.xrs |
| R32 route-param | a `route "/x/:id"` pattern/prop mismatch, non-String/Int param, or no `:param` | checker.rs:1368 | fail_route_param_missing.xrs | pass_route_param.xrs |
| R33 transaction | `transaction { }` used client-side or nested | checker.rs:760 | fail_transaction_nested.xrs | pass_db_transaction.xrs |
| R34 module-capability | an imported module uses `db`/`session`/`endpoint` without `requires` + `grant` | loader.rs:158 | fail_module_undeclared_cap.xrs | pass_module_grant.xrs |
| R35 module-visibility | a cross-module reference to a non-`pub` decl, or an unimported module | loader.rs:115 | fail_import_private.xrs | pass_import_model.xrs |
| R36 api-route | an `api` route's path/method/body structure is invalid, or routes collide | checker.rs:583 | fail_api_get_body.xrs | pass_api_get.xrs |
| R37 unknown-token | `token(x)` / `style Name` references an undeclared theme token or named style | checker.rs:492 | fail_unknown_token.xrs | pass_theme_tokens.xrs |

**R22 is structural, not a rejection rule** — there is no `raw` HTML sink besides
`raw(...)` (grep-verified: view value emission always routes through `__esc(...)`
in `node()`/`link_node()`, `src/backend/codegen.rs`), so no program can violate
it; there is nothing to reject. R30 is the rule that *does* reject something —
it closes the one way R22's designed escape hatch (`raw(...)`) could be misused.

## The secret-on-wire property

The property that makes the tier model credible: **a `secret` model field's
*value* never appears in JSON sent to a client**, on either surface a client can
reach — the `/__xeres/<fn>` RPC endpoint and an inbound `api` route response —
regardless of whether the value came from a literal, `db`, or a decoded external
`endpoint` response (wire serialization strips by field marker, not by data
provenance).

This is asserted two ways:
- **Compile time (R5):** `tests/fail_secret_scalar_leak.xrs` / `tests/
  pass_secret_scalar_declassified.xrs` — a `server fn` may not return a bare
  secret-derived scalar undeclassified.
- **Runtime, mechanically, both wire surfaces, in one test:**
  `interp::tests::secret_never_crosses_the_wire` (`src/interp.rs`) — builds an
  app with a `secret`-bearing model, calls it through both the RPC path
  (`Interp::call` + `wire_json`) and an `api` route (`call_api_route` +
  `wire_json`), and asserts the serialized JSON contains the non-secret field
  value but never the secret one. **Mutation-tested**: temporarily disabling
  the `!p.is_secret` filter in `wire_json` (`src/interp.rs`) turns this test
  red with the leaked value in the panic message — it isn't a tautology.
- **Ejected server, by construction:** `gen_server`'s `to_wire_json` (`src/
  backend/codegen.rs`) omits `secret` fields from the generated serialization
  code entirely — they are never emitted into the wire-JSON builder, not
  filtered from it at runtime. Verified by code inspection (not yet a
  compiled-and-curled integration test — that's real added confidence, but a
  materially heavier one than the interp-side test given it requires actually
  building the generated Rust crate; noted as a gap below).

### Finding from this pass (fixed, not just documented)

Before this pass, a `server fn` could return a bare secret-derived **scalar**
(e.g. `server fn get_hash(u: User) -> String { return u.password_hash }`) with
**zero** compiler errors — R5 only restricted *non*-server functions, on the
(sound-for-Models, unsound-for-scalars) assumption that wire-projection would
strip a `secret` value automatically. Confirmed live: `xeres serve` on this
exact program, then `curl`ing `/__xeres/get_hash` with a valid CSRF token,
returned `"TOPSECRET123"` verbatim. R5 now also rejects this (the `(b)` branch
in the matrix above); `declassify(...)` remains the deliberate opt-out, exactly
as R5's own error message always recommended (it just wasn't enforced).

## Out of scope for this pass

Deferred, per `_specs/29-security-pass.md`: a formal soundness proof, pen-testing
the HTTP host, `cargo-deny`/SBOM/supply-chain signing, and a compiled-and-curled
integration test of the *ejected* server's wire output (today verified by code
inspection + the interp-side property test, which shares the same checker gate).
