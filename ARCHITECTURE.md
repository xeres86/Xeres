# Xeres architecture — the two-layer trust model

Xeres has one job: make the dangerous things in a web app **inexpressible**
rather than merely discouraged. Secrets that must not reach the browser, database
access that must stay on the server, a dependency that must not phone home — in
Xeres these are not lint rules or review checklists. They are properties the
compiler proves, so a program that violates one **does not compile**.

Two ideas carry that weight, and the boundary between them *is* the trust model.

---

## 1. The tier boundary (the moat)

One `.xrs` file compiles to **two tiers** — a Rust server and a browser bundle —
under one type system. The split is enforced by the compiler ([`src/checker.rs`](src/checker.rs)),
not by convention:

- **`secret` containment** — a `secret` model field never crosses the wire (it is
  stripped from the client model and the wire codec by construction), and
  secret-derived data can't be returned from a non-`server` function (R3/R5) or
  logged (R27). `declassify(...)` is the single audited, greppable downgrade.
- **`Located` capabilities** — `db`, `session`, and `endpoint` (egress) are
  *server-only*. The DB connection, the signed session, and an outbound host +
  its bearer secret physically cannot appear in browser code (R15/R24/R26).
- **Tier-typed functions** — a `server fn` becomes a typed RPC stub on the
  client; a `ui` function/screen is browser-only. You never hand-write a `fetch`,
  and you can't accidentally run server logic in the browser.

Type-safety is the foundation; **tier-safety is the moat** — no mainstream
language enforces the server/client boundary in its type system. Rules R1–R33
make up this layer. See [`README.md`](README.md) and the rule list in the
checker.

---

## 2. The two layers: native core (TCB) + Xeres packages

The second idea is about **where code — and therefore vulnerability — lives.**

### Layer 1 — the native core is the Trusted Computing Base

The compiler exposes a small, fixed set of **unforgeable primitives** — only the
things that genuinely *cannot* be written safely in a high-level language:

- crypto: `hash()` / `verify()` (Argon2id), the HMAC-SHA256 session signer
  (`argon2`, `hmac`, `sha2`);
- TLS: the app's HTTPS listener (`rustls`, `ring` backend);
- the Postgres driver (`postgres` + `native-tls`);
- outbound HTTP for declared `endpoint`s (`ureq`);
- the raw HTTP socket and the interpreter/codegen themselves.

These are **vetted, pinned, feature-gated** Rust crates, exposed to Xeres **only**
as `Located` capability builtins. This layer is the program's *whole*
vulnerability surface. The discipline:

- keep it **small** and **pinned**;
- **`cargo audit`** it (the 0.5.13 release shipped the postgres-chain DoS fix this
  way — RUSTSEC-2026-0178/-0179/-0180);
- **never hand-roll crypto.**

### Layer 2 — the standard library and packages are written in Xeres

Everything that *can* be written safely in a high-level language **is**:
collections, validation, date/money helpers, formatting, UI component kits, and
all business logic. Each is `.xrs` source compiled under the same R1–R33 rules as
your app. A package therefore has **no ambient authority** — it can touch `db`,
egress, or a secret **only** if the importing app passes it that capability, and
the compiler checks it.

The vulnerability footprint of the package ecosystem is, by construction, **~0**:
a package is just more checked Xeres. There is no `require('child_process')`, no
`postinstall` script, no native addon — none of it is expressible.

---

## 3. Modules enforce the boundary (spec 20)

The module system ([`src/loader.rs`](src/loader.rs)) is what makes Layer 2 real.
A module is a file; the program is the merged graph. The loader resolves
`import "…"` edges, detects cycles, and merges every file into one
`XeresProgram` **before** the checker runs — so the tier/secret rules above
compose across files for free (a module cannot widen the boundary, because by the
time the checker runs there is no boundary, only one program).

Two rules are added, enforced while module identity is still known:

- **R35 module-visibility** — only `pub` declarations cross a boundary. A
  qualified call `money.cents(...)` must target a `pub fn`; a non-`pub` helper is
  module-private. (Mirrors Rust.)
- **R34 module-capability** — *the supply-chain guarantee.* An imported module
  that uses a `Located` capability must **declare** it (`requires db` at the
  module head) **and** the importing app must **grant** it (`import "m.xrs" grant
  db`). A dependency reaching for authority it didn't declare, or wasn't granted,
  **does not compile.** The entry app is the root of authority and is never gated.

```xeres
// repo.xrs — a dependency. Its authority is written down.
requires db
pub server fn purge() -> Int { return db.exec("DELETE FROM sessions") }

// app.xrs — the app authorizes that authority, explicitly.
import "repo.xrs" grant db
server fn admin() -> Int { return repo.purge() }
```

A `left-pad` / `event-stream` / `xz`-style attack — a dependency that quietly
exfiltrates data or touches the database — is **inexpressible**: the malicious
authority would have to appear as a `requires` in the package *and* a `grant` at
the import site, where an auditor (or a diff) sees it.

---

## The governing rule

> Anything expressible in safe Xeres must be Xeres; only unforgeable primitives
> earn a native-core builtin.

That single rule keeps Layer 1 (the audited TCB) tiny and pins the entire attack
surface to it, while letting Layer 2 (everything else) grow without growing the
risk.

---

## Status and cuts

**Shipped (spec 20, Cut 1):** local multi-file modules, `pub` exports, `import` /
`requires` / `grant`, R34 + R35, tier/secret composition across the merge, a
single merged server crate + client bundle. Verified across all three backends
(interpreter, ejected Rust, esbuild bundle).

**Shipped (spec 20, Cut 2 — multi-file types/components/screens):** the `pub`
+ import discipline now applies to **all** declaration kinds — `pub model`,
`pub enum`, `pub ui component`, `pub ui screen` — not just functions. The
"import a Badge into the dashboard" / "import a UserProfile model" feature. A
type-visibility pass in the loader walks every type reference in the merged
program (model field types, fn params/returns, screen props, state decls,
`let` annotations, record literals, component invocations, enum-variant access,
bare `navigate(Screen)` / `link "..." -> Screen` references). Cross-module
*type* names are **unqualified** (JSX/Python-style import); functions keep the
qualified `mod.fn(...)` from Cut 1 — *functions are called, types are named*.
This also closes the type-level R35 gap flagged in the codebase review.

**Shipped (spec 20, Cut 1.5 — the Layer-2 proof):** the first self-hosted stdlib
modules, [`std/math.xrs`](std/math.xrs) and [`std/text.xrs`](std/text.xrs),
written in Xeres and **compiled into the compiler binary** (`include_str!`).
`import "std:math"` resolves to embedded source rather than a file; the modules
declare **no `requires`**, so they have zero ambient authority — Layer 2 made
real. They are checked under the same R1–R33 rules and run on both tiers (pure
functions). A dogfooding finding worth recording: the Rust backend currently
**moves** a non-`Copy` argument (`List`/`String`) into a call, so a value can't be
reused after being passed to another function — the stdlib is written around it
(pass-as-last-use); a liveness-based clone/borrow in codegen is the proper fix and
a good next cut.

**Deliberately deferred (later cuts):** a package **registry**, an `xeres.toml`
**manifest**, **semver** resolution and **remote/cached** packages, package
**signing**; `module__name` **mangling** (so private helpers may share a name
across modules); per-module separate compilation; re-exports / glob imports /
nested namespaces; capability **attenuation** (granting a *narrowed* `db`); and
growing the self-hosted `std/*.xrs` library (more modules, and migrating the
native String/List builtins that are expressible in Xeres). Imports are local
files + the embedded `std:` scheme only — but the syntax is shaped so these slot in.
