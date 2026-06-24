# Xeres

**A tier-safe web language.** You write one `.xrs` file; the Xeres compiler
splits it into two tiers — a **Rust server** and a **browser bundle** — under a
single type system. The server/client boundary is enforced by the **compiler**,
not by convention: secrets and server capabilities *physically cannot* reach the
browser. Local-first by default. Zero framework runtime in the browser.

> Status: **v0.5.11**. See [CHANGELOG.md](CHANGELOG.md) for what's in it and
> [ROADMAP.md](ROADMAP.md) for what's next.

---

## Why Xeres exists

Modern web stacks make the most security-critical thing in the app — the line
between **server** and **client** — a matter of *discipline*:

- In Next.js you must remember `"use client"` / `"use server"` and never let a
  DB handle or secret drift into a client component.
- In React + a backend you hand-write an API, duplicate types across the wire,
  and remember to `select` only safe columns.
- A leaked password hash or API key is a **code-review item**, not a build error.

Xeres makes that boundary a **type**. A secret reaching the browser isn't a bug
you hunt for — it's a program that **doesn't compile**.

**Goals (in priority order):**
1. **Security** — the server/client boundary is compiler-enforced.
2. **Speed** — a small native server, a tiny browser bundle, no framework runtime.
3. **Familiar, low-friction syntax** — one file, declarative views, no boilerplate.
4. **A small dependency tree** — the browser tier ships **zero** dependencies; the
   server adds a dependency only when you actually use one (e.g. a DB driver).

See [COMPARISON.md](COMPARISON.md) for the same app written in Xeres vs
React/Vue/Svelte/Next/Angular, and the [cookbook](docs/cookbook.md) for
copy-pasteable recipes.

---

## The core idea: two tiers, one type system

Every function and screen declares **where it runs**:

| Placement | Runs | Compiles to |
|---|---|---|
| `server fn` | the server | Rust |
| `ui screen` / `ui fn` | the browser | TypeScript → JS |
| `fn` (unscoped) | either (shared) | both |

Two orthogonal properties make the boundary safe:

- **Placement** — where code executes (above).
- **Transport** — whether a *value* may cross the wire. Ordinary data crosses
  freely; `secret` fields and the `db` capability are **`Located`** — they have
  no wire representation and cannot be serialized to the browser.

A `ui` call to a `server fn` is automatically an **`await`-ed RPC**: the compiler
generates the fetch, serializes arguments, and **strips `secret` fields from the
response** — so the wire payload physically lacks them.

---

## Quickstart

**The fast path — Node 18+ only.** No global install, no `PATH`, no Rust
toolchain: `npm install` downloads the prebuilt `xeres` compiler and
[esbuild](https://esbuild.github.io/) into `node_modules`.

```bash
npm create xeres@latest my-app
cd my-app
npm install          # pulls the xeres compiler + esbuild
npm run dev          # = `xeres dev app.xrs`
```

(Contributors building the compiler from source instead: see
[Building the compiler](#building-the-compiler).)

Open **http://127.0.0.1:8080**.

`xeres dev` compiles `app.xrs`, serves it on `:8080`, and **rebuilds on every
change** — running the app **in-process** (an interpreter + built-in HTTP
server), so it needs **no cargo / Rust toolchain**. It loads a dotenv-style
`.env` — set `DATABASE_URL` to connect the `db` capability to hosted PostgreSQL.

Two run modes:
- **`xeres serve` / `xeres dev`** — run the app directly (no cargo). Default.
  Add **`--tls`** (with `TLS_CERT`/`TLS_KEY` set to PEM paths) to terminate
  HTTPS directly — no proxy needed; the always-on HSTS header becomes truthful.
- **`xeres build`** — emit a standalone Rust server crate (`out/server/`) to
  compile with cargo, for an eject / max-performance deployment. The emitted
  crate gains the same HTTPS behind a `tls` cargo feature (`--features tls`).

Plus **`xeres fmt <file.xrs>`** — reformat in the one canonical style (in place),
or `xeres fmt --check` to verify formatting in CI. It's comment-preserving and
idempotent (`fmt(fmt(x)) == fmt(x)`).

---

## A tour of the language

### Hello, Xeres (the default app)

```xeres
ui screen App {
  state count: Int = 0

  view {
    column {
      heading "Hello, Xeres!"
      text "Welcome to your new tier-safe app."
      button "count is " + count -> { count = count + 1 }
    }
  }
}
```

No `useState`, no JSX, no `main`/mount boilerplate (the compiler auto-mounts the
first prop-less screen), no CSS file, zero browser-runtime dependencies.

### Models and the secret boundary

```xeres
model User {
  id: String
  username: String
  secret password_hash: String      // Located — can never reach the browser
}
```

`secret` fields are stripped from the generated client interface *and* from the
RPC wire payload. Reading one in a `ui` context is a compile error.

### Server functions, called from the UI via `await`

```xeres
server fn greet(name: String) -> String {
  return name                       // body never ships to the browser
}

ui screen Hello {
  state msg: String = ""
  view {
    column {
      text msg
      button "greet" -> {
        let g = await greet("world")   // compiler-generated, typed RPC
        msg = g
      }
    }
  }
}
```

### Logic: control flow in functions

A `fn` body (server, shared, or a ui handler) has statement-level `if`/`else`,
`for x in list`, `for i in 0..n` (ranges), `while`, and `break`/`continue` —
not just the ternary expression. It compiles to Rust on the server and
TypeScript in the browser.

```xeres
server fn total(items: List<Int>) -> Int {
  let sum = 0
  for x in items {
    if x < 0 { continue }
    sum = sum + x
  }
  return sum
}
```

`List<T>` carries a stdlib alongside `for`: the safe accessors `.length()`,
`.first()`, `.last()`, `.at(i)`, `.reverse()` plus the index sugar `xs[i]` (all of
`.first()`/`.last()`/`.at(i)`/`xs[i]` return `Optional<T>`, so an empty or
out-of-bounds read is `none` — unwrap with `.or(default)` — never a crash), the
higher-order ops `.map`/`.filter`/`.reduce`, and `.contains(x)`:

```xeres
let names    = users.map(u -> u.name)               // List<String>
let adults   = users.filter(u -> u.age >= 18)       // List<User>
let total    = items.reduce(0, (acc, x) -> acc + x.qty)  // Int
let first    = users.filter(u -> u.role == "admin").first()  // chains
let urgent   = tags.contains("urgent")              // Bool
let second   = xs[1].or(0)                          // safe index
```

Closures (`x -> expr`) are **argument-only** in this cut — they may be passed
directly to `map`/`filter`/`reduce` but not stored, returned, or passed around
(first-class closures are a later addition). The tier/secret rules propagate into
the closure body for free: a `ui` closure still can't read a `secret` (R3) or
surface one to the wire (R5). Math stays exact end to end — a closure over a
`List<Decimal>` uses the same exact `Decimal` arithmetic.

Enums (string-backed) pair with `match` — exhaustiveness is compiler-checked
(**R20**), a `DateTime` (epoch ms) + `now()`, and a `Decimal` (exact,
string-backed money via `decimal("19.99")` — never mixed with `Float`, **R29**;
arithmetic `+ - *` and ordered compare `< > <= >=` are exact, never via `f64`)
round out the primitives:

```xeres
enum Status { Active Suspended Closed }

server fn describe(s: Status) -> String {
  match s {
    Active    -> { return "active" }
    Suspended -> { return "suspended" }
    Closed    -> { return "closed" }
  }
  return "?"
}
```

### Views: state, binding, lists, conditionals

```xeres
ui screen Login(  ) {
  state username: String = ""
  state password: String = ""
  state loggedIn: Bool = false

  view {
    column {
      if loggedIn {
        text "Welcome back!"
        button "Sign out" -> { loggedIn = false }
      } else {
        input "Username" bind username
        password "Password" bind password
        button "Sign in" -> { loggedIn = true }
      }
    }
  }
}
```

View primitives — **layout**: `column`, `row`, `grid` (CSS grid), `box`
(unstyled container); **text**: `heading`, `subheading`, `title`, `text`,
`paragraph`; **controls**: `button`, `input`, `password`, `number` (binds an
`Int`/`Float`), `textarea`, `checkbox`, `radio`, `select`, `image`, and `link` (a client-router
anchor — see [Navigation](#navigation-the-client-router)). Control flow:
`for x in items { ... }`, `if cond { ... } else { ... }`, and the conditional
expression `cond ? a : b`. `for` iterates a synced `Collection<T>` **or** a
plain `List<T>` state cell. Inputs use `bind <stateCell>` for two-way binding.

### Styling: the `style` modifier

Any element takes an inline `style "<css>"`. `row`/`column` are flex containers
(the compiler prepends `display:flex`); your CSS wins for everything else. When a
screen's root element is styled, the page renders **full-bleed** on a neutral
canvas — no centered card, logo, or default gradient — so the screen owns the
whole viewport. (Unstyled screens keep the branded centered shell.)

```xeres
ui screen Dashboard {
  state assets: List<Asset> = [ /* ... */ ]
  view {
    column style "min-height:100vh; padding:32px; background:#0f172a; color:white" {
      heading "Asset Management Dashboard"
      for asset in assets {
        row style "padding:16px; border-bottom:1px solid #334155" {
          text asset.name
          text "$" + asset.value
          if asset.change >= 0 { text "+" + asset.change + "%" }
          else { text asset.change + "%" }
        }
      }
    }
  }
}
```

See [`examples/dashboard.xrs`](examples/dashboard.xrs) for the full version
(`xeres dev examples/dashboard.xrs`).

### Reusable components

A `ui component` is a presentational, parameterized view — the same typed-view
machinery as a screen, but invoked by name instead of auto-mounted. Components
are **browser-tier only** (there is no `server component`): their args are
checked against the params (Capitalized name, each arg once, type-compatible,
required ones present — **R17**), and secret-containment (**R3**) and scope
(**R8**) apply inside the view, so a component is **not** a back door around the
tier boundary — reading a `secret` field in one is the same compile error as
anywhere else in browser code. Conditional expressions keep per-instance styling
concise.

```xeres
ui component StatCard(title: String, value: String, color: String) {
  view {
    column style "background:#fff; padding:24px; border-radius:12px" {
      row style "justify-content:space-between" {
        text title
        box style "width:8px; height:8px; border-radius:50%; background:" + color
      }
      heading value
    }
  }
}

ui screen Dashboard {
  state stats: List<Stat> = [ /* ... */ ]
  view {
    grid style "grid-template-columns:repeat(auto-fit, minmax(220px, 1fr)); gap:24px" {
      for s in stats {
        StatCard { title: s.title  value: s.value  color: s.color }   // invoke by name
      }
    }
  }
}
```

A **Capitalized** tag in a view is a component invocation (`StatCard { … }`),
mirroring how a Capitalized `Name { … }` is a record literal in expression
position; lowercase tags are built-in elements. The full admin dashboard —
sidebar with active-nav highlighting, a stats grid, a bar chart, and a status
table — is [`examples/acme.xrs`](examples/acme.xrs)
(`xeres dev examples/acme.xrs`).

### Navigation: the client router

Every prop-less screen is a **route**. The first is `/`; the rest are `/<name>`.
Move between them with a declarative `link` or the imperative `navigate(...)`:

```xeres
ui screen Home {
  view {
    column {
      heading "Home"
      link "About us" -> About            // an <a href> — no full reload
      button "Settings" -> { navigate(Settings) }   // imperative form
    }
  }
}

ui screen About {
  view { column { heading "About"  link "Back home" -> Home } }
}
```

A `link` click is intercepted and `pushState`s the URL, so the screen swaps with
no reload; the browser **Back/Forward** buttons work (`popstate`), and a
**deep link or reload** of `/about` boots straight to that screen (the server
serves `index.html` for client routes; real assets still 404 if missing). A
screen's `on load` runs each time it's navigated to, so a screen fetches its own
data on open. Navigation is browser-tier only — no new server surface.

Rule **R28**: a target must be a known, **prop-less, non-component** screen (a
route can't supply props — have the screen fetch its data in `on load`), and the
imperative `navigate(...)` is rejected outside ui/screen code. The full
three-screen demo is [`examples/router.xrs`](examples/router.xrs)
(`xeres dev examples/router.xrs`).

**Protected routes (R31).** Prefix a screen with `auth` — `auth ui screen
Dashboard { … }` — to require a session. Enforcement is two-tier: the client
router redirects unauthenticated users to the public root (it reads a non-secret
`xeres_auth` flag set alongside the signed session on `session.login`), and the
**server refuses to serve the route's shell** without a valid session cookie
(a `302` to `/`) — so a hand-crafted request or deep link can't reach it. The
real data stays gated regardless, since a protected screen's data comes from
`auth server fn`s (R24). R31 requires the app to establish a session and keeps
the default route public so there's always a landing/login page.

**Typed route params (R32).** A screen can carry a path pattern —
`ui screen Post(id: String) route "/post/:id" { … }` — and each `:name` segment
binds a prop (`String` or `Int`, parsed from the URL). A deep link or reload of
`/post/123` boots `Post` with `id = "123"`; in-app you navigate with the params:
`navigate(Post { id: someId })`. The param is **untrusted inbound data**, so
`raw(id)` is rejected by R30 for free. This is the one relaxation of R28's
"routes are prop-less": a route may take props *only* through a `route` pattern.

### Local-first synced collections

```xeres
model Task { id: String  title: String  done: Bool }

synced state tasks: Collection<Task>     // SQLite-style local store + sync

ui screen Todo {
  state draft: String = ""
  view {
    column {
      input "What needs doing?" bind draft
      button "add" -> { tasks.add(Task { id: uid(), title: draft, done: false }) draft = "" }
      for task in tasks {
        row { text task.title  button "x" -> { tasks.remove(task.id) } }
      }
    }
  }
}
```

A `synced state` is an offline-first collection: it persists locally and a
background **trawler** syncs changes to the server. The merge is **last-write-wins
per field** by a Lamport stamp (ties broken by a stable site id), so two clients
editing *different* fields of the same row both keep their edit instead of one
clobbering the other; a delete is a tombstone that a late write can't resurrect.
Local writes re-render immediately; pulled changes re-render reactively.

### The database (server-only)

```xeres
server fn get_user(name: String) -> User {
  // `db` is a Located capability — server-only, connects to a hosted Postgres
  // via DATABASE_URL. The connection + credentials can never reach the browser.
  return db.query_one("select id, username, password_hash from users where username = $1", name)
}

server fn add_user(id: String, username: String, password_hash: String) -> Int {
  return db.exec("insert into users (id, username, password_hash) values ($1, $2, $3)",
                 id, username, password_hash)
}
```

`db.query_one` maps a row onto the function's return model — or onto
`Optional<Model>`, in which case a **no-row result is `none`** rather than an
error (the graceful "miss" form). `db.query` returns `List<Model>`; `db.exec`
returns the affected-row count. `uid()` works server-side too (e.g. to mint a row
id on insert). The `postgres` driver is added to the generated server **only when
an app uses `db`** — db-free apps stay a zero-dependency `std` crate. See
[`examples/users.xrs`](examples/users.xrs) for the full read / lookup / write
round-trip.

Group writes that must succeed or fail together in a **`transaction { … }`**
(**R33**): its `db` calls run on one shared connection and **commit on success or
roll back on any failure**, so a multi-statement update is atomic. It's
server-only (it wraps `db`) and can't be nested.

```xeres
server fn transfer(from: String, to: String, amount: Int) -> Int {
  transaction {
    db.exec("update accounts set balance = balance - $1 where id = $2", amount, from)
    db.exec("update accounts set balance = balance + $1 where id = $2", amount, to)
  }
  return 1
}
```

### Auth: `hash` / `verify` + typed `let`

`hash(password)` and `verify(password, stored)` are **server-only** builtins
(**R19**) backed by Argon2id — hashing and the hash comparison happen on the
server, never in the browser. Because a salted hash can't be matched in SQL, a
login *fetches* the row and verifies it; binding a query result needs a type, so
`let` takes an optional annotation: `let u: User = db.query_one(...)`. The stored
hash stays a `secret` (stripped from the client + wire).

```xeres
server fn register(username: String, password: String) -> Int {
  return db.exec("insert into users (id, username, password_hash) values ($1, $2, $3)",
                 uid(), username, hash(password))
}
server fn login(username: String, password: String) -> Bool {
  let u: User = db.query_one("select id, username, password_hash from users where username = $1", username)
  return verify(password, u.password_hash)    // password_hash read server-side only (R3)
}
```

`hash`/`verify` add the `argon2` dependency to the generated server **only when
used**. The full screen is [`examples/login_db.xrs`](examples/login_db.xrs) —
verified end-to-end against a live Postgres.

---

## The rules (what the compiler guarantees)

Every program is checked against these. A violation is a compile error.

| Rule | Guarantee |
|---|---|
| **R1** unknown-type | every referenced type exists |
| **R2** duplicate-decl | no duplicate model/field/function/screen/component names |
| **R3** secret-containment | a `secret` field can only be read server-side |
| **R4** async-call-discipline | a browser→server call must be `await`-ed; `await` is browser-only |
| **R5** secret-leak-via-return | only `server` functions may return secret-derived data |
| **R6** declassify-context | `declassify(...)` is server-only |
| **R7** return-type | a `return` must match the declared return type |
| **R8** unknown-binding | a screen identifier must be a prop, `state`, `for`-binding, fn, or collection |
| **R9** record-construction | a model literal supplies each field once, type-compatible |
| **R10** sync-key | a `synced` collection's model needs an `id: String` merge key |
| **R11** state-init / assign | `state` initializers and assignments are type-compatible |
| **R12** collection-method | `add`/`remove`/`get`/`all` only on synced collections, client-side |
| **R13** input-binding | `bind x` requires a `state` cell of the control's type: `checkbox`→`Bool`, `number`→`Int`/`Float`, everything else→`String` (a `number` can't bind a `Decimal` — it yields a float) |
| **R14** if-condition | an `if` condition must be `Bool` |
| **R15** db-capability | `db` is server-only; methods are `query_one`/`query`/`exec` |
| **R16** try-context | `try`/`catch` is browser-only; server failures surface as a failed `await` |
| **R17** component | a `ui component` is Capitalized; an invocation names a known component with args supplied once, type-compatible, required ones present (R3/R8 still apply inside its view) |
| **R18** conditional-branch | both branches of `cond ? a : b` have one type (no silent mixing) |
| **R19** auth-builtin | `hash()` / `verify()` are server-only (no client-side hashing; the secret hash is compared on the server) |
| **R20** match | a `match` scrutinee is an enum, each arm is a real variant, and the arms are exhaustive (all variants, or `_`); `Enum.Variant` must exist |
| **R28** navigation | `navigate(X)` / `link … -> X` targets a known, prop-less, non-component screen (a route can't supply props); the imperative `navigate(...)` is browser-only |
| **R29** decimal | `decimal(...)` takes exactly one `String` (money is written as a string, e.g. `decimal("19.99")`); `Decimal` is never assignable to/from `Float`/`Int`, so binary-float error can't leak into money math. Arithmetic `+ - *` and ordered compare `< > <= >=` are exact (scaled-integer, never `f64`); `Decimal × Int` scales exactly, but `Decimal` with `Float`, `Decimal ± Int`, and `/` (rounding-mode, deferred) are compile errors |
| **R30** raw-taint | `raw(...)` (the audited un-escaped HTML sink) may not wrap untrusted *inbound* data — a screen/component prop or an input-bound `state`. Render it with default escaping, or build the trusted HTML in a `server fn` and `await` it into a non-bound `state`. Closes reflected XSS |
| **R31** auth-route | `auth ui screen X` is a protected route — needs a session (some fn calls `session.login`), can't be a component, and the default route must stay public. Unauthenticated requests are bounced to `/` on **both** tiers (client router + server shell guard) |
| **R32** route-param | `ui screen Post(id: String) route "/post/:id"` — each `:name` segment binds a `String`/`Int` prop (every prop bound, ≥1 param). The param is untrusted (R30 applies), and a param route is navigated with all params: `navigate(Post { id: x })` |
| **R33** transaction | `transaction { … }` runs its `db` writes as one atomic unit (commit on success, roll back on any failure). Server-only (it wraps `db`) and not nestable |

`secret` data that legitimately must be released (e.g. an auth result, not the
hash itself) passes through a single audited keyword: **`declassify(...)`**,
valid only server-side.

**R30** is the inbound mirror of that secret-*out* flow — the first cut of the
reserved information-flow layer. Everything in a view is HTML-escaped by default
(**R22**); `raw(...)` is the one opt-out. R30 makes that opt-out impossible to
feed with request-derived data (props, input-bound `state`), so the last
reflected-XSS hole is closed by the compiler rather than by review. The intended
escape hatch for genuinely-trusted HTML is to produce it in a `server fn` and
`await` it (a non-input-bound `state` stays clean).

---

## How it compiles

```
app.xrs ──► lexer ──► parser ──► checker (R1–R20) ──► codegen
                                                       ├─► out/server/         a self-contained Rust crate
                                                       │     ├─ src/main.rs      std-only HTTP server: router,
                                                       │     │                   RPC, secret-stripping, sync
                                                       │     ├─ Cargo.toml       (postgres added only if `db` used)
                                                       │     └─ static/
                                                       │         ├─ index.html   generated default page
                                                       │         └─ client.ts     screens, state, RPC stubs, sync
                                                       └─ esbuild client.ts ──► static/client.js   (~1 kb, no framework)
```

- The **server** is a `std`-only HTTP server (thread-per-connection) with a
  generated router, a hand-rolled JSON codec, per-model wire serialization that
  omits `secret` fields, and a generic local-first sync endpoint.
- The **client** is a small reactive runtime: a render-on-change mount, typed RPC
  stubs (`await`), two-way input binding, and the synced-collection store.

You never edit `out/` — it's regenerated from `.xrs` on every build.

---

## Repository layout

```
src/                     the Xeres compiler (Rust)
  token.rs  lexer.rs  parser.rs  checker.rs  codegen.rs  main.rs
tests/                   .xrs fixtures + run.sh — the spec / regression suite
examples/                reference apps (counter, todo, login, dashboard, acme,
                           users + login_db — Postgres read/write/auth)
tooling/create-xeres/    project scaffolder (the `npm create xeres` CLI)
package.json,            VS Code language extension (syntax highlighting)
  language-configuration.json, xeres.tmLanguage.json
ROADMAP.md               v0.1 plan + what's deferred
COMPARISON.md            Xeres vs React/Vue/Svelte/Next/Angular
```

### Building the compiler

```bash
cargo build --release          # produces target/release/xeres
cargo install --path .         # installs `xeres` to ~/.cargo/bin
bash tests/run.sh              # runs the fixture suite (BIN=./target/release/xeres)
```

---

## License

MIT OR Apache-2.0 (intended; see headers).
