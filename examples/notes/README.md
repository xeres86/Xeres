# Notes — Xeres reference app

A small auth'd, local-first notes app — the canonical example of putting v0.1
together. The whole thing is [`app.xrs`](app.xrs) (~70 lines).

## What it shows
- **The secret boundary** — `User.password_hash` is `secret`: it can't be read
  in the browser and is stripped from the wire.
- **Server auth over RPC** — `login()` is a `server fn` called from the UI with
  `await`, wrapped in `try`/`catch` so a failed sign-in shows a message instead
  of breaking.
- **Conditional rendering as navigation** — one screen, `if loggedIn { ... }
  else { ... }` swaps between the login form and the notes view.
- **Local-first data** — `synced state notes: Collection<Note>` gives offline
  add / list / per-item delete that persists and syncs.

## Run it
From this directory, with the `xeres` compiler on your PATH:

```bash
xeres build app.xrs
cd out/server/static && npx esbuild client.ts --bundle --format=esm --outfile=client.js
cd .. && cargo run            # http://127.0.0.1:8080
```

Sign in with any username/password (auth is a stub), then add notes.

> Note: this app needs no database — notes are local-first. A real build would
> swap the stub `login` for a `db.query_one(...)` against hosted Postgres.
