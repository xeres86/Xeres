#!/usr/bin/env node
// create-xeres — scaffold a new Xeres app.
//
//   npm create xeres@latest my-app        (once published)
//   node tooling/create-xeres/index.mjs my-app   (local dev)
//
// Distribution note: a published create-xeres downloads a prebuilt `xeres`
// compiler binary in postinstall (the esbuild/SWC pattern). For local use it
// resolves `xeres` from PATH or $XERES_BIN. See README in the scaffolded app.

import { mkdir, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { join, resolve } from "node:path";

const name = process.argv[2] || "my-xeres-app";
const dir = resolve(process.cwd(), name);

if (existsSync(dir)) {
  console.error(`✗ directory "${name}" already exists`);
  process.exit(1);
}

const files = {
  "app.xrs": APP_XRS(name),
  "package.json": PKG_JSON(name),
  ".env.example": ENV_EXAMPLE(),
  ".gitignore": "out/\nnode_modules/\n.env\n",
  "README.md": README(name),
};

console.log(`\n  ◆ creating Xeres app in ${dir}\n`);
await mkdir(dir, { recursive: true });
for (const [file, content] of Object.entries(files)) {
  await writeFile(join(dir, file), content);
  console.log(`    + ${file}`);
}

console.log(`
  Done. Next steps:

    cd ${name}
    npm install        # downloads the xeres compiler + esbuild — no global install
    npm run dev        # compile, serve, and rebuild on change

  Then open http://127.0.0.1:8080

  Node is the only prerequisite. \`npm install\` drops the prebuilt \`xeres\`
  compiler into node_modules — no PATH, no Rust, no cargo. (cargo is only
  needed for the optional \`npm run build\`: eject to a native Rust server.)
`);

// ---------------------------------------------------------------- templates

function APP_XRS(_app) {
  return `// Your whole app — edit me. One file, two tiers, one type system.

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
`;
}

function PKG_JSON(app) {
  return JSON.stringify(
    {
      name: app,
      version: "0.0.0",
      private: true,
      type: "module",
      scripts: {
        dev: "xeres dev app.xrs",
        build:
          "xeres build app.xrs && esbuild out/server/static/client.ts --bundle --format=esm --outfile=out/server/static/client.js && cargo build --release --manifest-path out/server/Cargo.toml",
      },
      // `xeres-cli` pulls the prebuilt compiler binary (postinstall) so dev needs
      // no global install / PATH; `esbuild` is the client bundler `xeres dev`/
      // `build` use — pinned so the first run is instant + offline (no npx fetch).
      devDependencies: {
        "xeres-cli": "^0.6.0",
        esbuild: "^0.28.0",
      },
    },
    null,
    2
  ) + "\n";
}

function ENV_EXAMPLE() {
  return `# Copy to .env and fill in. Loaded by \`xeres dev\` into the server.
# Only needed if your app uses the \`db\` capability (hosted PostgreSQL).
# DATABASE_URL=postgres://user:password@localhost:5432/mydb
`;
}

function README(app) {
  return `# ${app}

A [Xeres](https://example.com/xeres) app — tier-safe web, served by the built-in
Xeres server. No framework runtime in the browser.

## Develop

\`\`\`bash
npm install
npm run dev        # compile app.xrs, bundle the client, run the server
\`\`\`

Open http://127.0.0.1:8080

## How it works

- \`app.xrs\` is your whole app: models, \`server\` functions, \`ui\` screens, and
  \`synced\` local-first collections.
- \`npm run dev\` runs \`xeres dev\` — it compiles \`app.xrs\`, serves it, and
  rebuilds on every change. The app runs **in-process** (no cargo / Rust
  toolchain needed). \`npm run build\` emits a standalone Rust server crate to
  compile with cargo, for an eject / production deployment.
- Server functions become typed RPC endpoints. \`secret\` fields can never reach
  the browser — the compiler enforces it.

## Using a database

Server functions can talk to a hosted PostgreSQL via the server-only \`db\`
capability:

\`\`\`xeres
server fn get_user(name: String) -> User {
  return db.query_one("select id, username from users where username = $1", name)
}
\`\`\`

Configure the connection in \`.env\` (copy from \`.env.example\`):

\`\`\`
DATABASE_URL=postgres://user:password@localhost:5432/mydb
\`\`\`

\`xeres dev\` loads \`.env\` and passes it to the server. The connection string and
credentials are server-only — they can never reach the browser.

## Requirements

- **Node 18+** — the only prerequisite. \`npm install\` downloads the prebuilt
  \`xeres\` compiler and esbuild into \`node_modules\`; no global install, no
  \`PATH\`, no Rust toolchain. \`npm run dev\` runs the app in-process.
- \`cargo\` is needed **only** for \`npm run build\` (the optional eject to a
  standalone native Rust server). The released compiler is batteries-included
  (Postgres + Argon2 + HTTP built in), so even \`db\` apps run under
  \`npm run dev\` with no toolchain.
`;
}
