#!/usr/bin/env node
// create-xeres — scaffold a new Xeres app (multi-file, since v0.6.1).
//
//   npm create xeres@latest my-app        (once published)
//   node tooling/create-xeres/index.mjs my-app   (local dev)
//
// The scaffold produces a tree that demonstrates the spec-20 Cut 2 multi-file
// pattern: `pub model`s in models/, `pub ui component`s in components/, `pub ui
// screen`s in pages/. The entry app.xrs imports what the Home screen uses; new
// files drop into the right folder and get imported as you grow.
//
// Distribution: a published create-xeres downloads a prebuilt `xeres` compiler
// binary in postinstall (the esbuild/SWC pattern). For local use it resolves
// `xeres` from PATH or $XERES_BIN. See README in the scaffolded app.

import { mkdir, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { join, resolve, dirname } from "node:path";

const name = process.argv[2] || "my-xeres-app";
const dir = resolve(process.cwd(), name);

if (existsSync(dir)) {
  console.error(`✗ directory "${name}" already exists`);
  process.exit(1);
}

// Each key is a path relative to the project root. Nested paths are created
// on demand — the layout below is intentionally narrow (models / components /
// pages) so it stays cohesive, not a maze.
const files = {
  "app.xrs": APP_XRS(),
  "models/note.xrs": MODEL_NOTE(),
  "components/welcome.xrs": COMPONENT_WELCOME(),
  "pages/about.xrs": PAGE_ABOUT(),
  "package.json": PKG_JSON(name),
  ".env.example": ENV_EXAMPLE(),
  ".gitignore": "out/\nnode_modules/\n.env\n",
  "README.md": README(name),
};

console.log(`\n  ◆ creating Xeres app in ${dir}\n`);
await mkdir(dir, { recursive: true });
for (const [file, content] of Object.entries(files)) {
  const full = join(dir, file);
  await mkdir(dirname(full), { recursive: true });
  await writeFile(full, content);
  console.log(`    + ${file}`);
}

console.log(`
  Done. Next steps:

    cd ${name}
    npm install        # downloads the xeres compiler + esbuild — no global install
    npm run dev        # compile, serve, and rebuild on change

  Then open http://127.0.0.1:8080

  The project starts with three folders demonstrating the multi-file pattern:
    models/      — data models (\`pub model\`)
    components/  — reusable UI components (\`pub ui component\`)
    pages/       — additional screens / routes (\`pub ui screen\`)

  Drop a new file in the right folder, mark its declaration \`pub\`, and import
  it from app.xrs (or from any other file that uses it). See README.md.
`);

// ---------------------------------------------------------------- templates

function APP_XRS() {
  return `// app.xrs — your entry. Imports the pieces the Home screen uses and defines
// the routes. As your app grows, add new \`pub\` files under models/, components/,
// and pages/, then import them here (or from whichever file uses them).

import "components/welcome.xrs"
import "pages/about.xrs"

ui screen Home {
    state count: Int = 0

    view {
        column {
            Welcome { name: "Xeres" }
            heading "Hello, multi-file world"
            text "Edit app.xrs to change this screen, or drop a new file under pages/ for another route."
            button "count is " + count -> { count = count + 1 }
            link "About" -> About
        }
    }
}
`;
}

function COMPONENT_WELCOME() {
  return `// components/welcome.xrs — a reusable UI component. \`pub\` makes it importable
// from app.xrs (or any other module). Components are invoked by their
// Capitalized name in a view — no qualifier needed, just like JSX.

pub ui component Welcome(name: String) {
    view {
        box {
            heading "👋 Welcome, " + name
            style "padding: 1rem; background: rgba(124, 58, 237, .12); border-radius: .5rem;"
        }
    }
}
`;
}

function PAGE_ABOUT() {
  return `// pages/about.xrs — another screen in its own file. \`pub\` makes it a route the
// home screen can \`link\` / \`navigate\` to. The router picks it up automatically
// once it's imported by the entry.

pub ui screen About {
    view {
        column {
            heading "About this app"
            text "This page lives in pages/about.xrs."
            text "Add new pages by dropping more \`pub ui screen\` files here."
        }
    }
}
`;
}

function MODEL_NOTE() {
  return `// models/note.xrs — a typed data model in its own file. \`pub\` makes it
// importable. Models describe the shape of data that flows through your app —
// over RPC, in the database, between server fns. \`secret\` fields can never
// reach the browser; the compiler enforces it.
//
// To use this, add to app.xrs:
//   import "models/note.xrs"
//   server fn first_note() -> Note {
//     return Note { id: "1", title: "Hello", body: "First note." }
//   }

pub model Note {
    id: String
    title: String
    body: String
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
        "xeres-cli": "^0.7.1",
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

A [Xeres](https://github.com/xeres86/Xeres) app — tier-safe web, served by the
built-in Xeres server. No framework runtime in the browser.

## Develop

\`\`\`bash
npm install
npm run dev        # compile + serve + rebuild on change
\`\`\`

Open http://127.0.0.1:8080.

## Project layout

\`\`\`
${app}/
  app.xrs            # entry: imports + the Home screen
  models/            # pub model — data shapes (RPC, db rows, etc.)
    note.xrs
  components/        # pub ui component — reusable UI bits
    welcome.xrs
  pages/             # pub ui screen — additional routes
    about.xrs
\`\`\`

Every cross-file declaration starts with \`pub\` to make it crossable. The
\`import\` in app.xrs pulls modules into the program; from there, **types are
unqualified** (\`Badge { ... }\` in a view, \`Note\` as a return type — like a
JSX/Python import) while **server fns stay qualified** (\`utils.compute(...)\`).

Add a new component → drop a file in \`components/\`, mark it \`pub ui component\`,
\`import\` it from whichever file uses it. Same for models and pages.

## How it works

- One \`.xrs\` file (or many) → two tiers: a Rust server and a browser bundle,
  under one type system. The server/client boundary is enforced by the
  compiler — \`secret\` fields physically cannot reach the browser.
- Server functions become typed RPC endpoints the UI calls with \`await\`. No
  hand-written \`fetch\`.
- \`npm run dev\` runs \`xeres dev\` — compiles, serves, and rebuilds on every
  change. The app runs **in-process** (no cargo / Rust toolchain needed).
- \`npm run build\` ejects to a standalone Rust server crate compiled with
  cargo, for production deployment.

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
