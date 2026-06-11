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
  "xeres-dev.mjs": XERES_DEV(),
  ".gitignore": "out/\nnode_modules/\n",
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
    npm install
    npm run dev        # compiles app.xrs and starts the Xeres server

  Then open http://127.0.0.1:8080

  Needs: the \`xeres\` compiler on your PATH (or set XERES_BIN), plus cargo.
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
        dev: "node xeres-dev.mjs dev",
        build: "node xeres-dev.mjs build",
      },
    },
    null,
    2
  ) + "\n";
}

function XERES_DEV() {
  return `// Dev runner: compile app.xrs -> bundle client -> run the Xeres server.
import { spawnSync } from "node:child_process";

const XERES = process.env.XERES_BIN || "xeres";
const mode = process.argv[2] || "dev";

function run(cmd, args, opts = {}) {
  const r = spawnSync(cmd, args, { stdio: "inherit", shell: true, ...opts });
  if (r.status !== 0) {
    console.error(\`\\n✗ \${cmd} \${args.join(" ")} failed\`);
    process.exit(r.status ?? 1);
  }
}

console.log("→ compiling app.xrs");
run(XERES, ["build", "app.xrs"]);

console.log("→ bundling client");
run("npx", ["--yes", "esbuild", "out/server/static/client.ts",
  "--bundle", "--format=esm", "--outfile=out/server/static/client.js"]);

if (mode === "build") {
  console.log("✓ built to out/server");
  process.exit(0);
}

console.log("→ starting Xeres server on http://127.0.0.1:8080");
run("cargo", ["run", "--quiet"], { cwd: "out/server" });
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
- \`npm run dev\` compiles it to \`out/server/\` (a self-contained Rust server) plus
  a tiny browser bundle, then runs it.
- Server functions become typed RPC endpoints. \`secret\` fields can never reach
  the browser — the compiler enforces it.

## Requirements (local)

- The \`xeres\` compiler on PATH (or set \`XERES_BIN=/path/to/xeres\`).
- \`cargo\` (until prebuilt server runtimes ship).
`;
}
