#!/usr/bin/env node
// Thin launcher: exec the platform binary fetched by install.mjs, passing args.
import { spawnSync } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { existsSync } from "node:fs";

const here = dirname(fileURLToPath(import.meta.url));
const ext = process.platform === "win32" ? ".exe" : "";
const bin = join(here, `xeres-bin${ext}`);

if (!existsSync(bin)) {
  console.error(
    "xeres: the compiler binary isn't installed.\n" +
      "  Reinstall (it downloads on postinstall): npm install xeres\n" +
      "  Or point at a local build: XERES_BINARY_PATH=/path/to/xeres npm rebuild xeres"
  );
  process.exit(1);
}

const r = spawnSync(bin, process.argv.slice(2), { stdio: "inherit" });
process.exit(r.status ?? 1);
