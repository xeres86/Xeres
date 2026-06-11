// Fetch the prebuilt `xeres` binary for this platform (the esbuild model).
// Override with XERES_BINARY_PATH=<local file> to install from disk (dev/CI).
import { createWriteStream, mkdirSync, copyFileSync, chmodSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { pipeline } from "node:stream/promises";

const here = dirname(fileURLToPath(import.meta.url));
const { version } = JSON.parse(readFileSync(join(here, "package.json"), "utf8"));

// node platform/arch -> Rust target triple (matches release.yml asset names)
const TARGETS = {
  "win32 x64": "x86_64-pc-windows-msvc",
  "darwin x64": "x86_64-apple-darwin",
  "darwin arm64": "aarch64-apple-darwin",
  "linux x64": "x86_64-unknown-linux-gnu",
};
const ext = process.platform === "win32" ? ".exe" : "";
const binDir = join(here, "bin");
const dest = join(binDir, `xeres-bin${ext}`);
mkdirSync(binDir, { recursive: true });

function chmodIfUnix() {
  if (ext === "") chmodSync(dest, 0o755);
}

const local = process.env.XERES_BINARY_PATH;
if (local) {
  copyFileSync(local, dest);
  chmodIfUnix();
  console.log(`xeres: installed from ${local}`);
  process.exit(0);
}

const triple = TARGETS[`${process.platform} ${process.arch}`];
if (!triple) {
  console.warn(
    `xeres: no prebuilt binary for ${process.platform}/${process.arch}. ` +
      `Build from source (cargo install) or set XERES_BINARY_PATH.`
  );
  process.exit(0);
}

const url = `https://github.com/xeres86/Xeres/releases/download/v${version}/xeres-${triple}${ext}`;
try {
  const res = await fetch(url, { redirect: "follow" });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  await pipeline(res.body, createWriteStream(dest));
  chmodIfUnix();
  console.log(`xeres: downloaded ${url}`);
} catch (e) {
  // Don't fail the whole npm install — the launcher reports a clear error if run.
  console.warn(
    `xeres: could not download ${url} (${e.message}).\n` +
      `  Until v${version} is released, build from source: clone the repo and ` +
      `'cargo install --path .', or set XERES_BINARY_PATH and reinstall.`
  );
  process.exit(0);
}
