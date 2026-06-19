# Releasing Xeres

Goal: a developer installs Xeres **without cloning this repo** —
`npm create xeres@latest my-app` scaffolds a project whose `npm install` pulls a
**prebuilt compiler binary**, and `npm run dev` runs the app **in-process** (no
cargo). This is the create-react-app experience: a fresh machine needs only
**Node**.

## The two npm packages

| Package | Dir | What it is |
|---|---|---|
| **`create-xeres`** | `tooling/create-xeres` | the scaffolder (`npm create xeres`) |
| **`xeres-cli`** | `tooling/npm/xeres` | the compiler CLI; `postinstall` downloads the prebuilt binary; exposes the `xeres` command |

> The bare name `xeres` is taken on npm, so the CLI package is **`xeres-cli`**
> (the *command* it installs is still `xeres`). Scaffolded projects depend on
> `xeres-cli`, so `npm install` fetches the binary — no global install needed.

The binaries are built by `.github/workflows/release.yml` on a version tag.

## Cutting a release `vX.Y.Z`

1. **Bump versions** to `X.Y.Z`: `Cargo.toml`, `tooling/npm/xeres/package.json`,
   `tooling/create-xeres/package.json` (and its `devDependencies.xeres-cli`),
   `CHANGELOG.md`.
2. **Tag + push** — triggers the binary build:
   ```bash
   git commit -am "Release vX.Y.Z"
   git tag -a vX.Y.Z -m "Xeres vX.Y.Z"
   git push origin main --tags
   ```
   `release.yml` builds `xeres` for win/mac(x64+arm64)/linux and attaches
   `xeres-<target>[.exe]` to the GitHub Release for `vX.Y.Z`. **Wait for it to
   finish and confirm the assets are attached** (the npm install downloads them).
3. **Publish to npm** (requires `npm login`; the binaries must exist first):
   ```bash
   cd tooling/npm/xeres   && npm publish     # publishes xeres-cli
   cd ../create-xeres     && npm publish     # publishes create-xeres
   ```

## Fresh-machine flow this enables (post-publish)

```bash
npm create xeres@latest my-app
cd my-app
npm install      # pulls xeres-cli -> downloads the compiler binary
npm run dev      # xeres dev: serve + hot-reload, in-process (no cargo)
```
Open http://127.0.0.1:8080. **Node-only** for db-free apps.

## Notes / current limits

- **Released binaries are batteries-included.** `release.yml` builds
  `--features full` (db + auth + http), so `db.*`, `hash()`/`verify()`, and
  `endpoint` egress all work from the downloaded binary with **no toolchain on
  the user's machine**. CI (`ci.yml`) builds both the default std-only profile
  and `--features full` to keep both green.
- **`npm run build`** (the eject path → a standalone Rust server) still needs
  `cargo`. `npm run dev` does not.

## Local verification (no release/publish needed)

```bash
cargo build --release
cd tooling/npm/xeres
XERES_BINARY_PATH=../../../target/release/xeres.exe node install.mjs   # stage the binary
node bin/xeres.mjs build ../../../tests/pass_basic.xrs                 # run it via the launcher
```
