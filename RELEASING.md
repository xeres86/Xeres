# Releasing Xeres

The goal of the distribution setup: a developer installs Xeres **without cloning
this repo** — `npm i -g xeres` downloads a prebuilt compiler binary, and
`npm create xeres@latest` scaffolds a project (the esbuild model).

Two npm packages back this:
- **`xeres`** (`tooling/npm/xeres`) — a thin CLI whose `postinstall` downloads
  the prebuilt `xeres` binary for the platform from this repo's GitHub Release.
- **`create-xeres`** (`tooling/create-xeres`) — the project scaffolder.

The binaries themselves are built by `.github/workflows/release.yml` on a tag.

## Cutting a release `vX.Y.Z`

1. **Bump versions** to `X.Y.Z` in:
   - `Cargo.toml`
   - `tooling/npm/xeres/package.json`  (the binary URL uses this version)
   - `tooling/create-xeres/package.json`
   - add a `CHANGELOG.md` section.
2. **Commit, tag, push** — the tag triggers the release build:
   ```bash
   git commit -am "Release vX.Y.Z"
   git tag -a vX.Y.Z -m "Xeres vX.Y.Z"
   git push origin main --tags
   ```
   `release.yml` builds `xeres` for win/mac(x64+arm64)/linux and attaches
   `xeres-<target>[.exe]` to the GitHub Release for `vX.Y.Z`.
3. **Publish to npm** (once the release assets exist):
   ```bash
   cd tooling/npm/xeres      && npm publish
   cd ../create-xeres        && npm publish
   ```
   (`npm publish` requires an npm login with rights to those names.)

## The resulting fresh-machine flow (post-publish)

```bash
npm i -g xeres                 # downloads the compiler binary — no git, no cargo install
npm create xeres@latest my-app
cd my-app && npm run dev
```

Still requires Rust/`cargo` to build the *generated* server (the "Model B"
self-contained runtime removes that — see ROADMAP). Apps that use `db` need a
full C toolchain (MSVC Build Tools or MinGW-w64) for the Postgres driver.

## Local verification (no release needed)

The `xeres` wrapper can be exercised against a locally built binary:

```bash
cargo build --release
cd tooling/npm/xeres
XERES_BINARY_PATH=../../../target/release/xeres.exe node install.mjs   # stages the binary
node bin/xeres.mjs build ../../../tests/pass_basic.xrs                 # runs it via the launcher
```

## Post-publish refinement

Once `xeres` is on npm, the scaffold can depend on it directly so a global
install isn't needed — add to `create-xeres`'s generated `package.json`:
`"devDependencies": { "xeres": "^X.Y.Z" }`. Then `npm install` in a new project
pulls the compiler binary locally.
