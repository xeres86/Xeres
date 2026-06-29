// src/main.rs
// Compiler phases. `frontend` lexes + parses, `middle` resolves/checks/loads
// modules, `backend` emits the Rust server + TS client. `interp`/`serve` are the
// in-process runtime for `xeres serve`; `fmt` is the canonical formatter.
mod frontend;
mod middle;
mod backend;
mod json;
mod interp;
mod serve;
mod fmt;

use frontend::parser::XeresProgram;
use middle::{checker, diagnostics, loader};
use backend::codegen;
use std::fs;
use std::path::Path;
use std::process::{exit, Child, Command};
use std::time::{Duration, SystemTime};

const PORT: u16 = 8080;
const STATIC_DIR: &str = "out/static";

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).map(|s| s.as_str()).unwrap_or("");

    let path = args
        .iter()
        .skip(1)
        .find(|a| a.ends_with(".xrs") || a.ends_with(".xer"))
        .cloned()
        .or_else(|| if Path::new("app.xrs").exists() { Some("app.xrs".into()) } else { None });

    let path = match path {
        Some(p) => p,
        None => {
            eprintln!(
                "xeres - the Xeres compiler\n\nusage:\n  \
                 xeres dev   <file.xrs>   serve + rebuild on change (no cargo)\n  \
                 xeres serve <file.xrs>   compile + serve once on :8080 (no cargo)\n  \
                 xeres serve --tls <file.xrs>   serve over HTTPS (TLS_CERT/TLS_KEY = PEM paths)\n  \
                 xeres build <file.xrs>   emit a standalone Rust server crate (out/server/)\n  \
                 xeres fmt   <file.xrs>   reformat in canonical style (--check to verify only)"
            );
            exit(2);
        }
    };

    match cmd {
        "dev" => dev_loop(&path),
        "serve" => serve_once(&path, parse_tls(&args)),
        "fmt" => {
            if !fmt_command(&path, &args) {
                exit(1);
            }
        }
        _ => {
            if !build(&path) {
                exit(1);
            }
        }
    }
}

/// `xeres fmt` — reformat a file in canonical style (in place), or `--check` to
/// verify it's already formatted (exit 1 if not) without writing. Pure lexer
/// pass, so it formats even files that don't type-check.
fn fmt_command(path: &str, args: &[String]) -> bool {
    let source = match fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: cannot read {}: {}", path, e);
            return false;
        }
    };
    let formatted = fmt::format(&source);
    if args.iter().any(|a| a == "--check") {
        if formatted == source {
            println!("xeres fmt: {} is already formatted.", path);
            true
        } else {
            eprintln!("xeres fmt: {} is not formatted (run `xeres fmt {}`).", path, path);
            false
        }
    } else if formatted == source {
        println!("xeres fmt: {} already formatted.", path);
        true
    } else {
        match fs::write(path, &formatted) {
            Ok(_) => {
                println!("xeres fmt: formatted {}.", path);
                true
            }
            Err(e) => {
                eprintln!("error: cannot write {}: {}", path, e);
                false
            }
        }
    }
}

/// Load (resolve imports + merge modules) + check; returns the program (printing
/// diagnostics + None on error). The module loader (spec 20) runs first, so a
/// multi-file program is merged into one before the checker sees it. Both
/// stages produce the same `Diagnostic` type (spec 22 F4), so one renderer
/// formats either; a checker diagnostic has an empty `file` and is shown
/// against the entry path.
fn compile(path: &str) -> Option<XeresProgram> {
    let mut program = match loader::load_program(path) {
        Ok(p) => p,
        Err(errors) => return abort(path, &errors),
    };
    let analysis = checker::analyze(&program);
    if !analysis.errors.is_empty() {
        return abort(path, &analysis.errors);
    }
    // Typed desugaring (spec 18): rewrite Decimal `+ - * < > <= >=` into `__dec_*`
    // builtin calls now that types are known — both backends emit these directly.
    // Runs only on a checked program, so the R29 discipline already holds.
    checker::lower(&mut program);
    Some(program)
}

/// `xeres build` — emit a standalone Rust server crate (Model A / eject).
fn build(path: &str) -> bool {
    let Some(program) = compile(path) else { return false };
    let analysis = checker::analyze(&program);
    let (server_rs, client_ts, index_html, cargo_toml) =
        codegen::generate(&program, &analysis.returns_secret);

    let server_dir = Path::new("out").join("server");
    let src_dir = server_dir.join("src");
    let static_dir = server_dir.join("static");
    let _ = fs::create_dir_all(&src_dir);
    let _ = fs::create_dir_all(&static_dir);
    let _ = fs::write(server_dir.join("Cargo.toml"), &cargo_toml);
    let _ = fs::write(src_dir.join("main.rs"), &server_rs);
    let _ = fs::write(static_dir.join("client.ts"), &client_ts);
    let _ = fs::write(static_dir.join("index.html"), &index_html);

    let (screens, components) = screen_component_counts(&program);
    let enums = if program.enums.is_empty() {
        String::new()
    } else {
        format!(", {} enum(s)", program.enums.len())
    };
    println!(
        "xeres: compiled {} -> out/server/ ({} model(s){}, {} fn(s), {} screen(s), {} component(s))",
        path,
        program.models.len(),
        enums,
        program.functions.len(),
        screens,
        components
    );
    true
}

/// Split `program.screens` into page count vs reusable-component count
/// (components live in the same Vec, tagged by `is_component`).
fn screen_component_counts(program: &XeresProgram) -> (usize, usize) {
    let components = program.screens.iter().filter(|s| s.is_component).count();
    (program.screens.len() - components, components)
}

/// Resolve `--tls` into a `TlsConfig` from `TLS_CERT`/`TLS_KEY`. Absent flag ⇒
/// plain HTTP (today's default). Flag set but env missing ⇒ exit with guidance.
fn parse_tls(args: &[String]) -> Option<serve::TlsConfig> {
    if !args.iter().any(|a| a == "--tls") {
        return None;
    }
    match (std::env::var("TLS_CERT"), std::env::var("TLS_KEY")) {
        (Ok(cert), Ok(key)) => Some(serve::TlsConfig { cert, key }),
        _ => {
            eprintln!("xeres serve --tls: set TLS_CERT and TLS_KEY to PEM file paths");
            exit(2);
        }
    }
}

/// `xeres serve` — compile the client, then run the app in-process (no cargo).
fn serve_once(path: &str, tls: Option<serve::TlsConfig>) {
    let Some(program) = compile(path) else { return };
    let analysis = checker::analyze(&program);
    let (_server, client_ts, index_html, _cargo) =
        codegen::generate(&program, &analysis.returns_secret);

    let _ = fs::create_dir_all(STATIC_DIR);
    let _ = fs::write(format!("{}/client.ts", STATIC_DIR), &client_ts);
    let _ = fs::write(format!("{}/index.html", STATIC_DIR), &index_html);

    if !bundle() {
        eprintln!("xeres: client bundle failed (is npx/esbuild available?)");
        return;
    }
    let (screens, components) = screen_component_counts(&program);
    println!(
        "xeres: serving {} ({} fn(s), {} screen(s), {} component(s))",
        path,
        program.functions.len(),
        screens,
        components
    );
    serve::serve(&program, STATIC_DIR, PORT, tls);
}

/// `xeres dev` — watch the source; (re)spawn `xeres serve` on change. No cargo.
fn dev_loop(path: &str) {
    let env = load_env(".env");
    let exe = std::env::current_exe().expect("current exe");
    println!("xeres dev: watching {} — Ctrl-C to stop", path);

    let mut child: Option<Child> = None;
    let mut last = SystemTime::UNIX_EPOCH;

    loop {
        let mtime = fs::metadata(path).and_then(|m| m.modified()).unwrap_or(SystemTime::UNIX_EPOCH);
        if mtime != last {
            last = mtime;
            if let Some(mut c) = child.take() {
                let _ = c.kill();
                let _ = c.wait();
            }
            println!("\nxeres dev: change detected, restarting...");
            let mut cmd = Command::new(&exe);
            cmd.args(["serve", path]);
            for (k, v) in &env {
                cmd.env(k, v);
            }
            child = cmd.spawn().ok();
        }
        std::thread::sleep(Duration::from_millis(400));
    }
}

fn bundle() -> bool {
    sh(&format!(
        "npx --yes esbuild {dir}/client.ts --bundle --format=esm --outfile={dir}/client.js",
        dir = STATIC_DIR
    ))
}

fn sh(cmd: &str) -> bool {
    let status = if cfg!(windows) {
        Command::new("cmd").args(["/C", cmd]).status()
    } else {
        Command::new("sh").args(["-c", cmd]).status()
    };
    matches!(status, Ok(s) if s.success())
}

fn load_env(path: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    if let Ok(content) = fs::read_to_string(path) {
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some((k, v)) = line.split_once('=') {
                out.push((k.trim().to_string(), v.trim().trim_matches('"').to_string()));
            }
        }
        if !out.is_empty() {
            println!("xeres dev: loaded {} ({} var(s))", path, out.len());
        }
    }
    out
}

/// Print all diagnostics through the shared renderer and return `None` so the
/// caller's `compile`-step short-circuit reads as one expression. Used by both
/// the loader and the checker — they produce the same `Diagnostic` type now.
fn abort(entry_path: &str, errors: &[diagnostics::Diagnostic]) -> Option<XeresProgram> {
    diagnostics::report(errors, entry_path);
    let n = errors.len();
    eprintln!("\nxeres: {} error{} - compilation aborted.", n, if n == 1 { "" } else { "s" });
    None
}
