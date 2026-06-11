// src/main.rs
mod token;
mod lexer;
mod parser;
mod checker;
mod codegen;

use lexer::Lexer;
use parser::Parser;
use std::fs;
use std::path::Path;
use std::process::{exit, Child, Command};
use std::time::{Duration, SystemTime};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let dev = args.iter().any(|a| a == "dev");

    let path = args
        .iter()
        .skip(1)
        .find(|a| a.ends_with(".xrs") || a.ends_with(".xer"))
        .cloned()
        .or_else(|| {
            // default to app.xrs in the current directory
            if Path::new("app.xrs").exists() { Some("app.xrs".to_string()) } else { None }
        });

    let path = match path {
        Some(p) => p,
        None => {
            eprintln!(
                "xeres - the Xeres compiler\n\nusage:\n  \
                 xeres build <file.xrs>   compile to out/server/\n  \
                 xeres dev   <file.xrs>   watch, rebuild and serve on http://127.0.0.1:8080"
            );
            exit(2);
        }
    };

    if dev {
        dev_loop(&path);
    } else if !build(&path) {
        exit(1);
    }
}

/// Compile one .xrs into out/server/. Returns false (printing diagnostics) on
/// error rather than exiting, so the dev loop can keep watching.
fn build(path: &str) -> bool {
    let source = match fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: cannot read {}: {}", path, e);
            return false;
        }
    };

    let mut lexer = Lexer::new(&source);
    let mut parser = Parser::new(&mut lexer);
    let program = parser.parse_program();
    let analysis = checker::analyze(&program);

    if !analysis.errors.is_empty() {
        let lines: Vec<&str> = source.lines().collect();
        for e in &analysis.errors {
            print_diagnostic(path, &lines, e);
        }
        let n = analysis.errors.len();
        eprintln!("\nxeres: {} error{} - compilation aborted.", n, if n == 1 { "" } else { "s" });
        return false;
    }

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

    println!(
        "xeres: compiled {} - {} model(s), {} fn(s), {} screen(s)",
        path,
        program.models.len(),
        program.functions.len(),
        program.screens.len()
    );
    true
}

/// `xeres dev`: compile -> bundle client -> serve, then watch the source and
/// rebuild + restart on change. Loads .env (e.g. DATABASE_URL) into the server.
fn dev_loop(path: &str) {
    let env = load_env(".env");
    println!("xeres dev: watching {} — Ctrl-C to stop", path);

    let mut child: Option<Child> = None;
    let mut last = SystemTime::UNIX_EPOCH;

    loop {
        let mtime = fs::metadata(path)
            .and_then(|m| m.modified())
            .unwrap_or(SystemTime::UNIX_EPOCH);

        if mtime != last {
            last = mtime;
            if let Some(mut c) = child.take() {
                let _ = c.kill();
                let _ = c.wait();
            }
            println!("\nxeres dev: building {}...", path);
            if build(path) && bundle() && sh("cargo build --quiet --manifest-path out/server/Cargo.toml") {
                child = run_server(&env);
            } else {
                eprintln!("xeres dev: build failed — fix the error above; waiting for changes.");
            }
        }

        std::thread::sleep(Duration::from_millis(400));
    }
}

fn bundle() -> bool {
    sh("npx --yes esbuild out/server/static/client.ts --bundle --format=esm --outfile=out/server/static/client.js")
}

/// Run a command through the platform shell (so npx/cargo resolve from PATH).
fn sh(cmd: &str) -> bool {
    let status = if cfg!(windows) {
        Command::new("cmd").args(["/C", cmd]).status()
    } else {
        Command::new("sh").args(["-c", cmd]).status()
    };
    matches!(status, Ok(s) if s.success())
}

/// Spawn the built server binary with cwd=out/server (so it finds ./static)
/// and the loaded .env applied.
fn run_server(env: &[(String, String)]) -> Option<Child> {
    let bin = format!("out/server/target/debug/xeres-app{}", std::env::consts::EXE_SUFFIX);
    let abs = fs::canonicalize(&bin).ok()?;
    let mut cmd = Command::new(abs);
    cmd.current_dir("out/server");
    for (k, v) in env {
        cmd.env(k, v);
    }
    match cmd.spawn() {
        Ok(c) => Some(c),
        Err(e) => {
            eprintln!("xeres dev: could not start server: {}", e);
            None
        }
    }
}

/// Parse a dotenv-style file into (key, value) pairs. Missing file = no vars.
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

fn print_diagnostic(path: &str, lines: &[&str], e: &checker::SemanticError) {
    eprintln!("error: [{}] {}", e.rule, e.message);
    eprintln!("  --> {}:{}", path, e.line);
    if e.line >= 1 && e.line <= lines.len() {
        let src = lines[e.line - 1];
        let gutter = format!("{:>4}", e.line);
        eprintln!("     |");
        eprintln!("{} | {}", gutter, src);
        eprintln!("     |");
    }
    eprintln!();
}
