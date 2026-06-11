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
use std::process::exit;

fn main() {
    let args: Vec<String> = std::env::args().collect();

    // usage: xeres [build] <file.xrs>
    let path = args.iter().skip(1).find(|a| a.ends_with(".xrs") || a.ends_with(".xer"));
    let path = match path {
        Some(p) => p.clone(),
        None => {
            eprintln!("xeres - the Xeres compiler\n\nusage: xeres build <file.xrs>");
            exit(2);
        }
    };

    let source = match fs::read_to_string(&path) {
        Ok(s) => s,
        Err(e) => { eprintln!("error: cannot read {}: {}", path, e); exit(2); }
    };

    let mut lexer = Lexer::new(&source);
    let mut parser = Parser::new(&mut lexer);
    let program = parser.parse_program();

    let analysis = checker::analyze(&program);

    if !analysis.errors.is_empty() {
        let lines: Vec<&str> = source.lines().collect();
        for e in &analysis.errors {
            print_diagnostic(&path, &lines, e);
        }
        let n = analysis.errors.len();
        eprintln!("\nxeres: {} error{} - compilation aborted.", n, if n == 1 { "" } else { "s" });
        exit(1);
    }

    let (server_rs, client_ts, index_html, cargo_toml) =
        codegen::generate(&program, &analysis.returns_secret);

    // Emit a self-contained, runnable server crate: out/server/{Cargo.toml,
    // src/main.rs, static/}. `cd out/server && cargo run` serves on :8080.
    let server_dir = Path::new("out").join("server");
    let src_dir = server_dir.join("src");
    let static_dir = server_dir.join("static");
    let _ = fs::create_dir_all(&src_dir);
    let _ = fs::create_dir_all(&static_dir);
    let _ = fs::write(server_dir.join("Cargo.toml"), &cargo_toml);
    let _ = fs::write(src_dir.join("main.rs"), &server_rs);
    // client.ts lives beside the server's static dir, ready for the frontend build.
    let _ = fs::write(static_dir.join("client.ts"), &client_ts);
    let _ = fs::write(static_dir.join("index.html"), &index_html);

    println!(
        "xeres: compiled {} - {} model(s), {} fn(s), {} screen(s)\n  -> out/server/ (run: cd out/server && cargo run)",
        path,
        program.models.len(),
        program.functions.len(),
        program.screens.len()
    );
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
