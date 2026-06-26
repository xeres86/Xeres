// src/diagnostics.rs
//
// One diagnostic type + one renderer, shared by the module loader (import
// resolution, R34/R35) and the checker (R1..R35). Before this, each carried its
// own near-identical error struct and `main` had two separate print paths.
//
// `file` is the source file the diagnostic points at; an EMPTY string means "the
// entry file" — the common single-file case, and what the checker uses (it works
// on the merged program and attributes to the entry). The loader sets a real
// file so a multi-file program's errors point at the right source.

use std::collections::HashMap;
use std::fs;

pub struct Diagnostic {
    /// Source file this points at; empty = the entry file (renderer falls back).
    pub file: String,
    pub line: usize,
    pub rule: &'static str,
    pub message: String,
}

/// Print diagnostics to stderr with a GitHub-style source snippet. Any
/// diagnostic whose `file` is empty is shown against `entry_path`. File contents
/// are read once and cached, so N errors in one file cost one read.
pub fn report(diags: &[Diagnostic], entry_path: &str) {
    let mut cache: HashMap<String, Vec<String>> = HashMap::new();
    for d in diags {
        let path = if d.file.is_empty() { entry_path } else { d.file.as_str() };
        eprintln!("error: [{}] {}", d.rule, d.message);
        eprintln!("  --> {}:{}", path, d.line);
        let lines = cache.entry(path.to_string()).or_insert_with(|| {
            fs::read_to_string(path)
                .map(|s| s.lines().map(|l| l.to_string()).collect())
                .unwrap_or_default()
        });
        if d.line >= 1 && d.line <= lines.len() {
            let gutter = format!("{:>4}", d.line);
            eprintln!("     |");
            eprintln!("{} | {}", gutter, lines[d.line - 1]);
            eprintln!("     |");
        }
        eprintln!();
    }
}
