// The fixture suite as a cargo integration test. Every tests/*.xrs is the
// spec: pass_* must compile (exit 0), fail_* must be rejected (exit != 0).
use std::path::Path;
use std::process::Command;

#[test]
fn fixtures() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests");
    let bin = env!("CARGO_BIN_EXE_xeres");
    let mut checked = 0;

    let mut entries: Vec<_> = std::fs::read_dir(&dir)
        .expect("tests dir")
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().map(|x| x == "xrs").unwrap_or(false))
        .collect();
    entries.sort();

    for path in entries {
        let name = path.file_name().unwrap().to_string_lossy().to_string();
        let want_ok = name.starts_with("pass_");
        let out = Command::new(bin)
            .arg("build")
            .arg(&path)
            .output()
            .expect("run xeres");
        assert_eq!(
            out.status.success(),
            want_ok,
            "fixture {name}: expected {}, got exit {:?}\nstderr:\n{}",
            if want_ok { "pass" } else { "fail" },
            out.status.code(),
            String::from_utf8_lossy(&out.stderr)
        );
        checked += 1;
    }
    assert!(checked >= 30, "only {checked} fixtures found — suite incomplete?");
    println!("{checked} fixtures verified");
}
