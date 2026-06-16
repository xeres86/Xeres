// `xeres fmt` idempotence — the formatter's correctness bar: formatting an
// already-formatted file must be a no-op (`fmt(fmt(x)) == fmt(x)`). We drive the
// real binary over a temp copy of every `tests/*.xrs`: format once, then assert
// `fmt --check` passes. (The fixture corpus is the idempotence test set, per the
// spec — no golden strings while the style settles.)
use std::fs;
use std::path::Path;
use std::process::Command;

#[test]
fn fmt_is_idempotent_over_the_corpus() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests");
    let bin = env!("CARGO_BIN_EXE_xeres");
    let tmp = std::env::temp_dir().join("xeres_fmt_idem");
    let _ = fs::create_dir_all(&tmp);

    let mut entries: Vec<_> = fs::read_dir(&dir)
        .expect("tests dir")
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().map(|x| x == "xrs").unwrap_or(false))
        .collect();
    entries.sort();

    let mut checked = 0;
    for path in entries {
        let name = path.file_name().unwrap().to_string_lossy().to_string();
        let src = fs::read_to_string(&path).unwrap();
        let work = tmp.join(&name);
        fs::write(&work, &src).unwrap();

        // format once
        let f1 = Command::new(bin).arg("fmt").arg(&work).output().expect("run fmt");
        assert!(
            f1.status.success(),
            "fmt failed on {name}: {}",
            String::from_utf8_lossy(&f1.stderr)
        );
        let formatted = fs::read_to_string(&work).unwrap();

        // re-formatting must be a no-op
        let check = Command::new(bin).arg("fmt").arg("--check").arg(&work).output().expect("run fmt --check");
        assert!(
            check.status.success(),
            "fmt is not idempotent on {name}.\n--- formatted ---\n{formatted}"
        );
        checked += 1;
    }
    assert!(checked >= 30, "only {checked} fixtures formatted — suite incomplete?");
    println!("{checked} fixtures formatted idempotently");
}
