//! CLI-level tests that drive the built binary. These cover behaviour that
//! lives in `main.rs` (argument validation, output-path checks) which the
//! library tests can't reach directly.

use std::process::Command;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_i2pvanity"))
}

/// Pointing --out at an existing directory must fail fast with a clean error,
/// not panic after running the whole search. Regression test.
#[test]
fn out_is_directory_errors_cleanly() {
    let dir = std::env::temp_dir().join(format!("i2pvanity_cli_test_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();

    let output = bin()
        .arg("a")
        .arg("--out")
        .arg(&dir)
        .arg("--threads")
        .arg("2")
        .output()
        .expect("run binary");

    std::fs::remove_dir_all(&dir).ok();

    // Exit code 2 (usage/validation error), NOT a panic/abort (134).
    assert_eq!(
        output.status.code(),
        Some(2),
        "expected clean exit 2, got {:?}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("is a directory"),
        "stderr should explain the directory problem, got: {stderr}"
    );
}

/// A normal generate writes a 679-byte file and prints the address.
#[test]
fn generate_writes_valid_dat() {
    let out = std::env::temp_dir().join(format!("i2pvanity_cli_ok_{}.dat", std::process::id()));
    std::fs::remove_file(&out).ok();

    let output = bin()
        .arg("a")
        .arg("--out")
        .arg(&out)
        .arg("--threads")
        .arg("2")
        .output()
        .expect("run binary");

    assert!(
        output.status.success(),
        "generate failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let bytes = std::fs::read(&out).expect("output file exists");
    std::fs::remove_file(&out).ok();
    assert_eq!(bytes.len(), 679, "written .dat must be 679 bytes");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.trim().starts_with('a') && stdout.contains(".b32.i2p"),
        "stdout should print the address, got: {stdout}"
    );
}
