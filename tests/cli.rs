//! CLI-level tests that drive the built binary. These cover behaviour that
//! lives in `main.rs` (argument validation, output-path checks) which the
//! library tests can't reach directly.

use std::process::Command;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_i2pvanity"))
}

fn unique_dir(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("i2pvanity_{tag}_{}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    d
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

/// A non-writable output directory must be caught up front (exit 2) BEFORE the
/// search runs, not panic on the write afterwards. Regression test for the
/// read-only-dir abort that lost the found key. Unix-only (uses mode bits).
#[cfg(unix)]
#[test]
fn readonly_output_dir_fails_fast() {
    use std::os::unix::fs::PermissionsExt;

    // Skip when running as root (root ignores the mode bits and can write).
    if unsafe { libc_geteuid() } == 0 {
        eprintln!("skipping readonly test as root");
        return;
    }

    let dir = unique_dir("ro");
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o500)).unwrap();

    let output = bin()
        .arg("a")
        .arg("--out")
        .arg(dir.join("eepsite.dat"))
        .arg("--threads")
        .arg("2")
        .output()
        .expect("run binary");

    // Restore perms so cleanup works.
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).ok();
    std::fs::remove_dir_all(&dir).ok();

    assert_eq!(
        output.status.code(),
        Some(2),
        "read-only dir must fail fast with exit 2, got {:?}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    // Must NOT have run the search (no HIT line) - caught before searching.
    assert!(
        !stderr.contains("HIT:"),
        "should have failed before searching, but found a HIT: {stderr}"
    );
}

// Minimal geteuid shim so the test can skip under root without pulling in a
// dependency. `getuid`/`geteuid` are always present in libc.
#[cfg(unix)]
extern "C" {
    #[link_name = "geteuid"]
    fn libc_geteuid() -> u32;
}

/// Many concurrent generations to the SAME output path must all succeed
/// (exit 0), leave a valid final file, and leave no stray .tmp files. Regression
/// test for the fixed-name temp file that made concurrent writers clobber each
/// other. Unix-only.
#[cfg(unix)]
#[test]
fn concurrent_same_output_path() {
    let dir = unique_dir("conc");
    let out = dir.join("same.dat");

    let mut children: Vec<std::process::Child> = (0..6)
        .map(|_| {
            bin()
                .arg("sam")
                .arg("--out")
                .arg(&out)
                .arg("--threads")
                .arg("2")
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .expect("spawn")
        })
        .collect();

    for c in &mut children {
        let status = c.wait().expect("wait");
        assert!(status.success(), "a concurrent writer failed: {status:?}");
    }

    // Final file exists and is the right size.
    let meta = std::fs::metadata(&out).expect("final file must exist");
    assert_eq!(meta.len(), 679, "final file must be a full 679-byte key");

    // No stray temp files left behind.
    let leftovers: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().ends_with(".tmp"))
        .collect();
    std::fs::remove_dir_all(&dir).ok();
    assert!(
        leftovers.is_empty(),
        "left {} stray .tmp files behind",
        leftovers.len()
    );
}
