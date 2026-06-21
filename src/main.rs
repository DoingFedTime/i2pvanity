//! i2pvanity CLI.
//!
//!   i2pvanity <prefix> --out <path> [--threads N]
//!   i2pvanity <prefix> --bench [--seconds N] [--threads N]

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use i2p_vanity::{monty_params, parse_args, Found, Matcher};

// Keep a fat-fingered --threads from spawning a million OS threads.
const MAX_THREADS: usize = 4096;

fn main() {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let parsed = match parse_args(&argv) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("ERROR: {e}");
            usage();
            std::process::exit(2);
        }
    };

    if parsed.help {
        usage();
        return;
    }

    let prefix = match parsed.prefix {
        Some(p) => p,
        None => {
            usage();
            std::process::exit(2);
        }
    };
    let matcher = match Matcher::new(&prefix) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("ERROR: {e}");
            std::process::exit(2);
        }
    };

    let threads = parsed
        .threads
        .unwrap_or_else(|| {
            std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(1)
        })
        .clamp(1, MAX_THREADS);

    if parsed.bench {
        run_bench(&matcher, &prefix, threads, parsed.seconds.unwrap_or(10));
    } else {
        let out = match parsed.out {
            Some(o) => o,
            None => {
                eprintln!("ERROR: --out <path> required for generate mode");
                std::process::exit(2);
            }
        };
        // Check the path before spending minutes searching.
        if let Err(e) = check_writable(&out) {
            eprintln!("ERROR: cannot write to '{out}': {e}");
            std::process::exit(2);
        }
        run_generate(&matcher, &prefix, threads, &out, parsed.uid, parsed.gid);
    }
}

fn check_writable(path: &str) -> Result<(), String> {
    let p = std::path::Path::new(path);
    let dir = p
        .parent()
        .filter(|d| !d.as_os_str().is_empty())
        .unwrap_or_else(|| std::path::Path::new("."));
    let meta = std::fs::metadata(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    if !meta.is_dir() {
        return Err(format!("{} is not a directory", dir.display()));
    }
    Ok(())
}

fn usage() {
    eprintln!(
        "i2pvanity - fast .b32.i2p vanity generator\n\n\
         GENERATE:  i2pvanity <prefix> --out eepsite.dat [--threads N] [--uid N --gid N]\n\
         BENCH:     i2pvanity <prefix> --bench [--seconds N] [--threads N]\n\n\
         prefix: 1..=12 base32 chars (a-z, 2-7)\n\
         --uid/--gid: chown the written .dat (default 0 = leave as-is)"
    );
}

// One updating progress line, only on a TTY so piped output stays clean.
fn progress_monitor(found: &AtomicBool, live: &AtomicU64, start: Instant, expected: f64) {
    use std::io::{IsTerminal, Write};
    if !std::io::stderr().is_terminal() {
        return;
    }
    let mut last = Instant::now();
    let mut printed = false;
    while !found.load(Ordering::Relaxed) {
        std::thread::sleep(Duration::from_millis(100));
        if last.elapsed() < Duration::from_secs(2) {
            continue;
        }
        last = Instant::now();
        let n = live.load(Ordering::Relaxed) as f64;
        let el = start.elapsed().as_secs_f64().max(1e-9);
        let rate = n / el;
        let pct = (n / expected * 100.0).min(99.9);
        let eta = if rate > 0.0 {
            (expected - n).max(0.0) / rate
        } else {
            f64::INFINITY
        };
        eprint!("\r  searching… {n:.0} tried · {rate:.0}/s · {pct:.1}% · ETA {eta:.0}s    ");
        let _ = std::io::stderr().flush();
        printed = true;
    }
    if printed {
        eprint!("\r\x1b[K");
        let _ = std::io::stderr().flush();
    }
}

fn run_generate(matcher: &Matcher, prefix: &str, threads: usize, out: &str, uid: u32, gid: u32) {
    eprintln!(
        "generate: prefix='{prefix}'  threads={threads}  expected~{:.0} attempts",
        matcher.expected()
    );
    let params = monty_params();
    let found = AtomicBool::new(false);
    let total = AtomicU64::new(0);
    let live = AtomicU64::new(0); // approximate, for the progress line
    let result: std::sync::Mutex<Option<Found>> = std::sync::Mutex::new(None);
    let start = Instant::now();

    std::thread::scope(|scope| {
        scope.spawn(|| progress_monitor(&found, &live, start, matcher.expected()));

        for _ in 0..threads {
            scope.spawn(|| {
                let mut rng = rand::rngs::OsRng;
                let outcome = i2p_vanity::run_worker(matcher, &params, &mut rng, || {
                    live.fetch_add(i2p_vanity::STOP_INTERVAL, Ordering::Relaxed);
                    found.load(Ordering::Relaxed)
                });
                total.fetch_add(outcome.attempts, Ordering::Relaxed);
                if let Some(f) = outcome.hit {
                    found.store(true, Ordering::Relaxed);
                    *result.lock().unwrap() = Some(f);
                }
            });
        }
    });

    let elapsed = start.elapsed();
    let attempts = total.load(Ordering::Relaxed);
    match result.into_inner().unwrap() {
        Some(f) => {
            let rate = attempts as f64 / elapsed.as_secs_f64().max(1e-9);
            eprintln!(
                "HIT: {}\n     {attempts} attempts in {:.3}s ({:.0} keys/sec, {threads} threads)",
                f.address,
                elapsed.as_secs_f64(),
                rate
            );
            write_dat(out, &f.dat, uid, gid);
            println!("{}", f.address);
        }
        None => {
            eprintln!("ERROR: workers exited without a hit");
            std::process::exit(1);
        }
    }
}

fn run_bench(matcher: &Matcher, prefix: &str, threads: usize, seconds: u64) {
    eprintln!("bench: prefix='{prefix}'  threads={threads}  duration={seconds}s");
    let params = monty_params();
    let dur = Duration::from_secs(seconds);
    let total = AtomicU64::new(0);
    let start = Instant::now();

    std::thread::scope(|scope| {
        for _ in 0..threads {
            scope.spawn(|| {
                let mut rng = rand::rngs::OsRng;
                let t0 = Instant::now();
                let mut local = 0u64;
                // A short prefix hits and ends the worker early, so restart
                // until the time budget is spent.
                while t0.elapsed() < dur {
                    let outcome =
                        i2p_vanity::run_worker(matcher, &params, &mut rng, || t0.elapsed() >= dur);
                    local += outcome.attempts;
                }
                total.fetch_add(local, Ordering::Relaxed);
            });
        }
    });

    let elapsed = start.elapsed().as_secs_f64();
    let attempts = total.load(Ordering::Relaxed);
    let rate = attempts as f64 / elapsed.max(1e-9);
    eprintln!(
        "BENCH: {attempts} attempts in {:.2}s = {:.0} keys/sec ({threads} threads, {:.0}/sec/thread)",
        elapsed,
        rate,
        rate / threads as f64
    );
    println!("{rate:.0}");
}

#[cfg(unix)]
fn write_dat(path: &str, dat: &[u8], uid: u32, gid: u32) {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let tmp = format!("{path}.tmp");
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)
        .expect("open tmp");
    f.write_all(dat).expect("write");
    f.sync_all().ok();
    std::fs::rename(&tmp, path).expect("rename");
    if uid != 0 || gid != 0 {
        if let Err(e) = std::os::unix::fs::chown(path, Some(uid), Some(gid)) {
            eprintln!("warning: could not chown {path} to {uid}:{gid}: {e}");
        }
    }
    eprintln!("wrote {path} ({} bytes, mode 0600)", dat.len());
}

#[cfg(not(unix))]
fn write_dat(path: &str, dat: &[u8], _uid: u32, _gid: u32) {
    std::fs::write(path, dat).expect("write");
    eprintln!("wrote {path} ({} bytes)", dat.len());
}
