#![no_main]
//! Fuzz the CLI argument parser with arbitrary argv (NUL-separated tokens).
//! parse_args must always return Ok/Err, never panic, on any input.
use libfuzzer_sys::fuzz_target;
use i2p_vanity::parse_args;

fuzz_target!(|data: &[u8]| {
    let s = String::from_utf8_lossy(data);
    let argv: Vec<&str> = s.split('\0').collect();
    let _ = parse_args(&argv);
});
