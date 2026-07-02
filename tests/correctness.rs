//! Correctness tests for i2pvanity.
//!
//! These prove the two claims the tool lives or dies by:
//!   1. A "hit" address really does start with the requested prefix
//!      (the bit-matcher must agree with real base32 encoding).
//!   2. The stored ElGamal exponent `x` is the discrete log of the stored
//!      public key `y` (so the written .dat reproduces the address in i2pd).

use crypto_bigint::modular::MontyForm;
use crypto_bigint::U2048;
use i2p_vanity::{monty_params, parse_args, run_worker, Matcher};
use sha2::{Digest, Sha256};

// Same layout constants the library uses, re-declared here so a silent change
// to the .dat format is caught by these tests.
const DEST_LEN: usize = 391;
const ELG_PUB_LEN: usize = 256;
const DAT_LEN: usize = DEST_LEN + 256 + 32;

fn address_of(dest: &[u8]) -> String {
    let digest = Sha256::digest(dest);
    data_encoding::BASE32_NOPAD
        .encode(&digest)
        .to_ascii_lowercase()
        + ".b32.i2p"
}

/// The matcher's bit test must agree with real base32 for every possible
/// prefix bit-length (5, 10, 15, ... bits - i.e. lengths that are and are not
/// byte-aligned). This is where an off-by-one in the partial-byte mask hides.
#[test]
fn matcher_agrees_with_base32() {
    for len in 1..=12usize {
        // A deterministic spread of digests derived by hashing a counter.
        for seed in 0u32..2000 {
            let digest: [u8; 32] = Sha256::digest(seed.to_le_bytes()).into();
            let b32 = data_encoding::BASE32_NOPAD
                .encode(&digest)
                .to_ascii_lowercase();
            let prefix = &b32[..len];
            let m = Matcher::new(prefix).unwrap();
            assert!(
                m.matches(&digest),
                "matcher rejected its own prefix '{prefix}' (len {len})"
            );

            // And a matcher for a *different* prefix of the same length must
            // reject this digest (unless base32 actually collides on it).
            let other: String = prefix
                .chars()
                .map(|c| if c == 'a' { 'b' } else { 'a' })
                .collect();
            let mo = Matcher::new(&other).unwrap();
            let should = b32.starts_with(&other);
            assert_eq!(
                mo.matches(&digest),
                should,
                "matcher disagreed with base32 for '{other}' on digest {digest:02x?}"
            );
        }
    }
}

/// End-to-end: search for a short prefix, then verify the produced key really
/// yields that address and the stored exponent is the discrete log of the key.
#[test]
fn hit_is_valid_and_addresses_match() {
    let params = monty_params();
    let two = MontyForm::new(&U2048::from(2u64), params);

    for prefix in ["a", "z2", "sam"] {
        let matcher = Matcher::new(prefix).unwrap();
        let mut rng = rand::rngs::OsRng;
        let out = run_worker(&matcher, &params, &mut rng, || false);
        let found = out.hit.expect("short prefix must hit");

        // .dat is exactly 679 bytes.
        assert_eq!(found.dat.len(), DAT_LEN, "wrong .dat length");

        // The address recomputed from the destination must equal the reported
        // address AND start with the requested prefix.
        let dest = &found.dat[..DEST_LEN];
        let addr = address_of(dest);
        assert_eq!(addr, found.address, "reported address != sha256(dest)");
        assert!(
            found.address.starts_with(prefix),
            "address '{}' does not start with '{prefix}'",
            found.address
        );

        // y (stored pubkey) == 2^x mod p (stored exponent).
        let y_bytes: [u8; ELG_PUB_LEN] = dest[..ELG_PUB_LEN].try_into().unwrap();
        let x_bytes: [u8; 256] = found.dat[DEST_LEN..DEST_LEN + 256].try_into().unwrap();
        let y = U2048::from_be_slice(&y_bytes);
        let x = U2048::from_be_slice(&x_bytes);
        let recomputed = two.pow(&x).retrieve();
        assert_eq!(
            recomputed, y,
            "stored x is not the discrete log of stored y"
        );
    }
}

/// expected() must equal 32^len (the average number of attempts).
#[test]
fn expected_is_32_pow_len() {
    for len in 1..=12usize {
        let prefix = "a".repeat(len);
        let m = Matcher::new(&prefix).unwrap();
        let want = 32f64.powi(len as i32);
        assert_eq!(m.expected(), want, "expected() wrong for len {len}");
    }
}

#[test]
fn matcher_rejects_bad_prefixes() {
    assert!(Matcher::new("").is_err(), "empty must be rejected");
    assert!(
        Matcher::new("aaaaaaaaaaaaa").is_err(),
        "13 chars must be rejected"
    );
    assert!(Matcher::new("a1").is_err(), "'1' is not base32");
    assert!(Matcher::new("a8").is_err(), "'8' is not base32");
    assert!(Matcher::new("a0").is_err(), "'0' is not base32");
    // Uppercase should be accepted (normalized to lowercase).
    assert!(Matcher::new("SAM").is_ok(), "uppercase should be accepted");
}

#[test]
fn parse_args_basics() {
    let a = parse_args(&["sam", "--out", "x.dat", "--threads", "4"]).unwrap();
    assert_eq!(a.prefix.as_deref(), Some("sam"));
    assert_eq!(a.out.as_deref(), Some("x.dat"));
    assert_eq!(a.threads, Some(4));

    let a = parse_args(&["-p", "abc", "-j", "8", "--bench", "-s", "5"]).unwrap();
    assert_eq!(a.prefix.as_deref(), Some("abc"));
    assert!(a.bench);
    assert_eq!(a.seconds, Some(5));

    assert!(parse_args(&["--threads", "notanumber"]).is_err());
    assert!(parse_args(&["--out"]).is_err(), "missing value must error");
    assert!(parse_args(&["sam", "extra"]).is_err(), "double positional");
    assert!(parse_args(&["--nope"]).is_err(), "unknown flag");
}
