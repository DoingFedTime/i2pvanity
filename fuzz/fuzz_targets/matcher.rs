#![no_main]
//! Fuzz the prefix parser and matcher on arbitrary UTF-8 input. Matcher::new
//! must never panic on any string, and a successful matcher must never panic in
//! matches()/expected() on any 32-byte digest.
use libfuzzer_sys::fuzz_target;
use i2p_vanity::Matcher;

fuzz_target!(|data: &[u8]| {
    let s = String::from_utf8_lossy(data);
    if let Ok(m) = Matcher::new(&s) {
        // expected() must be a finite, sane number for any accepted prefix.
        let e = m.expected();
        assert!(e.is_finite() && e >= 1.0, "expected() insane for {s:?}: {e}");
        // matches() must never panic/index-out-of-bounds on any digest.
        let mut digest = [0u8; 32];
        for (i, b) in data.iter().take(32).enumerate() {
            digest[i] = *b;
        }
        let _ = m.matches(&digest);
    }
});
