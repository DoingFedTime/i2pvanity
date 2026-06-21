//! I2P `.b32.i2p` vanity address generator.
//!
//! Fixes the Ed25519 key and walks the ElGamal key instead. Since the ElGamal
//! generator is 2, the next public key is just `y` doubled mod p, and the next
//! private key is `x + 1`. That makes each attempt one big-int add plus a
//! SHA-256, not a fresh keypair, and the exponent is what i2pd stores anyway.

use crypto_bigint::modular::{MontyForm, MontyParams};
use crypto_bigint::{NonZero, Odd, RandomMod, U2048};
use ed25519_dalek::SigningKey;
use rand_core::CryptoRngCore;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

// RFC 3526 group 14, the 2048-bit MODP prime i2pd uses for ElGamal.
const P_HEX: &str = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74\
020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437\
4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED\
EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05\
98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB\
9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B\
E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718\
3995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF";

// Destination: elg pubkey(256) | zero pad(96) | ed pubkey(32) | cert(7) = 391.
const DEST_LEN: usize = 391;
const ELG_PUB_LEN: usize = 256;
const ED_PUB_OFF: usize = 352;
const CERT: [u8; 7] = [0x05, 0x00, 0x04, 0x00, 0x07, 0x00, 0x00];
// .dat = destination || ElGamal_priv(256) || Ed25519_priv(32).
const DAT_LEN: usize = DEST_LEN + 256 + 32;

// How often run_worker polls should_stop.
pub const STOP_INTERVAL: u64 = 8192;

pub struct Found {
    pub address: String,
    // 679-byte i2pd .dat, wiped from memory on drop.
    pub dat: Zeroizing<Vec<u8>>,
    pub attempts: u64,
}

#[derive(Clone)]
pub struct Matcher {
    full: usize, // leading whole bytes that must match
    mask: u8,    // mask for the partial trailing byte (0 if byte-aligned)
    target: Vec<u8>,
}

impl Matcher {
    pub fn new(prefix: &str) -> Result<Self, String> {
        let prefix = prefix.to_ascii_lowercase();
        if prefix.is_empty() || prefix.len() > 12 {
            return Err("prefix must be 1..=12 chars".into());
        }
        let nbits = prefix.len() * 5;
        let mut target = vec![0u8; nbits.div_ceil(8)];
        let mut bitpos = 0usize;
        for ch in prefix.chars() {
            let v = b32_val(ch).ok_or_else(|| format!("invalid base32 char '{ch}'"))?;
            for i in (0..5).rev() {
                if (v >> i) & 1 == 1 {
                    target[bitpos / 8] |= 1 << (7 - (bitpos % 8));
                }
                bitpos += 1;
            }
        }
        let rem = nbits % 8;
        let mask = if rem == 0 { 0 } else { 0xFFu8 << (8 - rem) };
        Ok(Matcher {
            full: nbits / 8,
            mask,
            target,
        })
    }

    // Average attempts to find this prefix: 32^len.
    pub fn expected(&self) -> f64 {
        2f64.powi((self.full * 8 + self.mask.count_ones() as usize) as i32)
    }

    #[inline(always)]
    pub fn matches(&self, digest: &[u8; 32]) -> bool {
        if digest[..self.full] != self.target[..self.full] {
            return false;
        }
        self.mask == 0 || (digest[self.full] & self.mask) == self.target[self.full]
    }
}

fn b32_val(ch: char) -> Option<u8> {
    match ch {
        'a'..='z' => Some(ch as u8 - b'a'),
        '2'..='7' => Some(ch as u8 - b'2' + 26),
        _ => None,
    }
}

fn address_of(dest: &[u8]) -> String {
    let digest = Sha256::digest(dest);
    let b32 = data_encoding::BASE32_NOPAD
        .encode(&digest)
        .to_ascii_lowercase();
    format!("{b32}.b32.i2p")
}

pub fn monty_params() -> MontyParams<{ U2048::LIMBS }> {
    let p = U2048::from_be_hex(P_HEX);
    MontyParams::new_vartime(Odd::new(p).expect("prime is odd"))
}

pub struct WorkerOutcome {
    pub attempts: u64,
    pub hit: Option<Found>,
}

// should_stop is polled every STOP_INTERVAL attempts; true ends the loop.
pub fn run_worker<R: CryptoRngCore + ?Sized>(
    matcher: &Matcher,
    params: &MontyParams<{ U2048::LIMBS }>,
    rng: &mut R,
    mut should_stop: impl FnMut() -> bool,
) -> WorkerOutcome {
    let sk = SigningKey::generate(rng);
    let ed_pub = sk.verifying_key().to_bytes();
    let mut ed_priv = sk.to_bytes();

    let p = U2048::from_be_hex(P_HEX);
    let g_m = MontyForm::new(&U2048::from(2u64), *params);

    let p_nz = NonZero::new(p).expect("prime is nonzero");
    let mut x = U2048::random_mod(rng, &p_nz);
    if x == U2048::ZERO {
        x = U2048::ONE;
    }
    let mut y = g_m.pow(&x).retrieve(); // y = 2^x mod p

    let mut dest = [0u8; DEST_LEN];
    dest[ED_PUB_OFF..ED_PUB_OFF + 32].copy_from_slice(&ed_pub);
    dest[DEST_LEN - 7..].copy_from_slice(&CERT);

    let mut attempts: u64 = 0;
    loop {
        dest[..ELG_PUB_LEN].copy_from_slice(&y.to_be_bytes());
        let digest: [u8; 32] = Sha256::digest(dest).into();
        attempts += 1;

        if matcher.matches(&digest) {
            let mut xb = x.to_be_bytes();
            let mut dat = Vec::with_capacity(DAT_LEN);
            dat.extend_from_slice(&dest);
            dat.extend_from_slice(&xb);
            dat.extend_from_slice(&ed_priv);
            let address = address_of(&dest);
            xb.zeroize();
            x.zeroize();
            ed_priv.zeroize();
            return WorkerOutcome {
                attempts,
                hit: Some(Found {
                    address,
                    dat: Zeroizing::new(dat),
                    attempts,
                }),
            };
        }

        // g == 2: next pubkey is y doubled mod p, next exponent is x + 1.
        y = y.add_mod(&y, &p);
        x = x.wrapping_add(&U2048::ONE);

        if attempts.is_multiple_of(STOP_INTERVAL) && should_stop() {
            x.zeroize();
            ed_priv.zeroize();
            return WorkerOutcome {
                attempts,
                hit: None,
            };
        }
    }
}

#[derive(Default)]
pub struct ParsedArgs {
    pub prefix: Option<String>,
    pub out: Option<String>,
    pub threads: Option<usize>,
    pub bench: bool,
    pub seconds: Option<u64>,
    pub uid: u32,
    pub gid: u32,
    pub help: bool,
}

pub fn parse_args<S: AsRef<str>>(argv: &[S]) -> Result<ParsedArgs, String> {
    let mut a = ParsedArgs::default();
    let mut it = argv.iter();
    while let Some(arg) = it.next() {
        let arg = arg.as_ref();
        macro_rules! value {
            () => {
                match it.next() {
                    Some(v) => v.as_ref(),
                    None => return Err(format!("missing value for {arg}")),
                }
            };
        }
        macro_rules! parse_num {
            ($what:literal) => {{
                let v = value!();
                v.parse()
                    .map_err(|_| format!("invalid {} '{}'", $what, v))?
            }};
        }
        match arg {
            "--prefix" | "-p" => a.prefix = Some(value!().to_string()),
            "--out" | "-o" => a.out = Some(value!().to_string()),
            "--threads" | "-j" => a.threads = Some(parse_num!("--threads")),
            "--uid" => a.uid = parse_num!("--uid"),
            "--gid" => a.gid = parse_num!("--gid"),
            "--seconds" | "-s" => a.seconds = Some(parse_num!("--seconds")),
            "--bench" => a.bench = true,
            "--help" | "-h" => a.help = true,
            s if !s.starts_with('-') => {
                if a.prefix.is_some() {
                    return Err(format!("unexpected extra argument '{s}'"));
                }
                a.prefix = Some(s.to_string());
            }
            other => return Err(format!("unknown arg: {other}")),
        }
    }
    Ok(a)
}
