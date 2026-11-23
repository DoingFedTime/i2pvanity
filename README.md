# i2pvanity

Generates I2P `.b32.i2p` vanity addresses (eepsites). It writes a standard
i2pd-compatible 679-byte `PrivateKeys` `.dat` whose base32 address starts with a
prefix you pick.

On a 32-thread box it does about 95 million candidates/sec, roughly 130x faster
than a naive Python generator that regenerates the keypair every attempt. A
7-character prefix drops from an overnight run to about 6 minutes.

```
$ i2pvanity sam --out eepsite.dat --threads 16
generate: prefix='sam'  threads=16  expected~32768 attempts
HIT: sam4kxhwisjadmtfxgx65mohdarhc3kw66uk3ea2odju3egkvmsa.b32.i2p
     103671 attempts in 0.010s (10678965 keys/sec, 16 threads)
wrote eepsite.dat (679 bytes, mode 0600)
```

## Why it's fast

An I2P address is `base32(sha256(destination))`, and the destination holds two
public keys: an ElGamal-2048 encryption key and an Ed25519 signing key. To
search for a prefix you change one of them and re-hash.

The slow way is to vary the Ed25519 key: i2pd stores it as a seed, so every
attempt is a full SHA-512 + scalar-mult keygen with no shortcut.

i2pvanity fixes the Ed25519 key and walks the ElGamal key instead. The ElGamal
generator is 2, so the next public key is just the current one doubled mod p,
`y = (y + y) mod p`, and the matching private key is `x + 1`. That's one big-int
add per attempt instead of a keygen, and `x` is exactly what i2pd stores, so the
`.dat` is valid. Same idea as mkp224o's point-addition trick, on the ElGamal
side. Prefix matching works on the raw SHA-256 bits, so the loop never
base32-encodes.

| Threads | Python (naive) | i2pvanity    | Speedup |
| ------- | -------------: | -----------: | ------- |
| 1       |   47,096 keys/s |  4.3M keys/s | ~91x    |
| 30      |  747,572 keys/s | 94.7M keys/s | ~127x   |

## Install

```
cargo install i2pvanity
```

Or build it:

```
git clone https://sambent.dev/sam/i2pvanity
cd i2pvanity
cargo build --release      # target/release/i2pvanity
```

For a static binary (Alpine etc.): `cargo build --release --target x86_64-unknown-linux-musl`.

## Usage

```
i2pvanity <prefix> --out eepsite.dat [--threads N] [--uid N --gid N]
i2pvanity <prefix> --bench [--seconds N] [--threads N]
```

- `<prefix>` is 1 to 12 base32 chars (`a-z`, `2-7`).
- `--threads` defaults to all cores.
- `--uid`/`--gid` chown the written file (useful when generating as root in a container).
- `--bench` measures throughput instead of writing a key.

On a terminal a long search prints a live progress line; when output is piped it
stays quiet.

The file is `Destination(391) || ElGamal_priv(256) || Ed25519_priv(32)`, mode
`0600`. Drop it in i2pd's `destinations/` or point a tunnel's `keys=` at it.

## Difficulty

Each extra character is 5 more bits, so 32x the work:

| Prefix length | Avg attempts | Time at 95M/s (30 threads) |
| ------------- | -----------: | -------------------------- |
| 3 (`sam`)     |       32,768 | instant                    |
| 5             |        33.5M | under a second             |
| 6             |        1.07B | ~11 seconds                |
| 7 (`sambent`) |        34.4B | ~6 minutes                 |
| 8             |         1.1T | ~3 hours                   |

## Verify a key

The address comes straight out of the file, so you can check it without this tool:

```sh
printf "%s.b32.i2p\n" "$(head -c 391 eepsite.dat | sha256sum | cut -d' ' -f1 \
  | xxd -r -p | base32 | tr -d = | tr A-Z a-z)"
```

`i2pd-tools keyinfo eepsite.dat` prints the same address if you have it.

## Notes

The `.dat` is your private key, written in plaintext (i2pd needs it that way) at
mode `0600`. In-memory key material is zeroized on drop. The tool makes no
network connections.

## Development

```
cargo test
```

The tests check generated keys against an independent SHA-256/base32 derivation,
confirm the stored Ed25519 key signs for the published identity, and drive the
CLI end to end. `fuzz/` holds cargo-fuzz targets for the prefix matcher and the
argument parser (`cargo fuzz run matcher`, needs a nightly toolchain).

## License

MIT OR Apache-2.0.
