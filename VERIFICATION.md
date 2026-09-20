# Verification record

Performed on 2026-09-20 with Rust 1.98.1, edition 2024. Application version: **0.1.1**.
The Rust-only verification migration changes tests and build metadata, not application
commands, encryption formats, or key derivation. See `REVIEW.md` for earlier fixes.

## Current Rust-only suite

Run `cargo test --locked --release`; no Python interpreter, Python packages,
OpenSSL installation, or libsodium installation is needed. Cargo obtains the Rust
test dependencies. The Windows and Linux GitHub jobs run this same command.

| Coverage | Windows | Linux |
| --- | ---: | ---: |
| Unit tests | 56 | 43 |
| CLI integration tests | 9 | 8 |
| Independent crypto and large-file integration tests | 3 | 3 |
| Native Windows console tests | 17 | Not applicable |
| Total | 85 | 54 |

The Windows suite passed locally with no ignored tests. Formatting and Clippy with
warnings denied passed for Windows and Linux. Native Linux execution is performed
by the required GitHub check; its result is recorded on the pull request.

The three former Python scripts have been replaced as follows:

| Former script | Rust coverage |
| --- | --- |
| `windows_console.py` | `tests/windows_console.rs`: all 17 hidden-console, Unicode, editing, password, and Ctrl-C scenarios |
| `cancel_windows.py` | The Windows XOR cancellation case retains the 1,073,741,843-byte original-file hash check |
| `interop.py` | `tests/interop.rs`, `src/keygen_tests.rs`, and `tests/support/key_reference.rs` |

The independent references are `tiny-keccak` for SHA3-512, `crypto_secretstream`
for libsodium-compatible secretstream, `rust-argon2` for Argon2id, and `orion` for
ChaCha20. These are test-only dependencies and use different implementations from
the application's crypto. Secretstream is checked in both directions at six
boundary sizes. Key generation is checked byte-for-byte across a 1 MiB boundary;
the actual hidden Unicode password flow is independently checked on Windows too.
These checks now run automatically instead of requiring an optional manual script.

The 256 MiB test checks XChaCha encryption/decryption and repeating XOR recovery,
verifies full SHA3-512 hashes, and enforces a sampled process RSS below 96 MiB for
each transform. Timing is reported with `-- --nocapture`, without a speed threshold.
Key derivation's separate 64 MiB allocation is not subject to this streaming limit.
Windows cancellation tests wait for a live file-handle size above 1 MiB, then
require exit 130, unchanged originals/metadata, and removal of temporary output.
The 20 GB cancellation cases do not generate complete 20 GB keys.

The updated lockfile has 112 dependencies, including test-only dependencies.
The RustSec advisory scan reported zero vulnerabilities and zero warnings against
the same 1,251-advisory database used below. This offline recheck did not query
yanked-release status. See `verification/audit-rust-tests.json`.

## Historical release verification

The remaining record and older JSON reports describe earlier release runs. Their
Python/libsodium/OpenSSL references document those completed checks; they are not
requirements for building, using, or testing the current source.

## Windows x86_64 (MSVC, static CRT)

- **55 unit tests and 9 executable-level integration tests passed** in release mode
  (64 Rust tests, up from 23). No tests were skipped or ignored.
- **17 additional real-console scenarios passed**, including hidden Unicode
  password generation/restoration, empty/mismatched passwords, private SHA3 input,
  backspace over an emoji, Ctrl-U/Ctrl-W editing, cancellation at idle prompts and
  confirmation, and keyboard Ctrl-C. Console input mode was restored.
- Real Ctrl-C during XOR, XChaCha encryption, XChaCha decryption, key generation,
  and key restoration returned 130 and cleaned temporary output. The file transform
  cases preserved SHA3-512 of all 536,870,931 original plaintext bytes (or the whole
  ciphertext when testing decryption). Key restoration preserved the saved metadata.
  See `verification/windows-console-results.json`, which records the tested binary hash.
- Formatting check and Clippy with warnings denied passed.
- SHA3-512 matched the standard `abc` vector and Python hashlib for five text inputs.
- ChaCha20 matched the RFC 8439 block vector. Expansion across buffer boundaries
  matched one continuous stream; a seek to the 20 GB boundary succeeded without
  counter exhaustion.
- Password-generated output (1,048,593 bytes, spanning a buffer boundary) matched
  independent argon2-cffi and OpenSSL-backed ChaCha20 byte-for-byte.
- XChaCha files interoperated with actual libsodium through PyNaCl in **both
  directions**, for lengths 0, 1, 1,048,575, 1,048,576, 1,048,593, and 2,097,152.
- Rejection tests cover wrong keys, corrupted headers/ciphertext, missing final
  markers, truncated records, trailing bytes, reordered records, malformed lengths,
  short XOR keys, empty keys, invalid arguments, traversal/device names, protected
  hard-link aliases, existing destinations, and synthetic write/read failures.
- Tested in-place XOR -> XChaCha encryption -> XChaCha decryption -> XOR recovery.
  Authentication failure preserved the original and removed plaintext temporaries.
- Unicode filenames and 24 varying filename lengths exercised the Windows native
  rename buffer and destination identity check. Hard-linked in-place files and
  alternate data streams were refused. Directory locking was tested.
- Additional Windows tests checked protected DACLs before and after replacement,
  existing writers, new write attempts during reads, byte-range locks, read-only
  files, case aliases, empty/late alternate streams, paths longer than 260 characters,
  and surrogate pairs. A no-console process could hash text and create an XChaCha key.
- Publication tests checked an output created after preflight, an input path replaced
  during processing, a late hard link, old readers retaining old contents after
  replacement, and preservation of a completed temporary output after a sharing error.
- Every individual bit mutation and every truncation point of a small encrypted
  container was rejected. Tests also covered validly authenticated but forbidden
  record sequences, duplicated/deleted/spliced records, interrupted reads, partial
  writes, zero-byte writes mid-stream, and actual read-back byte corruption.
- Recovery metadata tests covered invalid costs/sizes/algorithms, unknown and
  duplicate fields, invalid UTF-8/hex, oversize JSON, and digest tampering. Late
  authentication failure after writing partial plaintext still preserved the original
  ciphertext and cleaned the temporary file.
- A real Windows Ctrl-C event during an in-place transform of 1,073,741,843 bytes
  returned exit code 130, removed the temporary output, and left the original's
  full SHA3-512 unchanged. See `verification/cancel-results.json`.
- Manual terminal password entry/confirmation completed key generation without
  echoing the password. The command accepts no password argument.
- A complete **20,000,000,000-byte key** was generated, synchronized, read back,
  verified, and published with metadata. The disposable test key was then removed.
  That run preceded the console-delivery fix; the generator code was unchanged.

Independent 256 MiB streaming measurements on 0.1.1 (one local run, not a benchmark promise):

| Operation | Seconds | Sampled peak process RSS |
| --- | ---: | ---: |
| XChaCha encrypt, including read-back verification | 2.05 | 7.31 MiB |
| XChaCha decrypt, including read-back verification | 2.09 | 7.05 MiB |
| Repeating XOR, including read-back verification | 1.97 | 6.99 MiB |
| Repeating XOR recovery, including read-back verification | 1.95 | 6.99 MiB |

The XChaCha plaintext was independently checked using libsodium and SHA3-512;
XOR recovery also matched the original SHA3-512. Password derivation separately
requires approximately 64 MiB plus process/buffer overhead. Measurements were made
on the updated executable. SHA3 vectors and two-way libsodium interoperability
were rerun as well. See `verification/interop-v0.1.1-results.json`.
The saved key-generator fixture from 0.1.0 still matches the independent derivation;
the cipher and key expansion formats are unchanged.

## Historical Linux build and subsequent baseline CI

- A separate **x86_64-unknown-linux-musl** release binary was cross-compiled on
  Windows using Rust's bundled LLD and statically linked musl runtime.
- Linux source and tests were checked by Clippy with warnings denied for musl and
  checked for the GNU target as well.
- WSL was not installed locally. After publication, the baseline suite passed on
  native GitHub Linux and Windows runners in pull request #1, including Linux-only
  symlink/FIFO checks. The Windows-cross-compiled musl executable itself was not run
  locally; native CI builds and tests the GNU target.

## Dependency audit and remaining limits

`cargo-audit 0.22.2` checked the lockfile's 86 dependencies against 1,251 RustSec
advisories (database commit `d5c17953a895cf19e8d3ce66eaa42b6fcfe1fb16`, updated
2026-09-19). **Zero reported vulnerabilities and zero warnings.** The audit also
checked yanked releases in the initial run. A repeat advisory scan of the 0.1.1
lockfile passed against the same database; dependency versions were unchanged.
See `verification/audit.json` and `verification/audit-v0.1.1.json`.

This verifies tested behavior, not an independent security audit or a proof of
correctness. Real power-loss tests, physical disk-full/device failures, hostile
filesystem races, all supported Linux filesystems, and non-x86_64 runtime behavior
have not been exercised here. CI results do not establish power-loss durability on
every user's filesystem or storage hardware.
