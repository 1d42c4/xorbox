# Verification record

Performed on 2026-09-20 with Rust 1.98.1, edition 2024. Current release: **0.1.1**.
See `REVIEW.md` for the review findings and fixes in this release.

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

## Linux

- A separate **x86_64-unknown-linux-musl** release binary was cross-compiled on
  Windows using Rust's bundled LLD and statically linked musl runtime.
- Linux source and tests were checked by Clippy with warnings denied for musl and
  checked for the GNU target as well.
- **The Linux executable has not been run on a native Linux host.** WSL was not
  installed. The supplied `build-linux.sh` runs the full native suite, including
  Linux-only symlink/FIFO checks, before producing its native release binary.
- The supplied CI workflow defines Windows and Linux native test jobs; it was not
  pushed or executed remotely.

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
have not been exercised here. The Linux binary requires native testing before
relying on its in-place mode for irreplaceable data.
