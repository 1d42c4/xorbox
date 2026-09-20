# xorbox

A small Rust 2024 command-line app for Windows and Linux. Processes large files
with bounded memory. Rust 1.98.1 is pinned in `rust-toolchain.toml`.

## Use

Keep the executable, input files, and applicable keys in the same private folder.
File arguments are **filenames**, not paths. The app always uses the executable's
directory, even when your terminal is elsewhere. Quote filenames containing spaces.

On Windows, run `./xorbox.exe` from PowerShell. On Linux, run `./xorbox`.
The commands below omit that prefix's platform-specific extension for readability.

| Command | Result |
| --- | --- |
| `xorbox xor INPUT OUTPUT` | XOR with `key.key`; key must be at least as long as input. |
| `xorbox xor INPUT OUTPUT --repeat-key` | XOR while explicitly permitting a shorter key to repeat. |
| `xorbox xor FILE --in-place` | XOR and atomically replace FILE after completion. |
| `xorbox xor FILE --in-place --repeat-key` | In-place XOR with repetition permitted. |
| `xorbox keymake BYTES` | Privately prompt twice; create `key.key` and `key.meta`. |
| `xorbox keyrestore` | Privately prompt; regenerate `key.key` using `key.meta`. |
| `xorbox sha3 TEXT` | Print the SHA3-512 digest of the literal UTF-8 text. |
| `xorbox sha3` | Privately prompt for text and print its SHA3-512 digest. |
| `xorbox xcha K` | Generate a random, 32-byte `xcha.key`. |
| `xorbox xcha E FILE` | Encrypt with XChaCha20-Poly1305; create `FILE.xcha`. |
| `xorbox xcha D FILE.xcha` | Authenticate and decrypt; remove the final `.xcha` suffix for the output name. |
| `xorbox xcha E FILE --in-place` | Encrypt and replace FILE, retaining its name. |
| `xorbox xcha D FILE --in-place` | Authenticate, decrypt, and replace FILE, retaining its name. |

There are deliberately no `--help` or `--version` options. E, D, and K are uppercase.
Invalid arguments produce a brief error. Exit codes: 0 success; 1 error; 130 cancellation.
Only SHA3 results go to standard output. Status/errors go to standard error;
private prompts use the terminal. An interactive terminal is needed for private input.

`sha3 apple` hashes the text **apple**, not a file. No newline is included in the
hashed bytes; the printed 128-character lowercase digest ends with a newline.
Quote text containing spaces. Use the private prompt for secrets; literal arguments
can appear in shell history and process listings. Unicode is UTF-8, with no Unicode
normalization, trimming, or case conversion.

## Keys

`keymake` accepts decimal digits only, from **1 to 20,000,000,000 bytes** (20 GB).
Each invocation uses fresh random salt and nonce values. It applies Argon2id v19
(64 MiB, 3 passes, 4 lanes) to the password, then streams ChaCha20 bytes. The stream
counter never resets at buffer boundaries, and generation fails before counter
exhaustion. Byte patterns can occur by chance; the generator does not loop a short
key. The output is deterministic given the password and the exact `key.meta`.

Keep a backup of `key.meta` and remember the exact password. It contains the size,
generation version and settings, salt, nonce, and a SHA3-512 digest of the resulting
key. It contains no password or seed. `keyrestore` checks this digest before
publishing a restored key, rejecting a wrong password or inconsistent metadata.
It may need to generate the entire file before rejecting a wrong password.

`keymake` refuses to replace either key file or metadata. `keyrestore` requires
`key.key` to be absent. Move an existing key to a safe backup location first.
The metadata is published and synchronized before the key. If interruption occurs
between these two publications, saved metadata permits `keyrestore`; two filenames
cannot be published atomically as a pair. Protect your backup metadata from changes.

`xcha.key` is exactly 32 **binary bytes**, not a password or a hexadecimal string.
Back it up: `keyrestore` restores only `key.key`, not `xcha.key`. XChaCha can use one
key for multiple files because each encryption creates a fresh random stream header.

The password-derived XOR pad is not a true one-time pad. Its strength depends on
the password and computational cryptography. Reusing XOR pad bytes for different
plaintexts leaks information. `--repeat-key` is unsuitable for protecting sensitive
data. Raw XOR cannot detect wrong keys or tampering. XChaCha adds authentication.
The SHA3 utility does not turn a weak password into a strong one.

## Files and in-place operation

Normal commands never overwrite an existing destination. Sources and keys are read
only. In-place mode is the sole explicit exception and replaces only the named data
file. Key files, metadata, the executable, and known aliases are protected.

Every data output is written to a uniquely created, restricted temporary file in
the same directory. The app synchronizes it, reads it back to verify length and
SHA3-512 against the intended bytes, and publishes it. XChaCha decryption also
requires every authentication tag, the final marker, and exact end-of-file to pass.
Read-back verification can use OS caches; it is not proof against failing hardware.

In-place mode needs enough free space for another complete output. The filename
changes from the complete old file to the complete new file at the replacement
operation. There is no delete-first or copy-over fallback. Failures before that
point leave the original intact. A failure to synchronize after publication clearly
reports that the replacement **already happened**; do not blindly repeat XOR.

Current in-place filesystem support:

- Windows: local fixed **NTFS**, using handle-based `FileRenameInfoEx` replacement.
- Linux: **ext2/3/4, XFS, Btrfs, tmpfs, F2FS**, using the `renameat2` system call.
- Remote, FUSE, and other filesystems are refused for in-place use. Filesystems
  must also support the required locking and no-clobber rename operations.

File bytes are preserved through recovery, not original filesystem metadata.
New files use owner-only permissions on Linux (0600) and a protected owner/System
DACL on Windows. Replacement uses these new permissions too; it does not preserve
original ACLs, timestamps, extended attributes, compression, or sparse layout.
In-place files with hard links are refused, including links detected just before
replacement. Windows read-only files and alternate data streams are
refused for in-place use to prevent their silent loss. Symbolic links, reparse
points, device names, pipes, path traversal, and alternate-stream filename syntax
are rejected. Normal encryption handles the default data stream only.

The persistent empty `.xorbox.lock` file coordinates operations in the folder.
Do not remove it while a command runs. Ctrl-C stops processing and attempts to
remove its temporary file. A forced kill or power failure can leave `.xorbox-*.tmp`
files. A publication failure deliberately retains its completed temporary file and
reports its name. Treat leftover temporaries as potentially sensitive plaintext;
inspect them only after all app processes have stopped.

Atomicity is not a universal power-loss guarantee. Linux synchronizes the file and
directory; Windows flushes the file before and after replacement but has no equivalent
unprivileged directory-fsync guarantee. Storage hardware, filesystem behavior, and
mount settings still matter. Replacement does not securely erase old disk blocks,
snapshots, backups, or cloud history. Keep important backups.

Use a private directory and leave input/key files untouched during processing.
Windows opens prevent concurrent writes; Linux locks are advisory. File identity,
size, and timestamps are checked before publication, but the app is not a security
boundary against another process that can maliciously mutate its working directory.

## Combining both layers

Encrypt: XOR the plaintext with `key.key`, then XChaCha-encrypt the XOR result with
`xcha.key`. Recover in reverse order. You need both keys (or the XOR password plus
metadata and `xcha.key`). In-place commands can use the same filename throughout.
XChaCha authenticates the XOR ciphertext; it cannot catch a wrong XOR key used
afterwards. Compare recovered plaintext with a trusted external checksum when needed.

## Build

The source is platform-selected at compile time: `src/platform/windows.rs` versus
`src/platform/linux.rs`. Only 64-bit Windows and Linux are supported.

- Windows: run `./build-windows.ps1` from PowerShell in the source directory.
  Requires Rust/rustup and Visual Studio C++ build tools. Produces
  `dist/windows-x86_64/xorbox.exe` with the MSVC runtime statically linked.
- Linux: run `sh build-linux.sh` on a native x86_64 or aarch64 Linux machine with
  Rust/rustup and a C linker. Produces `dist/<target>/xorbox` and runs native tests.
- Cross-build a static x86_64 Linux executable from Windows:
  `rustup target add x86_64-unknown-linux-musl --toolchain 1.98.1`, then
  `cargo build --locked --release --target x86_64-unknown-linux-musl`.
  The configured Rust LLD linker requires no Linux C compiler. On Linux, mark a
  transferred executable executable with `chmod +x xorbox`.

Native scripts run formatting, Clippy, tests, and release compilation. `Cargo.lock`
fixes dependency versions. GitHub Actions runs the full native suite on Windows
and Linux. Building and testing requires Rust and the platform build tools above;
there is no Python dependency or separately installed cryptography library.

Run all tests with `cargo test --locked --release`. This includes independent Rust
crypto comparisons, 256 MiB streaming checks with a 96 MiB process-memory limit,
and, on Windows, 17 hidden-console tests for passwords, Unicode editing and Ctrl-C
cancellation. Allow approximately 2.1 GiB of free temporary disk space. The tests
use disposable public data and never send input or Ctrl-C to your console.
Use `cargo test --locked --release --test interop -- --nocapture` to see streaming
timings and sampled memory use. Password derivation has a separate 64 MiB memory
cost; the streaming memory limit applies only to file transforms.

See `FORMAT.md` for the file formats and `VERIFICATION.md` for performed checks.
This new application has not undergone an independent security audit.
