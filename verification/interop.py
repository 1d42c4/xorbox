"""Independent release checks (optional Python dependencies, not app dependencies).

Run with Python 3.12+, PyNaCl, cryptography, argon2-cffi, and psutil installed.
Uses disposable public test data. Never point --key-fixture at a real key folder.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import time

from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from nacl import bindings as sodium
import psutil

CHUNK = 1024 * 1024
MAGIC = b"XORBOX\0\x01"


def run(exe, *args):
    p = subprocess.run([str(exe), *args], capture_output=True, timeout=180)
    if p.returncode:
        raise AssertionError(p.stderr.decode(errors="replace"))
    return p.stdout


def sodium_read(path, key):
    digest = hashlib.sha3_512()
    size = 0
    with path.open("rb") as f:
        header = f.read(36)
        assert header[:8] == MAGIC
        assert struct.unpack("<I", header[8:12])[0] == CHUNK
        state = sodium.crypto_secretstream_xchacha20poly1305_state()
        sodium.crypto_secretstream_xchacha20poly1305_init_pull(state, header[12:], key)
        while True:
            n, = struct.unpack("<I", f.read(4))
            assert 17 <= n <= CHUNK + 17
            plain, tag = sodium.crypto_secretstream_xchacha20poly1305_pull(state, f.read(n), header)
            if tag == sodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL:
                assert not plain and not f.read(1)
                break
            assert tag == sodium.crypto_secretstream_xchacha20poly1305_TAG_MESSAGE
            digest.update(plain)
            size += len(plain)
    return digest.hexdigest(), size


def sodium_write(path, key, data):
    state = sodium.crypto_secretstream_xchacha20poly1305_state()
    nonce = sodium.crypto_secretstream_xchacha20poly1305_init_push(state, key)
    header = MAGIC + struct.pack("<I", CHUNK) + nonce
    with path.open("wb") as f:
        f.write(header)
        for offset in range(0, len(data), CHUNK):
            msg = sodium.crypto_secretstream_xchacha20poly1305_push(
                state, data[offset:offset + CHUNK], header,
                sodium.crypto_secretstream_xchacha20poly1305_TAG_MESSAGE)
            f.write(struct.pack("<I", len(msg)))
            f.write(msg)
        final = sodium.crypto_secretstream_xchacha20poly1305_push(
            state, b"", header, sodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL)
        f.write(struct.pack("<I", len(final)))
        f.write(final)


def timed_run(exe, *args):
    start = time.monotonic()
    process = subprocess.Popen([str(exe), *args], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    observer = psutil.Process(process.pid)
    peak = 0
    while process.poll() is None:
        try:
            peak = max(peak, observer.memory_info().rss)
        except psutil.NoSuchProcess:
            break
        if time.monotonic() - start > 180:
            process.kill()
            raise AssertionError("streaming check timed out")
        time.sleep(0.01)
    out, error = process.communicate()
    assert process.returncode == 0, error.decode(errors="replace")
    return {"seconds": round(time.monotonic() - start, 2), "sampled_peak_rss_mib": round(peak / CHUNK, 2)}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--exe", type=Path, required=True)
    parser.add_argument("--key-fixture", type=Path)
    parser.add_argument("--large-mib", type=int, default=256)
    args = parser.parse_args()
    report = {}
    with tempfile.TemporaryDirectory(prefix="xorbox-interop-") as folder:
        root = Path(folder)
        exe = root / args.exe.name
        shutil.copy2(args.exe, exe)
        for text in ["", "apple", "abc", "日本語 text", "a\nb"]:
            assert run(exe, "sha3", text) == hashlib.sha3_512(text.encode()).hexdigest().encode() + b"\n"
        report["sha3_vs_python"] = "5 vectors passed"
        run(exe, "xcha", "K")
        key = (root / "xcha.key").read_bytes()
        for size in [0, 1, CHUNK - 1, CHUNK, CHUNK + 17, CHUNK * 2]:
            data = (bytes(range(256)) * (size // 256 + 1))[:size]
            name = f"sample-{size}"
            (root / name).write_bytes(data)
            run(exe, "xcha", "E", name)
            assert sodium_read(root / (name + ".xcha"), key) == (hashlib.sha3_512(data).hexdigest(), size)
            sodium_write(root / (name + "-sodium.xcha"), key, data)
            run(exe, "xcha", "D", name + "-sodium.xcha")
            assert (root / (name + "-sodium")).read_bytes() == data
        report["secretstream_vs_libsodium"] = "6 sizes passed in both directions"
        large = root / "large"
        block = bytes(range(256)) * (CHUNK // 256)
        digest = hashlib.sha3_512()
        with large.open("wb") as f:
            for _ in range(args.large_mib):
                f.write(block)
                digest.update(block)
        report["large_file_mib"] = args.large_mib
        report["large_xcha_encrypt"] = timed_run(exe, "xcha", "E", "large")
        assert sodium_read(root / "large.xcha", key) == (digest.hexdigest(), args.large_mib * CHUNK)
        large.rename(root / "large-original")
        report["large_xcha_decrypt"] = timed_run(exe, "xcha", "D", "large.xcha")
        with large.open("rb") as f:
            assert hashlib.file_digest(f, "sha3_512").hexdigest() == digest.hexdigest()
        (root / "key.key").write_bytes(b"\x55\xaa\x31")
        report["large_xor_repeat"] = timed_run(exe, "xor", "large", "xor-out", "--repeat-key")
        report["large_xor_restore"] = timed_run(exe, "xor", "xor-out", "xor-restored", "--repeat-key")
        with (root / "xor-restored").open("rb") as f:
            assert hashlib.file_digest(f, "sha3_512").hexdigest() == digest.hexdigest()
    if args.key_fixture:
        # This is exclusively the public test password used during manual QA.
        password = b"xorbox verification password"
        meta = json.loads((args.key_fixture / "key.meta").read_text())
        seed = hash_secret_raw(password, bytes.fromhex(meta["salt_hex"]),
                               time_cost=3, memory_cost=65536, parallelism=4,
                               hash_len=32, type=Type.ID, version=19)
        # The 16-byte initial ChaCha state tail matches IETF counter0 + nonce.
        # Counter layouts agree for this fixture and all outputs below 2**32 blocks.
        nonce = b"\0" * 4 + bytes.fromhex(meta["nonce_hex"])
        cipher = Cipher(algorithms.ChaCha20(seed, nonce), mode=None).encryptor()
        expected = cipher.update(bytes(meta["bytes"]))
        assert expected == (args.key_fixture / "key.key").read_bytes()
        assert hashlib.sha3_512(expected).hexdigest() == meta["key_sha3_512"]
        report["keymake_vs_argon2_and_openssl"] = f"{len(expected)} bytes matched"
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
