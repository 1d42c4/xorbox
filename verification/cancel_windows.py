"""Exercise real Ctrl-C delivery in a hidden Windows console with public data."""
import ctypes
from ctypes import wintypes
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time

kernel = ctypes.WinDLL("kernel32", use_last_error=True)
kernel.AttachConsole.argtypes = [wintypes.DWORD]
kernel.AttachConsole.restype = wintypes.BOOL
kernel.FreeConsole.restype = wintypes.BOOL
kernel.SetConsoleCtrlHandler.argtypes = [ctypes.c_void_p, wintypes.BOOL]
kernel.GenerateConsoleCtrlEvent.argtypes = [wintypes.DWORD, wintypes.DWORD]
kernel.GenerateConsoleCtrlEvent.restype = wintypes.BOOL

with tempfile.TemporaryDirectory(prefix="xorbox-cancel-") as directory:
    root = Path(directory)
    exe = root / "xorbox.exe"
    shutil.copy2(sys.argv[1], exe)
    data = root / "data"
    with data.open("wb") as f:
        f.truncate(1024 * 1024 * 1024 + 19)
    (root / "key.key").write_bytes(b"\x11\x22\x33")
    with data.open("rb") as f:
        before = hashlib.file_digest(f, "sha3_512").hexdigest()
    startup = subprocess.STARTUPINFO()
    startup.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    startup.wShowWindow = 0
    p = subprocess.Popen([str(exe), "xor", "data", "--in-place", "--repeat-key"],
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                         creationflags=subprocess.CREATE_NEW_CONSOLE,
                         startupinfo=startup)
    try:
        deadline = time.monotonic() + 5
        while not list(root.glob(".xorbox-*.tmp")):
            assert p.poll() is None, p.communicate()
            assert time.monotonic() < deadline
            time.sleep(0.01)
        time.sleep(0.15)
        kernel.FreeConsole()
        assert kernel.AttachConsole(p.pid), ctypes.get_last_error()
        assert kernel.SetConsoleCtrlHandler(None, True)
        assert kernel.GenerateConsoleCtrlEvent(0, 0), ctypes.get_last_error()
        out, error = p.communicate(timeout=10)
        kernel.FreeConsole()
        assert p.returncode == 130, (p.returncode, error)
        assert b"cancelled before publication" in error
        assert not out
        assert not list(root.glob(".xorbox-*.tmp"))
        with data.open("rb") as f:
            after = hashlib.file_digest(f, "sha3_512").hexdigest()
        assert before == after
        print(json.dumps({"ctrl_c_exit": p.returncode, "original_bytes_unchanged": True,
                          "original_size": data.stat().st_size, "temporary_cleaned": True}, indent=2))
    finally:
        if p.poll() is None:
            p.kill()
            p.wait()
