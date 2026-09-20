"""Windows console/password/cancellation checks using disposable public data.

Python 3.12+ standard library only. Run: python windows_console.py PATH_TO_EXE
Uses hidden new consoles; never sends input or Ctrl-C to the user's console.
"""
import ctypes as c
from ctypes import wintypes as w
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time

k = c.WinDLL("kernel32", use_last_error=True)
INVALID = c.c_void_p(-1).value


class Coord(c.Structure):
    _fields_ = [("x", w.SHORT), ("y", w.SHORT)]


class KeyEvent(c.Structure):
    _fields_ = [("down", w.BOOL), ("repeat", w.WORD), ("vk", w.WORD),
                ("scan", w.WORD), ("char", w.WCHAR), ("state", w.DWORD)]


class Event(c.Union):
    _fields_ = [("key", KeyEvent), ("padding", c.c_byte * 16)]


class InputRecord(c.Structure):
    _fields_ = [("type", w.WORD), ("event", Event)]


assert c.sizeof(InputRecord) == 20
k.AttachConsole.argtypes = [w.DWORD]
k.AttachConsole.restype = w.BOOL
k.FreeConsole.restype = w.BOOL
k.SetConsoleCtrlHandler.argtypes = [c.c_void_p, w.BOOL]
k.SetConsoleCtrlHandler.restype = w.BOOL
k.GenerateConsoleCtrlEvent.argtypes = [w.DWORD, w.DWORD]
k.GenerateConsoleCtrlEvent.restype = w.BOOL
k.CreateFileW.argtypes = [w.LPCWSTR, w.DWORD, w.DWORD, c.c_void_p,
                          w.DWORD, w.DWORD, w.HANDLE]
k.CreateFileW.restype = w.HANDLE
k.CloseHandle.argtypes = [w.HANDLE]
k.ReadConsoleOutputCharacterW.argtypes = [w.HANDLE, w.LPWSTR, w.DWORD,
                                        Coord, c.POINTER(w.DWORD)]
k.ReadConsoleOutputCharacterW.restype = w.BOOL
k.WriteConsoleInputW.argtypes = [w.HANDLE, c.POINTER(InputRecord), w.DWORD, c.POINTER(w.DWORD)]
k.WriteConsoleInputW.restype = w.BOOL
k.GetConsoleMode.argtypes = [w.HANDLE, c.POINTER(w.DWORD)]
k.GetConsoleMode.restype = w.BOOL


def check(ok):
    if not ok:
        raise c.WinError(c.get_last_error())


def wait_for(predicate, process, seconds=10):
    end = time.monotonic() + seconds
    while not predicate():
        assert process.poll() is None, process.communicate()
        assert time.monotonic() < end, "timed out waiting for test state"
        time.sleep(0.01)


class Console:
    def __init__(self, exe, args):
        self.exe, self.args = exe, args

    def __enter__(self):
        info = subprocess.STARTUPINFO()
        info.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        info.wShowWindow = 0
        self.p = subprocess.Popen([str(self.exe), *self.args], stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE, creationflags=subprocess.CREATE_NEW_CONSOLE,
                                  startupinfo=info)
        self.handles = []
        try:
            k.FreeConsole()
            wait_for(lambda: bool(k.AttachConsole(self.p.pid)), self.p)
            check(k.SetConsoleCtrlHandler(None, True))
            for name in ["CONIN$", "CONOUT$"]:
                handle = k.CreateFileW(name, 0xc0000000, 3, None, 3, 0, None)
                assert handle != INVALID, c.get_last_error()
                self.handles.append(handle)
            return self
        except BaseException:
            self.__exit__(None, None, None)
            raise

    def __exit__(self, *_):
        if self.p.poll() is None:
            self.p.kill()
            self.p.wait(timeout=5)
        for handle in self.handles:
            k.CloseHandle(handle)
        k.FreeConsole()

    def screen(self):
        text = c.create_unicode_buffer(4000)
        read = w.DWORD()
        check(k.ReadConsoleOutputCharacterW(self.handles[1], text, 4000, Coord(0, 0), c.byref(read)))
        return text[:read.value]

    def prompt(self, text):
        wait_for(lambda: text in self.screen(), self.p)
        # The prompt is written just before raw mode is enabled.
        wait_for(lambda: self.mode() & 6 == 0, self.p)

    def mode(self):
        mode = w.DWORD()
        check(k.GetConsoleMode(self.handles[0], c.byref(mode)))
        return mode.value

    def type(self, text):
        encoded = text.encode("utf-16-le")
        units = [chr(int.from_bytes(encoded[i:i+2], "little")) for i in range(0, len(encoded), 2)]
        events = (InputRecord * len(units))()
        for event, unit in zip(events, units):
            event.type = 1
            event.event.key = KeyEvent(True, 1, 13 if unit == "\r" else 0, 0, unit, 0)
        written = w.DWORD()
        check(k.WriteConsoleInputW(self.handles[0], events, len(events), c.byref(written)))
        assert written.value == len(events)

    def finish(self, code=0):
        out, err = self.p.communicate(timeout=15)
        assert self.p.returncode == code, (self.args, self.p.returncode, out, err)
        return out, err

    def cancel(self):
        check(k.GenerateConsoleCtrlEvent(0, 0))
        return self.finish(130)


def no_temp(root):
    assert not list(root.glob(".xorbox-*.tmp"))


def digest(path):
    with path.open("rb") as f:
        return hashlib.file_digest(f, "sha3_512").hexdigest()


def main():
    source = Path(sys.argv[1]).resolve()
    results = []
    with tempfile.TemporaryDirectory(prefix="xorbox-console-") as directory:
        base = Path(directory)

        def fixture(name):
            root = base / name
            root.mkdir()
            exe = root / "xorbox.exe"
            shutil.copy2(source, exe)
            return root, exe

        for args, confirmation in [(["sha3"], False), (["keymake", "65"], False),
                                    (["keymake", "65"], True)]:
            root, exe = fixture("prompt-" + str(len(results)))
            with Console(exe, args) as console:
                console.prompt("Text: " if args[0] == "sha3" else "Password: ")
                if confirmation:
                    console.type("public test phrase\r")
                    console.prompt("Confirm password: ")
                out, _ = console.cancel()
                assert not out
                assert console.mode() & 6 == 6, "echo/line mode was not restored"
            assert not (root / "key.key").exists()
            assert not (root / "key.meta").exists()
            no_temp(root)
            results.append({"test": "prompt_cancel", "command": args, "confirmation": confirmation,
                            "exit": 130, "console_restored": True})

        root, exe = fixture("password")
        password = "public test phrase 日本語 🔐"
        with Console(exe, ["keymake", "65"]) as console:
            console.prompt("Password: ")
            console.type(password + "\r")
            console.prompt("Confirm password: ")
            assert "public test phrase" not in console.screen(), "password echoed"
            console.type(password + "\r")
            console.finish()
            assert "public test phrase" not in console.screen(), "confirmation echoed"
            assert console.mode() & 6 == 6
        original = (root / "key.key").read_bytes()
        recipe = (root / "key.meta").read_bytes()
        (root / "key.key").unlink()
        with Console(exe, ["keyrestore"]) as console:
            console.prompt("Password: ")
            console.type(password + "\r")
            console.finish()
        assert (root / "key.key").read_bytes() == original
        no_temp(root)
        results.append({"test": "unicode_hidden_password_round_trip", "key_bytes": len(original)})

        for texts in [("\r", None), ("one\r", "two\r")]:
            root, exe = fixture("bad-password-" + str(len(results)))
            with Console(exe, ["keymake", "65"]) as console:
                console.prompt("Password: ")
                console.type(texts[0])
                if texts[1] is not None:
                    console.prompt("Confirm password: ")
                    console.type(texts[1])
                console.finish(1)
                assert console.mode() & 6 == 6
            assert not (root / "key.key").exists()
            assert not (root / "key.meta").exists()
            no_temp(root)
            results.append({"test": "empty_or_mismatched_password", "empty": texts[1] is None})

        root, exe = fixture("private-sha3")
        text = "apple 日本語 🔐"
        with Console(exe, ["sha3"]) as console:
            console.prompt("Text: ")
            console.type(text + "\r")
            out, _ = console.finish()
            assert out == hashlib.sha3_512(text.encode()).hexdigest().encode() + b"\n"
            assert "apple" not in console.screen()
        results.append({"test": "private_sha3_unicode"})

        for typed, expected in [("a🔐\bpple", "apple"), ("discard\x15apple", "apple"),
                                ("apple banana  \x17", "apple "), ("", "")]:
            root, exe = fixture("editing-" + str(len(results)))
            with Console(exe, ["sha3"]) as console:
                console.prompt("Text: ")
                console.type(typed + "\r")
                out, _ = console.finish()
                assert out == hashlib.sha3_512(expected.encode()).hexdigest().encode() + b"\n"
                assert console.mode() & 6 == 6
            results.append({"test": "hidden_input_editing", "expected": expected})

        root, exe = fixture("keyboard-cancel")
        with Console(exe, ["sha3"]) as console:
            console.prompt("Text: ")
            console.type("not hashed\x03")
            out, _ = console.finish(130)
            assert not out
            assert console.mode() & 6 == 6
        results.append({"test": "keyboard_ctrl_c", "exit": 130})

        for command in ["xor", "xcha-encrypt", "xcha-decrypt", "keymake", "keyrestore"]:
            root, exe = fixture(command)
            data = root / "data"
            if command not in ("keymake", "keyrestore"):
                with data.open("wb") as f:
                    f.truncate(512 * 1024 * 1024 + 19)
                (root / "key.key").write_bytes(b"\x11\x22\x33")
                (root / "xcha.key").write_bytes(bytes(range(32)))
                if command == "xcha-decrypt":
                    subprocess.run([str(exe), "xcha", "E", "data", "--in-place"],
                                   capture_output=True, timeout=30, check=True)
                before = digest(data)
            if command == "keyrestore":
                # Public valid recipe with a larger requested stream. Cancellation
                # is checked before finishing/validating its deliberately old digest.
                meta = json.loads(recipe)
                meta["bytes"] = 20_000_000_000
                saved_recipe = json.dumps(meta).encode()
                (root / "key.meta").write_bytes(saved_recipe)
            args = {"xor": ["xor", "data", "--in-place", "--repeat-key"],
                    "xcha-encrypt": ["xcha", "E", "data", "--in-place"],
                    "xcha-decrypt": ["xcha", "D", "data", "--in-place"],
                    "keymake": ["keymake", "20000000000"],
                    "keyrestore": ["keyrestore"]}[command]
            with Console(exe, args) as console:
                if command == "keymake":
                    console.prompt("Password: ")
                    console.type("public cancellation fixture\r")
                    console.prompt("Confirm password: ")
                    console.type("public cancellation fixture\r")
                if command == "keyrestore":
                    console.prompt("Password: ")
                    console.type(password + "\r")
                wait_for(lambda: any(p.stat().st_size > 1024 * 1024 for p in root.glob(".xorbox-*.tmp")), console.p)
                console.cancel()
            no_temp(root)
            if command in ("keymake", "keyrestore"):
                assert not (root / "key.key").exists()
                if command == "keymake":
                    assert not (root / "key.meta").exists()
                else:
                    assert (root / "key.meta").read_bytes() == saved_recipe
            else:
                assert digest(data) == before
            results.append({"test": "streaming_cancel", "command": command, "exit": 130,
                            "original_preserved": True, "temporary_cleaned": True})
    print(json.dumps({"executable_sha256": digest_exe(source), "tests_passed": len(results),
                      "cases": results}, indent=2))


def digest_exe(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


if __name__ == "__main__":
    main()
