//! Hidden, isolated Windows consoles. No input is sent to the user's console.
use super::Fixture;
use std::fs::{self, File};
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::ptr::{null, null_mut};
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::Storage::FileSystem::*;
use windows_sys::Win32::System::{Console::*, Threading::*};

// AttachConsole/FreeConsole and the Ctrl-C ignore setting are process-wide.
static CONSOLE: Mutex<()> = Mutex::new(());
pub fn serial() -> MutexGuard<'static, ()> {
    CONSOLE.lock().unwrap_or_else(|e| e.into_inner())
}

fn wide(value: &std::ffi::OsStr) -> Vec<u16> {
    value.encode_wide().chain(Some(0)).collect()
}
fn check(ok: i32) {
    assert_ne!(ok, 0, "{}", io::Error::last_os_error());
}

pub struct Console<'a> {
    process: OwnedHandle,
    input: Option<OwnedHandle>,
    output: Option<OwnedHandle>,
    fixture: &'a Fixture,
}

impl<'a> Console<'a> {
    // The caller holds the serial guard for the entire test (including console cleanup).
    pub fn launch(fixture: &'a Fixture, args: &[&str], _guard: &MutexGuard<'_, ()>) -> Self {
        assert!(args.iter().all(|s| !s.contains(['"', '\\', '\0'])));
        let exe = wide(fixture.exe.as_os_str());
        let mut command = wide(std::ffi::OsStr::new(&format!(
            "\"{}\" {}",
            fixture.exe.display(),
            args.iter()
                .map(|s| format!("\"{s}\""))
                .collect::<Vec<_>>()
                .join(" ")
        )));
        let directory = wide(fixture.elsewhere.path().as_os_str());
        let stdin = File::open("NUL").unwrap();
        let stdout = File::create(fixture.path("console.stdout")).unwrap();
        let stderr = File::create(fixture.path("console.stderr")).unwrap();
        let handles = [
            stdin.as_raw_handle(),
            stdout.as_raw_handle(),
            stderr.as_raw_handle(),
        ];
        // SAFETY: these are live file handles; inheritance is cleared immediately after creation.
        unsafe {
            for handle in handles {
                check(SetHandleInformation(
                    handle,
                    HANDLE_FLAG_INHERIT,
                    HANDLE_FLAG_INHERIT,
                ));
            }
        }
        let info = STARTUPINFOW {
            cb: size_of::<STARTUPINFOW>() as u32,
            dwFlags: STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES,
            wShowWindow: 0, // SW_HIDE; no visible console window, including on CI.
            hStdInput: stdin.as_raw_handle(),
            hStdOutput: stdout.as_raw_handle(),
            hStdError: stderr.as_raw_handle(),
            ..Default::default()
        };
        let mut process = PROCESS_INFORMATION::default();
        // SAFETY: all strings are NUL-terminated and live, command is mutable, and structs have correct sizes.
        let ok = unsafe {
            CreateProcessW(
                exe.as_ptr(),
                command.as_mut_ptr(),
                null(),
                null(),
                1,
                CREATE_NEW_CONSOLE,
                null(),
                directory.as_ptr(),
                &info,
                &mut process,
            )
        };
        let error = io::Error::last_os_error();
        // SAFETY: the parent still owns these live file handles.
        unsafe {
            for handle in handles {
                check(SetHandleInformation(handle, HANDLE_FLAG_INHERIT, 0));
            }
        }
        assert_ne!(ok, 0, "CreateProcessW: {error}");
        // SAFETY: successful CreateProcessW returned two independently owned handles.
        let process_handle = unsafe { OwnedHandle::from_raw_handle(process.hProcess) };
        // SAFETY: this is the unused primary thread handle returned by CreateProcessW.
        drop(unsafe { OwnedHandle::from_raw_handle(process.hThread) });
        let mut console = Self {
            process: process_handle,
            input: None,
            output: None,
            fixture,
        };
        // SAFETY: tests serialize console attachment; this detaches only this test process.
        unsafe {
            FreeConsole();
        }
        console.wait_for(|| {
            // SAFETY: attaches this test process to the newly created disposable child's console.
            unsafe { AttachConsole(process.dwProcessId) != 0 }
        });
        // SAFETY: this process ignores broadcast Ctrl-C; the child retains its own handler.
        unsafe {
            check(SetConsoleCtrlHandler(None, 1));
        }
        console.input = Some(Self::open_console("CONIN$"));
        console.output = Some(Self::open_console("CONOUT$"));
        console
    }

    fn open_console(name: &str) -> OwnedHandle {
        let name = wide(std::ffi::OsStr::new(name));
        // SAFETY: name is NUL-terminated; no security attributes or template handle are used.
        let handle = unsafe {
            CreateFileW(
                name.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                null(),
                OPEN_EXISTING,
                0,
                null_mut(),
            )
        };
        assert_ne!(
            handle,
            INVALID_HANDLE_VALUE,
            "{}",
            io::Error::last_os_error()
        );
        // SAFETY: CreateFileW returned a newly owned, valid handle.
        unsafe { OwnedHandle::from_raw_handle(handle) }
    }

    fn exited(&self) -> bool {
        // SAFETY: process is a live owned kernel handle; a zero timeout never blocks.
        let result = unsafe { WaitForSingleObject(self.process.as_raw_handle(), 0) };
        assert_ne!(result, WAIT_FAILED);
        result == WAIT_OBJECT_0
    }

    pub fn wait_for(&self, mut predicate: impl FnMut() -> bool) {
        let start = Instant::now();
        while !predicate() {
            assert!(
                !self.exited(),
                "child exited before test state: {:?}",
                self.captured()
            );
            assert!(
                start.elapsed() < Duration::from_secs(60),
                "timed out waiting for test state"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    pub fn screen(&self) -> String {
        let mut buffer = [0u16; 4000];
        let mut read = 0;
        // SAFETY: the console output handle and buffer are valid; the requested size fits the buffer.
        unsafe {
            check(ReadConsoleOutputCharacterW(
                self.output.as_ref().unwrap().as_raw_handle(),
                buffer.as_mut_ptr(),
                buffer.len() as u32,
                COORD { X: 0, Y: 0 },
                &mut read,
            ));
        }
        String::from_utf16_lossy(&buffer[..read as usize])
    }

    pub fn mode(&self) -> u32 {
        let mut mode = 0;
        // SAFETY: the console input handle is live; mode points to writable storage.
        unsafe {
            check(GetConsoleMode(
                self.input.as_ref().unwrap().as_raw_handle(),
                &mut mode,
            ));
        }
        mode
    }

    pub fn prompt(&self, text: &str) {
        self.wait_for(|| self.screen().contains(text));
        self.wait_for(|| self.mode() & (ENABLE_ECHO_INPUT | ENABLE_LINE_INPUT) == 0);
    }

    pub fn type_text(&self, text: &str) {
        let events: Vec<INPUT_RECORD> = text
            .encode_utf16()
            .map(|unit| INPUT_RECORD {
                EventType: KEY_EVENT as u16,
                Event: INPUT_RECORD_0 {
                    KeyEvent: KEY_EVENT_RECORD {
                        bKeyDown: 1,
                        wRepeatCount: 1,
                        wVirtualKeyCode: if unit == 13 { 13 } else { 0 },
                        wVirtualScanCode: 0,
                        uChar: KEY_EVENT_RECORD_0 { UnicodeChar: unit },
                        dwControlKeyState: 0,
                    },
                },
            })
            .collect();
        let mut written = 0;
        // SAFETY: every union contains a KeyEvent matching EventType; the array and handle remain live.
        unsafe {
            check(WriteConsoleInputW(
                self.input.as_ref().unwrap().as_raw_handle(),
                events.as_ptr(),
                events.len() as u32,
                &mut written,
            ));
        }
        assert_eq!(written as usize, events.len());
    }

    fn captured(&self) -> (Vec<u8>, String) {
        (
            fs::read(self.fixture.path("console.stdout")).unwrap(),
            fs::read_to_string(self.fixture.path("console.stderr")).unwrap(),
        )
    }

    pub fn finish(&self, expected: u32) -> Vec<u8> {
        assert_eq!(
            // SAFETY: process is a live kernel handle. A bounded wait prevents a hung test runner.
            unsafe { WaitForSingleObject(self.process.as_raw_handle(), 60_000) },
            WAIT_OBJECT_0,
            "child timed out"
        );
        let mut code = 0;
        // SAFETY: process remains live, and code points to writable storage.
        unsafe {
            check(GetExitCodeProcess(self.process.as_raw_handle(), &mut code));
        }
        let (out, err) = self.captured();
        assert_eq!(code, expected, "{err}");
        out
    }

    pub fn cancel(&self) -> Vec<u8> {
        // SAFETY: this process is attached exclusively to the disposable child's hidden console.
        unsafe {
            check(GenerateConsoleCtrlEvent(CTRL_C_EVENT, 0));
        }
        self.finish(130)
    }

    pub fn restored(&self) {
        assert_eq!(self.mode() & 6, 6, "echo/line input mode was not restored");
    }
}

impl Drop for Console<'_> {
    fn drop(&mut self) {
        // SAFETY: the handle is owned until after Drop; termination reaps a failed/timed-out child.
        unsafe {
            if WaitForSingleObject(self.process.as_raw_handle(), 0) != WAIT_OBJECT_0 {
                TerminateProcess(self.process.as_raw_handle(), 1);
                WaitForSingleObject(self.process.as_raw_handle(), 5_000);
            }
        }
        self.input.take();
        self.output.take();
        // SAFETY: only this test process is detached; no events are sent to any other console.
        unsafe {
            FreeConsole();
        }
    }
}
