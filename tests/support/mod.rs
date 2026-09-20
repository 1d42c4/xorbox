#![allow(dead_code)]

use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tiny_keccak::{Hasher, Sha3};

pub const CHUNK: usize = 1024 * 1024;
// Prevent Linux fork/exec from inheriting another fixture's executable writer.
static EXECUTABLE_SETUP: Mutex<()> = Mutex::new(());

pub struct Fixture {
    pub dir: tempfile::TempDir,
    pub elsewhere: tempfile::TempDir,
    pub exe: PathBuf,
}

impl Fixture {
    pub fn new() -> Self {
        let _guard = EXECUTABLE_SETUP.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join(if cfg!(windows) {
            "xorbox.exe"
        } else {
            "xorbox"
        });
        fs::copy(env!("CARGO_BIN_EXE_xorbox"), &exe).unwrap();
        Self {
            dir,
            exe,
            elsewhere: tempfile::tempdir().unwrap(),
        }
    }

    pub fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    pub fn run(&self, args: &[&str]) -> Output {
        self.run_observed(args, false)
    }

    pub fn ok(&self, args: &[&str]) -> Output {
        let out = self.run(args);
        assert!(
            out.status.success(),
            "{args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        out
    }

    pub fn measured(&self, args: &[&str]) {
        let out = self.run_observed(args, true);
        assert!(
            out.status.success(),
            "{args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    fn run_observed(&self, args: &[&str], measure: bool) -> Output {
        let child = {
            let _guard = EXECUTABLE_SETUP.lock().unwrap();
            Command::new(&self.exe)
                .args(args)
                .current_dir(self.elsewhere.path())
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap()
        };
        let mut child = Reap(Some(child));
        let start = Instant::now();
        let mut peak = 0;
        while child.0.as_mut().unwrap().try_wait().unwrap().is_none() {
            assert!(
                start.elapsed() < Duration::from_secs(300),
                "{args:?} timed out"
            );
            if measure {
                peak = peak.max(resident_bytes(child.0.as_ref().unwrap()));
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let output = child.0.take().unwrap().wait_with_output().unwrap();
        if measure {
            eprintln!(
                "{args:?}: {:.2}s, sampled peak RSS {:.2} MiB",
                start.elapsed().as_secs_f64(),
                peak as f64 / CHUNK as f64
            );
            assert!(peak > 0, "no process memory samples collected");
            assert!(
                peak < 96 * CHUNK,
                "streaming memory exceeded 96 MiB: {peak}"
            );
        }
        output
    }

    pub fn no_temps(&self) {
        assert!(!fs::read_dir(self.dir.path()).unwrap().any(|entry| {
            entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".xorbox-")
        }));
    }
}

struct Reap(Option<Child>);
impl Drop for Reap {
    fn drop(&mut self) {
        if let Some(child) = &mut self.0 {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

#[cfg(windows)]
fn resident_bytes(child: &Child) -> usize {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::System::ProcessStatus::{
        GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS,
    };
    let mut counters = PROCESS_MEMORY_COUNTERS::default();
    // SAFETY: the live Child owns this handle; counters points to a writable struct of the given size.
    let ok = unsafe {
        GetProcessMemoryInfo(
            child.as_raw_handle(),
            &mut counters,
            size_of::<PROCESS_MEMORY_COUNTERS>() as u32,
        )
    };
    assert_ne!(ok, 0, "{}", std::io::Error::last_os_error());
    counters.WorkingSetSize
}

#[cfg(target_os = "linux")]
fn resident_bytes(child: &Child) -> usize {
    // A process can exit between try_wait and this read; later/earlier samples remain valid.
    fs::read_to_string(format!("/proc/{}/status", child.id()))
        .unwrap_or_default()
        .lines()
        .find_map(|line| {
            line.strip_prefix("VmRSS:")
                .and_then(|value| value.split_whitespace().next())
                .map(|value| value.parse::<usize>().unwrap() * 1024)
        })
        .unwrap_or(0)
}

pub fn finish_hash(hash: Sha3) -> String {
    let mut bytes = [0; 64];
    hash.finalize(&mut bytes);
    hex::encode(bytes)
}

pub fn digest(bytes: &[u8]) -> String {
    let mut hash = Sha3::v512();
    hash.update(bytes);
    finish_hash(hash)
}

pub fn file_digest(path: &Path) -> String {
    let mut file = File::open(path).unwrap();
    let mut hash = Sha3::v512();
    let mut buffer = vec![0; CHUNK];
    loop {
        let n = file.read(&mut buffer).unwrap();
        if n == 0 {
            break;
        }
        hash.update(&buffer[..n]);
    }
    finish_hash(hash)
}
