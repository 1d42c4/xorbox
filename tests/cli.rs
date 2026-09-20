use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};

struct Fixture {
    dir: tempfile::TempDir,
    elsewhere: tempfile::TempDir,
    exe: PathBuf,
}
impl Fixture {
    fn new() -> Self {
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
    fn run(&self, args: &[&str]) -> Output {
        Command::new(&self.exe)
            .args(args)
            .current_dir(self.elsewhere.path())
            .output()
            .unwrap()
    }
    fn ok(&self, args: &[&str]) -> Output {
        let out = self.run(args);
        assert!(
            out.status.success(),
            "{args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        out
    }
}

#[test]
fn sha3_hashes_literal_utf8_without_newline() {
    let f = Fixture::new();
    fs::write(f.dir.path().join("abc"), b"this must not be hashed").unwrap();
    let out = f.ok(&["sha3", "abc"]);
    assert_eq!(
        String::from_utf8(out.stdout).unwrap(),
        concat!(
            "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e",
            "10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0\n"
        )
    );
    assert!(out.stderr.is_empty());
    let empty = f.ok(&["sha3", ""]);
    assert_eq!(empty.stdout.len(), 129);
    assert_ne!(empty.stdout, f.ok(&["sha3", "\n"]).stdout);
}

#[test]
fn rejects_help_version_paths_and_invalid_sizes() {
    let f = Fixture::new();
    for args in [
        vec!["--help"],
        vec!["--version"],
        vec!["keymake", "20gb"],
        vec!["keymake", "20000000001"],
        vec!["xor", "../a", "b"],
    ] {
        let out = f.run(&args);
        assert!(!out.status.success());
        assert!(out.stdout.is_empty());
        assert!(!out.stderr.is_empty());
    }
}

#[test]
fn portable_folder_cli_and_no_clobber() {
    let f = Fixture::new();
    let root = f.dir.path();
    fs::write(root.join("key.key"), [0xa5; 7]).unwrap();
    fs::write(root.join("日本語 file.bin"), b"1234567").unwrap();
    f.ok(&["xor", "日本語 file.bin", "encrypted"]);
    assert_eq!(
        fs::read(root.join("encrypted")).unwrap(),
        b"1234567".iter().map(|b| b ^ 0xa5).collect::<Vec<_>>()
    );
    assert!(
        !f.run(&["xor", "日本語 file.bin", "encrypted"])
            .status
            .success()
    );
    f.ok(&["xor", "encrypted", "recovered"]);
    assert_eq!(fs::read(root.join("recovered")).unwrap(), b"1234567");
    f.ok(&["xcha", "K"]);
    assert_eq!(fs::metadata(root.join("xcha.key")).unwrap().len(), 32);
    assert!(!f.run(&["xcha", "K"]).status.success());
    f.ok(&["xcha", "E", "encrypted"]);
    let cipher = fs::read(root.join("encrypted.xcha")).unwrap();
    assert!(!f.run(&["xcha", "D", "encrypted.xcha"]).status.success());
    fs::rename(root.join("encrypted"), root.join("saved-xor")).unwrap();
    f.ok(&["xcha", "D", "encrypted.xcha"]);
    assert_eq!(
        fs::read(root.join("encrypted")).unwrap(),
        fs::read(root.join("saved-xor")).unwrap()
    );
    assert_eq!(fs::read(root.join("encrypted.xcha")).unwrap(), cipher);
    assert_eq!(fs::read_dir(f.elsewhere.path()).unwrap().count(), 0);
}

#[test]
fn repeat_mode_is_explicit_and_crosses_key_boundaries() {
    let f = Fixture::new();
    fs::write(f.dir.path().join("key.key"), [1, 2, 3]).unwrap();
    fs::write(f.dir.path().join("data"), [0; 19]).unwrap();
    assert!(!f.run(&["xor", "data", "out"]).status.success());
    assert!(!f.dir.path().join("out").exists());
    f.ok(&["xor", "data", "out", "--repeat-key"]);
    assert_eq!(
        fs::read(f.dir.path().join("out")).unwrap(),
        (0..19).map(|i| (i % 3 + 1) as u8).collect::<Vec<_>>()
    );
}

#[test]
fn invalid_raw_xcha_key_sizes_never_publish_or_replace_data() {
    let f = Fixture::new();
    fs::write(f.dir.path().join("data"), b"original").unwrap();
    for length in [0, 1, 31, 33, 64] {
        fs::write(f.dir.path().join("xcha.key"), vec![7; length]).unwrap();
        for args in [
            vec!["xcha", "E", "data"],
            vec!["xcha", "E", "data", "--in-place"],
        ] {
            assert!(!f.run(&args).status.success());
            assert_eq!(fs::read(f.dir.path().join("data")).unwrap(), b"original");
            assert!(!f.dir.path().join("data.xcha").exists());
        }
    }
}

#[test]
fn late_authentication_failure_removes_partial_plaintext_and_preserves_ciphertext() {
    let f = Fixture::new();
    fs::write(f.dir.path().join("xcha.key"), [19; 32]).unwrap();
    fs::write(f.dir.path().join("data"), vec![71; 2 * 1024 * 1024 + 17]).unwrap();
    f.ok(&["xcha", "E", "data", "--in-place"]);
    let mut corrupted = fs::read(f.dir.path().join("data")).unwrap();
    *corrupted.last_mut().unwrap() ^= 1;
    fs::write(f.dir.path().join("data"), &corrupted).unwrap();
    assert!(!f.run(&["xcha", "D", "data", "--in-place"]).status.success());
    assert_eq!(fs::read(f.dir.path().join("data")).unwrap(), corrupted);
    assert!(!fs::read_dir(f.dir.path()).unwrap().any(|e| {
        e.unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".xorbox-")
    }));
}

#[test]
fn folder_lock_blocks_other_processes_and_is_released_after_exit() {
    let f = Fixture::new();
    f.ok(&["xcha", "K"]);
    let lock = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(f.dir.path().join(".xorbox.lock"))
        .unwrap();
    lock.try_lock().unwrap();
    fs::write(f.dir.path().join("data"), b"original").unwrap();
    assert!(!f.run(&["xcha", "E", "data"]).status.success());
    assert!(!f.dir.path().join("data.xcha").exists());
    // Literal hashing doesn't operate on this folder or need its lock.
    f.ok(&["sha3", "abc"]);
    drop(lock);
    f.ok(&["xcha", "E", "data"]);
}

#[cfg(windows)]
#[test]
fn commands_work_without_a_console_when_no_prompt_is_needed() {
    use std::os::windows::process::CommandExt;
    let f = Fixture::new();
    for args in [vec!["sha3", "abc"], vec!["xcha", "K"]] {
        let out = Command::new(&f.exe)
            .args(args)
            .creation_flags(0x08000000)
            .output()
            .unwrap(); // CREATE_NO_WINDOW
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

#[test]
fn empty_files_round_trip_with_both_algorithms() {
    let f = Fixture::new();
    fs::write(f.dir.path().join("data"), []).unwrap();
    fs::write(f.dir.path().join("key.key"), [9]).unwrap();
    f.ok(&["xor", "data", "--in-place"]);
    assert_eq!(fs::metadata(f.dir.path().join("data")).unwrap().len(), 0);
    f.ok(&["xcha", "K"]);
    f.ok(&["xcha", "E", "data", "--in-place"]);
    assert!(fs::metadata(f.dir.path().join("data")).unwrap().len() > 0);
    f.ok(&["xcha", "D", "data", "--in-place"]);
    assert_eq!(fs::metadata(f.dir.path().join("data")).unwrap().len(), 0);
}
