use std::ffi::{OsStr, OsString};
use std::fs::{self, File, Metadata};
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result, bail, ensure};
use same_file::Handle;
use tempfile::NamedTempFile;

use crate::{platform, stream};

pub struct Root {
    pub dir: PathBuf,
    executable: PathBuf,
}
pub struct Input {
    pub file: File,
    path: PathBuf,
    snapshot: Metadata,
    identity: Handle,
}

pub fn valid_name(name: &OsStr) -> Result<()> {
    let path = Path::new(name);
    ensure!(
        matches!(path.components().next(), Some(Component::Normal(_)))
            && path.components().count() == 1,
        "use a filename beside the executable, not a path"
    );
    let s = name.to_string_lossy();
    ensure!(
        !s.is_empty()
            && !s.starts_with('-')
            && !s.ends_with(['.', ' '])
            && !s
                .chars()
                .any(|c| c.is_control() || "<>:\"/\\|?*".contains(c)),
        "invalid filename"
    );
    let upper = s
        .split('.')
        .next()
        .unwrap_or("")
        .trim_end_matches(' ')
        .to_uppercase();
    ensure!(
        !["CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"].contains(&upper.as_str())
            && !(upper.starts_with("COM") || upper.starts_with("LPT"))
                .then(|| &upper[3..])
                .is_some_and(
                    |s| ["1", "2", "3", "4", "5", "6", "7", "8", "9", "¹", "²", "³"].contains(&s)
                ),
        "reserved device filename"
    );
    Ok(())
}

fn reserved(name: &OsStr) -> bool {
    let s = name.to_string_lossy().to_ascii_lowercase();
    ["key.key", "key.meta", "xcha.key", ".xorbox.lock"].contains(&s.as_str())
        || s.starts_with(".xorbox-")
}

impl Root {
    pub fn current() -> Result<Self> {
        let executable = std::env::current_exe()?.canonicalize()?;
        let dir = executable
            .parent()
            .context("executable has no parent directory")?
            .to_owned();
        Ok(Self { dir, executable })
    }

    #[cfg(test)]
    pub fn for_test(dir: &Path) -> Self {
        Self {
            dir: dir.canonicalize().unwrap(),
            executable: dir.join("xorbox-test-executable"),
        }
    }

    pub fn path(&self, name: &OsStr) -> Result<PathBuf> {
        valid_name(name)?;
        Ok(self.dir.join(name))
    }

    /// The persistent lock coordinates all xorbox file commands in this folder.
    /// Never unlink it: doing so would let processes lock different inodes.
    pub fn lock(&self) -> Result<File> {
        let path = self.dir.join(".xorbox.lock");
        let file = match platform::create_private(&path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                platform::open_regular(&path, true)?
            }
            Err(e) => return Err(e.into()),
        };
        ensure!(
            platform::links(&file)? == 1,
            "lock file must not have hard links"
        );
        file.try_lock()
            .context("another xorbox operation is using this folder, or the lock is unavailable")?;
        Ok(file)
    }

    pub fn input(&self, name: &OsStr, data: bool) -> Result<Input> {
        let path = self.path(name)?;
        if data {
            ensure!(
                !reserved(name),
                "key, metadata, and internal files cannot be transformed"
            );
        }
        let file = platform::open_regular(&path, false)
            .with_context(|| format!("cannot open {}", name.to_string_lossy()))?;
        file.try_lock_shared()
            .context("file is locked by another operation")?;
        let snapshot = file.metadata()?;
        let identity = Handle::from_file(file.try_clone()?)?;
        if data {
            for protected in [
                self.executable.clone(),
                self.dir.join("key.key"),
                self.dir.join("key.meta"),
                self.dir.join("xcha.key"),
                self.dir.join(".xorbox.lock"),
            ] {
                match Handle::from_path(&protected) {
                    Ok(other) => ensure!(other != identity, "input aliases a protected file"),
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(e) => {
                        return Err(e).with_context(|| {
                            format!(
                                "cannot verify protected file identity: {}",
                                protected.display()
                            )
                        });
                    }
                }
            }
        }
        Ok(Input {
            file,
            path,
            snapshot,
            identity,
        })
    }

    pub fn destination(&self, name: &OsStr, data: bool) -> Result<PathBuf> {
        let path = self.path(name)?;
        if data {
            ensure!(!reserved(name), "protected destination filename");
            ensure!(path != self.executable, "cannot replace the executable");
        }
        self.require_absent(&path)?;
        Ok(path)
    }

    pub fn require_absent(&self, path: &Path) -> Result<()> {
        match fs::symlink_metadata(path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
            Ok(_) => bail!(
                "destination already exists: {}",
                path.file_name().unwrap_or_default().to_string_lossy()
            ),
        }
    }

    pub fn temporary(&self) -> Result<NamedTempFile> {
        tempfile::Builder::new()
            .prefix(".xorbox-")
            .suffix(".tmp")
            .make_in(&self.dir, platform::create_private)
            .context("cannot create protected temporary file")
    }

    pub fn publish(
        &self,
        temp: NamedTempFile,
        target: &Path,
        original: Option<&Input>,
    ) -> Result<()> {
        stream::check_cancel()?;
        temp.as_file()
            .sync_all()
            .context("could not synchronize temporary output; original unchanged")?;
        if let Some(input) = original {
            input.unchanged()?;
            // Hard links and alternate streams can be added while we process the
            // original. Repeat the replacement checks immediately before commit.
            input.prepare_in_place()?;
        }
        stream::check_cancel()?;
        let (file, mut temp_path) = temp.into_parts();
        if let Err(e) = platform::publish(&file, &temp_path, target, original.is_some()) {
            // Keep a completed output if publication itself fails, to avoid
            // destroying potentially useful recovery data after an OS error.
            temp_path.disable_cleanup(true);
            bail!(
                "publication failed; completed temporary file retained at {}: {e}",
                temp_path.display()
            );
        }
        temp_path.disable_cleanup(true);
        let published = Handle::from_path(target)
            .context("publication reported success but destination could not be verified; inspect the directory before retrying")?;
        ensure!(
            published == Handle::from_file(file.try_clone()?)?,
            "publication reported success but destination identity did not match; inspect the directory before retrying"
        );
        platform::sync_publication(&file, &self.dir).with_context(||
            format!("REPLACEMENT/PUBLICATION ALREADY OCCURRED for {}; final synchronization failed; do not blindly retry XOR", target.display()))?;
        Ok(())
    }
}

impl Input {
    pub fn len(&self) -> u64 {
        self.snapshot.len()
    }
    pub fn path(&self) -> &Path {
        &self.path
    }
    pub fn prepare_in_place(&self) -> Result<()> {
        ensure!(
            platform::links(&self.file)? == 1,
            "in-place input must not have hard links"
        );
        platform::check_in_place(&self.file, &self.path)
            .context("atomic in-place replacement is unavailable")
    }
    pub fn unchanged(&self) -> Result<()> {
        let current = self.file.metadata()?;
        ensure!(
            platform::same_snapshot(&self.snapshot, &current),
            "file changed during processing"
        );
        let path_file = platform::open_regular(&self.path, false)
            .context("input path changed during processing")?;
        ensure!(
            Handle::from_file(path_file)? == self.identity,
            "input path now identifies a different file"
        );
        Ok(())
    }
}

pub fn xcha_output(input: &OsStr, encrypt: bool) -> Result<OsString> {
    if encrypt {
        let mut out = input.to_os_string();
        out.push(".xcha");
        Ok(out)
    } else {
        let path = Path::new(input);
        ensure!(
            path.extension() == Some(OsStr::new("xcha")),
            "decryption input needs a .xcha suffix unless --in-place is used"
        );
        let stem = path
            .file_stem()
            .context("missing output filename")?
            .to_owned();
        valid_name(&stem)?;
        Ok(stem)
    }
}

#[cfg(test)]
#[path = "files_tests.rs"]
mod regression_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn filenames_cannot_escape_or_name_devices() {
        for name in [
            "",
            ".",
            "..",
            "../a",
            "a/b",
            "a\\b",
            "C:foo",
            "NUL.txt",
            "COM1",
            "lpt9.pdf",
            "a:stream",
            "a.",
            "a ",
            "NUL .txt",
            "COM1 .bin",
            "LPT¹.txt",
            "CONOUT$.txt",
        ] {
            assert!(valid_name(OsStr::new(name)).is_err(), "{name}");
        }
        for name in ["hello.txt", "long name.bin", "日本語.dat", "COM10.txt"] {
            valid_name(OsStr::new(name)).unwrap();
        }
    }

    #[test]
    fn publishing_never_clobbers_without_in_place() {
        let dir = tempfile::tempdir().unwrap();
        let root = Root::for_test(dir.path());
        let target = dir.path().join("output");
        fs::write(&target, b"original").unwrap();
        let mut temp = root.temporary().unwrap();
        temp.write_all(b"new").unwrap();
        assert!(root.publish(temp, &target, None).is_err());
        assert_eq!(fs::read(&target).unwrap(), b"original");
    }

    #[test]
    fn protected_hardlink_and_in_place_hardlink_are_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let root = Root::for_test(dir.path());
        fs::write(dir.path().join("key.key"), b"secret").unwrap();
        fs::hard_link(dir.path().join("key.key"), dir.path().join("alias")).unwrap();
        assert!(root.input(OsStr::new("alias"), true).is_err());
        fs::write(dir.path().join("data"), b"data").unwrap();
        fs::hard_link(dir.path().join("data"), dir.path().join("data2")).unwrap();
        assert!(
            root.input(OsStr::new("data"), true)
                .unwrap()
                .prepare_in_place()
                .is_err()
        );
    }

    #[test]
    fn directory_lock_serializes_operations() {
        let dir = tempfile::tempdir().unwrap();
        let root = Root::for_test(dir.path());
        let first = root.lock().unwrap();
        assert!(root.lock().is_err());
        drop(first);
        assert!(root.lock().is_ok());
    }

    #[cfg(windows)]
    #[test]
    fn in_place_rejects_alternate_streams_without_losing_them() {
        let dir = tempfile::tempdir().unwrap();
        let root = Root::for_test(dir.path());
        fs::write(dir.path().join("data"), b"main").unwrap();
        fs::write(dir.path().join("data:extra"), b"extra").unwrap();
        let input = root.input(OsStr::new("data"), true).unwrap();
        assert!(input.prepare_in_place().is_err());
        assert_eq!(fs::read(dir.path().join("data:extra")).unwrap(), b"extra");
    }

    #[test]
    fn atomic_publish_handles_unicode_and_filename_buffer_boundaries() {
        let dir = tempfile::tempdir().unwrap();
        let root = Root::for_test(dir.path());
        for length in 1..=24 {
            let name = format!("日本語-{}", "a".repeat(length));
            let target = root.destination(OsStr::new(&name), true).unwrap();
            let mut temp = root.temporary().unwrap();
            temp.write_all(name.as_bytes()).unwrap();
            root.publish(temp, &target, None).unwrap();
            assert_eq!(fs::read(&target).unwrap(), name.as_bytes());
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn symlinks_and_fifos_are_rejected_without_blocking() {
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().unwrap();
        let root = Root::for_test(dir.path());
        fs::write(dir.path().join("data"), b"data").unwrap();
        symlink("data", dir.path().join("link")).unwrap();
        assert!(root.input(OsStr::new("link"), true).is_err());
        let name = std::ffi::CString::new(dir.path().join("fifo").as_os_str().as_bytes()).unwrap();
        // SAFETY: name is a valid terminated path inside our temporary test directory.
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        assert!(root.input(OsStr::new("fifo"), true).is_err());
    }
}
