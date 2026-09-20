use std::ffi::CString;
use std::fs::{File, Metadata, OpenOptions};
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

pub fn enable_cancellation() -> io::Result<()> {
    Ok(())
}

pub fn prompt_password(prompt: &str) -> io::Result<String> {
    rpassword::prompt_password(prompt)
}

pub fn create_private(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
}

pub fn open_regular(path: &Path, write: bool) -> io::Result<File> {
    // O_NONBLOCK prevents a malicious FIFO from blocking before the type check.
    let f = OpenOptions::new()
        .read(true)
        .write(write)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)?;
    if !f.metadata()?.is_file() {
        return Err(io::Error::other("expected a regular file"));
    }
    Ok(f)
}

pub fn links(file: &File) -> io::Result<u64> {
    Ok(file.metadata()?.nlink())
}

pub fn same_snapshot(a: &Metadata, b: &Metadata) -> bool {
    a.dev() == b.dev()
        && a.ino() == b.ino()
        && a.len() == b.len()
        && a.mtime() == b.mtime()
        && a.mtime_nsec() == b.mtime_nsec()
        && a.ctime() == b.ctime()
        && a.ctime_nsec() == b.ctime_nsec()
}

pub fn check_in_place(file: &File, _: &Path) -> io::Result<()> {
    let mut info = std::mem::MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: info points to writable storage of the required size; fd remains open.
    if unsafe { libc::fstatfs(file.as_raw_fd(), info.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fstatfs succeeded and initialized the structure.
    let kind = unsafe { info.assume_init() }.f_type;
    // Deliberately reject remote, FUSE, and unknown filesystems for replacement.
    if ![0xef53, 0x58465342, 0x9123683e, 0x01021994, 0xf2f52010].contains(&kind) {
        return Err(io::Error::other(
            "in-place mode requires ext4/ext3/ext2, XFS, Btrfs, tmpfs, or F2FS",
        ));
    }
    Ok(())
}

pub fn publish(_: &File, temp: &Path, target: &Path, replace: bool) -> io::Result<()> {
    let from = CString::new(temp.as_os_str().as_bytes())?;
    let to = CString::new(target.as_os_str().as_bytes())?;
    let flags = if replace { 0 } else { libc::RENAME_NOREPLACE };
    // SAFETY: both NUL-terminated paths remain alive during the call. This performs
    // a same-directory atomic rename, with no copy/delete or overwrite fallback.
    if unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            libc::AT_FDCWD,
            from.as_ptr(),
            libc::AT_FDCWD,
            to.as_ptr(),
            flags,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

pub fn sync_publication(file: &File, dir: &Path) -> io::Result<()> {
    file.sync_all()?;
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(dir)?;
    directory.sync_all()
}
