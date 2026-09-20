use super::*;
use crate::{app, files::Root};
use std::ffi::OsStr;
use std::fs;
use std::io::Write;
use windows_sys::Win32::Security::Authorization::{
    ConvertSecurityDescriptorToStringSecurityDescriptorW, GetSecurityInfo, SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::DACL_SECURITY_INFORMATION;

fn root() -> (tempfile::TempDir, Root) {
    let dir = tempfile::tempdir().unwrap();
    let root = Root::for_test(dir.path());
    fs::write(root.dir.join("data"), b"original").unwrap();
    fs::write(root.dir.join("key.key"), [42; 8]).unwrap();
    (dir, root)
}

fn assert_no_temp(root: &Root) {
    assert!(!fs::read_dir(&root.dir).unwrap().any(|f| {
        f.unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".xorbox-")
    }));
}

fn dacl(file: &File) -> String {
    let mut descriptor = std::ptr::null_mut();
    // SAFETY: the live file supports READ_CONTROL; output storage is valid and
    // the returned allocation is freed below, including on conversion failure.
    let code = unsafe {
        GetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut descriptor,
        )
    };
    assert_eq!(code, 0);
    let mut text = std::ptr::null_mut();
    let mut length = 0;
    // SAFETY: descriptor came from GetSecurityInfo; text and length are outputs.
    let ok = unsafe {
        ConvertSecurityDescriptorToStringSecurityDescriptorW(
            descriptor,
            1,
            DACL_SECURITY_INFORMATION,
            &mut text,
            &mut length,
        )
    };
    // SAFETY: descriptor is a LocalAlloc-owned buffer, released exactly once.
    unsafe {
        LocalFree(descriptor);
    }
    assert_ne!(ok, 0);
    // SAFETY: a successful conversion returned length UTF-16 units including NUL.
    let value =
        unsafe { String::from_utf16_lossy(std::slice::from_raw_parts(text, length as usize - 1)) };
    // SAFETY: the converted string is a separate LocalAlloc-owned buffer.
    unsafe {
        LocalFree(text.cast());
    }
    value.trim_end_matches('\0').to_owned()
}

#[test]
fn protected_dacl_is_present_on_temp_and_preserved_through_replacement() {
    let (_dir, root) = root();
    let input = root.input(OsStr::new("data"), true).unwrap();
    let mut temp = root.temporary().unwrap();
    temp.write_all(b"new").unwrap();
    let expected = "D:P(A;;FA;;;OW)(A;;FA;;;SY)";
    assert_eq!(dacl(temp.as_file()), expected);
    root.publish(temp, input.path(), Some(&input)).unwrap();
    let published = open_regular(input.path(), false).unwrap();
    assert_eq!(dacl(&published), expected);
}

#[test]
fn open_input_denies_new_write_handles() {
    let (_dir, root) = root();
    let input = root.input(OsStr::new("data"), true).unwrap();
    assert!(OpenOptions::new().write(true).open(input.path()).is_err());
    drop(input);
    assert!(
        OpenOptions::new()
            .write(true)
            .open(root.dir.join("data"))
            .is_ok()
    );
}

#[test]
fn preexisting_writer_prevents_processing_input_or_key() {
    for name in ["data", "key.key"] {
        let (_dir, root) = root();
        let writer = OpenOptions::new()
            .write(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .open(root.dir.join(name))
            .unwrap();
        assert!(app::xor_file(&root, OsStr::new("data"), None, false).is_err());
        assert_eq!(fs::read(root.dir.join("data")).unwrap(), b"original");
        assert_no_temp(&root);
        drop(writer);
    }
}

#[test]
fn exclusive_byte_range_lock_prevents_processing() {
    let (_dir, root) = root();
    let locked = File::open(root.dir.join("data")).unwrap();
    locked.try_lock().unwrap();
    assert!(app::xor_file(&root, OsStr::new("data"), None, false).is_err());
    assert_no_temp(&root);
    drop(locked);
    assert_eq!(fs::read(root.dir.join("data")).unwrap(), b"original");
}

#[test]
fn read_only_in_place_input_is_rejected_before_temporary_creation() {
    let (_dir, root) = root();
    let path = root.dir.join("data");
    let original_permissions = fs::metadata(&path).unwrap().permissions();
    let mut permissions = original_permissions.clone();
    permissions.set_readonly(true);
    fs::set_permissions(&path, permissions).unwrap();
    let result = app::xor_file(&root, OsStr::new("data"), None, false);
    fs::set_permissions(&path, original_permissions).unwrap();
    assert!(result.is_err());
    assert_eq!(fs::read(path).unwrap(), b"original");
    assert_no_temp(&root);
}

#[test]
fn windows_case_aliases_cannot_overwrite_source_or_transform_key() {
    let (_dir, root) = root();
    assert!(app::xor_file(&root, OsStr::new("data"), Some(OsStr::new("DATA")), false).is_err());
    for name in ["KEY.KEY", "Key.Key", "kEy.kEy"] {
        assert!(root.input(OsStr::new(name), true).is_err());
    }
    assert_eq!(fs::read(root.dir.join("data")).unwrap(), b"original");
    assert_no_temp(&root);
}

#[test]
fn empty_alternate_stream_also_blocks_in_place() {
    let (_dir, root) = root();
    fs::write(root.dir.join("data:empty"), b"").unwrap();
    assert!(app::xor_file(&root, OsStr::new("data"), None, false).is_err());
    assert_eq!(fs::read(root.dir.join("data")).unwrap(), b"original");
    assert_eq!(fs::metadata(root.dir.join("data:empty")).unwrap().len(), 0);
    assert_no_temp(&root);
}

#[test]
fn alternate_stream_added_during_processing_is_not_discarded() {
    let (_dir, root) = root();
    let input = root.input(OsStr::new("data"), true).unwrap();
    input.prepare_in_place().unwrap();
    fs::write(root.dir.join("data:late"), b"preserve this").unwrap();
    let mut temp = root.temporary().unwrap();
    temp.write_all(b"completed output").unwrap();
    assert!(root.publish(temp, input.path(), Some(&input)).is_err());
    assert_eq!(fs::read(input.path()).unwrap(), b"original");
    assert_eq!(
        fs::read(root.dir.join("data:late")).unwrap(),
        b"preserve this"
    );
}

#[test]
fn private_creation_never_truncates_existing_file() {
    let (_dir, root) = root();
    assert_eq!(
        create_private(&root.dir.join("data")).unwrap_err().kind(),
        io::ErrorKind::AlreadyExists
    );
    assert_eq!(fs::read(root.dir.join("data")).unwrap(), b"original");
}

#[test]
fn publication_failure_retains_output_when_delete_sharing_is_denied() {
    let (_dir, root) = root();
    let blocker = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .open(root.dir.join("data"))
        .unwrap();
    let result = app::xor_file(&root, OsStr::new("data"), None, false);
    assert!(
        result.is_err(),
        "a reader denying delete sharing must block replacement"
    );
    assert_eq!(fs::read(root.dir.join("data")).unwrap(), b"original");
    let temporary: Vec<_> = fs::read_dir(&root.dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| {
            p.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with(".xorbox-")
        })
        .collect();
    assert_eq!(temporary.len(), 1);
    assert_eq!(
        fs::read(&temporary[0]).unwrap(),
        b"original".iter().map(|b| b ^ 42).collect::<Vec<_>>()
    );
    drop(blocker);
}

#[test]
fn inaccessible_protected_identity_is_not_silently_ignored() {
    let (_dir, root) = root();
    let blocker = OpenOptions::new()
        .read(true)
        .share_mode(0)
        .open(root.dir.join("key.key"))
        .unwrap();
    assert!(root.input(OsStr::new("data"), true).is_err());
    drop(blocker);
}

#[test]
fn extended_paths_and_surrogate_pairs_survive_publication() {
    let dir = tempfile::tempdir().unwrap();
    let mut deep = dir.path().canonicalize().unwrap();
    for _ in 0..4 {
        deep.push("a".repeat(70));
    }
    fs::create_dir_all(&deep).unwrap();
    let root = Root::for_test(&deep);
    let name = OsStr::new("🔐-日本語-𝄞.bin");
    fs::write(root.path(name).unwrap(), b"original").unwrap();
    fs::write(root.dir.join("key.key"), [42; 8]).unwrap();
    app::xor_file(&root, name, None, false).unwrap();
    app::xor_file(&root, name, None, false).unwrap();
    assert_eq!(fs::read(root.path(name).unwrap()).unwrap(), b"original");
}
