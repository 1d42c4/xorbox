use super::*;
use std::io::{Read, Write};

fn completed(root: &Root) -> NamedTempFile {
    let mut temp = root.temporary().unwrap();
    temp.write_all(b"completed output").unwrap();
    temp
}

#[test]
fn in_place_rechecks_links_added_after_initial_validation() {
    let dir = tempfile::tempdir().unwrap();
    let root = Root::for_test(dir.path());
    fs::write(root.dir.join("data"), b"original").unwrap();
    let input = root.input(OsStr::new("data"), true).unwrap();
    input.prepare_in_place().unwrap();
    fs::hard_link(input.path(), root.dir.join("late-alias")).unwrap();
    assert!(
        root.publish(completed(&root), input.path(), Some(&input))
            .is_err()
    );
    assert_eq!(fs::read(input.path()).unwrap(), b"original");
    assert_eq!(fs::read(root.dir.join("late-alias")).unwrap(), b"original");
}

#[test]
fn replaced_input_path_is_detected_before_publication() {
    let dir = tempfile::tempdir().unwrap();
    let root = Root::for_test(dir.path());
    fs::write(root.dir.join("data"), b"original").unwrap();
    let input = root.input(OsStr::new("data"), true).unwrap();
    fs::rename(input.path(), root.dir.join("moved")).unwrap();
    fs::write(input.path(), b"replacement").unwrap();
    assert!(
        root.publish(completed(&root), input.path(), Some(&input))
            .is_err()
    );
    assert_eq!(fs::read(input.path()).unwrap(), b"replacement");
    assert_eq!(fs::read(root.dir.join("moved")).unwrap(), b"original");
}

#[test]
fn output_created_after_preflight_is_preserved_and_completed_temp_retained() {
    let dir = tempfile::tempdir().unwrap();
    let root = Root::for_test(dir.path());
    let target = root.destination(OsStr::new("output"), true).unwrap();
    let temp = completed(&root);
    let retained = temp.path().to_owned();
    fs::write(&target, b"other writer").unwrap();
    let error = root.publish(temp, &target, None).unwrap_err().to_string();
    assert!(
        error.contains("completed temporary file retained"),
        "{error}"
    );
    assert_eq!(fs::read(&target).unwrap(), b"other writer");
    assert_eq!(fs::read(retained).unwrap(), b"completed output");
}

#[test]
fn old_open_reader_sees_complete_old_file_after_atomic_replacement() {
    let dir = tempfile::tempdir().unwrap();
    let root = Root::for_test(dir.path());
    fs::write(root.dir.join("data"), b"original").unwrap();
    let mut input = root.input(OsStr::new("data"), true).unwrap();
    root.publish(completed(&root), input.path(), Some(&input))
        .unwrap();
    let mut original = Vec::new();
    input.file.read_to_end(&mut original).unwrap();
    assert_eq!(original, b"original");
    assert_eq!(fs::read(input.path()).unwrap(), b"completed output");
}

#[test]
fn all_protected_names_and_hardlink_aliases_are_rejected_as_data() {
    for name in [
        "key.key",
        "key.meta",
        "xcha.key",
        ".xorbox.lock",
        "xorbox-test-executable",
    ] {
        let dir = tempfile::tempdir().unwrap();
        let root = Root::for_test(dir.path());
        fs::write(root.dir.join(name), b"protected").unwrap();
        fs::hard_link(root.dir.join(name), root.dir.join("innocent.bin")).unwrap();
        assert!(root.input(OsStr::new(name), true).is_err(), "{name}");
        assert!(
            root.input(OsStr::new("innocent.bin"), true).is_err(),
            "{name}"
        );
        assert_eq!(fs::read(root.dir.join(name)).unwrap(), b"protected");
    }
}

#[test]
fn directories_cannot_be_used_as_data_or_keys() {
    let dir = tempfile::tempdir().unwrap();
    let root = Root::for_test(dir.path());
    fs::create_dir(root.dir.join("folder")).unwrap();
    assert!(root.input(OsStr::new("folder"), true).is_err());
    assert!(root.input(OsStr::new("folder"), false).is_err());
    assert!(root.destination(OsStr::new("folder"), true).is_err());
}
