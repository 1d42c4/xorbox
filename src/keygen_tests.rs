use super::*;
use serde_json::json;
use std::fs;

fn empty_of_keys_and_temps(root: &Root) {
    assert!(!root.dir.join("key.key").exists());
    assert!(!fs::read_dir(&root.dir).unwrap().any(|e| {
        e.unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".xorbox-")
    }));
}

#[test]
fn invalid_metadata_is_rejected_before_key_generation() {
    let mut meta = KeyMeta::new(65).unwrap();
    meta.key_sha3_512 = "00".repeat(64);
    let valid = serde_json::to_value(meta).unwrap();
    for (field, bad) in [
        ("format", json!("unknown")),
        ("version", json!(0)),
        ("bytes", json!(0)),
        ("bytes", json!(-1)),
        ("bytes", json!(1.5)),
        ("bytes", json!(20_000_000_001u64)),
        ("memory_kib", json!(u32::MAX)),
        ("memory_kib", json!(8)),
        ("passes", json!(1)),
        ("lanes", json!(1)),
        ("kdf", json!("argon2i-v19")),
        ("generator", json!("repeat")),
        ("salt_hex", json!("0".repeat(31))),
        ("salt_hex", json!("gg".repeat(16))),
        ("nonce_hex", json!("00".repeat(13))),
        ("key_sha3_512", json!("00".repeat(63))),
        ("unknown", json!(true)),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let root = Root::for_test(dir.path());
        let mut value = valid.clone();
        value[field] = bad;
        let bytes = serde_json::to_vec(&value).unwrap();
        fs::write(root.dir.join("key.meta"), &bytes).unwrap();
        assert!(restore(&root, b"test only").is_err(), "field {field}");
        empty_of_keys_and_temps(&root);
        assert_eq!(fs::read(root.dir.join("key.meta")).unwrap(), bytes);
    }
}

#[test]
fn oversized_duplicate_and_non_utf8_metadata_are_rejected() {
    let mut meta = KeyMeta::new(65).unwrap();
    meta.key_sha3_512 = "00".repeat(64);
    let mut duplicate = serde_json::to_string(&meta).unwrap();
    duplicate.pop();
    duplicate.push_str(",\"bytes\":65}");
    for bytes in [
        vec![b' '; 16_385],
        vec![0xff, 0xfe],
        duplicate.into_bytes(),
        b"{}".to_vec(),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let root = Root::for_test(dir.path());
        fs::write(root.dir.join("key.meta"), bytes).unwrap();
        assert!(restore(&root, b"test only").is_err());
        empty_of_keys_and_temps(&root);
    }
}

#[test]
fn empty_password_creates_no_key_metadata_or_temporary() {
    let dir = tempfile::tempdir().unwrap();
    let root = Root::for_test(dir.path());
    assert!(make(&root, 1, b"").is_err());
    empty_of_keys_and_temps(&root);
    assert!(!root.dir.join("key.meta").exists());
}

#[test]
fn saved_metadata_without_key_can_be_restored_without_changing_recipe() {
    let dir = tempfile::tempdir().unwrap();
    let root = Root::for_test(dir.path());
    make(&root, 65, b"public regression passphrase").unwrap();
    let key = fs::read(root.dir.join("key.key")).unwrap();
    let meta = fs::read(root.dir.join("key.meta")).unwrap();
    fs::remove_file(root.dir.join("key.key")).unwrap();
    assert!(make(&root, 12, b"different").is_err());
    restore(&root, b"public regression passphrase").unwrap();
    assert_eq!(fs::read(root.dir.join("key.key")).unwrap(), key);
    assert_eq!(fs::read(root.dir.join("key.meta")).unwrap(), meta);
}

#[test]
fn digest_tampering_does_not_publish_generated_key() {
    let dir = tempfile::tempdir().unwrap();
    let root = Root::for_test(dir.path());
    make(&root, 65, b"test only").unwrap();
    fs::remove_file(root.dir.join("key.key")).unwrap();
    let mut meta: KeyMeta =
        serde_json::from_slice(&fs::read(root.dir.join("key.meta")).unwrap()).unwrap();
    meta.key_sha3_512 = "00".repeat(64);
    fs::write(
        root.dir.join("key.meta"),
        serde_json::to_vec(&meta).unwrap(),
    )
    .unwrap();
    assert!(restore(&root, b"test only").is_err());
    empty_of_keys_and_temps(&root);
}

#[test]
fn expansion_propagates_write_failure_and_invalid_size() {
    struct Full;
    impl Write for Full {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("disk full"))
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    assert!(expand(&[1; 32], &[2; 12], 65, &mut Full).is_err());
    for length in [0, MAX_KEY_BYTES + 1, u64::MAX] {
        let mut out = Vec::new();
        assert!(expand(&[1; 32], &[2; 12], length, &mut out).is_err());
        assert!(out.is_empty());
    }
}
