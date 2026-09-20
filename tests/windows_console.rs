#![cfg(windows)]
#[path = "support/console.rs"]
mod console;
#[path = "support/key_reference.rs"]
mod key_reference;
mod support;
use console::{Console, serial};
use std::fs::{self, File};
use support::{CHUNK, Fixture, digest, file_digest};

fn prompt_cancel(args: &[&str], confirmation: bool) {
    let guard = serial();
    let f = Fixture::new();
    let c = Console::launch(&f, args, &guard);
    c.prompt(if args[0] == "sha3" {
        "Text: "
    } else {
        "Password: "
    });
    if confirmation {
        c.type_text("public test phrase\r");
        c.prompt("Confirm password: ");
    }
    assert!(c.cancel().is_empty());
    c.restored();
    assert!(!f.path("key.key").exists());
    assert!(!f.path("key.meta").exists());
    f.no_temps();
}

#[test]
fn cancel_idle_sha3_prompt() {
    prompt_cancel(&["sha3"], false);
}
#[test]
fn cancel_idle_keymake_prompt() {
    prompt_cancel(&["keymake", "65"], false);
}
#[test]
fn cancel_keymake_confirmation() {
    prompt_cancel(&["keymake", "65"], true);
}

#[test]
fn unicode_hidden_password_round_trip_matches_independent_reference() {
    let guard = serial();
    let f = Fixture::new();
    let password = "public test phrase 日本語 🔐";
    {
        let c = Console::launch(&f, &["keymake", "65"], &guard);
        c.prompt("Password: ");
        c.type_text(&format!("{password}\r"));
        c.prompt("Confirm password: ");
        assert!(!c.screen().contains("public test phrase"));
        c.type_text(&format!("{password}\r"));
        c.finish(0);
        c.restored();
        assert!(!c.screen().contains("public test phrase"));
    }
    let key = fs::read(f.path("key.key")).unwrap();
    let recipe = fs::read(f.path("key.meta")).unwrap();
    assert_eq!(key.len(), 65);
    assert_eq!(
        key,
        key_reference::expected_key(
            password.as_bytes(),
            &serde_json::from_slice(&recipe).unwrap()
        )
    );
    fs::remove_file(f.path("key.key")).unwrap();
    {
        let c = Console::launch(&f, &["keyrestore"], &guard);
        c.prompt("Password: ");
        c.type_text(&format!("{password}\r"));
        c.finish(0);
        c.restored();
        assert!(!c.screen().contains("public test phrase"));
    }
    assert_eq!(fs::read(f.path("key.key")).unwrap(), key);
    assert_eq!(fs::read(f.path("key.meta")).unwrap(), recipe);
    f.no_temps();
}

fn bad_password(first: &str, second: Option<&str>) {
    let guard = serial();
    let f = Fixture::new();
    let c = Console::launch(&f, &["keymake", "65"], &guard);
    c.prompt("Password: ");
    c.type_text(first);
    if let Some(second) = second {
        c.prompt("Confirm password: ");
        c.type_text(second);
    }
    c.finish(1);
    c.restored();
    assert!(!f.path("key.key").exists());
    assert!(!f.path("key.meta").exists());
    f.no_temps();
}
#[test]
fn empty_password_is_rejected() {
    bad_password("\r", None);
}
#[test]
fn mismatched_password_is_rejected() {
    bad_password("one\r", Some("two\r"));
}

fn hidden_sha3(typed: &str, expected: &str) {
    let guard = serial();
    let f = Fixture::new();
    let c = Console::launch(&f, &["sha3"], &guard);
    c.prompt("Text: ");
    c.type_text(&format!("{typed}\r"));
    assert_eq!(
        c.finish(0),
        format!("{}\n", digest(expected.as_bytes())).as_bytes()
    );
    assert!(!c.screen().contains("apple"));
    c.restored();
}
#[test]
fn hidden_sha3_unicode() {
    hidden_sha3("apple 日本語 🔐", "apple 日本語 🔐");
}
#[test]
fn backspace_removes_surrogate_pair() {
    hidden_sha3("a🔐\u{8}pple", "apple");
}
#[test]
fn control_u_clears_line() {
    hidden_sha3("discard\u{15}apple", "apple");
}
#[test]
fn control_w_removes_word() {
    hidden_sha3("apple banana  \u{17}", "apple ");
}
#[test]
fn hidden_sha3_empty_input() {
    hidden_sha3("", "");
}
#[test]
fn keyboard_control_c_cancels_hidden_input() {
    let guard = serial();
    let f = Fixture::new();
    let c = Console::launch(&f, &["sha3"], &guard);
    c.prompt("Text: ");
    c.type_text("not hashed\u{3}");
    assert!(c.finish(130).is_empty());
    c.restored();
}

fn cancel_stream(command: &str) {
    let guard = serial();
    let f = Fixture::new();
    let is_key = command.starts_with("key");
    let mut before = String::new();
    if !is_key {
        // Covers the old standalone 1 GiB cancellation check as well as XChaCha.
        let size = if command == "xor" { 1024 } else { 512 };
        File::create(f.path("data"))
            .unwrap()
            .set_len(size * CHUNK as u64 + 19)
            .unwrap();
        fs::write(f.path("key.key"), [0x11, 0x22, 0x33]).unwrap();
        fs::write(f.path("xcha.key"), (0..32).collect::<Vec<u8>>()).unwrap();
        if command == "decrypt" {
            f.ok(&["xcha", "E", "data", "--in-place"]);
        }
        before = file_digest(&f.path("data"));
    }
    // Valid public recipe, with a deliberately unfinished digest. Cancellation
    // must happen during expansion, before final digest validation/publication.
    let recipe = serde_json::to_vec(&serde_json::json!({
        "format": "xorbox-key", "version": 1, "bytes": 20_000_000_000u64,
        "kdf": "argon2id-v19", "memory_kib": 65536, "passes": 3, "lanes": 4,
        "salt_hex": "00".repeat(16), "generator": "chacha20-ietf-counter0",
        "nonce_hex": "11".repeat(12), "key_sha3_512": "00".repeat(64)
    }))
    .unwrap();
    if command == "keyrestore" {
        fs::write(f.path("key.meta"), &recipe).unwrap();
    }
    let args: &[&str] = match command {
        "xor" => &["xor", "data", "--in-place", "--repeat-key"],
        "encrypt" => &["xcha", "E", "data", "--in-place"],
        "decrypt" => &["xcha", "D", "data", "--in-place"],
        "keymake" => &["keymake", "20000000000"],
        "keyrestore" => &["keyrestore"],
        _ => unreachable!(),
    };
    {
        let c = Console::launch(&f, args, &guard);
        if is_key {
            c.prompt("Password: ");
            c.type_text("public cancellation fixture\r");
            if command == "keymake" {
                c.prompt("Confirm password: ");
                c.type_text("public cancellation fixture\r");
            }
        }
        c.wait_for(|| {
            fs::read_dir(f.dir.path()).unwrap().any(|entry| {
                let entry = entry.unwrap();
                entry.file_name().to_string_lossy().starts_with(".xorbox-")
                    // Windows directory metadata can cache a zero length while
                    // a file is open for writing. Query the live file handle.
                    && File::open(entry.path())
                        .and_then(|file| file.metadata())
                        .is_ok_and(|meta| meta.len() > CHUNK as u64)
            })
        });
        c.cancel();
    }
    f.no_temps();
    if is_key {
        assert!(!f.path("key.key").exists());
        if command == "keymake" {
            assert!(!f.path("key.meta").exists());
        } else {
            assert_eq!(fs::read(f.path("key.meta")).unwrap(), recipe);
        }
    } else {
        assert_eq!(file_digest(&f.path("data")), before);
    }
}
#[test]
fn cancel_xor_preserves_original() {
    cancel_stream("xor");
}
#[test]
fn cancel_xcha_encrypt_preserves_original() {
    cancel_stream("encrypt");
}
#[test]
fn cancel_xcha_decrypt_preserves_original() {
    cancel_stream("decrypt");
}
#[test]
fn cancel_20gb_keymake_cleans_temporary() {
    cancel_stream("keymake");
}
#[test]
fn cancel_20gb_keyrestore_preserves_recipe() {
    cancel_stream("keyrestore");
}
