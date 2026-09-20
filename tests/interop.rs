//! Independent pure-Rust references: no Python, OpenSSL or libsodium installation.
mod support;
use crypto_secretstream::{Header, Key, PullStream, PushStream, Tag};
use rand_core::OsRng;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::Path;
use support::{CHUNK, Fixture, digest, file_digest, finish_hash};
use tiny_keccak::{Hasher, Sha3};

fn reference_read(path: &Path, key: [u8; 32]) -> (String, usize) {
    let mut file = File::open(path).unwrap();
    let mut header = [0; 36];
    file.read_exact(&mut header).unwrap();
    assert_eq!(&header[..8], b"XORBOX\0\x01");
    assert_eq!(
        u32::from_le_bytes(header[8..12].try_into().unwrap()),
        CHUNK as u32
    );
    let mut stream = PullStream::init(Header::try_from(&header[12..]).unwrap(), &Key::from(key));
    let mut hash = Sha3::v512();
    let mut size = 0;
    let mut short = false;
    loop {
        let mut length = [0; 4];
        file.read_exact(&mut length).unwrap();
        let length = u32::from_le_bytes(length) as usize;
        assert!((17..=CHUNK + 17).contains(&length));
        let mut message = vec![0; length];
        file.read_exact(&mut message).unwrap();
        let tag = stream.pull(&mut message, &header).unwrap();
        if tag == Tag::Final {
            assert!(message.is_empty());
            assert_eq!(file.read(&mut [0]).unwrap(), 0);
            break;
        }
        assert_eq!(tag, Tag::Message);
        assert!(!message.is_empty() && !short);
        short = message.len() < CHUNK;
        hash.update(&message);
        size += message.len();
    }
    (finish_hash(hash), size)
}

fn reference_write(path: &Path, key: [u8; 32], data: &[u8]) {
    let (nonce, mut stream) = PushStream::init(OsRng, &Key::from(key));
    let mut header = b"XORBOX\0\x01".to_vec();
    header.extend_from_slice(&(CHUNK as u32).to_le_bytes());
    header.extend_from_slice(nonce.as_ref());
    let mut file = File::create(path).unwrap();
    file.write_all(&header).unwrap();
    for (data, tag) in data
        .chunks(CHUNK)
        .map(|block| (block, Tag::Message))
        .chain(std::iter::once((&[][..], Tag::Final)))
    {
        let mut message = data.to_vec();
        stream.push(&mut message, &header, tag).unwrap();
        file.write_all(&(message.len() as u32).to_le_bytes())
            .unwrap();
        file.write_all(&message).unwrap();
    }
}

#[test]
fn sha3_matches_independent_reference() {
    let f = Fixture::new();
    for text in ["", "apple", "abc", "日本語 text", "a\nb"] {
        assert_eq!(
            f.ok(&["sha3", text]).stdout,
            format!("{}\n", digest(text.as_bytes())).as_bytes()
        );
    }
}

#[test]
fn secretstream_matches_independent_reference_in_both_directions() {
    let f = Fixture::new();
    f.ok(&["xcha", "K"]);
    let key: [u8; 32] = fs::read(f.path("xcha.key")).unwrap().try_into().unwrap();
    for size in [0, 1, CHUNK - 1, CHUNK, CHUNK + 17, 2 * CHUNK] {
        let data: Vec<u8> = (0..size).map(|i| i as u8).collect();
        let name = format!("sample-{size}");
        fs::write(f.path(&name), &data).unwrap();
        f.ok(&["xcha", "E", &name]);
        assert_eq!(
            reference_read(&f.path(&format!("{name}.xcha")), key),
            (digest(&data), size)
        );
        let reference = format!("{name}-reference");
        reference_write(&f.path(&format!("{reference}.xcha")), key, &data);
        f.ok(&["xcha", "D", &format!("{reference}.xcha")]);
        assert_eq!(fs::read(f.path(&reference)).unwrap(), data);
    }
}

#[test]
fn large_files_round_trip_with_bounded_process_memory() {
    let f = Fixture::new();
    f.ok(&["xcha", "K"]);
    let key: [u8; 32] = fs::read(f.path("xcha.key")).unwrap().try_into().unwrap();
    let block: Vec<u8> = (0..CHUNK).map(|i| i as u8).collect();
    let mut hash = Sha3::v512();
    {
        let mut file = File::create(f.path("large")).unwrap();
        for _ in 0..256 {
            file.write_all(&block).unwrap();
            hash.update(&block);
        }
    }
    let expected = finish_hash(hash);
    f.measured(&["xcha", "E", "large"]);
    assert_eq!(
        reference_read(&f.path("large.xcha"), key),
        (expected.clone(), 256 * CHUNK)
    );
    fs::remove_file(f.path("large")).unwrap();
    f.measured(&["xcha", "D", "large.xcha"]);
    assert_eq!(file_digest(&f.path("large")), expected);
    fs::remove_file(f.path("large.xcha")).unwrap();
    fs::write(f.path("key.key"), [0x55, 0xaa, 0x31]).unwrap();
    f.measured(&["xor", "large", "xor-out", "--repeat-key"]);
    f.measured(&["xor", "xor-out", "xor-restored", "--repeat-key"]);
    assert_eq!(file_digest(&f.path("xor-restored")), expected);
    f.no_temps();
}
