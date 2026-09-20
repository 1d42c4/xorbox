//! Separate implementations from the application's Argon2, ChaCha20 and SHA3.
pub fn expected_key(password: &[u8], meta: &serde_json::Value) -> Vec<u8> {
    let config = argon2_reference::Config {
        hash_length: 32,
        lanes: 4,
        mem_cost: 65_536,
        time_cost: 3,
        variant: argon2_reference::Variant::Argon2id,
        version: argon2_reference::Version::Version13,
        ..Default::default()
    };
    assert_eq!(meta["memory_kib"], 65_536);
    assert_eq!(meta["passes"], 3);
    assert_eq!(meta["lanes"], 4);
    let salt = hex::decode(meta["salt_hex"].as_str().unwrap()).unwrap();
    let seed: [u8; 32] = argon2_reference::hash_raw(password, &salt, &config)
        .unwrap()
        .try_into()
        .unwrap();
    let nonce: [u8; 12] = hex::decode(meta["nonce_hex"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    use orion::hazardous::stream::chacha20::{ChaCha20, Nonce, SecretKey};
    let mut stream = ChaCha20::new(&SecretKey::from(seed), &Nonce::from(nonce));
    stream.set_position(0);
    let length = meta["bytes"].as_u64().unwrap() as usize;
    assert!(
        length <= 2 * 1024 * 1024,
        "reference fixtures must remain small"
    );
    let mut expected = vec![0; length];
    stream.xor_keystream_into(&mut expected).unwrap();
    use tiny_keccak::{Hasher, Sha3};
    let mut hash = Sha3::v512();
    hash.update(&expected);
    let mut digest = [0; 64];
    hash.finalize(&mut digest);
    assert_eq!(hex::encode(digest), meta["key_sha3_512"]);
    expected
}
