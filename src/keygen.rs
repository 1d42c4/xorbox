use std::ffi::OsStr;
use std::io::{Read, Write};

use anyhow::{Context, Result, ensure};
use argon2::{Algorithm, Argon2, Block, Params, Version};
use chacha20::cipher::{KeyIvInit, StreamCipher};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_512};
use zeroize::Zeroizing;

use crate::cli::MAX_KEY_BYTES;
use crate::files::Root;
use crate::stream::{CHUNK, check_cancel};

const MEMORY_KIB: u32 = 65_536;
const PASSES: u32 = 3;
const LANES: u32 = 4;

#[derive(Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct KeyMeta {
    format: String,
    version: u32,
    bytes: u64,
    kdf: String,
    memory_kib: u32,
    passes: u32,
    lanes: u32,
    salt_hex: String,
    generator: String,
    nonce_hex: String,
    key_sha3_512: String,
}

fn random<const N: usize>() -> Result<[u8; N]> {
    let mut out = [0u8; N];
    getrandom::fill(&mut out).context("operating system randomness unavailable")?;
    Ok(out)
}

impl KeyMeta {
    fn new(bytes: u64) -> Result<Self> {
        ensure!((1..=MAX_KEY_BYTES).contains(&bytes), "invalid key size");
        Ok(Self {
            format: "xorbox-key".into(),
            version: 1,
            bytes,
            kdf: "argon2id-v19".into(),
            memory_kib: MEMORY_KIB,
            passes: PASSES,
            lanes: LANES,
            salt_hex: hex::encode(random::<16>()?),
            generator: "chacha20-ietf-counter0".into(),
            nonce_hex: hex::encode(random::<12>()?),
            key_sha3_512: String::new(),
        })
    }
    fn validate(&self) -> Result<()> {
        ensure!(
            self.format == "xorbox-key" && self.version == 1,
            "unsupported key.meta format/version"
        );
        ensure!(
            (1..=MAX_KEY_BYTES).contains(&self.bytes),
            "invalid size in key.meta"
        );
        // Pin parameters by format version; metadata cannot request arbitrary RAM,
        // downgrade the KDF, or silently change an existing regeneration recipe.
        ensure!(
            self.kdf == "argon2id-v19"
                && self.memory_kib == MEMORY_KIB
                && self.passes == PASSES
                && self.lanes == LANES,
            "unsupported Argon2 settings"
        );
        ensure!(
            self.generator == "chacha20-ietf-counter0",
            "unsupported key generator"
        );
        decode::<16>(&self.salt_hex)?;
        decode::<12>(&self.nonce_hex)?;
        decode::<64>(&self.key_sha3_512)?;
        Ok(())
    }
}

fn decode<const N: usize>(value: &str) -> Result<[u8; N]> {
    ensure!(value.len() == N * 2, "invalid metadata hex length");
    let mut bytes = [0u8; N];
    hex::decode_to_slice(value, &mut bytes).context("invalid hexadecimal metadata")?;
    Ok(bytes)
}

fn derive(password: &[u8], meta: &KeyMeta) -> Result<Zeroizing<[u8; 32]>> {
    ensure!(!password.is_empty(), "password must not be empty");
    check_cancel()?;
    let salt = decode::<16>(&meta.salt_hex)?;
    let params = Params::new(MEMORY_KIB, PASSES, LANES, Some(32))
        .map_err(|e| anyhow::anyhow!("Argon2 parameters: {e}"))?;
    let count = params.block_count();
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut memory = Zeroizing::new(vec![Block::default(); count]);
    let mut seed = Zeroizing::new([0u8; 32]);
    argon
        .hash_password_into_with_memory(password, &salt, &mut *seed, &mut *memory)
        .map_err(|e| anyhow::anyhow!("password derivation failed: {e}"))?;
    check_cancel()?;
    Ok(seed)
}

fn expand<W: Write>(
    seed: &[u8; 32],
    nonce: &[u8; 12],
    bytes: u64,
    output: &mut W,
) -> Result<String> {
    ensure!((1..=MAX_KEY_BYTES).contains(&bytes), "invalid key size");
    let mut cipher = chacha20::ChaCha20::new(seed.into(), nonce.into());
    let mut buffer = Zeroizing::new(vec![0u8; CHUNK]);
    let mut hash = Sha3_512::new();
    let mut remaining = bytes;
    while remaining > 0 {
        check_cancel()?;
        let n = remaining.min(CHUNK as u64) as usize;
        buffer[..n].fill(0);
        cipher
            .try_apply_keystream(&mut buffer[..n])
            .map_err(|_| anyhow::anyhow!("key generator counter exhausted"))?;
        output.write_all(&buffer[..n])?;
        hash.update(&buffer[..n]);
        remaining -= n as u64;
    }
    check_cancel()?;
    Ok(hex::encode(hash.finalize()))
}

pub fn make(root: &Root, bytes: u64, password: &[u8]) -> Result<()> {
    let key_path = root.destination(OsStr::new("key.key"), false)?;
    let meta_path = root.destination(OsStr::new("key.meta"), false)?;
    let mut meta = KeyMeta::new(bytes)?;
    let seed = derive(password, &meta)?;
    let mut key_temp = root.temporary()?;
    meta.key_sha3_512 = expand(&seed, &decode::<12>(&meta.nonce_hex)?, bytes, &mut key_temp)?;
    crate::verify::read_back(key_temp.as_file_mut(), &meta.key_sha3_512, bytes)?;
    let mut meta_temp = root.temporary()?;
    let mut checked = crate::verify::CheckedWriter::new(meta_temp.as_file_mut());
    serde_json::to_writer_pretty(&mut checked, &meta)?;
    checked.write_all(b"\n")?;
    let (digest, length) = checked.finish();
    crate::verify::read_back(meta_temp.as_file_mut(), &digest, length)?;
    // Two filenames cannot be committed atomically together. Durable metadata goes
    // first, so interruption before key publication still permits keyrestore.
    root.publish(meta_temp, &meta_path, None)?;
    root.publish(key_temp, &key_path, None)
        .context("key.meta was saved; if key.key is absent, use keyrestore with the same password")
}

pub fn restore(root: &Root, password: &[u8]) -> Result<()> {
    let key_path = root.destination(OsStr::new("key.key"), false)?;
    let mut input = root.input(OsStr::new("key.meta"), false)?;
    ensure!(input.len() <= 16_384, "key.meta is too large");
    let mut json = String::new();
    Read::by_ref(&mut input.file)
        .take(16_385)
        .read_to_string(&mut json)?;
    ensure!(json.len() <= 16_384, "key.meta is too large");
    let meta: KeyMeta = serde_json::from_str(&json).context("invalid key.meta")?;
    meta.validate()?;
    let seed = derive(password, &meta)?;
    let mut temp = root.temporary()?;
    let digest = expand(
        &seed,
        &decode::<12>(&meta.nonce_hex)?,
        meta.bytes,
        &mut temp,
    )?;
    ensure!(
        digest == meta.key_sha3_512.to_ascii_lowercase(),
        "wrong password or damaged key.meta; no key published"
    );
    crate::verify::read_back(temp.as_file_mut(), &digest, meta.bytes)?;
    input.unchanged()?;
    root.publish(temp, &key_path, None)
}

pub fn make_xcha(root: &Root) -> Result<()> {
    let destination = root.destination(OsStr::new("xcha.key"), false)?;
    let key = Zeroizing::new(random::<32>()?);
    let mut temp = root.temporary()?;
    temp.write_all(&*key)?;
    let digest = hex::encode(Sha3_512::digest(key.as_slice()));
    crate::verify::read_back(temp.as_file_mut(), &digest, 32)?;
    root.publish(temp, &destination, None)
}

#[cfg(test)]
#[path = "keygen_tests.rs"]
mod regression_tests;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc8439_chacha20_block_vector() {
        use chacha20::cipher::StreamCipherSeek;
        let key: [u8; 32] = std::array::from_fn(|i| i as u8);
        let nonce = decode::<12>("000000090000004a00000000").unwrap();
        let mut cipher = chacha20::ChaCha20::new((&key).into(), (&nonce).into());
        cipher.seek(64u64);
        let mut output = [0u8; 64];
        cipher.apply_keystream(&mut output);
        assert_eq!(
            hex::encode(output),
            concat!(
                "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e",
                "d2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e"
            )
        );
    }

    #[test]
    fn expanding_stream_does_not_restart_at_chunks() {
        let seed = [7u8; 32];
        let nonce = [4u8; 12];
        let mut out = Vec::new();
        expand(&seed, &nonce, (CHUNK * 2 + 13) as u64, &mut out).unwrap();
        let mut expected = vec![0; out.len()];
        chacha20::ChaCha20::new((&seed).into(), (&nonce).into()).apply_keystream(&mut expected);
        assert_eq!(out, expected);
        assert_ne!(&out[..64], &out[CHUNK..CHUNK + 64]);
        // Exercise a byte offset beyond the promised maximum without a 20 GB allocation.
        use chacha20::cipher::StreamCipherSeek;
        let mut cipher = chacha20::ChaCha20::new((&seed).into(), (&nonce).into());
        cipher.try_seek(MAX_KEY_BYTES - 64).unwrap();
        let mut tail = [0u8; 64];
        cipher.try_apply_keystream(&mut tail).unwrap();
        assert_ne!(&out[..64], &tail);
    }

    #[test]
    fn restores_identical_key_and_rejects_wrong_password_and_overwrite() {
        let dir = tempfile::tempdir().unwrap();
        let root = Root::for_test(dir.path());
        make(&root, 129, b"test passphrase only").unwrap();
        let original = std::fs::read(dir.path().join("key.key")).unwrap();
        assert_eq!(original.len(), 129);
        assert!(make(&root, 129, b"another").is_err());
        assert!(restore(&root, b"test passphrase only").is_err());
        std::fs::remove_file(dir.path().join("key.key")).unwrap();
        assert!(restore(&root, b"wrong password").is_err());
        assert!(!dir.path().join("key.key").exists());
        restore(&root, b"test passphrase only").unwrap();
        assert_eq!(original, std::fs::read(dir.path().join("key.key")).unwrap());
    }

    #[test]
    fn metadata_rejects_cost_tampering_and_unsupported_versions() {
        let mut meta = KeyMeta::new(1).unwrap();
        meta.key_sha3_512 = "00".repeat(64);
        meta.validate().unwrap();
        meta.memory_kib = u32::MAX;
        assert!(meta.validate().is_err());
        meta.memory_kib = MEMORY_KIB;
        meta.version = 2;
        assert!(meta.validate().is_err());
    }
}
