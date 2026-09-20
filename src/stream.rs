use std::io::{self, Read, Seek, SeekFrom, Write};
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::{Context, Result, ensure};
use dryoc::dryocstream::{DryocStream, Tag};
use zeroize::Zeroizing;

pub const CHUNK: usize = 1024 * 1024;
pub static CANCELLED: AtomicBool = AtomicBool::new(false);
const MAGIC: &[u8; 8] = b"XORBOX\0\x01";
const HEADER_SIZE: usize = 8 + 4 + 24;
const TAG_BYTES: usize = 17;

pub fn check_cancel() -> Result<()> {
    ensure!(
        !CANCELLED.load(Ordering::Relaxed),
        "cancelled before publication"
    );
    Ok(())
}

/// Fill a buffer until it is full or reaches EOF. Short reads are not EOF.
pub fn fill<R: Read>(reader: &mut R, out: &mut [u8]) -> io::Result<usize> {
    let mut n = 0;
    while n < out.len() {
        match reader.read(&mut out[n..]) {
            Ok(0) => break,
            Ok(count) => n += count,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(n)
}

pub fn require_eof<R: Read>(reader: &mut R) -> Result<()> {
    ensure!(
        fill(reader, &mut [0u8; 1])? == 0,
        "unexpected trailing data or file growth"
    );
    Ok(())
}

pub fn xor<R: Read, K: Read + Seek, W: Write>(
    input: &mut R,
    key: &mut K,
    output: &mut W,
    input_len: u64,
    key_len: u64,
    repeat: bool,
) -> Result<()> {
    ensure!(key_len > 0, "key.key is empty");
    ensure!(
        repeat || key_len >= input_len,
        "key.key is shorter than the input; --repeat-key is required to repeat it"
    );
    let mut data = Zeroizing::new(vec![0u8; CHUNK]);
    let mut pad = Zeroizing::new(vec![0u8; CHUNK]);
    let cached = if repeat && key_len <= CHUNK as u64 {
        let mut bytes = Zeroizing::new(vec![0u8; key_len as usize]);
        key.read_exact(&mut bytes).context("key ended early")?;
        Some(bytes)
    } else {
        None
    };
    let (mut remaining, mut key_pos) = (input_len, 0u64);
    while remaining > 0 {
        check_cancel()?;
        let n = remaining.min(CHUNK as u64) as usize;
        input
            .read_exact(&mut data[..n])
            .context("input ended early")?;
        let mut done = 0;
        while done < n {
            if key_pos == key_len {
                ensure!(repeat, "key ended early");
                if cached.is_none() {
                    key.seek(SeekFrom::Start(0))?;
                }
                key_pos = 0;
            }
            let take = (n - done).min((key_len - key_pos).min(CHUNK as u64) as usize);
            if let Some(bytes) = &cached {
                pad[done..done + take]
                    .copy_from_slice(&bytes[key_pos as usize..key_pos as usize + take]);
            } else {
                key.read_exact(&mut pad[done..done + take])
                    .context("key ended early")?;
            }
            key_pos += take as u64;
            done += take;
        }
        for (b, k) in data[..n].iter_mut().zip(&pad[..n]) {
            *b ^= *k;
        }
        output.write_all(&data[..n])?;
        remaining -= n as u64;
    }
    require_eof(input)?;
    check_cancel()
}

/// Version 1: 36-byte authenticated header; length-prefixed secretstream messages;
/// a mandatory empty FINAL message. All integers are little endian.
pub fn encrypt<R: Read, W: Write>(input: &mut R, output: &mut W, key: &[u8; 32]) -> Result<()> {
    let (mut state, stream_header): (_, [u8; 24]) = DryocStream::init_push(key);
    let mut header = [0u8; HEADER_SIZE];
    header[..8].copy_from_slice(MAGIC);
    header[8..12].copy_from_slice(&(CHUNK as u32).to_le_bytes());
    header[12..].copy_from_slice(&stream_header);
    output.write_all(&header)?;
    let mut data = Zeroizing::new(vec![0u8; CHUNK]);
    loop {
        check_cancel()?;
        let n = fill(input, &mut data)?;
        let tag = if n == 0 { Tag::FINAL } else { Tag::MESSAGE };
        let message: &[u8] = &data[..n];
        let encrypted = state.push_to_vec(&message, Some(&header.as_slice()), tag)?;
        output.write_all(&(encrypted.len() as u32).to_le_bytes())?;
        output.write_all(&encrypted)?;
        if n == 0 {
            break;
        }
    }
    check_cancel()
}

pub fn decrypt<R: Read, W: Write>(input: &mut R, output: &mut W, key: &[u8; 32]) -> Result<()> {
    let mut header = [0u8; HEADER_SIZE];
    input
        .read_exact(&mut header)
        .context("truncated XChaCha header")?;
    ensure!(&header[..8] == MAGIC, "not a supported xorbox XChaCha file");
    ensure!(
        header[8..12] == (CHUNK as u32).to_le_bytes(),
        "unsupported chunk size"
    );
    let stream_header: [u8; 24] = header[12..].try_into()?;
    let mut state = DryocStream::init_pull(key, &stream_header);
    let mut cipher = vec![0u8; CHUNK + TAG_BYTES];
    let mut saw_short = false;
    loop {
        check_cancel()?;
        let mut length = [0u8; 4];
        input
            .read_exact(&mut length)
            .context("missing authenticated ending or truncated record")?;
        let n = u32::from_le_bytes(length) as usize;
        ensure!(
            (TAG_BYTES..=CHUNK + TAG_BYTES).contains(&n),
            "invalid record length"
        );
        input
            .read_exact(&mut cipher[..n])
            .context("truncated encrypted record")?;
        let ciphertext: &[u8] = &cipher[..n];
        let (plain, tag) = state
            .pull_to_vec(&ciphertext, Some(&header.as_slice()))
            .context("authentication failed: wrong xcha.key or damaged ciphertext")?;
        let plain = Zeroizing::new(plain);
        if tag == Tag::FINAL {
            ensure!(plain.is_empty(), "invalid final record");
            require_eof(input)?;
            break;
        }
        ensure!(
            tag == Tag::MESSAGE && !plain.is_empty() && !saw_short,
            "invalid stream sequence"
        );
        saw_short = plain.len() < CHUNK;
        output.write_all(&plain)?;
    }
    check_cancel()
}

#[cfg(test)]
#[path = "stream_tests.rs"]
mod regression_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    struct Short<R>(R);
    impl<R: Read> Read for Short<R> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let n = buf.len().min(13);
            self.0.read(&mut buf[..n])
        }
    }
    struct FailingWriter;
    impl Write for FailingWriter {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::Error::other("disk full"))
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn xor_known_bytes_and_wrapping_cross_chunk_boundaries() {
        let plain: Vec<u8> = (0..CHUNK + 19).map(|n| n as u8).collect();
        let key = vec![0x12, 0x45, 0xa2, 0xff, 0x77, 0, 9];
        let expected: Vec<u8> = plain
            .iter()
            .enumerate()
            .map(|(i, b)| b ^ key[i % key.len()])
            .collect();
        let mut out = Vec::new();
        xor(
            &mut Short(Cursor::new(&plain)),
            &mut Cursor::new(&key),
            &mut out,
            plain.len() as u64,
            key.len() as u64,
            true,
        )
        .unwrap();
        assert_eq!(out, expected);
        assert!(
            xor(
                &mut Cursor::new(&plain),
                &mut Cursor::new(&key),
                &mut Vec::new(),
                plain.len() as u64,
                key.len() as u64,
                false
            )
            .is_err()
        );
    }

    #[test]
    fn exact_key_short_reads_and_io_failures() {
        let p = [0x00, 0xff, 0x55];
        let k = [0xaa, 0x12, 0x0f];
        let mut out = Vec::new();
        xor(
            &mut Cursor::new(p),
            &mut Cursor::new(k),
            &mut out,
            3,
            3,
            false,
        )
        .unwrap();
        assert_eq!(out, [0xaa, 0xed, 0x5a]);
        assert!(
            xor(
                &mut Cursor::new(p),
                &mut Cursor::new(k),
                &mut FailingWriter,
                3,
                3,
                false
            )
            .is_err()
        );
        assert!(
            xor(
                &mut Cursor::new(p),
                &mut Cursor::new(k),
                &mut Vec::new(),
                4,
                4,
                false
            )
            .is_err()
        );
        assert!(
            xor(
                &mut Cursor::new(p),
                &mut Cursor::new(k),
                &mut Vec::new(),
                2,
                3,
                false
            )
            .is_err()
        );
        assert!(
            xor(
                &mut Cursor::new([]),
                &mut Cursor::new([]),
                &mut Vec::new(),
                0,
                0,
                true
            )
            .is_err()
        );
    }

    #[test]
    fn xcha_boundaries_and_randomized_ciphertext() {
        for len in [0, 1, 63, CHUNK - 1, CHUNK, CHUNK + 1, 2 * CHUNK + 31] {
            let plain: Vec<u8> = (0..len).map(|i| (i * 17) as u8).collect();
            let mut cipher = Vec::new();
            encrypt(&mut Short(Cursor::new(&plain)), &mut cipher, &[23; 32]).unwrap();
            let mut result = Vec::new();
            decrypt(&mut Short(Cursor::new(&cipher)), &mut result, &[23; 32]).unwrap();
            assert_eq!(plain, result);
            let mut again = Vec::new();
            encrypt(&mut Cursor::new(&plain), &mut again, &[23; 32]).unwrap();
            assert_ne!(cipher, again);
        }
    }

    #[test]
    fn rejects_wrong_key_corruption_truncation_appending_and_record_reordering() {
        let mut cipher = Vec::new();
        encrypt(
            &mut Cursor::new(vec![42u8; CHUNK * 2]),
            &mut cipher,
            &[23; 32],
        )
        .unwrap();
        assert!(decrypt(&mut Cursor::new(&cipher), &mut Vec::new(), &[24; 32]).is_err());
        for cut in [
            0,
            7,
            HEADER_SIZE - 1,
            HEADER_SIZE,
            HEADER_SIZE + 4,
            cipher.len() - 1,
            cipher.len() - 21,
        ] {
            assert!(decrypt(&mut Cursor::new(&cipher[..cut]), &mut Vec::new(), &[23; 32]).is_err());
        }
        for pos in [0, 8, 12, 35, 36, 40, 51, cipher.len() - 1] {
            let mut bad = cipher.clone();
            bad[pos] ^= 1;
            assert!(decrypt(&mut Cursor::new(bad), &mut Vec::new(), &[23; 32]).is_err());
        }
        let mut bad = cipher.clone();
        bad.push(0);
        assert!(decrypt(&mut Cursor::new(bad), &mut Vec::new(), &[23; 32]).is_err());
        let record = 4 + CHUNK + TAG_BYTES;
        let mut bad = cipher.clone();
        let (a, rest) = bad[HEADER_SIZE..].split_at_mut(record);
        a.swap_with_slice(&mut rest[..record]);
        assert!(decrypt(&mut Cursor::new(bad), &mut Vec::new(), &[23; 32]).is_err());
        assert!(encrypt(&mut Cursor::new([1]), &mut FailingWriter, &[23; 32]).is_err());
    }
}
