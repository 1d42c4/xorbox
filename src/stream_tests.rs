use super::*;
use std::io::Cursor;

fn encrypted(plain: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    encrypt(&mut Cursor::new(plain), &mut out, &[19; 32]).unwrap();
    out
}

fn rejects(cipher: &[u8]) {
    assert!(decrypt(&mut Cursor::new(cipher), &mut Vec::new(), &[19; 32]).is_err());
}

#[test]
fn every_single_bit_change_in_small_container_is_rejected() {
    let valid = encrypted(b"small authenticated payload");
    for offset in 0..valid.len() {
        for bit in 0..8 {
            let mut changed = valid.clone();
            changed[offset] ^= 1 << bit;
            rejects(&changed);
        }
    }
}

#[test]
fn every_truncation_of_small_container_is_rejected() {
    let valid = encrypted(b"small authenticated payload");
    for end in 0..valid.len() {
        rejects(&valid[..end]);
    }
}

#[test]
fn oversized_and_undersized_record_lengths_are_rejected() {
    let valid = encrypted(b"payload");
    for length in [0, 1, 16, (CHUNK + TAG_BYTES + 1) as u32, u32::MAX] {
        let mut bad = valid.clone();
        bad[HEADER_SIZE..HEADER_SIZE + 4].copy_from_slice(&length.to_le_bytes());
        rejects(&bad);
    }
}

#[test]
fn duplicated_removed_and_cross_file_spliced_records_are_rejected() {
    let a = encrypted(&vec![11; CHUNK * 2]);
    let b = encrypted(&vec![22; CHUNK * 2]);
    let start = HEADER_SIZE;
    let record = 4 + CHUNK + TAG_BYTES;
    let mut duplicated = a.clone();
    duplicated.splice(start..start, a[start..start + record].iter().copied());
    rejects(&duplicated);
    let mut removed = a.clone();
    removed.drain(start..start + record);
    rejects(&removed);
    let mut spliced = a.clone();
    spliced[start + record..start + 2 * record]
        .copy_from_slice(&b[start + record..start + 2 * record]);
    rejects(&spliced);
    let mut appended = a.clone();
    appended.extend_from_slice(&b);
    rejects(&appended);
}

// Valid authentication does not excuse a sequence that violates our file format.
fn authenticated_records(records: &[(&[u8], Tag)]) -> Vec<u8> {
    let (mut state, stream_header): (_, [u8; 24]) = DryocStream::init_push(&[19; 32]);
    let mut header = Vec::from(MAGIC.as_slice());
    header.extend_from_slice(&(CHUNK as u32).to_le_bytes());
    header.extend_from_slice(&stream_header);
    let mut result = header.clone();
    for (plain, tag) in records {
        let record = state
            .push_to_vec(plain, Some(&header.as_slice()), *tag)
            .unwrap();
        result.extend_from_slice(&(record.len() as u32).to_le_bytes());
        result.extend_from_slice(&record);
    }
    result
}

#[test]
fn authenticated_but_invalid_record_sequences_are_rejected() {
    for records in [
        vec![(b"".as_slice(), Tag::MESSAGE), (b"", Tag::FINAL)],
        vec![(b"data".as_slice(), Tag::FINAL)],
        vec![
            (b"a".as_slice(), Tag::MESSAGE),
            (b"b", Tag::MESSAGE),
            (b"", Tag::FINAL),
        ],
        vec![(b"data".as_slice(), Tag::PUSH), (b"", Tag::FINAL)],
        vec![(b"data".as_slice(), Tag::REKEY), (b"", Tag::FINAL)],
    ] {
        rejects(&authenticated_records(&records));
    }
}

struct InterruptedShort<R> {
    inner: R,
    interrupt: bool,
}
impl<R: Read> Read for InterruptedShort<R> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.interrupt = !self.interrupt;
        if self.interrupt {
            return Err(io::ErrorKind::Interrupted.into());
        }
        let n = bytes.len().min(31);
        self.inner.read(&mut bytes[..n])
    }
}

struct ShortWriter {
    bytes: Vec<u8>,
    calls: usize,
}
impl Write for ShortWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.calls += 1;
        if self.calls.is_multiple_of(3) {
            return Err(io::ErrorKind::Interrupted.into());
        }
        let n = bytes.len().min(17);
        self.bytes.extend_from_slice(&bytes[..n]);
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn interrupted_short_reads_and_partial_writes_preserve_data() {
    let plain = vec![37; CHUNK + 31];
    let mut source = InterruptedShort {
        inner: Cursor::new(&plain),
        interrupt: false,
    };
    let mut writer = ShortWriter {
        bytes: Vec::new(),
        calls: 0,
    };
    encrypt(&mut source, &mut writer, &[19; 32]).unwrap();
    let mut reader = InterruptedShort {
        inner: Cursor::new(writer.bytes),
        interrupt: false,
    };
    let mut recovered = ShortWriter {
        bytes: Vec::new(),
        calls: 0,
    };
    decrypt(&mut reader, &mut recovered, &[19; 32]).unwrap();
    assert_eq!(plain, recovered.bytes);
}

struct StopsWriting {
    remaining: usize,
}
impl Write for StopsWriting {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let n = bytes.len().min(self.remaining);
        self.remaining -= n;
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn write_zero_mid_stream_is_an_error_for_both_ciphers() {
    let data = vec![37; CHUNK + 31];
    assert!(
        encrypt(
            &mut Cursor::new(&data),
            &mut StopsWriting { remaining: 100 },
            &[19; 32]
        )
        .is_err()
    );
    assert!(
        decrypt(
            &mut Cursor::new(encrypted(&data)),
            &mut StopsWriting { remaining: 100 },
            &[19; 32]
        )
        .is_err()
    );
    assert!(
        xor(
            &mut Cursor::new(&data),
            &mut Cursor::new([9]),
            &mut StopsWriting { remaining: 100 },
            data.len() as u64,
            1,
            true
        )
        .is_err()
    );
}

#[test]
fn xor_cached_and_streamed_key_boundaries_match_independent_oracle() {
    for key_len in [1, 7, CHUNK - 1, CHUNK, CHUNK + 1, CHUNK + 13] {
        let plain: Vec<_> = (0..CHUNK * 2 + 37).map(|i| (i * 31) as u8).collect();
        let key: Vec<_> = (0..key_len).map(|i| (i * 17 + i / 255) as u8).collect();
        let expected: Vec<_> = plain
            .iter()
            .enumerate()
            .map(|(i, b)| b ^ key[i % key_len])
            .collect();
        let mut out = Vec::new();
        xor(
            &mut Cursor::new(&plain),
            &mut Cursor::new(&key),
            &mut out,
            plain.len() as u64,
            key_len as u64,
            true,
        )
        .unwrap();
        assert_eq!(out, expected, "key length {key_len}");
    }
}

#[test]
fn xor_longer_key_and_empty_input_do_not_change_the_key() {
    for plain in [b"".as_slice(), b"abc"] {
        let key = b"0123456789";
        let mut out = Vec::new();
        let mut reader = Cursor::new(key);
        xor(
            &mut Cursor::new(plain),
            &mut reader,
            &mut out,
            plain.len() as u64,
            key.len() as u64,
            false,
        )
        .unwrap();
        assert_eq!(
            out,
            plain
                .iter()
                .zip(key)
                .map(|(a, b)| a ^ b)
                .collect::<Vec<_>>()
        );
        assert_eq!(reader.position(), plain.len() as u64);
    }
}

#[test]
fn read_error_after_valid_cipher_record_is_propagated() {
    struct BrokenAfter(Cursor<Vec<u8>>);
    impl Read for BrokenAfter {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let n = self.0.read(buf)?;
            if n == 0 {
                Err(io::Error::other("device read failure"))
            } else {
                Ok(n)
            }
        }
    }
    let valid = encrypted(b"payload");
    assert!(
        decrypt(
            &mut BrokenAfter(Cursor::new(valid)),
            &mut Vec::new(),
            &[19; 32]
        )
        .is_err()
    );
    assert!(
        encrypt(
            &mut BrokenAfter(Cursor::new(vec![0; CHUNK])),
            &mut Vec::new(),
            &[19; 32]
        )
        .is_err()
    );
}
