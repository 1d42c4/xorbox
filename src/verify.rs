use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};

use anyhow::{Context, Result, ensure};
use sha3::{Digest, Sha3_512};
use zeroize::Zeroizing;

use crate::stream::{CHUNK, check_cancel};

/// Hash only bytes the writer actually accepts, including partial writes.
pub struct CheckedWriter<'a> {
    file: &'a mut File,
    hash: Sha3_512,
    count: u64,
}
impl<'a> CheckedWriter<'a> {
    pub fn new(file: &'a mut File) -> Self {
        Self {
            file,
            hash: Sha3_512::new(),
            count: 0,
        }
    }
    pub fn finish(self) -> (String, u64) {
        (hex::encode(self.hash.finalize()), self.count)
    }
}
impl Write for CheckedWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let n = self.file.write(bytes)?;
        self.hash.update(&bytes[..n]);
        self.count = self
            .count
            .checked_add(n as u64)
            .ok_or_else(|| io::Error::other("output too large"))?;
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

pub fn read_back(file: &mut File, expected: &str, expected_len: u64) -> Result<()> {
    file.sync_all().context("output synchronization failed")?;
    file.seek(SeekFrom::Start(0))?;
    let mut hash = Sha3_512::new();
    let mut buffer = Zeroizing::new(vec![0u8; CHUNK]);
    let mut count = 0u64;
    loop {
        check_cancel()?;
        let n = match file.read(&mut buffer) {
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            other => other?,
        };
        if n == 0 {
            break;
        }
        count = count
            .checked_add(n as u64)
            .context("read-back length overflow")?;
        hash.update(&buffer[..n]);
    }
    ensure!(
        count == expected_len && hex::encode(hash.finalize()) == expected,
        "output read-back verification failed"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn verifies_written_bytes_and_rejects_wrong_digest_or_length() {
        let mut f = tempfile::tempfile().unwrap();
        let mut writer = CheckedWriter::new(&mut f);
        writer.write_all(b"hello").unwrap();
        let (digest, len) = writer.finish();
        read_back(&mut f, &digest, len).unwrap();
        assert!(read_back(&mut f, &digest, len + 1).is_err());
        assert!(read_back(&mut f, &"00".repeat(64), len).is_err());
    }

    #[test]
    fn actual_corruption_truncation_and_appending_fail_read_back() {
        for operation in 0..3 {
            let mut file = tempfile::tempfile().unwrap();
            let mut writer = CheckedWriter::new(&mut file);
            writer.write_all(b"test data").unwrap();
            let (digest, count) = writer.finish();
            match operation {
                0 => {
                    file.seek(SeekFrom::Start(4)).unwrap();
                    file.write_all(b"X").unwrap();
                }
                1 => file.set_len(3).unwrap(),
                _ => {
                    file.seek(SeekFrom::End(0)).unwrap();
                    file.write_all(b"extra").unwrap();
                }
            }
            assert!(read_back(&mut file, &digest, count).is_err());
        }
    }
}
