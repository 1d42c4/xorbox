use std::ffi::OsStr;
use std::io::{Read, Write};

use anyhow::{Context, Result, ensure};
use sha3::{Digest, Sha3_512};
use zeroize::Zeroizing;

use crate::{
    cli::Command,
    files::{Root, xcha_output},
    keygen, stream,
    verify::{CheckedWriter, read_back},
};

fn private_prompt(prompt: &str) -> Result<Zeroizing<String>> {
    stream::check_cancel()?;
    let result = crate::platform::prompt_password(prompt);
    // rpassword signals Ctrl-C asynchronously. Mark Interrupted synchronously as
    // well, so a prompt cancellation reliably returns exit 130.
    if result
        .as_ref()
        .is_err_and(|e| e.kind() == std::io::ErrorKind::Interrupted)
    {
        stream::CANCELLED.store(true, std::sync::atomic::Ordering::Relaxed);
    }
    let value = result.map(Zeroizing::new);
    stream::check_cancel()?;
    Ok(value?)
}

fn password(confirm: bool) -> Result<Zeroizing<String>> {
    let value = private_prompt("Password: ")?;
    ensure!(!value.is_empty(), "password must not be empty");
    if confirm {
        let again = private_prompt("Confirm password: ")?;
        ensure!(*value == *again, "passwords do not match");
    }
    stream::check_cancel()?;
    Ok(value)
}

pub fn run(command: Command) -> Result<()> {
    if let Command::Sha3(text) = command {
        let text = match text {
            Some(value) => Zeroizing::new(value),
            None => private_prompt("Text: ")?,
        };
        stream::check_cancel()?;
        let digest = hex::encode(Sha3_512::digest(text.as_bytes()));
        let mut stdout = std::io::stdout().lock();
        writeln!(stdout, "{digest}")?;
        stdout.flush()?;
        return Ok(());
    }
    let root = Root::current()?;
    let _lock = root.lock()?;
    match command {
        Command::Xor {
            input,
            output,
            repeat,
        } => {
            xor_file(&root, &input, output.as_deref(), repeat)?;
        }
        Command::Xcha {
            encrypt,
            input,
            in_place,
        } => {
            xcha_file(&root, &input, encrypt, in_place)?;
        }
        Command::KeyMake(bytes) => {
            root.destination(OsStr::new("key.key"), false)?;
            root.destination(OsStr::new("key.meta"), false)?;
            let secret = password(true)?;
            eprintln!("Generating and verifying {bytes} key bytes...");
            keygen::make(&root, bytes, secret.as_bytes())?;
            eprintln!("Created key.key and key.meta");
        }
        Command::KeyRestore => {
            root.destination(OsStr::new("key.key"), false)?;
            root.input(OsStr::new("key.meta"), false)?;
            let secret = password(false)?;
            eprintln!("Regenerating and verifying key.key...");
            keygen::restore(&root, secret.as_bytes())?;
            eprintln!("Created key.key");
        }
        Command::XchaKey => {
            keygen::make_xcha(&root)?;
            eprintln!("Created xcha.key");
        }
        Command::Sha3(_) => unreachable!(),
    }
    Ok(())
}

pub fn xor_file(
    root: &Root,
    input_name: &OsStr,
    output_name: Option<&OsStr>,
    repeat: bool,
) -> Result<()> {
    let mut input = root.input(input_name, true)?;
    let in_place = output_name.is_none();
    let target = if let Some(name) = output_name {
        root.destination(name, true)?
    } else {
        input.prepare_in_place()?;
        input.path().to_owned()
    };
    let mut key = root.input(OsStr::new("key.key"), false)?;
    let (input_len, key_len) = (input.len(), key.len());
    ensure!(key_len > 0, "key.key is empty");
    ensure!(
        repeat || key_len >= input_len,
        "key.key is shorter than input; --repeat-key is required to repeat it"
    );
    let mut temp = root.temporary()?;
    let mut output = CheckedWriter::new(temp.as_file_mut());
    stream::xor(
        &mut input.file,
        &mut key.file,
        &mut output,
        input_len,
        key_len,
        repeat,
    )?;
    let (digest, count) = output.finish();
    ensure!(count == input_len, "unexpected XOR output length");
    read_back(temp.as_file_mut(), &digest, count)?;
    input.unchanged()?;
    key.unchanged()?;
    root.publish(temp, &target, in_place.then_some(&input))?;
    eprintln!(
        "Written {} ({count} bytes)",
        target.file_name().unwrap_or_default().to_string_lossy()
    );
    Ok(())
}

pub fn xcha_file(root: &Root, input_name: &OsStr, encrypt: bool, in_place: bool) -> Result<()> {
    let mut input = root.input(input_name, true)?;
    let target = if in_place {
        input.prepare_in_place()?;
        input.path().to_owned()
    } else {
        root.destination(&xcha_output(input_name, encrypt)?, true)?
    };
    let mut key_input = root.input(OsStr::new("xcha.key"), false)?;
    ensure!(
        key_input.len() == 32,
        "xcha.key must contain exactly 32 raw bytes"
    );
    let mut key = Zeroizing::new([0u8; 32]);
    key_input.file.read_exact(&mut *key)?;
    stream::require_eof(&mut key_input.file)?;
    let mut temp = root.temporary()?;
    let mut output = CheckedWriter::new(temp.as_file_mut());
    if encrypt {
        stream::encrypt(&mut input.file, &mut output, &key)?;
    } else {
        stream::decrypt(&mut input.file, &mut output, &key)?;
    }
    let (digest, count) = output.finish();
    read_back(temp.as_file_mut(), &digest, count)?;
    input.unchanged()?;
    key_input.unchanged()?;
    root.publish(temp, &target, in_place.then_some(&input))
        .context("XChaCha output publication")?;
    eprintln!(
        "Written {} ({count} bytes)",
        target.file_name().unwrap_or_default().to_string_lossy()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn in_place_both_layers_and_restore() {
        let dir = tempfile::tempdir().unwrap();
        let root = Root::for_test(dir.path());
        fs::write(dir.path().join("key.key"), vec![0xa5; 8193]).unwrap();
        fs::write(dir.path().join("xcha.key"), [7; 32]).unwrap();
        let original: Vec<u8> = (0..8193).map(|i| i as u8).collect();
        fs::write(dir.path().join("data"), &original).unwrap();
        xor_file(&root, OsStr::new("data"), None, false).unwrap();
        let middle = fs::read(dir.path().join("data")).unwrap();
        assert!(middle != original, "XOR did not replace the original bytes");
        xcha_file(&root, OsStr::new("data"), true, true).unwrap();
        assert_ne!(fs::read(dir.path().join("data")).unwrap(), middle);
        xcha_file(&root, OsStr::new("data"), false, true).unwrap();
        assert_eq!(fs::read(dir.path().join("data")).unwrap(), middle);
        xor_file(&root, OsStr::new("data"), None, false).unwrap();
        assert_eq!(fs::read(dir.path().join("data")).unwrap(), original);
    }

    #[test]
    fn authentication_failure_keeps_original_and_publishes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let root = Root::for_test(dir.path());
        fs::write(dir.path().join("xcha.key"), [7; 32]).unwrap();
        fs::write(dir.path().join("data"), vec![9; stream::CHUNK + 1]).unwrap();
        xcha_file(&root, OsStr::new("data"), true, true).unwrap();
        let cipher = fs::read(dir.path().join("data")).unwrap();
        fs::write(dir.path().join("xcha.key"), [8; 32]).unwrap();
        assert!(xcha_file(&root, OsStr::new("data"), false, true).is_err());
        assert_eq!(fs::read(dir.path().join("data")).unwrap(), cipher);
        fs::write(dir.path().join("xcha.key"), [7; 32]).unwrap();
        let truncated = &cipher[..cipher.len() - 1];
        fs::write(dir.path().join("bad.xcha"), truncated).unwrap();
        assert!(xcha_file(&root, OsStr::new("bad.xcha"), false, false).is_err());
        assert!(!dir.path().join("bad").exists());
        assert!(!fs::read_dir(dir.path()).unwrap().any(|f| {
            f.unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".xorbox-")
        }));
    }

    #[test]
    fn short_key_and_existing_output_never_change_inputs() {
        let dir = tempfile::tempdir().unwrap();
        let root = Root::for_test(dir.path());
        fs::write(dir.path().join("key.key"), [1]).unwrap();
        fs::write(dir.path().join("data"), b"original").unwrap();
        assert!(xor_file(&root, OsStr::new("data"), None, false).is_err());
        assert_eq!(fs::read(dir.path().join("data")).unwrap(), b"original");
        assert!(xor_file(&root, OsStr::new("data"), Some(OsStr::new("data")), true).is_err());
        assert_eq!(fs::read(dir.path().join("data")).unwrap(), b"original");
    }
}
