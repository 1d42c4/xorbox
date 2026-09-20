use std::ffi::OsString;

use anyhow::{Result, bail, ensure};

pub const MAX_KEY_BYTES: u64 = 20_000_000_000;

#[derive(Debug, PartialEq, Eq)]
pub enum Command {
    Xor {
        input: OsString,
        output: Option<OsString>,
        repeat: bool,
    },
    KeyMake(u64),
    KeyRestore,
    Sha3(Option<String>),
    XchaKey,
    Xcha {
        encrypt: bool,
        input: OsString,
        in_place: bool,
    },
}

pub fn parse(args: Vec<OsString>) -> Result<Command> {
    let Some(command) = args.first().and_then(|v| v.to_str()) else {
        bail!("expected a command: xor, keymake, keyrestore, sha3, or xcha");
    };
    let tail = &args[1..];
    match command {
        "xor" => {
            let mut names = Vec::new();
            let (mut in_place, mut repeat) = (false, false);
            for arg in tail {
                if arg == "--in-place" {
                    ensure!(!in_place, "duplicate --in-place");
                    in_place = true;
                } else if arg == "--repeat-key" {
                    ensure!(!repeat, "duplicate --repeat-key");
                    repeat = true;
                } else {
                    ensure!(!arg.to_string_lossy().starts_with('-'), "unknown option");
                    names.push(arg.clone());
                }
            }
            ensure!(
                names.len() == if in_place { 1 } else { 2 },
                "expected xor INPUT OUTPUT, or xor INPUT --in-place; optional --repeat-key"
            );
            let input = names.remove(0);
            Ok(Command::Xor {
                input,
                output: names.pop(),
                repeat,
            })
        }
        "keymake" => {
            ensure!(tail.len() == 1, "expected keymake BYTES");
            let size = tail[0].to_str().unwrap_or("");
            ensure!(
                !size.is_empty() && size.bytes().all(|b| b.is_ascii_digit()),
                "size must contain decimal digits only"
            );
            let size: u64 = size
                .parse()
                .map_err(|_| anyhow::anyhow!("size is too large"))?;
            ensure!(
                (1..=MAX_KEY_BYTES).contains(&size),
                "size must be 1..={MAX_KEY_BYTES} bytes"
            );
            Ok(Command::KeyMake(size))
        }
        "keyrestore" => {
            ensure!(tail.is_empty(), "keyrestore takes no arguments");
            Ok(Command::KeyRestore)
        }
        "sha3" => {
            ensure!(
                tail.len() <= 1,
                "expected sha3 TEXT, or sha3 for a private prompt"
            );
            let text = tail
                .first()
                .map(|s| {
                    s.clone()
                        .into_string()
                        .map_err(|_| anyhow::anyhow!("sha3 text must be valid Unicode"))
                })
                .transpose()?;
            Ok(Command::Sha3(text))
        }
        "xcha" => {
            if tail.len() == 1 && tail[0] == "K" {
                return Ok(Command::XchaKey);
            }
            ensure!(
                tail.len() == 2 || tail.len() == 3,
                "expected xcha K, xcha E FILE, or xcha D FILE; optional --in-place"
            );
            ensure!(
                tail[0] == "E" || tail[0] == "D",
                "xcha operation must be K, E, or D"
            );
            let in_place = tail.len() == 3;
            ensure!(!in_place || tail[2] == "--in-place", "unknown xcha option");
            Ok(Command::Xcha {
                encrypt: tail[0] == "E",
                input: tail[1].clone(),
                in_place,
            })
        }
        _ => bail!("unknown command"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn p(args: &[&str]) -> Result<Command> {
        parse(args.iter().map(OsString::from).collect())
    }

    #[test]
    fn rejects_extras_and_ambiguous_operations() {
        for args in [
            vec![],
            vec!["--help"],
            vec!["--version"],
            vec!["xor", "a"],
            vec!["xor", "a", "b", "--in-place"],
            vec!["xor", "a", "--in-place", "--in-place"],
            vec!["keyrestore", "x"],
            vec!["keymake", "20GB"],
            vec!["keymake", "0"],
            vec!["keymake", "20000000001"],
            vec!["keymake", "-1"],
            vec!["keymake", "+12"],
            vec!["xcha", "e", "a"],
            vec!["xcha", "K", "a"],
            vec!["sha3", "a", "b"],
        ] {
            assert!(p(&args).is_err(), "{args:?}");
        }
        assert_eq!(
            p(&["keymake", "20000000000"]).unwrap(),
            Command::KeyMake(MAX_KEY_BYTES)
        );
        assert_eq!(
            p(&["sha3", "apple"]).unwrap(),
            Command::Sha3(Some("apple".into()))
        );
        assert_eq!(p(&["sha3"]).unwrap(), Command::Sha3(None));
        assert_eq!(
            p(&["xor", "a", "--in-place", "--repeat-key"]).unwrap(),
            Command::Xor {
                input: "a".into(),
                output: None,
                repeat: true
            }
        );
    }
}
