use std::fs::{File, OpenOptions};
use std::io;
use std::os::windows::io::AsRawHandle;
use std::sync::atomic::Ordering;
use windows_sys::Win32::Foundation::{WAIT_OBJECT_0, WAIT_TIMEOUT};
use windows_sys::Win32::System::Console::*;
use windows_sys::Win32::System::Threading::WaitForSingleObject;
use zeroize::{Zeroize, Zeroizing};

struct InputMode<'a> {
    file: &'a File,
    saved: u32,
}
impl Drop for InputMode<'_> {
    fn drop(&mut self) {
        // SAFETY: the borrowed file outlives this guard and saved came from this
        // console. Restore on success, cancellation, I/O errors, and unwinding.
        unsafe {
            SetConsoleMode(self.file.as_raw_handle(), self.saved);
        }
    }
}

fn cancelled() -> io::Result<()> {
    if crate::stream::CANCELLED.load(Ordering::Relaxed) {
        Err(io::Error::new(io::ErrorKind::Interrupted, "cancelled"))
    } else {
        Ok(())
    }
}

fn write_console(output: &File, text: &str) -> io::Result<()> {
    let wide: Vec<_> = text.encode_utf16().collect();
    let mut offset = 0;
    while offset < wide.len() {
        let mut written = 0;
        // SAFETY: output is an open console handle, input remains live, and
        // written is valid output storage. Prompts are short static strings.
        if unsafe {
            WriteConsoleW(
                output.as_raw_handle(),
                wide[offset..].as_ptr().cast(),
                (wide.len() - offset) as u32,
                &mut written,
                std::ptr::null(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        if written == 0 {
            return Err(io::ErrorKind::WriteZero.into());
        }
        offset += written as usize;
    }
    Ok(())
}

fn remove_character(value: &mut Vec<u16>) {
    let mut start = value.len().saturating_sub(1);
    if start > 0
        && (0xdc00..=0xdfff).contains(&value[start])
        && (0xd800..=0xdbff).contains(&value[start - 1])
    {
        start -= 1;
    }
    value[start..].zeroize();
    value.truncate(start);
}

/// Poll console input records so a handled Ctrl-C can cancel an idle prompt.
/// A blocking ReadConsoleW password reader can remain asleep after the signal.
pub fn prompt_password(prompt: &str) -> io::Result<String> {
    cancelled()?;
    let input = OpenOptions::new().read(true).write(true).open("CONIN$")?;
    let output = OpenOptions::new().read(true).write(true).open("CONOUT$")?;
    let mut saved = 0;
    // SAFETY: input is a live console input handle and saved is writable storage.
    if unsafe { GetConsoleMode(input.as_raw_handle(), &mut saved) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let _mode = InputMode {
        file: &input,
        saved,
    };
    // Disable line input, echo, VT escape translation and QuickEdit. Read Ctrl-C
    // keystrokes ourselves; externally generated control events set CANCELLED.
    // SAFETY: the console handle is valid; the guard restores its prior mode.
    if unsafe { SetConsoleMode(input.as_raw_handle(), ENABLE_EXTENDED_FLAGS) } == 0 {
        return Err(io::Error::last_os_error());
    }
    write_console(&output, prompt)?;
    let mut value = Zeroizing::new(Vec::<u16>::new());
    let result = (|| {
        loop {
            cancelled()?;
            // SAFETY: console input handles are waitable. A short timeout lets
            // cancellation work even when there are no keyboard events.
            match unsafe { WaitForSingleObject(input.as_raw_handle(), 50) } {
                WAIT_TIMEOUT => continue,
                WAIT_OBJECT_0 => {}
                _ => return Err(io::Error::last_os_error()),
            }
            cancelled()?;
            let mut record = INPUT_RECORD::default();
            let mut read = 0;
            // SAFETY: the signaled buffer has input; record holds one complete
            // event and read is valid writable storage. No second reader exists
            // in this process for this console during a prompt.
            if unsafe { ReadConsoleInputW(input.as_raw_handle(), &mut record, 1, &mut read) } == 0 {
                return Err(io::Error::last_os_error());
            }
            if read != 1 || record.EventType != KEY_EVENT as u16 {
                continue;
            }
            // SAFETY: EventType identifies the active union member as KeyEvent.
            let event = unsafe { record.Event.KeyEvent };
            if event.bKeyDown == 0 {
                continue;
            }
            // SAFETY: ReadConsoleInputW fills the Unicode form of this union.
            let unit = unsafe { event.uChar.UnicodeChar };
            for _ in 0..event.wRepeatCount {
                match unit {
                    3 => {
                        crate::stream::CANCELLED.store(true, Ordering::Relaxed);
                        return Err(io::ErrorKind::Interrupted.into());
                    }
                    4 if value.is_empty() => return Err(io::ErrorKind::UnexpectedEof.into()),
                    8 | 127 => remove_character(&mut value),
                    10 | 13 => {
                        return String::from_utf16(&value).map_err(|_| {
                            io::Error::new(io::ErrorKind::InvalidData, "invalid Unicode input")
                        });
                    }
                    21 => value.zeroize(),
                    23 => {
                        let whitespace =
                            |u: &u16| char::from_u32(*u as u32).is_some_and(char::is_whitespace);
                        while value.last().is_some_and(whitespace) {
                            remove_character(&mut value);
                        }
                        while value.last().is_some_and(|u| !whitespace(u)) {
                            remove_character(&mut value);
                        }
                    }
                    _ if unit >= 32 && !(0x7f..=0x9f).contains(&unit) => value.push(unit),
                    _ => {}
                }
            }
        }
    })();
    // End the hidden input line even on cancellation. Preserve an earlier error.
    let newline = write_console(&output, "\r\n");
    let mut value = result.map(Zeroizing::new)?;
    newline?;
    Ok(std::mem::take(&mut *value))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backspace_erases_complete_surrogate_pair_and_clears_removed_units() {
        let mut value: Vec<u16> = "a🔐".encode_utf16().collect();
        remove_character(&mut value);
        assert_eq!(String::from_utf16(&value).unwrap(), "a");
        remove_character(&mut value);
        remove_character(&mut value);
        assert!(value.is_empty());
    }
}
