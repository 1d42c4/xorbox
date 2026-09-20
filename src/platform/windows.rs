use std::ffi::c_void;
use std::fs::{File, Metadata, OpenOptions};
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::os::windows::io::{AsRawHandle, FromRawHandle};
use std::path::Path;
use windows_sys::Win32::Foundation::{
    GENERIC_READ, GENERIC_WRITE, INVALID_HANDLE_VALUE, LocalFree,
};
use windows_sys::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
use windows_sys::Win32::Storage::FileSystem::*;

mod console;
pub use console::prompt_password;

fn wide(path: &Path) -> Vec<u16> {
    path.as_os_str().encode_wide().chain(Some(0)).collect()
}

pub fn enable_cancellation() -> io::Result<()> {
    // A shell can pass its "ignore Ctrl-C" attribute to a child. Installing a
    // custom handler alone does not clear it; explicitly enable delivery.
    // SAFETY: a null handler with FALSE only resets the process's ignore attribute.
    if unsafe { windows_sys::Win32::System::Console::SetConsoleCtrlHandler(None, 0) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

pub fn create_private(path: &Path) -> io::Result<File> {
    // A protected DACL grants full access only to the owner and LocalSystem.
    // Applying it at CREATE_NEW avoids a window with inherited broad permissions.
    let sddl: Vec<u16> = "D:P(A;;FA;;;OW)(A;;FA;;;SY)\0".encode_utf16().collect();
    let mut descriptor: *mut c_void = std::ptr::null_mut();
    // SAFETY: the terminated SDDL and output pointer are valid for the call.
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            1,
            &mut descriptor,
            std::ptr::null_mut(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor,
        bInheritHandle: 0,
    };
    let name = wide(path);
    // SAFETY: all pointers reference live, correctly sized data. The descriptor is
    // copied by CreateFileW. The returned owning handle is transferred to File.
    let handle = unsafe {
        CreateFileW(
            name.as_ptr(),
            GENERIC_READ | GENERIC_WRITE | DELETE,
            FILE_SHARE_READ | FILE_SHARE_DELETE,
            &attributes,
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
            std::ptr::null_mut(),
        )
    };
    let error = io::Error::last_os_error();
    // SAFETY: ConvertStringSecurityDescriptorToSecurityDescriptorW allocated this
    // descriptor with LocalAlloc and requires LocalFree exactly once.
    unsafe {
        LocalFree(descriptor);
    }
    if handle == INVALID_HANDLE_VALUE {
        return Err(error);
    }
    // SAFETY: the valid handle is uniquely owned and will be closed by File.
    Ok(unsafe { File::from_raw_handle(handle) })
}

pub fn open_regular(path: &Path, write: bool) -> io::Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .write(write)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    let info = file.metadata()?;
    if !info.is_file() || info.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(io::Error::other(
            "expected a regular file without a reparse point",
        ));
    }
    Ok(file)
}

pub fn links(file: &File) -> io::Result<u64> {
    let mut info = std::mem::MaybeUninit::<BY_HANDLE_FILE_INFORMATION>::uninit();
    // SAFETY: info points to valid writable storage and the handle remains open.
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), info.as_mut_ptr()) } == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a successful call initialized the structure.
    Ok(unsafe { info.assume_init() }.nNumberOfLinks as u64)
}

pub fn same_snapshot(a: &Metadata, b: &Metadata) -> bool {
    a.file_size() == b.file_size()
        && a.last_write_time() == b.last_write_time()
        && a.creation_time() == b.creation_time()
        && a.file_attributes() == b.file_attributes()
}

pub fn check_in_place(file: &File, path: &Path) -> io::Result<()> {
    if file.metadata()?.file_attributes() & FILE_ATTRIBUTE_READONLY != 0 {
        return Err(io::Error::other("in-place mode refuses read-only files"));
    }
    let mut fs = [0u16; 64];
    // SAFETY: output buffers are valid; optional outputs are explicitly null.
    if unsafe {
        GetVolumeInformationByHandleW(
            file.as_raw_handle(),
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            fs.as_mut_ptr(),
            fs.len() as u32,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let n = fs.iter().position(|&c| c == 0).unwrap_or(fs.len());
    if String::from_utf16_lossy(&fs[..n]) != "NTFS" {
        return Err(io::Error::other(
            "in-place mode requires local NTFS on Windows",
        ));
    }
    let mut volume = vec![0u16; 32768];
    // SAFETY: path is terminated and the volume buffer has the declared capacity.
    if unsafe {
        GetVolumePathNameW(
            wide(path).as_ptr(),
            volume.as_mut_ptr(),
            volume.len() as u32,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful GetVolumePathNameW produced a terminated volume path.
    if unsafe { GetDriveTypeW(volume.as_ptr()) } != 3
    /* DRIVE_FIXED */
    {
        return Err(io::Error::other(
            "in-place mode requires a local fixed NTFS volume",
        ));
    }
    reject_alternate_streams(path)
}

fn reject_alternate_streams(path: &Path) -> io::Result<()> {
    let mut data = std::mem::MaybeUninit::<WIN32_FIND_STREAM_DATA>::uninit();
    // SAFETY: path is terminated and data has the exact required writable size.
    let search = unsafe {
        FindFirstStreamW(
            wide(path).as_ptr(),
            FindStreamInfoStandard,
            data.as_mut_ptr().cast(),
            0,
        )
    };
    if search == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    let result = (|| {
        loop {
            // SAFETY: either FindFirstStreamW or FindNextStreamW has initialized data.
            let stream = unsafe { data.assume_init_ref() };
            let n = stream
                .cStreamName
                .iter()
                .position(|&c| c == 0)
                .unwrap_or(stream.cStreamName.len());
            if String::from_utf16_lossy(&stream.cStreamName[..n]) != "::$DATA" {
                return Err(io::Error::other(
                    "in-place mode refuses files with alternate data streams",
                ));
            }
            // SAFETY: search is a live enumeration handle and data is writable storage.
            if unsafe { FindNextStreamW(search, data.as_mut_ptr().cast()) } == 0 {
                let error = io::Error::last_os_error();
                if error.raw_os_error() == Some(38)
                /* ERROR_HANDLE_EOF */
                {
                    return Ok(());
                }
                return Err(error);
            }
        }
    })();
    // SAFETY: search was returned by FindFirstStreamW and is closed exactly once.
    unsafe {
        FindClose(search);
    }
    result
}

pub fn publish(file: &File, _: &Path, target: &Path, replace: bool) -> io::Result<()> {
    let name: Vec<u16> = target.as_os_str().encode_wide().collect();
    let offset = std::mem::offset_of!(FILE_RENAME_INFO, FileName);
    // FILE_RENAME_INFO requires a terminating NUL even though FileNameLength
    // excludes it. Keep an explicit zeroed UTF-16 slot after the filename.
    let bytes = offset
        .checked_add((name.len() + 1) * 2)
        .ok_or_else(|| io::Error::other("filename too long"))?;
    // Vec<usize> gives the flexible structure the alignment it needs.
    let mut storage = vec![0usize; bytes.div_ceil(size_of::<usize>())];
    let info = storage.as_mut_ptr().cast::<FILE_RENAME_INFO>();
    // SAFETY: storage is aligned, large enough for the header and UTF-16 name, and
    // exclusively owned. SetFileInformationByHandle reads it only during the call.
    unsafe {
        (*info).Anonymous.Flags = if replace {
            1 | 2 /* REPLACE_IF_EXISTS | POSIX_SEMANTICS */
        } else {
            0
        };
        (*info).RootDirectory = std::ptr::null_mut();
        (*info).FileNameLength = (name.len() * 2) as u32;
        std::ptr::copy_nonoverlapping(name.as_ptr(), (*info).FileName.as_mut_ptr(), name.len());
        if SetFileInformationByHandle(
            file.as_raw_handle(),
            FileRenameInfoEx,
            info.cast(),
            bytes as u32,
        ) == 0
        {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

pub fn sync_publication(file: &File, _: &Path) -> io::Result<()> {
    // Windows has no unprivileged POSIX directory-fsync equivalent. Flush the
    // still-open renamed file; do not claim unconditional power-loss durability.
    file.sync_all()
}

#[cfg(test)]
#[path = "windows_tests.rs"]
mod tests;
