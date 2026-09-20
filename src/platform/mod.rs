#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::*;
#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::*;

#[cfg(not(any(windows, target_os = "linux")))]
compile_error!("xorbox supports only Windows and Linux");
#[cfg(not(target_pointer_width = "64"))]
compile_error!("xorbox requires a 64-bit target");
