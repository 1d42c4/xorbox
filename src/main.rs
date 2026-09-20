mod app;
mod cli;
mod files;
mod keygen;
mod platform;
mod stream;
mod verify;

use std::process::ExitCode;
use std::sync::atomic::Ordering;

fn main() -> ExitCode {
    let result = (|| -> anyhow::Result<()> {
        let command = cli::parse(std::env::args_os().skip(1).collect())?;
        ctrlc::set_handler(|| stream::CANCELLED.store(true, Ordering::Relaxed))?;
        platform::enable_cancellation()?;
        app::run(command)
    })();
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error:#}");
            ExitCode::from(if stream::CANCELLED.load(Ordering::Relaxed) {
                130
            } else {
                1
            })
        }
    }
}
