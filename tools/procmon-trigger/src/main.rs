//! Performs the syscalls behind Procmon operations, so that a Procmon capture taken while this
//! process runs contains at least one event per operation.
//!
//! The capture (PML + its CSV export) is meant to become a `procmon-parser` test resource, which
//! is how the unimplemented operations in the README TODO list get covered.

#[cfg(windows)]
mod cli;
#[cfg(windows)]
mod manifest;
#[cfg(windows)]
mod registry;
#[cfg(windows)]
mod run;
#[cfg(windows)]
mod sys;
#[cfg(windows)]
mod trigger;
#[cfg(windows)]
mod triggers;

#[cfg(windows)]
fn main() -> std::process::ExitCode {
    match run::main() {
        Ok(code) => code,
        Err(err) => {
            eprintln!("error: {err:#}");
            std::process::ExitCode::FAILURE
        }
    }
}

#[cfg(not(windows))]
fn main() -> std::process::ExitCode {
    eprintln!("procmon-trigger triggers Windows I/O operations and only runs on Windows");
    std::process::ExitCode::FAILURE
}
