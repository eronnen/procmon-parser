//! `IRP_MJ_LOCK_CONTROL`. Procmon splits it into lock, unlock-single, unlock-all and
//! unlock-all-by-key; only the first two have a Win32 entry point.

use anyhow::{Context as _, Result};
use windows::Win32::Foundation::HANDLE;
use windows::Win32::Storage::FileSystem::{
    LockFileEx, UnlockFile, FILE_GENERIC_READ, FILE_GENERIC_WRITE, LOCKFILE_EXCLUSIVE_LOCK,
    OPEN_EXISTING,
};
use windows::Win32::System::IO::OVERLAPPED;

use crate::sys::handle::{open, OpenOptions};
use crate::trigger::{Ctx, Expected, Outcome};

const CONTENT: &[u8] = b"procmon-trigger lock control payload";

fn lock(handle: HANDLE, offset: u32, length: u32) -> Result<()> {
    let mut overlapped = OVERLAPPED {
        Anonymous: windows::Win32::System::IO::OVERLAPPED_0 {
            Anonymous: windows::Win32::System::IO::OVERLAPPED_0_0 {
                Offset: offset,
                OffsetHigh: 0,
            },
        },
        ..Default::default()
    };
    unsafe {
        LockFileEx(
            handle,
            LOCKFILE_EXCLUSIVE_LOCK,
            None,
            length,
            0,
            &mut overlapped,
        )
    }
    .context("LockFileEx")
}

pub fn expected() -> Vec<Expected> {
    vec![
        Expected::sub("LockUnlockFile", "LockFile"),
        Expected::sub("LockUnlockFile", "UnlockFileSingle"),
        // The kernel releases the remaining ranges when the last handle is closed.
        Expected::sub("LockUnlockFile", "UnlockFileAll").best_effort(),
    ]
}

pub fn run(ctx: &Ctx) -> Result<Outcome> {
    let path = ctx.create_file("lock.txt", CONTENT)?;
    let file = open(
        &path,
        &OpenOptions::new(FILE_GENERIC_READ.0 | FILE_GENERIC_WRITE.0, OPEN_EXISTING),
    )?;

    lock(file.raw(), 0, 8)?;
    ctx.log("LockFileEx [0, 8)");
    unsafe { UnlockFile(file.raw(), 0, 0, 8, 0) }.context("UnlockFile")?;
    ctx.log("UnlockFile [0, 8)");

    // Left locked on purpose: closing the handle makes the filesystem issue the unlock-all.
    lock(file.raw(), 16, 8)?;
    ctx.log("LockFileEx [16, 24), released by handle close");
    drop(file);

    Ok(Outcome::Ran)
}
