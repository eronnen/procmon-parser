//! `IRP_MJ_CREATE_MAILSLOT`, plus a write through the client end so the capture also holds the
//! mailslot's read/write path.

use anyhow::{Context as _, Result};
use windows::core::PCWSTR;
use windows::Win32::Storage::FileSystem::{WriteFile, FILE_GENERIC_WRITE, OPEN_EXISTING};
use windows::Win32::System::Mailslots::CreateMailslotW;

use crate::sys::handle::{open_name, Handle, OpenOptions};
use crate::sys::strings::wide;
use crate::trigger::{Ctx, Expected, Outcome};

/// `lReadTimeout` value that makes a read wait indefinitely.
const MAILSLOT_WAIT_FOREVER: u32 = u32::MAX;

pub fn expected() -> Vec<Expected> {
    vec![
        Expected::new("CreateMailSlot"),
        Expected::new("WriteFile").best_effort(),
    ]
}

pub fn run(ctx: &Ctx) -> Result<Outcome> {
    let name = format!(r"\\.\mailslot\procmon-trigger\{}", std::process::id());
    let wide_name = wide(&name);
    let server =
        unsafe { CreateMailslotW(PCWSTR(wide_name.as_ptr()), 0, MAILSLOT_WAIT_FOREVER, None) }
            .with_context(|| format!("CreateMailslotW({name})"))?;
    let server = unsafe { Handle::from_raw(server) };
    ctx.log(format!("CreateMailslotW({name})"));

    let client = open_name(
        &name,
        &OpenOptions::new(FILE_GENERIC_WRITE.0, OPEN_EXISTING),
    )?;
    let message = b"procmon-trigger";
    let mut written = 0u32;
    unsafe { WriteFile(client.raw(), Some(message), Some(&mut written), None) }
        .context("WriteFile to the mailslot")?;
    ctx.log(format!("WriteFile: {written} bytes"));

    drop(client);
    drop(server);

    Ok(Outcome::Ran)
}
