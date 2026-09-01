//! Named pipes. Procmon reports these under the IPC event class, reusing the filesystem
//! operation names (`CreatePipe`, `SetInformationFile: SetPipeInformation`).

use anyhow::{Context as _, Result};
use windows::core::PCWSTR;
use windows::Win32::Storage::FileSystem::PIPE_ACCESS_DUPLEX;
use windows::Win32::System::Pipes::{
    CreateNamedPipeW, PIPE_READMODE_BYTE, PIPE_TYPE_BYTE, PIPE_WAIT,
};

use crate::sys::handle::Handle;
use crate::sys::strings::wide;

/// Creates the server end of a byte-mode named pipe.
pub fn create_named_pipe(name: &str) -> Result<Handle> {
    let wide_name = wide(name);
    let handle = unsafe {
        CreateNamedPipeW(
            PCWSTR(wide_name.as_ptr()),
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            1,
            0x1000,
            0x1000,
            0,
            None,
        )
    };
    if handle.is_invalid() {
        return Err(windows::core::Error::from_thread())
            .with_context(|| format!("CreateNamedPipeW({name})"));
    }
    Ok(unsafe { Handle::from_raw(handle) })
}
