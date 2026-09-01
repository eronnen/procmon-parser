use std::ffi::OsStr;
use std::path::Path;

use anyhow::{Context as _, Result};
use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_CREATION_DISPOSITION, FILE_FLAGS_AND_ATTRIBUTES, FILE_FLAG_BACKUP_SEMANTICS,
    FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_MODE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    OPEN_EXISTING,
};

use crate::sys::strings::wide;

pub const SHARE_ALL: FILE_SHARE_MODE =
    FILE_SHARE_MODE(FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0 | FILE_SHARE_DELETE.0);

/// Owns a kernel handle and closes it on drop, so each trigger's `IRP_MJ_CLEANUP` /
/// `IRP_MJ_CLOSE` events land inside its own slice of the capture.
pub struct Handle(HANDLE);

impl Handle {
    /// # Safety
    /// `handle` must be a valid handle that is not owned by anything else.
    pub unsafe fn from_raw(handle: HANDLE) -> Self {
        Self(handle)
    }

    pub fn raw(&self) -> HANDLE {
        self.0
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

pub struct OpenOptions {
    pub access: u32,
    pub share: FILE_SHARE_MODE,
    pub disposition: FILE_CREATION_DISPOSITION,
    pub flags: FILE_FLAGS_AND_ATTRIBUTES,
}

impl OpenOptions {
    pub fn new(access: u32, disposition: FILE_CREATION_DISPOSITION) -> Self {
        Self {
            access,
            share: SHARE_ALL,
            disposition,
            flags: FILE_FLAGS_AND_ATTRIBUTES(0),
        }
    }

    pub fn flags(mut self, flags: FILE_FLAGS_AND_ATTRIBUTES) -> Self {
        self.flags = flags;
        self
    }
}

/// Opens a filesystem object by name, which also covers the non-path namespaces
/// (`\\.\pipe\...`, `\\.\mailslot\...`, `\\.\C:`).
pub fn open_name(name: impl AsRef<OsStr>, options: &OpenOptions) -> Result<Handle> {
    let name = name.as_ref();
    let wide_name = wide(name);
    let handle = unsafe {
        CreateFileW(
            PCWSTR(wide_name.as_ptr()),
            options.access,
            options.share,
            None,
            options.disposition,
            options.flags,
            None,
        )
    }
    .with_context(|| format!("CreateFileW({})", name.to_string_lossy()))?;
    Ok(unsafe { Handle::from_raw(handle) })
}

pub fn open(path: &Path, options: &OpenOptions) -> Result<Handle> {
    open_name(path, options)
}

/// Opens `path` as a directory handle.
pub fn open_directory(path: &Path, access: u32) -> Result<Handle> {
    open(
        path,
        &OpenOptions::new(access, OPEN_EXISTING).flags(FILE_FLAG_BACKUP_SEMANTICS),
    )
}

/// Opens a path that is known not to exist, purely to place a named marker event in the capture.
/// The `CreateFile` event fails with NAME NOT FOUND, which is exactly what makes it easy to find.
pub fn marker(path: &Path) {
    let _ = open(
        path,
        &OpenOptions::new(FILE_READ_ATTRIBUTES.0, OPEN_EXISTING),
    );
}
