use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;

/// Encodes `value` as a NUL-terminated UTF-16 string for the `*W` Win32 entry points.
pub fn wide(value: impl AsRef<OsStr>) -> Vec<u16> {
    value
        .as_ref()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

/// Encodes `path` as UTF-16 without a NUL terminator, for the counted strings the native API uses.
pub fn wide_counted(path: &Path) -> Vec<u16> {
    path.as_os_str().encode_wide().collect()
}
