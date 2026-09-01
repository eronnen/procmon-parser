use std::os::windows::ffi::OsStrExt;
use std::path::Path;

/// Encodes `path` as UTF-16 without a NUL terminator, for the counted strings the native API uses.
pub fn wide_counted(path: &Path) -> Vec<u16> {
    path.as_os_str().encode_wide().collect()
}
