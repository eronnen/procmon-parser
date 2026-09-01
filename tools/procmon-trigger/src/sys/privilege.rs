use anyhow::{Context as _, Result};
use windows::core::PCWSTR;
use windows::Win32::Foundation::{GetLastError, ERROR_NOT_ALL_ASSIGNED, HANDLE, LUID};
use windows::Win32::Security::{
    AdjustTokenPrivileges, LookupPrivilegeValueW, LUID_AND_ATTRIBUTES, SE_PRIVILEGE_ENABLED,
    TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY,
};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

use crate::sys::handle::Handle;
use crate::sys::strings::wide;

/// Enables `name` in the process token, returning whether the token actually holds it.
///
/// A missing privilege is not an error: the triggers that need one report themselves as skipped.
pub fn enable(name: &str) -> Result<bool> {
    let mut token = HANDLE::default();
    unsafe {
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut token,
        )
    }
    .context("OpenProcessToken")?;
    let token = unsafe { Handle::from_raw(token) };

    let wide_name = wide(name);
    let mut luid = LUID::default();
    unsafe { LookupPrivilegeValueW(PCWSTR::null(), PCWSTR(wide_name.as_ptr()), &mut luid) }
        .with_context(|| format!("LookupPrivilegeValueW({name})"))?;

    let privileges = TOKEN_PRIVILEGES {
        PrivilegeCount: 1,
        Privileges: [LUID_AND_ATTRIBUTES {
            Luid: luid,
            Attributes: SE_PRIVILEGE_ENABLED,
        }],
    };

    unsafe {
        AdjustTokenPrivileges(
            token.raw(),
            false,
            Some(&privileges),
            std::mem::size_of::<TOKEN_PRIVILEGES>() as u32,
            None,
            None,
        )
    }
    .with_context(|| format!("AdjustTokenPrivileges({name})"))?;

    // AdjustTokenPrivileges succeeds even when the token does not hold the privilege.
    Ok(unsafe { GetLastError() } != ERROR_NOT_ALL_ASSIGNED)
}
