//! `IRP_MJ_QUERY_SECURITY` / `IRP_MJ_SET_SECURITY`.

use anyhow::{Context as _, Result};
use windows::Win32::Security::{
    GetKernelObjectSecurity, SetKernelObjectSecurity, DACL_SECURITY_INFORMATION,
    GROUP_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
};
use windows::Win32::Storage::FileSystem::{OPEN_EXISTING, READ_CONTROL, SYNCHRONIZE, WRITE_DAC};

use crate::sys::handle::{open, OpenOptions};
use crate::trigger::{Ctx, Expected, Outcome};

/// A self-relative descriptor for a file fits comfortably; the query reports the required size
/// if it does not, and the trigger fails loudly rather than truncating.
const DESCRIPTOR_SIZE: usize = 4096;

pub fn query_expected() -> Vec<Expected> {
    vec![Expected::new("QuerySecurityFile")]
}

pub fn query(ctx: &Ctx) -> Result<Outcome> {
    let path = ctx.create_file("security.txt", b"procmon-trigger")?;
    let file = open(
        &path,
        &OpenOptions::new(READ_CONTROL.0 | SYNCHRONIZE.0, OPEN_EXISTING),
    )?;

    let mut descriptor = vec![0u8; DESCRIPTOR_SIZE];
    let mut length = 0u32;
    unsafe {
        GetKernelObjectSecurity(
            file.raw(),
            (OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION).0,
            Some(PSECURITY_DESCRIPTOR(descriptor.as_mut_ptr().cast())),
            descriptor.len() as u32,
            &mut length,
        )
    }
    .context("GetKernelObjectSecurity")?;
    ctx.log(format!("GetKernelObjectSecurity: {length} bytes"));

    Ok(Outcome::Ran)
}

pub fn set_expected() -> Vec<Expected> {
    vec![
        Expected::new("QuerySecurityFile"),
        Expected::new("SetSecurityFile"),
    ]
}

/// Reads the file's own DACL back and writes it unchanged, so the trigger reaches
/// `IRP_MJ_SET_SECURITY` without altering who can touch the scratch tree.
pub fn set(ctx: &Ctx) -> Result<Outcome> {
    let path = ctx.create_file("security_set.txt", b"procmon-trigger")?;
    let file = open(
        &path,
        &OpenOptions::new(READ_CONTROL.0 | WRITE_DAC.0 | SYNCHRONIZE.0, OPEN_EXISTING),
    )?;

    let mut descriptor = vec![0u8; DESCRIPTOR_SIZE];
    let mut length = 0u32;
    unsafe {
        GetKernelObjectSecurity(
            file.raw(),
            DACL_SECURITY_INFORMATION.0,
            Some(PSECURITY_DESCRIPTOR(descriptor.as_mut_ptr().cast())),
            descriptor.len() as u32,
            &mut length,
        )
    }
    .context("GetKernelObjectSecurity")?;

    unsafe {
        SetKernelObjectSecurity(
            file.raw(),
            DACL_SECURITY_INFORMATION,
            PSECURITY_DESCRIPTOR(descriptor.as_mut_ptr().cast()),
        )
    }
    .context("SetKernelObjectSecurity")?;
    ctx.log("SetKernelObjectSecurity: DACL rewritten unchanged");

    Ok(Outcome::Ran)
}
