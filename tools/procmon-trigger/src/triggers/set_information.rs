//! `IRP_MJ_SET_INFORMATION`, one trigger per sub-operation. The Win32 entry points are preferred
//! where one maps cleanly onto an information class, since that is how real programs reach it.

use anyhow::{Context as _, Result};
use windows::core::PCWSTR;
use windows::Win32::Foundation::FILETIME;
use windows::Win32::Storage::FileSystem::{
    CreateHardLinkW, MoveFileExW, ReplaceFileW, SetEndOfFile, SetFilePointerEx, SetFileTime,
    CREATE_ALWAYS, DELETE, FILE_ATTRIBUTE_HIDDEN, FILE_BEGIN, FILE_GENERIC_READ,
    FILE_GENERIC_WRITE, FILE_WRITE_ATTRIBUTES, MOVEFILE_REPLACE_EXISTING, OPEN_EXISTING,
    REPLACE_FILE_FLAGS, SYNCHRONIZE,
};
use windows::Win32::System::Pipes::{
    SetNamedPipeHandleState, PIPE_NOWAIT, PIPE_READMODE_BYTE, PIPE_TYPE_BYTE,
};

use crate::sys::handle::{open, OpenOptions};
use crate::sys::strings::wide;
use crate::sys::{nt, privilege};
use crate::trigger::{Ctx, Expected, Outcome};
use crate::triggers::basic_information;

const FILE_BASIC_INFORMATION_CLASS: i32 = 0x4;
const FILE_DISPOSITION_INFORMATION_CLASS: i32 = 0xd;
const FILE_ALLOCATION_INFORMATION_CLASS: i32 = 0x13;
const FILE_PIPE_INFORMATION_CLASS: i32 = 0x17;
const FILE_VALID_DATA_LENGTH_INFORMATION_CLASS: i32 = 0x27;
const FILE_SHORT_NAME_INFORMATION_CLASS: i32 = 0x28;
const FILE_DISPOSITION_INFORMATION_EX_CLASS: i32 = 0x40;
const FILE_RENAME_INFORMATION_EX_CLASS: i32 = 0x41;

const FILE_DISPOSITION_DELETE: u32 = 0x1;
const FILE_DISPOSITION_POSIX_SEMANTICS: u32 = 0x2;
const FILE_RENAME_REPLACE_IF_EXISTS: u32 = 0x1;
const FILE_RENAME_POSIX_SEMANTICS: u32 = 0x2;

fn expected_sub(sub_operation: &'static str) -> Vec<Expected> {
    vec![Expected::sub("SetInformationFile", sub_operation)]
}

/// `\??\` turns a DOS path into the object-manager path the native API expects.
fn nt_path(path: &std::path::Path) -> Vec<u16> {
    let mut name: Vec<u16> = r"\??\".encode_utf16().collect();
    name.extend(crate::sys::strings::wide_counted(path));
    name
}

pub fn basic_expected() -> Vec<Expected> {
    expected_sub("SetBasicInformationFile")
}

pub fn basic(ctx: &Ctx) -> Result<Outcome> {
    let path = ctx.create_file("basic.txt", b"procmon-trigger")?;
    let file = open(
        &path,
        &OpenOptions::new(FILE_WRITE_ATTRIBUTES.0 | SYNCHRONIZE.0, OPEN_EXISTING),
    )?;

    // 2019-04-17, the same filetime the parser tests use.
    let filetime = FILETIME {
        dwLowDateTime: 0x9db22000,
        dwHighDateTime: 0x01d4f4b0,
    };
    unsafe { SetFileTime(file.raw(), Some(&filetime), None, Some(&filetime)) }
        .context("SetFileTime")?;
    ctx.log("SetFileTime");

    Ok(Outcome::Ran)
}

pub fn position_expected() -> Vec<Expected> {
    expected_sub("SetPositionInformationFile")
}

pub fn position(ctx: &Ctx) -> Result<Outcome> {
    let path = ctx.create_file("position.txt", b"procmon-trigger")?;
    let file = open(&path, &OpenOptions::new(FILE_GENERIC_READ.0, OPEN_EXISTING))?;

    unsafe { SetFilePointerEx(file.raw(), 8, None, FILE_BEGIN) }.context("SetFilePointerEx")?;
    ctx.log("SetFilePointerEx");

    Ok(Outcome::Ran)
}

pub fn end_of_file_expected() -> Vec<Expected> {
    expected_sub("SetEndOfFileInformationFile")
}

pub fn end_of_file(ctx: &Ctx) -> Result<Outcome> {
    let path = ctx.create_file("end_of_file.txt", b"procmon-trigger")?;
    let file = open(
        &path,
        &OpenOptions::new(FILE_GENERIC_WRITE.0, OPEN_EXISTING),
    )?;

    unsafe { SetFilePointerEx(file.raw(), 0x1000, None, FILE_BEGIN) }
        .context("SetFilePointerEx")?;
    unsafe { SetEndOfFile(file.raw()) }.context("SetEndOfFile")?;
    ctx.log("SetEndOfFile");

    Ok(Outcome::Ran)
}

pub fn allocation_expected() -> Vec<Expected> {
    expected_sub("SetAllocationInformationFile")
}

pub fn allocation(ctx: &Ctx) -> Result<Outcome> {
    let path = ctx.create_file("allocation.txt", b"procmon-trigger")?;
    let file = open(
        &path,
        &OpenOptions::new(FILE_GENERIC_WRITE.0, OPEN_EXISTING),
    )?;

    let allocation_size = 0x4000i64;
    nt::set_information_file(
        file.raw(),
        FILE_ALLOCATION_INFORMATION_CLASS,
        &allocation_size.to_le_bytes(),
    )?;
    ctx.log("FileAllocationInformation");

    Ok(Outcome::Ran)
}

pub fn rename_expected() -> Vec<Expected> {
    expected_sub("SetRenameInformationFile")
}

pub fn rename(ctx: &Ctx) -> Result<Outcome> {
    let source = ctx.create_file("rename_source.txt", b"procmon-trigger")?;
    let target = ctx.path("rename_target.txt");

    let wide_source = wide(&source);
    let wide_target = wide(&target);
    unsafe {
        MoveFileExW(
            PCWSTR(wide_source.as_ptr()),
            PCWSTR(wide_target.as_ptr()),
            MOVEFILE_REPLACE_EXISTING,
        )
    }
    .context("MoveFileExW")?;
    ctx.log("MoveFileExW");

    Ok(Outcome::Ran)
}

pub fn rename_ex_expected() -> Vec<Expected> {
    expected_sub("SetRenameInformationEx")
}

pub fn rename_ex(ctx: &Ctx) -> Result<Outcome> {
    let source = ctx.create_file("rename_ex_source.txt", b"procmon-trigger")?;
    let target = ctx.path("rename_ex_target.txt");
    let file = open(
        &source,
        &OpenOptions::new(DELETE.0 | SYNCHRONIZE.0, OPEN_EXISTING),
    )?;

    let information = nt::rename_information(
        FILE_RENAME_REPLACE_IF_EXISTS | FILE_RENAME_POSIX_SEMANTICS,
        &nt_path(&target),
    );
    nt::set_information_file(file.raw(), FILE_RENAME_INFORMATION_EX_CLASS, &information)?;
    ctx.log("FileRenameInformationEx");

    Ok(Outcome::Ran)
}

pub fn link_expected() -> Vec<Expected> {
    expected_sub("SetLinkInformationFile")
}

pub fn link(ctx: &Ctx) -> Result<Outcome> {
    let source = ctx.create_file("link_source.txt", b"procmon-trigger")?;
    let target = ctx.path("link_target.txt");

    let wide_target = wide(&target);
    let wide_source = wide(&source);
    unsafe {
        CreateHardLinkW(
            PCWSTR(wide_target.as_ptr()),
            PCWSTR(wide_source.as_ptr()),
            None,
        )
    }
    .context("CreateHardLinkW")?;
    ctx.log("CreateHardLinkW");

    Ok(Outcome::Ran)
}

pub fn disposition_expected() -> Vec<Expected> {
    expected_sub("SetDispositionInformationFile")
}

pub fn disposition(ctx: &Ctx) -> Result<Outcome> {
    let path = ctx.create_file("disposition.txt", b"procmon-trigger")?;
    let file = open(
        &path,
        &OpenOptions::new(DELETE.0 | SYNCHRONIZE.0, OPEN_EXISTING),
    )?;

    nt::set_information_file(file.raw(), FILE_DISPOSITION_INFORMATION_CLASS, &[1u8])?;
    ctx.log("FileDispositionInformation: delete");
    // Clearing the disposition keeps the scratch tree intact for inspection after the run.
    nt::set_information_file(file.raw(), FILE_DISPOSITION_INFORMATION_CLASS, &[0u8])?;
    ctx.log("FileDispositionInformation: keep");

    Ok(Outcome::Ran)
}

pub fn disposition_ex_expected() -> Vec<Expected> {
    expected_sub("SetDispositionInformationEx")
}

pub fn disposition_ex(ctx: &Ctx) -> Result<Outcome> {
    let path = ctx.create_file("disposition_ex.txt", b"procmon-trigger")?;
    let file = open(
        &path,
        &OpenOptions::new(DELETE.0 | SYNCHRONIZE.0, OPEN_EXISTING),
    )?;

    let flags = FILE_DISPOSITION_DELETE | FILE_DISPOSITION_POSIX_SEMANTICS;
    nt::set_information_file(
        file.raw(),
        FILE_DISPOSITION_INFORMATION_EX_CLASS,
        &flags.to_le_bytes(),
    )?;
    ctx.log("FileDispositionInformationEx: delete");
    nt::set_information_file(
        file.raw(),
        FILE_DISPOSITION_INFORMATION_EX_CLASS,
        &0u32.to_le_bytes(),
    )?;
    ctx.log("FileDispositionInformationEx: keep");

    Ok(Outcome::Ran)
}

pub fn pipe_expected() -> Vec<Expected> {
    expected_sub("SetPipeInformation")
}

pub fn pipe(ctx: &Ctx) -> Result<Outcome> {
    let name = format!(r"\\.\pipe\procmon-trigger-{}", std::process::id());
    let server = crate::triggers::pipes::create_named_pipe(&name)?;
    ctx.log(format!("CreateNamedPipeW({name})"));

    let mode = PIPE_READMODE_BYTE | PIPE_NOWAIT;
    unsafe { SetNamedPipeHandleState(server.raw(), Some(&mode), None, None) }
        .context("SetNamedPipeHandleState")?;
    ctx.log("SetNamedPipeHandleState");

    // The native path as well, so the capture holds the information class even if the Win32 call
    // is served without an IRP on this Windows version.
    let information = [PIPE_READMODE_BYTE.0, PIPE_TYPE_BYTE.0];
    let mut bytes = Vec::with_capacity(8);
    for value in information {
        bytes.extend_from_slice(&value.to_le_bytes());
    }
    let result = nt::set_information_file(server.raw(), FILE_PIPE_INFORMATION_CLASS, &bytes);
    ctx.log(format!("FilePipeInformation: {result:?}"));

    Ok(Outcome::Ran)
}

pub fn replace_completion_expected() -> Vec<Expected> {
    vec![
        Expected::sub("SetInformationFile", "SetReplaceCompletionInformation"),
        Expected::sub("SetInformationFile", "SetRenameInformationFile").best_effort(),
    ]
}

pub fn replace_completion(ctx: &Ctx) -> Result<Outcome> {
    let replaced = ctx.create_file("replaced.txt", b"replaced")?;
    let replacement = ctx.create_file("replacement.txt", b"replacement")?;
    let backup = ctx.path("replaced.bak");

    let wide_replaced = wide(&replaced);
    let wide_replacement = wide(&replacement);
    let wide_backup = wide(&backup);
    unsafe {
        ReplaceFileW(
            PCWSTR(wide_replaced.as_ptr()),
            PCWSTR(wide_replacement.as_ptr()),
            PCWSTR(wide_backup.as_ptr()),
            REPLACE_FILE_FLAGS(0),
            None,
            None,
        )
    }
    .context("ReplaceFileW")?;
    ctx.log("ReplaceFileW");

    Ok(Outcome::Ran)
}

pub fn short_name_expected() -> Vec<Expected> {
    expected_sub("SetShortNameInformation")
}

pub fn short_name(ctx: &Ctx) -> Result<Outcome> {
    if !privilege::enable("SeRestorePrivilege")? {
        return Ok(Outcome::Skipped("SeRestorePrivilege is not held".into()));
    }

    let path = ctx.create_file("short_name_source.txt", b"procmon-trigger")?;
    let file = open(
        &path,
        &OpenOptions::new(DELETE.0 | SYNCHRONIZE.0, OPEN_EXISTING),
    )?;

    let short_name: Vec<u16> = "TRIGGER.TMP".encode_utf16().collect();
    nt::set_information_file(
        file.raw(),
        FILE_SHORT_NAME_INFORMATION_CLASS,
        &nt::name_information(&short_name),
    )?;
    ctx.log("FileShortNameInformation");

    Ok(Outcome::Ran)
}

pub fn valid_data_length_expected() -> Vec<Expected> {
    expected_sub("SetValidDataLengthInformationFile")
}

pub fn valid_data_length(ctx: &Ctx) -> Result<Outcome> {
    if !privilege::enable("SeManageVolumePrivilege")? {
        return Ok(Outcome::Skipped(
            "SeManageVolumePrivilege is not held".into(),
        ));
    }

    let path = ctx.path("valid_data_length.bin");
    let file = open(
        &path,
        &OpenOptions::new(FILE_GENERIC_WRITE.0 | SYNCHRONIZE.0, CREATE_ALWAYS),
    )?;
    unsafe { SetFilePointerEx(file.raw(), 0x10000, None, FILE_BEGIN) }
        .context("SetFilePointerEx")?;
    unsafe { SetEndOfFile(file.raw()) }.context("SetEndOfFile")?;

    let valid_data_length = 0x8000i64;
    nt::set_information_file(
        file.raw(),
        FILE_VALID_DATA_LENGTH_INFORMATION_CLASS,
        &valid_data_length.to_le_bytes(),
    )?;
    ctx.log("FileValidDataLengthInformation");

    Ok(Outcome::Ran)
}

/// Also produces `SetBasicInformationFile`: the attribute change goes through the same class.
pub fn attributes_expected() -> Vec<Expected> {
    expected_sub("SetBasicInformationFile")
}

pub fn attributes(ctx: &Ctx) -> Result<Outcome> {
    let path = ctx.create_file("attributes.txt", b"procmon-trigger")?;
    let information = basic_information(FILE_ATTRIBUTE_HIDDEN.0);
    let file = open(
        &path,
        &OpenOptions::new(FILE_WRITE_ATTRIBUTES.0 | SYNCHRONIZE.0, OPEN_EXISTING),
    )?;

    nt::set_information_file(file.raw(), FILE_BASIC_INFORMATION_CLASS, &information)?;
    ctx.log("FileBasicInformation");

    Ok(Outcome::Ran)
}
