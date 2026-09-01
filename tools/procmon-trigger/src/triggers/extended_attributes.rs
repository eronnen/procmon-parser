//! `IRP_MJ_SET_EA` / `IRP_MJ_QUERY_EA`. Extended attributes have no Win32 surface, so both
//! directions go through the native API.

use anyhow::Result;
use windows::Win32::Storage::FileSystem::{
    FILE_READ_EA, FILE_WRITE_EA, OPEN_EXISTING, SYNCHRONIZE,
};

use crate::sys::handle::{open, OpenOptions};
use crate::sys::nt;
use crate::trigger::{Ctx, Expected, Outcome};

const ENTRIES: &[(&str, &[u8])] = &[
    ("PROCMON.TRIGGER", b"procmon-trigger"),
    ("PROCMON.SECOND", b"\x01\x02\x03\x04"),
];

pub fn set_expected() -> Vec<Expected> {
    vec![Expected::new("SetEAFile")]
}

pub fn set(ctx: &Ctx) -> Result<Outcome> {
    let path = ctx.create_file("ea.txt", b"procmon-trigger")?;
    let file = open(
        &path,
        &OpenOptions::new(FILE_WRITE_EA.0 | SYNCHRONIZE.0, OPEN_EXISTING),
    )?;

    nt::set_ea_file(*file, &nt::full_ea_information(ENTRIES))?;
    ctx.log("NtSetEaFile");

    Ok(Outcome::Ran)
}

pub fn query_expected() -> Vec<Expected> {
    vec![Expected::new("QueryEAFile")]
}

pub fn query(ctx: &Ctx) -> Result<Outcome> {
    let path = ctx.create_file("ea.txt", b"procmon-trigger")?;
    let file = open(
        &path,
        &OpenOptions::new(
            FILE_READ_EA.0 | FILE_WRITE_EA.0 | SYNCHRONIZE.0,
            OPEN_EXISTING,
        ),
    )?;
    nt::set_ea_file(*file, &nt::full_ea_information(ENTRIES))?;

    let mut buffer = nt::buffer();
    let length = nt::query_ea_file(*file, &mut buffer, None)?;
    ctx.log(format!("NtQueryEaFile (full list): {length} bytes"));

    let names: Vec<&str> = ENTRIES.iter().map(|(name, _)| *name).collect();
    let ea_list = nt::get_ea_information(&names);
    let length = nt::query_ea_file(*file, &mut buffer, Some(&ea_list))?;
    ctx.log(format!("NtQueryEaFile (by name): {length} bytes"));

    Ok(Outcome::Ran)
}
