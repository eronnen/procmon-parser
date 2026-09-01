//! `IRP_MJ_QUERY_VOLUME_INFORMATION` - one call per `FS_INFORMATION_CLASS` Procmon names.

use anyhow::Result;
use windows::Win32::Storage::FileSystem::{FILE_GENERIC_READ, OPEN_EXISTING};

use crate::sys::handle::{open, OpenOptions};
use crate::sys::nt;
use crate::trigger::{Ctx, Expected, Outcome};

const CLASSES: &[(&str, i32)] = &[
    ("QueryInformationVolume", 0x1),
    ("QueryLabelInformationVolume", 0x2),
    ("QuerySizeInformationVolume", 0x3),
    ("QueryDeviceInformationVolume", 0x4),
    ("QueryAttributeInformationVolume", 0x5),
    ("QueryControlInformationVolume", 0x6),
    ("QueryFullSizeInformationVolume", 0x7),
    ("QueryObjectIdInformationVolume", 0x8),
];

pub fn expected() -> Vec<Expected> {
    CLASSES
        .iter()
        .map(|(name, _)| Expected::sub("QueryVolumeInformation", name))
        .collect()
}

pub fn run(ctx: &Ctx) -> Result<Outcome> {
    let path = ctx.create_file("volume.txt", b"procmon-trigger")?;
    let file = open(&path, &OpenOptions::new(FILE_GENERIC_READ.0, OPEN_EXISTING))?;
    let mut buffer = nt::buffer();

    for (name, class) in CLASSES {
        // Classes the volume rejects (a label query on a handle without the right access, an
        // object id on a volume that has none) still produce the event the capture needs.
        let result = nt::query_volume_information_file(file.raw(), *class, &mut buffer);
        match result {
            Ok(length) => ctx.log(format!("{name}: {length} bytes")),
            Err(err) => ctx.log(format!("{name}: {err:#}")),
        }
    }

    Ok(Outcome::Ran)
}
