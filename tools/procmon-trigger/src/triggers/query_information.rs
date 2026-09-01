//! `IRP_MJ_QUERY_INFORMATION` - one call per information class, so every sub-operation name
//! `procmon-parser` knows about shows up in the capture.

use anyhow::Result;
use windows::Win32::Storage::FileSystem::{FILE_GENERIC_READ, OPEN_EXISTING};

use crate::sys::handle::{open, open_directory, OpenOptions};
use crate::sys::nt;
use crate::trigger::{Ctx, Expected, Outcome};

/// The information classes Procmon names, paired with the `FilesystemQueryInformationOperation`
/// value `procmon-parser` reports for them.
const CLASSES: &[(&str, i32)] = &[
    ("QueryBasicInformationFile", 0x4),
    ("QueryStandardInformationFile", 0x5),
    ("QueryFileInternalInformationFile", 0x6),
    ("QueryEaInformationFile", 0x7),
    ("QueryNameInformationFile", 0x9),
    ("QueryPositionInformationFile", 0xe),
    ("QueryAllInformationFile", 0x12),
    ("QueryEndOfFile", 0x14),
    ("QueryStreamInformationFile", 0x16),
    ("QueryCompressionInformationFile", 0x1c),
    ("QueryId", 0x1d),
    ("QueryMoveClusterInformationFile", 0x1f),
    ("QueryNetworkOpenInformationFile", 0x22),
    ("QueryAttributeTagFile", 0x23),
    ("QueryValidDataLength", 0x27),
    ("QueryShortNameInformationFile", 0x28),
    ("QueryIoPiorityHint", 0x2b),
    ("QueryLinks", 0x2e),
    ("QueryNormalizedNameInformationFile", 0x30),
    ("QueryNetworkPhysicalNameInformationFile", 0x31),
    ("QueryIsRemoteDeviceInformation", 0x33),
    ("QueryAttributeCacheInformation", 0x34),
    ("QueryNumaNodeInformation", 0x35),
    ("QueryStandardLinkInformation", 0x36),
    ("QueryRemoteProtocolInformation", 0x37),
    ("QueryVolumeNameInformation", 0x3a),
    ("QueryIdInformation", 0x3b),
    ("QueryDesiredStorageClassInformation", 0x43),
    ("QueryStatInformation", 0x44),
    ("QueryMemoryPartitionInformation", 0x45),
    ("QuerySatLxInformation", 0x46),
    ("QueryCaseSensitiveInformation", 0x47),
    ("QueryLinkInformationEx", 0x48),
    ("QueryStorageReservedIdInformation", 0x4a),
];

/// Directory handles are needed for the classes that describe directory entries.
const DIRECTORY_CLASSES: &[(&str, i32)] = &[
    ("QueryIdBothDirectory", 0x25),
    ("QueryIdGlobalTxDirectoryInformation", 0x32),
    ("QueryIdExtdDirectoryInformation", 0x3c),
    ("QueryIdExtdBothDirectoryInformation", 0x3f),
];

pub fn expected() -> Vec<Expected> {
    CLASSES
        .iter()
        .chain(DIRECTORY_CLASSES)
        .map(|(name, _)| Expected::sub("QueryInformationFile", name))
        .collect()
}

pub fn run(ctx: &Ctx) -> Result<Outcome> {
    let path = ctx.create_file("query.txt", b"procmon-trigger")?;
    let file = open(&path, &OpenOptions::new(FILE_GENERIC_READ.0, OPEN_EXISTING))?;
    let mut buffer = nt::buffer();

    for (name, class) in CLASSES {
        let result = nt::query_information_file(*file, *class, &mut buffer);
        ctx.log(format!("{name}: {}", describe(&result)));
    }
    drop(file);

    let directory = open_directory(ctx.directory(), FILE_GENERIC_READ.0)?;
    for (name, class) in DIRECTORY_CLASSES {
        let result = nt::query_information_file(*directory, *class, &mut buffer);
        ctx.log(format!("{name}: {}", describe(&result)));
    }

    Ok(Outcome::Ran)
}

/// A rejected class still produces the event the capture is after, so failures are only logged.
fn describe(result: &Result<usize>) -> String {
    match result {
        Ok(length) => format!("{length} bytes"),
        Err(err) => format!("{err:#}"),
    }
}
