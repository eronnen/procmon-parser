//! Thin wrappers over the native API calls that have no Win32 equivalent expressive enough to
//! reach every Procmon sub-operation.

use anyhow::{bail, Result};
use windows::Wdk::Storage::FileSystem::{
    NtQueryEaFile, NtQueryInformationFile, NtQueryVolumeInformationFile, NtSetEaFile,
    NtSetInformationFile, FILE_INFORMATION_CLASS, FS_INFORMATION_CLASS,
};
use windows::Win32::Foundation::{HANDLE, NTSTATUS};
use windows::Win32::System::IO::IO_STATUS_BLOCK;

/// Big enough for every information class queried here, including the variable-length ones
/// (`FileAllInformation`, `FileStreamInformation`, EA lists).
pub const BUFFER_SIZE: usize = 4096;

pub fn buffer() -> Vec<u8> {
    vec![0u8; BUFFER_SIZE]
}

fn io_status_block() -> IO_STATUS_BLOCK {
    unsafe { std::mem::zeroed() }
}

fn check(call: &str, status: NTSTATUS) -> Result<()> {
    if status.0 >= 0 {
        Ok(())
    } else {
        bail!("{call} failed with NTSTATUS {:#010x}", status.0 as u32);
    }
}

/// Issues `IRP_MJ_QUERY_INFORMATION` with `class`, returning the number of bytes written.
///
/// A failing status is returned as an error but the event is still logged by Procmon, which is
/// what the capture needs - several classes exist only to be rejected by the filesystem.
pub fn query_information_file(handle: HANDLE, class: i32, buffer: &mut [u8]) -> Result<usize> {
    let mut iosb = io_status_block();
    let status = unsafe {
        NtQueryInformationFile(
            handle,
            &mut iosb,
            buffer.as_mut_ptr().cast(),
            buffer.len() as u32,
            FILE_INFORMATION_CLASS(class),
        )
    };
    check("NtQueryInformationFile", status)?;
    Ok(iosb.Information)
}

/// Issues `IRP_MJ_SET_INFORMATION` with `class` and the already-encoded `information` buffer.
pub fn set_information_file(handle: HANDLE, class: i32, information: &[u8]) -> Result<()> {
    let mut iosb = io_status_block();
    let status = unsafe {
        NtSetInformationFile(
            handle,
            &mut iosb,
            information.as_ptr().cast(),
            information.len() as u32,
            FILE_INFORMATION_CLASS(class),
        )
    };
    check("NtSetInformationFile", status)
}

/// Issues `IRP_MJ_QUERY_VOLUME_INFORMATION` with `class`.
pub fn query_volume_information_file(
    handle: HANDLE,
    class: i32,
    buffer: &mut [u8],
) -> Result<usize> {
    let mut iosb = io_status_block();
    let status = unsafe {
        NtQueryVolumeInformationFile(
            handle,
            &mut iosb,
            buffer.as_mut_ptr().cast(),
            buffer.len() as u32,
            FS_INFORMATION_CLASS(class),
        )
    };
    check("NtQueryVolumeInformationFile", status)?;
    Ok(iosb.Information)
}

/// Issues `IRP_MJ_SET_EA`.
pub fn set_ea_file(handle: HANDLE, ea_buffer: &[u8]) -> Result<()> {
    let mut iosb = io_status_block();
    let status = unsafe {
        NtSetEaFile(
            handle,
            &mut iosb,
            ea_buffer.as_ptr().cast(),
            ea_buffer.len() as u32,
        )
    };
    check("NtSetEaFile", status)
}

/// Issues `IRP_MJ_QUERY_EA`, either for the whole EA list or for the names in `ea_list`.
pub fn query_ea_file(handle: HANDLE, buffer: &mut [u8], ea_list: Option<&[u8]>) -> Result<usize> {
    let mut iosb = io_status_block();
    let status = unsafe {
        NtQueryEaFile(
            handle,
            &mut iosb,
            buffer.as_mut_ptr().cast(),
            buffer.len() as u32,
            false,
            ea_list.map(|list| list.as_ptr().cast()),
            ea_list.map_or(0, |list| list.len() as u32),
            None,
            true,
        )
    };
    check("NtQueryEaFile", status)?;
    Ok(iosb.Information)
}

/// Encodes the `FILE_RENAME_INFORMATION` / `FILE_LINK_INFORMATION` layout, whose fixed part is
/// `{ union { BOOLEAN ReplaceIfExists; ULONG Flags; }; HANDLE RootDirectory; ULONG FileNameLength; }`
/// followed by the counted name. The union is padded to the handle's alignment, so the layout
/// differs between 32-bit and 64-bit builds.
pub fn rename_information(flags: u32, name: &[u16]) -> Vec<u8> {
    let pointer_size = std::mem::size_of::<usize>();
    let name_offset = 2 * pointer_size + 4;
    let mut information = vec![0u8; name_offset + name.len() * 2];
    information[..4].copy_from_slice(&flags.to_le_bytes());
    let name_length = (name.len() * 2) as u32;
    information[2 * pointer_size..name_offset].copy_from_slice(&name_length.to_le_bytes());
    for (index, unit) in name.iter().enumerate() {
        let offset = name_offset + index * 2;
        information[offset..offset + 2].copy_from_slice(&unit.to_le_bytes());
    }
    information
}

/// Encodes the `FILE_NAME_INFORMATION` layout (`{ ULONG FileNameLength; WCHAR FileName[]; }`),
/// used by `FileShortNameInformation`.
pub fn name_information(name: &[u16]) -> Vec<u8> {
    let mut information = Vec::with_capacity(4 + name.len() * 2);
    information.extend_from_slice(&((name.len() * 2) as u32).to_le_bytes());
    for unit in name {
        information.extend_from_slice(&unit.to_le_bytes());
    }
    information
}

/// Encodes a `FILE_FULL_EA_INFORMATION` list. Entries are 4-byte aligned and the name is an
/// ASCII, NUL-terminated string that is *not* counted in `EaNameLength`.
pub fn full_ea_information(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut buffer: Vec<u8> = Vec::new();
    let mut entry_offsets = Vec::with_capacity(entries.len());

    for (name, value) in entries {
        while buffer.len() % 4 != 0 {
            buffer.push(0);
        }
        entry_offsets.push(buffer.len());
        buffer.extend_from_slice(&0u32.to_le_bytes()); // NextEntryOffset, patched below
        buffer.push(0); // Flags
        buffer.push(name.len() as u8); // EaNameLength, excluding the NUL
        buffer.extend_from_slice(&(value.len() as u16).to_le_bytes());
        buffer.extend_from_slice(name.as_bytes());
        buffer.push(0);
        buffer.extend_from_slice(value);
    }

    for window in entry_offsets.windows(2) {
        let (current, next) = (window[0], window[1]);
        let next_entry_offset = (next - current) as u32;
        buffer[current..current + 4].copy_from_slice(&next_entry_offset.to_le_bytes());
    }

    buffer
}

/// Encodes a `FILE_GET_EA_INFORMATION` list, which names the EAs to return from a query.
pub fn get_ea_information(names: &[&str]) -> Vec<u8> {
    let mut buffer: Vec<u8> = Vec::new();
    let mut entry_offsets = Vec::with_capacity(names.len());

    for name in names {
        while buffer.len() % 4 != 0 {
            buffer.push(0);
        }
        entry_offsets.push(buffer.len());
        buffer.extend_from_slice(&0u32.to_le_bytes()); // NextEntryOffset, patched below
        buffer.push(name.len() as u8);
        buffer.extend_from_slice(name.as_bytes());
        buffer.push(0);
    }

    for window in entry_offsets.windows(2) {
        let (current, next) = (window[0], window[1]);
        let next_entry_offset = (next - current) as u32;
        buffer[current..current + 4].copy_from_slice(&next_entry_offset.to_le_bytes());
    }

    buffer
}

#[cfg(test)]
mod tests {
    use super::{full_ea_information, get_ea_information, name_information, rename_information};

    #[test]
    fn rename_information_places_the_counted_name_after_the_fixed_part() {
        let pointer_size = std::mem::size_of::<usize>();
        let name: Vec<u16> = "ab".encode_utf16().collect();
        let information = rename_information(1, &name);

        assert_eq!(information.len(), 2 * pointer_size + 4 + 4);
        assert_eq!(information[0], 1);
        let length_offset = 2 * pointer_size;
        assert_eq!(
            &information[length_offset..length_offset + 4],
            &4u32.to_le_bytes()
        );
        assert_eq!(&information[length_offset + 4..], &[b'a', 0, b'b', 0]);
    }

    #[test]
    fn name_information_is_length_prefixed() {
        let name: Vec<u16> = "A".encode_utf16().collect();
        assert_eq!(name_information(&name), vec![2, 0, 0, 0, b'A', 0]);
    }

    #[test]
    fn ea_entries_are_aligned_and_chained() {
        let buffer = full_ea_information(&[("AB", &[1, 2, 3]), ("CD", &[4])]);
        let first_next = u32::from_le_bytes(buffer[..4].try_into().unwrap()) as usize;

        assert_eq!(first_next % 4, 0);
        assert_eq!(buffer[5], 2); // EaNameLength of the first entry
        assert_eq!(&buffer[8..11], b"AB\0");
        assert_eq!(&buffer[11..14], &[1, 2, 3]);
        assert_eq!(buffer[first_next + 5], 2);
        assert_eq!(
            u32::from_le_bytes(buffer[first_next..first_next + 4].try_into().unwrap()),
            0
        );
    }

    #[test]
    fn get_ea_entries_hold_names_only() {
        let buffer = get_ea_information(&["AB"]);
        assert_eq!(buffer[4], 2);
        assert_eq!(&buffer[5..8], b"AB\0");
    }
}
