//! Trigger implementations, grouped by the Procmon operation they aim at.

pub mod extended_attributes;
pub mod lock_unlock;
pub mod mailslot;
pub mod pipes;
pub mod query_information;
pub mod security;
pub mod set_information;
pub mod volume_information;

/// Encodes `FILE_BASIC_INFORMATION`: four `LARGE_INTEGER` timestamps followed by `FileAttributes`
/// and the tail padding the structure carries on both architectures. A zero timestamp leaves that
/// field untouched.
pub fn basic_information(attributes: u32) -> Vec<u8> {
    let mut information = vec![0u8; 40];
    information[32..36].copy_from_slice(&attributes.to_le_bytes());
    information
}

#[cfg(test)]
mod tests {
    use super::basic_information;

    #[test]
    fn basic_information_only_sets_the_attributes() {
        let information = basic_information(0x2);
        assert_eq!(information.len(), 40);
        assert!(information[..32].iter().all(|byte| *byte == 0));
        assert_eq!(&information[32..36], &2u32.to_le_bytes());
    }
}
