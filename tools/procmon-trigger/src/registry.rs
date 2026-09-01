//! The table of triggers. Adding an operation means adding a row here and the function it names.

use crate::trigger::Trigger;
use crate::triggers::{
    extended_attributes, lock_unlock, mailslot, query_information, security, set_information,
    volume_information,
};

const NONE: &[&str] = &[];
const NTFS: &[&str] = &["an NTFS volume"];

pub const TRIGGERS: &[Trigger] = &[
    Trigger {
        name: "query_information",
        event_class: "File System",
        requirements: NONE,
        expected: query_information::expected,
        run: query_information::run,
    },
    Trigger {
        name: "set_information.basic",
        event_class: "File System",
        requirements: NONE,
        expected: set_information::basic_expected,
        run: set_information::basic,
    },
    Trigger {
        name: "set_information.attributes",
        event_class: "File System",
        requirements: NONE,
        expected: set_information::attributes_expected,
        run: set_information::attributes,
    },
    Trigger {
        name: "set_information.position",
        event_class: "File System",
        requirements: NONE,
        expected: set_information::position_expected,
        run: set_information::position,
    },
    Trigger {
        name: "set_information.end_of_file",
        event_class: "File System",
        requirements: NONE,
        expected: set_information::end_of_file_expected,
        run: set_information::end_of_file,
    },
    Trigger {
        name: "set_information.allocation",
        event_class: "File System",
        requirements: NONE,
        expected: set_information::allocation_expected,
        run: set_information::allocation,
    },
    Trigger {
        name: "set_information.rename",
        event_class: "File System",
        requirements: NONE,
        expected: set_information::rename_expected,
        run: set_information::rename,
    },
    Trigger {
        name: "set_information.rename_ex",
        event_class: "File System",
        requirements: NTFS,
        expected: set_information::rename_ex_expected,
        run: set_information::rename_ex,
    },
    Trigger {
        name: "set_information.link",
        event_class: "File System",
        requirements: NTFS,
        expected: set_information::link_expected,
        run: set_information::link,
    },
    Trigger {
        name: "set_information.disposition",
        event_class: "File System",
        requirements: NONE,
        expected: set_information::disposition_expected,
        run: set_information::disposition,
    },
    Trigger {
        name: "set_information.disposition_ex",
        event_class: "File System",
        requirements: NTFS,
        expected: set_information::disposition_ex_expected,
        run: set_information::disposition_ex,
    },
    Trigger {
        name: "set_information.replace_completion",
        event_class: "File System",
        requirements: NTFS,
        expected: set_information::replace_completion_expected,
        run: set_information::replace_completion,
    },
    Trigger {
        name: "set_information.short_name",
        event_class: "File System",
        requirements: &[
            "SeRestorePrivilege",
            "an NTFS volume with 8.3 names enabled",
        ],
        expected: set_information::short_name_expected,
        run: set_information::short_name,
    },
    Trigger {
        name: "set_information.valid_data_length",
        event_class: "File System",
        requirements: &["SeManageVolumePrivilege"],
        expected: set_information::valid_data_length_expected,
        run: set_information::valid_data_length,
    },
    Trigger {
        name: "set_information.pipe",
        event_class: "IPC",
        requirements: NONE,
        expected: set_information::pipe_expected,
        run: set_information::pipe,
    },
    Trigger {
        name: "extended_attributes.set",
        event_class: "File System",
        requirements: NTFS,
        expected: extended_attributes::set_expected,
        run: extended_attributes::set,
    },
    Trigger {
        name: "extended_attributes.query",
        event_class: "File System",
        requirements: NTFS,
        expected: extended_attributes::query_expected,
        run: extended_attributes::query,
    },
    Trigger {
        name: "volume_information.query",
        event_class: "File System",
        requirements: NONE,
        expected: volume_information::expected,
        run: volume_information::run,
    },
    Trigger {
        name: "lock_unlock",
        event_class: "File System",
        requirements: NONE,
        expected: lock_unlock::expected,
        run: lock_unlock::run,
    },
    Trigger {
        name: "mailslot",
        event_class: "File System",
        requirements: NONE,
        expected: mailslot::expected,
        run: mailslot::run,
    },
    Trigger {
        name: "security.query",
        event_class: "File System",
        requirements: NONE,
        expected: security::query_expected,
        run: security::query,
    },
    Trigger {
        name: "security.set",
        event_class: "File System",
        requirements: NONE,
        expected: security::set_expected,
        run: security::set,
    },
];

#[cfg(test)]
mod tests {
    use super::TRIGGERS;

    #[test]
    fn trigger_names_are_unique() {
        let mut names: Vec<&str> = TRIGGERS.iter().map(|trigger| trigger.name).collect();
        let count = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), count);
    }

    #[test]
    fn every_trigger_declares_expected_events() {
        for trigger in TRIGGERS {
            assert!(
                !(trigger.expected)().is_empty(),
                "{} declares no expected events",
                trigger.name
            );
        }
    }
}
