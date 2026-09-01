use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;

use crate::trigger::Expected;

/// Bumped whenever the manifest layout changes, so the Python side can reject captures it does
/// not understand.
pub const SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Serialize, PartialEq, Eq, Clone, Copy)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Ran,
    Skipped,
    Failed,
}

#[derive(Debug, Serialize)]
pub struct TriggerRecord {
    pub name: &'static str,
    pub event_class: &'static str,
    pub directory: PathBuf,
    pub status: Status,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    pub requirements: &'static [&'static str],
    pub expected: Vec<Expected>,
}

#[derive(Debug, Serialize)]
pub struct Manifest {
    pub schema_version: u32,
    pub pid: u32,
    pub image_path: PathBuf,
    /// `32-bit` or `64-bit`, matching the Procmon CSV Architecture column of this process.
    pub architecture: &'static str,
    pub workdir: PathBuf,
    pub started_unix_ms: u128,
    pub finished_unix_ms: u128,
    pub triggers: Vec<TriggerRecord>,
}

impl Manifest {
    pub fn counts(&self) -> (usize, usize, usize) {
        let count = |status| self.triggers.iter().filter(|t| t.status == status).count();
        (
            count(Status::Ran),
            count(Status::Skipped),
            count(Status::Failed),
        )
    }

    pub fn write(&self, path: &Path) -> anyhow::Result<()> {
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(path, json)?;
        Ok(())
    }
}

pub fn unix_ms(time: SystemTime) -> u128 {
    time.duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or_default()
}
