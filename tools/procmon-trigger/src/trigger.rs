use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result};
use serde::Serialize;

/// An event the capture is expected to contain because of a trigger.
///
/// `operation` and `sub_operation` use the names `procmon-parser` produces for the CSV Operation
/// column, so the manifest can be matched against a parsed PML without a translation table.
#[derive(Clone, Debug, Serialize)]
pub struct Expected {
    pub operation: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub_operation: Option<&'static str>,
    /// The event is emitted by the kernel rather than directly by a syscall, so its presence is
    /// not guaranteed (for example the unlock-all that happens during handle cleanup).
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub best_effort: bool,
}

impl Expected {
    pub fn new(operation: &'static str) -> Self {
        Self {
            operation,
            sub_operation: None,
            best_effort: false,
        }
    }

    pub fn sub(operation: &'static str, sub_operation: &'static str) -> Self {
        Self {
            operation,
            sub_operation: Some(sub_operation),
            best_effort: false,
        }
    }

    pub fn best_effort(mut self) -> Self {
        self.best_effort = true;
        self
    }
}

#[derive(Debug)]
pub enum Outcome {
    Ran,
    /// The host cannot produce this operation (missing privilege, wrong filesystem, ...).
    Skipped(String),
}

pub struct Trigger {
    /// Dot-delimited identifier, also the name of the trigger's scratch directory.
    pub name: &'static str,
    /// Procmon event class of the expected events, as it appears in the CSV Event Class column.
    pub event_class: &'static str,
    /// Free-text requirements shown by `--list` and recorded in the manifest.
    pub requirements: &'static [&'static str],
    pub expected: fn() -> Vec<Expected>,
    pub run: fn(&Ctx) -> Result<Outcome>,
}

/// Per-trigger scratch directory and logging.
pub struct Ctx {
    directory: PathBuf,
    verbose: bool,
}

impl Ctx {
    pub fn new(directory: PathBuf, verbose: bool) -> Self {
        Self { directory, verbose }
    }

    pub fn directory(&self) -> &Path {
        &self.directory
    }

    pub fn path(&self, name: &str) -> PathBuf {
        self.directory.join(name)
    }

    /// Creates a file with `content` and returns its path. The file is closed on return, so it
    /// does not add events in the middle of the trigger's own operations.
    pub fn create_file(&self, name: &str, content: &[u8]) -> Result<PathBuf> {
        let path = self.path(name);
        fs::write(&path, content).with_context(|| format!("creating {}", path.display()))?;
        Ok(path)
    }

    pub fn log(&self, message: impl AsRef<str>) {
        if self.verbose {
            println!("    {}", message.as_ref());
        }
    }
}
