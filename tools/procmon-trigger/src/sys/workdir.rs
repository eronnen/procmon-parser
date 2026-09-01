use std::fs;
use std::path::{Path, PathBuf};
use std::process;
use std::time::SystemTime;

use anyhow::{Context as _, Result};

use crate::manifest::unix_ms;

/// Name of the directory every scratch path goes through, so events can be attributed to this
/// tool by path alone.
const MARKER: &str = "procmon-trigger";

/// Creates `<parent>/procmon-trigger/<pid>-<timestamp>`.
pub fn create(parent: Option<&Path>) -> Result<PathBuf> {
    let parent = parent
        .map(Path::to_path_buf)
        .unwrap_or_else(std::env::temp_dir);
    let directory =
        parent
            .join(MARKER)
            .join(format!("{}-{}", process::id(), unix_ms(SystemTime::now())));
    fs::create_dir_all(&directory).with_context(|| format!("creating {}", directory.display()))?;
    Ok(directory)
}
