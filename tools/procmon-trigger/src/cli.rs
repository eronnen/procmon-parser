use std::path::PathBuf;

use clap::Parser;

#[derive(Parser, Debug)]
#[command(
    name = "procmon-trigger",
    about = "Trigger Procmon operations for procmon-parser captures",
    long_about = None
)]
pub struct Cli {
    /// List the available triggers and exit.
    #[arg(long)]
    pub list: bool,

    /// Run only these triggers. A value matches a trigger by full name or by name prefix, so
    /// `--only set_information` runs every `set_information.*` trigger.
    #[arg(long, value_name = "NAME")]
    pub only: Vec<String>,

    /// Skip these triggers, matched the same way as `--only`.
    #[arg(long, value_name = "NAME")]
    pub skip: Vec<String>,

    /// Directory to create the scratch tree in (default: the system temporary directory).
    #[arg(long, value_name = "DIR")]
    pub workdir: Option<PathBuf>,

    /// Write the run manifest, describing the events each trigger is expected to have produced.
    #[arg(long, value_name = "FILE")]
    pub manifest: Option<PathBuf>,

    /// Keep the scratch tree after the run instead of deleting it.
    #[arg(long)]
    pub keep: bool,

    /// Print every operation as it is triggered.
    #[arg(long, short)]
    pub verbose: bool,
}

/// Returns whether `name` is selected by `patterns`, where a pattern matches the whole name or a
/// dot-delimited prefix of it.
pub fn matches(patterns: &[String], name: &str) -> bool {
    patterns.iter().any(|pattern| {
        name == pattern
            || (name.len() > pattern.len()
                && name.starts_with(pattern.as_str())
                && name.as_bytes()[pattern.len()] == b'.')
    })
}

#[cfg(test)]
mod tests {
    use super::matches;

    #[test]
    fn pattern_matches_whole_name_and_prefix_segments() {
        let patterns = vec!["set_information".to_string(), "ea.query".to_string()];
        assert!(matches(&patterns, "set_information"));
        assert!(matches(&patterns, "set_information.rename"));
        assert!(matches(&patterns, "ea.query"));
        assert!(!matches(&patterns, "ea.set"));
        assert!(!matches(&patterns, "set_information_extra"));
    }
}
