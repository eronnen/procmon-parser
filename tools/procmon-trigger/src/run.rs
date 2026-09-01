use std::fs;
use std::path::Path;
use std::process::ExitCode;
use std::time::SystemTime;

use anyhow::{Context as _, Result};
use clap::Parser;

use crate::cli::{matches, Cli};
use crate::manifest::{unix_ms, Manifest, Status, TriggerRecord, SCHEMA_VERSION};
use crate::registry::TRIGGERS;
use crate::sys::handle::marker;
use crate::sys::workdir;
use crate::trigger::{Ctx, Outcome, Trigger};

const ARCHITECTURE: &str = if cfg!(target_pointer_width = "64") {
    "64-bit"
} else {
    "32-bit"
};

pub fn main() -> Result<ExitCode> {
    let cli = Cli::parse();

    if cli.list {
        list();
        return Ok(ExitCode::SUCCESS);
    }

    let selected: Vec<&Trigger> = TRIGGERS
        .iter()
        .filter(|trigger| cli.only.is_empty() || matches(&cli.only, trigger.name))
        .filter(|trigger| !matches(&cli.skip, trigger.name))
        .collect();
    if selected.is_empty() {
        anyhow::bail!("no trigger matches the given --only/--skip filters");
    }

    let directory = workdir::create(cli.workdir.as_deref())?;
    println!("workdir: {}", directory.display());

    let started = SystemTime::now();
    let mut records = Vec::with_capacity(selected.len());
    sentinel(&directory, "run-start");
    for trigger in selected {
        records.push(run_one(trigger, &directory, cli.verbose)?);
    }
    sentinel(&directory, "run-end");
    let finished = SystemTime::now();

    let manifest = Manifest {
        schema_version: SCHEMA_VERSION,
        pid: std::process::id(),
        image_path: std::env::current_exe().unwrap_or_default(),
        architecture: ARCHITECTURE,
        workdir: directory.clone(),
        started_unix_ms: unix_ms(started),
        finished_unix_ms: unix_ms(finished),
        triggers: records,
    };

    let (ran, skipped, failed) = manifest.counts();
    if let Some(path) = &cli.manifest {
        manifest.write(path)?;
        println!("manifest: {}", path.display());
    }
    println!("{ran} ran, {skipped} skipped, {failed} failed");

    if !cli.keep {
        // The capture is already taken by the time the process exits, so removing the tree only
        // adds the delete events - which are themselves part of what is being exercised.
        if let Err(err) = fs::remove_dir_all(&directory) {
            eprintln!("warning: could not remove {}: {err}", directory.display());
        }
    }

    Ok(if failed == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    })
}

fn run_one(trigger: &Trigger, workdir: &Path, verbose: bool) -> Result<TriggerRecord> {
    let directory = workdir.join(trigger.name);
    fs::create_dir_all(&directory).with_context(|| format!("creating {}", directory.display()))?;

    sentinel(workdir, trigger.name);
    println!("  {}", trigger.name);
    let outcome = (trigger.run)(&Ctx::new(directory.clone(), verbose));

    let (status, detail) = match outcome {
        Ok(Outcome::Ran) => (Status::Ran, None),
        Ok(Outcome::Skipped(reason)) => {
            println!("    skipped: {reason}");
            (Status::Skipped, Some(reason))
        }
        // A trigger that cannot run on this host must not cost the rest of the capture.
        Err(err) => {
            let detail = format!("{err:#}");
            eprintln!("    failed: {detail}");
            (Status::Failed, Some(detail))
        }
    };

    Ok(TriggerRecord {
        name: trigger.name,
        event_class: trigger.event_class,
        directory,
        status,
        detail,
        requirements: trigger.requirements,
        expected: (trigger.expected)(),
    })
}

/// Opens a path that does not exist, so the capture holds a named `CreateFile ... NAME NOT FOUND`
/// event right before the trigger's own events.
fn sentinel(workdir: &Path, name: &str) {
    marker(&workdir.join(format!("--{name}--")));
}

fn list() {
    for trigger in TRIGGERS {
        println!("{} [{}]", trigger.name, trigger.event_class);
        for expected in (trigger.expected)() {
            match expected.sub_operation {
                Some(sub_operation) => println!("    {}: {sub_operation}", expected.operation),
                None => println!("    {}", expected.operation),
            }
        }
        if !trigger.requirements.is_empty() {
            println!("    requires: {}", trigger.requirements.join(", "));
        }
    }
}
