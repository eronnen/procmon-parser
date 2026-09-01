# procmon-trigger

A Windows binary that deliberately performs I/O operations so a Process Monitor capture of it
contains events `procmon-parser` has no test resource for yet. The README TODO list is the
backlog: each unchecked filesystem operation needs a capture before it can be parsed with
confidence.

Every trigger works inside its own scratch directory below
`%TEMP%\procmon-trigger\<pid>-<timestamp>\<trigger name>\`, and the run emits a
`CreateFile ... NAME NOT FOUND` on a `--<trigger name>--` path right before each trigger, so a
capture can be sliced per trigger by path alone.

## Building

The crate only builds for Windows. On a Windows host:

```
cargo build --release
```

Cross-compiling from Linux is possible for checking (`cargo check --target
x86_64-pc-windows-msvc`), but running it obviously needs Windows. Build the 32-bit binary with
`--target i686-pc-windows-msvc` when a capture of a 32-bit process is wanted.

## Running

```
procmon-trigger --list
procmon-trigger --verbose --keep --manifest manifest.json
procmon-trigger --only set_information --skip set_information.short_name
```

- `--only` / `--skip` match a trigger by full name or by dot-delimited prefix, so
  `--only set_information` selects every `set_information.*` trigger.
- `--manifest` writes what the run is expected to have produced (see below).
- `--keep` leaves the scratch tree in place; by default it is deleted after the run.

A trigger that the host cannot support (a missing privilege, a filesystem without extended
attributes) is reported as skipped with a reason instead of failing the run. A trigger that fails
unexpectedly is recorded and the run continues, but the exit code is non-zero.

## Capturing

1. Start Procmon with all filters disabled (`Filter > Enable Advanced Output` as well, so
   `IRP_MJ_*` and `FASTIO_*` are not hidden) - `tools/convert_all_pml_to_csv.py` shows the
   configuration the parser tests expect.
2. Run `procmon-trigger --manifest manifest.json`.
3. Stop the capture and save it as a PML, then export the same capture to CSV.

The manifest lists, per trigger, the `Operation`/sub-operation names `procmon-parser` should
report for the events it produced:

```json
{
  "schema_version": 1,
  "pid": 4242,
  "architecture": "64-bit",
  "workdir": "C:\\Users\\me\\AppData\\Local\\Temp\\procmon-trigger\\4242-1750000000000",
  "triggers": [
    {
      "name": "lock_unlock",
      "event_class": "File System",
      "status": "ran",
      "expected": [
        { "operation": "LockUnlockFile", "sub_operation": "LockFile" },
        { "operation": "LockUnlockFile", "sub_operation": "UnlockFileSingle" },
        { "operation": "LockUnlockFile", "sub_operation": "UnlockFileAll", "best_effort": true }
      ]
    }
  ]
}
```

`best_effort` marks an event the kernel emits on its own behalf (the unlock-all issued while a
handle is being closed, for example), so its absence from a capture is not a failure.

## Adding a trigger

Add a function to a module in `src/triggers/` and a row to the table in `src/registry.rs`. The
row names the trigger, the Procmon event class, the requirements to show in `--list`, and the
events the trigger is expected to produce.

## Coverage

Phase 1 covers the user-mode filesystem operations from the README TODO:
`QueryInformationFile`, `SetInformationFile`, `QueryEAFile`, `SetEAFile`,
`QueryVolumeInformation`, `LockUnlockFile`, `CreateMailSlot`, `QuerySecurityFile` and
`SetSecurityFile`.

Not covered yet:

- `SetVolumeInformation`, `QueryFileQuota`, `SetFileQuota` and volume mount/dismount mutate a
  whole volume, so they need a disposable scratch VHDX rather than the system volume.
- `Power`, `PlugAndPlay` and `DeviceChange` originate from the PnP/power stack.
- `Shutdown`, `SystemControl` and `InternalDeviceIoControl` are not reachable from user mode at
  all; a capture of them needs a driver.
