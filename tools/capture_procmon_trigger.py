"""Capture a live Procmon trace while running procmon-trigger and export the result to CSV.

This script starts Process Monitor with the all-standard-columns configuration used by
procmon-parser tests, runs the procmon-trigger binary, stops the capture, and writes the
resulting PML/CSV pair plus the trigger manifest to an output directory.
"""

from __future__ import annotations

import argparse
import logging
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
from datetime import datetime
from pathlib import Path

from procmon_common import (
    convert_pml_to_csv,
    find_procmon_executable,
    generate_pmc_config_bytes,
)

logger = logging.getLogger(__name__)


def find_trigger_executable() -> Path:
    """Find and return the path to the procmon-trigger executable."""
    script_dir = Path(__file__).resolve().parent
    candidates = [
        script_dir / "procmon-trigger" / "target" / "release" / "procmon-trigger.exe",
        script_dir / "procmon-trigger" / "target" / "debug" / "procmon-trigger.exe",
        Path("target") / "release" / "procmon-trigger.exe",
        Path("target") / "debug" / "procmon-trigger.exe",
    ]
    for candidate in candidates:
        if candidate.is_file():
            return candidate.resolve()

    for name in ("procmon-trigger.exe", "procmon-trigger"):
        found = shutil.which(name)
        if found:
            return Path(found).resolve()

    raise FileNotFoundError(
        "Could not find procmon-trigger executable. Build it with 'cargo build --release' "
        "or provide the path with --trigger-exe."
    )


def wait_for_procmon(proc: subprocess.Popen, pml_path: Path, timeout: float = 10.0) -> None:
    """Wait for the Procmon process to start and the backing file to appear."""
    start = time.time()
    while time.time() - start < timeout:
        ret = proc.poll()
        if ret is not None:
            raise RuntimeError(f"Procmon exited early with code {ret}")
        if pml_path.is_file() and pml_path.stat().st_size > 0:
            logger.debug("Procmon backing file created after %.2fs", time.time() - start)
            return
        time.sleep(0.1)
    logger.warning("Procmon backing file did not appear within %.2fs; continuing", timeout)


def parse_args(args: list[str] | None = None) -> argparse.ArgumentParser:
    """Create and return argument parser for the capture script."""
    repo_root = Path(__file__).resolve().parent.parent
    default_output_base = repo_root / "captures"

    parser = argparse.ArgumentParser(
        description="Capture a Procmon trace of procmon-trigger and export it to CSV."
    )
    parser.add_argument(
        "--output-dir",
        "-o",
        type=Path,
        default=None,
        help=f"Directory for PML, CSV and manifest (default: {default_output_base} / <timestamp>).",
    )
    parser.add_argument(
        "--procmon-exe",
        "-p",
        type=Path,
        default=None,
        help="Path to the Procmon executable (default: auto-detect).",
    )
    parser.add_argument(
        "--trigger-exe",
        "-t",
        type=Path,
        default=None,
        help="Path to the procmon-trigger executable (default: auto-detect).",
    )
    parser.add_argument(
        "--manifest",
        "-m",
        type=Path,
        default=None,
        help="Path where procmon-trigger writes its manifest (default: <output-dir>/manifest.json).",
    )
    parser.add_argument(
        "--trigger-args",
        type=str,
        default="",
        help="Extra arguments to pass to procmon-trigger (e.g. '--only set_information --keep').",
    )
    parser.add_argument(
        "--compress-csv",
        action="store_true",
        help="Compress the CSV output with zlib like convert_all_pml_to_csv.py and save as .CSV.",
    )
    parser.add_argument(
        "--capture-timeout",
        type=float,
        default=120.0,
        help="Maximum seconds to wait for the procmon-trigger run (default: 120).",
    )
    parser.add_argument(
        "--export-timeout",
        type=float,
        default=120.0,
        help="Maximum seconds to wait for the PML -> CSV export (default: 120).",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable verbose / debug logging output.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """Main CLI entry point."""
    parser = parse_args(argv)
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
    )

    if sys.platform != "win32":
        logger.error("Process Monitor (Procmon) requires a Windows environment to run.")
        return 1

    try:
        procmon_exe = (args.procmon_exe or find_procmon_executable()).resolve()
        logger.info("Using Procmon: %s", procmon_exe)
    except FileNotFoundError as e:
        logger.error("%s", e)
        return 1

    try:
        trigger_exe = (args.trigger_exe or find_trigger_executable()).resolve()
        logger.info("Using procmon-trigger: %s", trigger_exe)
    except FileNotFoundError as e:
        logger.error("%s", e)
        return 1

    repo_root = Path(__file__).resolve().parent.parent
    if args.output_dir:
        output_dir = args.output_dir.resolve()
    else:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_dir = (repo_root / "captures" / f"capture_{timestamp}").resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    logger.info("Output directory: %s", output_dir)

    manifest_path = args.manifest.resolve() if args.manifest else output_dir / "manifest.json"

    pml_path = output_dir / "capture.pml"
    csv_path = output_dir / ("capture.CSV" if args.compress_csv else "capture.csv")

    for path in (pml_path, csv_path, manifest_path):
        if path.exists():
            raise RuntimeError(f"Output path already exists; use a different --output-dir: {path}")

    pmc_bytes = generate_pmc_config_bytes()

    with tempfile.TemporaryDirectory() as tmpdir:
        pmc_path = Path(tmpdir) / "config.pmc"
        pmc_path.write_bytes(pmc_bytes)

        start_cmd = [
            str(procmon_exe),
            "/AcceptEula",
            "/Quiet",
            "/LoadConfig",
            str(pmc_path),
            "/BackingFile",
            str(pml_path),
        ]
        logger.info("Starting Procmon capture")
        logger.debug("Command: %s", " ".join(start_cmd))
        procmon_proc = subprocess.Popen(
            start_cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )

        try:
            wait_for_procmon(procmon_proc, pml_path, timeout=10.0)

            trigger_cmd = [str(trigger_exe), "--manifest", str(manifest_path)]
            extra = shlex.split(args.trigger_args)
            if args.verbose and "--verbose" not in extra and "-v" not in extra:
                trigger_cmd.append("--verbose")
            trigger_cmd.extend(extra)

            logger.info("Running procmon-trigger")
            logger.debug("Command: %s", " ".join(trigger_cmd))
            result = subprocess.run(trigger_cmd, timeout=args.capture_timeout)
            if result.returncode != 0:
                logger.warning("procmon-trigger exited with code %d", result.returncode)
        finally:
            logger.info("Stopping Procmon")
            terminate_cmd = [str(procmon_exe), "/AcceptEula", "/Quiet", "/Terminate"]
            try:
                subprocess.run(
                    terminate_cmd,
                    timeout=30.0,
                    creationflags=subprocess.CREATE_NO_WINDOW,
                )
            except Exception as e:
                logger.warning("Procmon /Terminate failed: %s", e)

            try:
                procmon_proc.wait(timeout=30.0)
            except subprocess.TimeoutExpired:
                logger.warning("Procmon did not exit cleanly; killing process")
                procmon_proc.kill()
                procmon_proc.wait()

        if not pml_path.is_file():
            raise RuntimeError(f"Procmon did not produce the expected PML file: {pml_path}")

        convert_pml_to_csv(
            pml_input_path=pml_path,
            csv_output_path=csv_path,
            procmon_exe=procmon_exe,
            pmc_config_path=pmc_path,
            compress_output=args.compress_csv,
            timeout=args.export_timeout,
        )

    logger.info("Capture complete. PML: %s, CSV: %s, manifest: %s", pml_path, csv_path, manifest_path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
