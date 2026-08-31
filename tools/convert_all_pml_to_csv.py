"""Utility script to convert Procmon PML log files to compressed CSV files using Process Monitor (Procmon).

This script decompresses compressed PML files, runs Process Monitor to export them
as CSV with all 27 standard columns, and compresses the resulting CSV with zlib.
"""

from __future__ import annotations

import argparse
import logging
import shutil
import subprocess
import sys
import tempfile
import time
import zlib
from pathlib import Path

from procmon_parser import dumps_configuration
from procmon_parser.consts import Column

logger = logging.getLogger(__name__)

PML_SUFFIX = "PML"
CSV_SUFFIX = "CSV"
COMPRESSION_LEVEL = 9

ALL_STANDARD_COLUMNS: list[Column] = [
    Column.TIME_OF_DAY,
    Column.PROCESS_NAME,
    Column.PID,
    Column.OPERATION,
    Column.PATH,
    Column.RESULT,
    Column.DETAIL,
    Column.DATE_AND_TIME,
    Column.RELATIVE_TIME,
    Column.DURATION,
    Column.COMPLETION_TIME,
    Column.EVENT_CLASS,
    Column.SEQUENCE,
    Column.IMAGE_PATH,
    Column.COMPANY,
    Column.DESCRIPTION,
    Column.VERSION,
    Column.USER,
    Column.AUTHENTICATION_ID,
    Column.SESSION,
    Column.COMMAND_LINE,
    Column.TID,
    Column.VIRTUALIZED,
    Column.INTEGRITY,
    Column.CATEGORY,
    Column.PARENT_PID,
    Column.ARCHITECTURE,
]

COMMON_PROCMON_PATHS = [
    r"C:\SysinternalsSuite\Procmon.exe",
    r"C:\SysinternalsSuite\Procmon64.exe",
    r"C:\Program Files\Sysinternals\Procmon.exe",
    r"C:\Program Files\Sysinternals\Procmon64.exe",
    r"C:\Program Files (x86)\Sysinternals\Procmon.exe",
    r"C:\Tools\Sysinternals\Procmon.exe",
]


def find_procmon_executable() -> Path:
    """Find and return the path to the Procmon executable."""
    # Check PATH
    for name in ("Procmon.exe", "Procmon64.exe", "procmon.exe", "procmon"):
        found = shutil.which(name)
        if found:
            return Path(found).resolve()

    # Check common installation locations
    for common_path in COMMON_PROCMON_PATHS:
        path = Path(common_path)
        if path.is_file():
            return path.resolve()

    raise FileNotFoundError(
        "Could not find Procmon executable automatically in PATH or common Sysinternals installation paths."
    )


def generate_pmc_config_bytes() -> bytes:
    """Build binary PMC configuration bytes that enable all standard columns and disable filters."""
    col_map = list(ALL_STANDARD_COLUMNS) + [Column.NONE] * (64 - len(ALL_STANDARD_COLUMNS))
    widths = [100] * len(ALL_STANDARD_COLUMNS) + [0] * (64 - len(ALL_STANDARD_COLUMNS))
    config = {
        "Columns": widths,
        "ColumnCount": len(ALL_STANDARD_COLUMNS),
        "ColumnMap": col_map,
        "DestructiveFilter": 0,
        "FilterRules": [],
        "HighlightRules": [],
    }
    return dumps_configuration(config)


def decompress_pml_data(raw_data: bytes) -> bytes:
    """Decompress PML data using zlib if compressed, or return raw data if already uncompressed."""
    try:
        return zlib.decompress(raw_data)
    except zlib.error:
        # File is already uncompressed
        return raw_data


def convert_pml_to_csv(
    pml_input_path: Path,
    csv_output_path: Path,
    procmon_exe: Path,
    pmc_config_path: Path,
    timeout: float = 120.0,
) -> None:
    """Convert a single PML file to a CSV file using Procmon."""
    logger.info("Converting %s -> %s", pml_input_path.name, csv_output_path.name)

    with open(pml_input_path, "rb") as f:
        input_data = f.read()

    decompressed_pml = decompress_pml_data(input_data)
    logger.debug("Decompressed PML size: %d bytes", len(decompressed_pml))

    with tempfile.TemporaryDirectory() as tmpdir:
        temp_dir = Path(tmpdir)
        temp_pml = temp_dir / "input.pml"
        temp_csv = temp_dir / "output.csv"

        temp_pml.write_bytes(decompressed_pml)

        cmd = [
            str(procmon_exe),
            "/AcceptEula",
            "/Quiet",
            "/LoadConfig",
            str(pmc_config_path),
            "/OpenLog",
            str(temp_pml),
            "/SaveAs",
            str(temp_csv),
        ]

        logger.debug("Running Procmon command: %s", " ".join(cmd))
        start_time = time.time()
        result = subprocess.run(cmd, capture_output=True, timeout=timeout)
        elapsed = time.time() - start_time
        logger.debug("Procmon completed in %.2fs with exit code %d", elapsed, result.returncode)

        if result.returncode != 0:
            stderr = result.stderr.decode("utf-8", errors="replace")
            raise RuntimeError(f"Procmon failed with exit code {result.returncode}: {stderr}")

        if not temp_csv.is_file():
            raise RuntimeError(f"Procmon did not produce expected output CSV at: {temp_csv}")

        raw_csv_bytes = temp_csv.read_bytes()
        if not raw_csv_bytes:
            raise RuntimeError(f"Exported CSV for {pml_input_path.name} is empty")

        logger.debug("Exported uncompressed CSV size: %d bytes", len(raw_csv_bytes))

        csv_output_path.parent.mkdir(parents=True, exist_ok=True)
        compressed_csv = zlib.compress(raw_csv_bytes, level=COMPRESSION_LEVEL)
        logger.debug("Compressed CSV size: %d bytes (level %d)", len(compressed_csv), COMPRESSION_LEVEL)
        csv_output_path.write_bytes(compressed_csv)

        # Verification roundtrip
        verified = zlib.decompress(csv_output_path.read_bytes())
        if verified != raw_csv_bytes:
            raise RuntimeError(f"Integrity check failed for compressed CSV: {csv_output_path}")

    logger.info("Successfully updated %s", csv_output_path.name)


def parse_args(args: list[str] | None = None) -> argparse.ArgumentParser:
    """Create and return argument parser for PML to CSV conversion."""
    default_resources_dir = Path(__file__).resolve().parent.parent / "tests" / "resources"

    parser = argparse.ArgumentParser(
        description="Convert Procmon PML log files to compressed CSV files using Process Monitor (Procmon)."
    )
    parser.add_argument(
        "--resources-dir",
        "-d",
        type=Path,
        default=default_resources_dir,
        help=f"Directory containing PML resource files (default: {default_resources_dir}).",
    )
    parser.add_argument(
        "--pml-files",
        "-f",
        nargs="+",
        type=Path,
        default=None,
        help="Specific PML files to convert. If omitted, all matching PML files in --resources-dir are converted.",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=120.0,
        help="Timeout in seconds per Procmon export execution (default: 120s).",
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
        procmon_exe = find_procmon_executable()
        logger.info("Using Procmon executable: %s", procmon_exe)
    except FileNotFoundError as e:
        logger.error("%s", e)
        return 1

    if args.pml_files:
        pml_paths = [p.resolve() for p in args.pml_files]
    else:
        resources_dir = args.resources_dir.resolve()
        if not resources_dir.is_dir():
            logger.error("Resources directory does not exist: %s", resources_dir)
            return 1
        pml_paths = sorted([p for p in resources_dir.iterdir() if p.name.endswith(PML_SUFFIX) and p.is_file()])

    if not pml_paths:
        logger.warning("No PML files found to convert.")
        return 0

    logger.info("Found %d PML file(s) to convert", len(pml_paths))

    pmc_bytes = generate_pmc_config_bytes()

    with tempfile.TemporaryDirectory() as config_tmpdir:
        pmc_config_path = Path(config_tmpdir) / "config.pmc"
        pmc_config_path.write_bytes(pmc_bytes)

        failed_files: list[str] = []
        for pml_path in pml_paths:
            if pml_path.name.endswith(PML_SUFFIX):
                csv_name = pml_path.name[: -len(PML_SUFFIX)] + CSV_SUFFIX
            else:
                csv_name = pml_path.stem + "." + CSV_SUFFIX.lower()
            csv_path = pml_path.parent / csv_name

            try:
                convert_pml_to_csv(
                    pml_input_path=pml_path,
                    csv_output_path=csv_path,
                    procmon_exe=procmon_exe,
                    pmc_config_path=pmc_config_path,
                    timeout=args.timeout,
                )
            except Exception as e:
                logger.error("Failed to convert %s: %s", pml_path.name, e)
                failed_files.append(pml_path.name)

        if failed_files:
            logger.error("Failed to convert %d file(s): %s", len(failed_files), ", ".join(failed_files))
            return 1

    logger.info("All PML files converted successfully.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
