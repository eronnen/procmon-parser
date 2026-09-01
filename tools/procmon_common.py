"""Shared helpers for the Procmon command-line utilities in this repository."""

from __future__ import annotations

import logging
import shutil
import subprocess
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
    for name in ("Procmon.exe", "Procmon64.exe", "procmon.exe", "procmon"):
        found = shutil.which(name)
        if found:
            return Path(found).resolve()

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


def _decompress_pml_data(raw_data: bytes) -> bytes:
    """Decompress PML data using zlib if compressed, or return raw data if already uncompressed."""
    try:
        return zlib.decompress(raw_data)
    except zlib.error:
        return raw_data


def convert_pml_to_csv(
    pml_input_path: Path,
    csv_output_path: Path,
    procmon_exe: Path,
    pmc_config_path: Path,
    compress_output: bool = True,
    timeout: float = 120.0,
) -> None:
    """Convert a single PML file to a CSV file using Procmon."""
    logger.info("Converting %s -> %s", pml_input_path.name, csv_output_path.name)

    with open(pml_input_path, "rb") as f:
        input_data = f.read()

    decompressed_pml = _decompress_pml_data(input_data)
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
        result = subprocess.run(
            cmd,
            capture_output=True,
            timeout=timeout,
            creationflags=int(getattr(subprocess, "CREATE_NO_WINDOW", 0)),
        )
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
        if compress_output:
            compressed_csv = zlib.compress(raw_csv_bytes, level=COMPRESSION_LEVEL)
            logger.debug("Compressed CSV size: %d bytes (level %d)", len(compressed_csv), COMPRESSION_LEVEL)
            csv_output_path.write_bytes(compressed_csv)

            verified = zlib.decompress(csv_output_path.read_bytes())
            if verified != raw_csv_bytes:
                raise RuntimeError(f"Integrity check failed for compressed CSV: {csv_output_path}")
        else:
            logger.debug("Writing uncompressed CSV size: %d bytes", len(raw_csv_bytes))
            csv_output_path.write_bytes(raw_csv_bytes)

    logger.info("Successfully updated %s", csv_output_path.name)
