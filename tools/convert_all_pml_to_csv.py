"""Utility script to convert Procmon PML log files to CSV files using Process Monitor (Procmon).

This script decompresses compressed PML files, runs Process Monitor to export them
as CSV with all 27 standard columns, and optionally compresses the resulting CSV with zlib.
"""

from __future__ import annotations

import argparse
import logging
import sys
import tempfile
from pathlib import Path

from procmon_common import (
    CSV_SUFFIX,
    PML_SUFFIX,
    convert_pml_to_csv,
    find_procmon_executable,
    generate_pmc_config_bytes,
)

logger = logging.getLogger(__name__)


def parse_args(args: list[str] | None = None) -> argparse.ArgumentParser:
    """Create and return argument parser for PML to CSV conversion."""
    default_resources_dir = Path(__file__).resolve().parent.parent / "tests" / "resources"

    parser = argparse.ArgumentParser(description="Convert Procmon PML log files to CSV files using Process Monitor (Procmon).")
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
        "--no-compress",
        action="store_true",
        help="Do not compress the output CSV files with zlib (save as raw CSV files with .CSV extension).",
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
                csv_name = pml_path.name[: -len(PML_SUFFIX)] + (".CSV" if args.no_compress else CSV_SUFFIX)
            else:
                csv_name = pml_path.stem + (".CSV" if args.no_compress else "." + CSV_SUFFIX.lower())
            csv_path = pml_path.parent / csv_name

            try:
                convert_pml_to_csv(
                    pml_input_path=pml_path,
                    csv_output_path=csv_path,
                    procmon_exe=procmon_exe,
                    pmc_config_path=pmc_config_path,
                    compress_output=not args.no_compress,
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
