"""Utility script to uncompress all compressed resource files in tests/resources to .PML and .CSV files."""

from __future__ import annotations

import argparse
import logging
import sys
import zlib
from pathlib import Path

logger = logging.getLogger(__name__)

PML_SIGNATURE = b"PML_"


def get_uncompressed_filename(filename: str, decompressed_data: bytes) -> str:
    """Determine the uncompressed target filename with appropriate extension (.PML or .CSV)."""
    if filename.endswith(".PML") or filename.endswith(".CSV") or filename.endswith(".pml") or filename.endswith(".csv"):
        return filename

    if filename.endswith("PML"):
        return filename[:-3] + ".PML"
    elif filename.endswith("CSV"):
        return filename[:-3] + ".CSV"
    elif filename.endswith("pml"):
        return filename[:-3] + ".pml"
    elif filename.endswith("csv"):
        return filename[:-3] + ".csv"

    # Auto-detect format from decompressed data
    if decompressed_data.startswith(PML_SIGNATURE):
        return filename + ".PML"
    else:
        return filename + ".CSV"


def uncompress_file(input_path: Path, output_path: Path) -> None:
    """Decompress a single zlib-compressed resource file and write to output_path."""
    logger.info("Decompressing %s -> %s", input_path.name, output_path.name)

    raw_data = input_path.read_bytes()
    try:
        decompressed = zlib.decompress(raw_data)
    except zlib.error:
        logger.warning("%s is not zlib-compressed, copying as-is", input_path.name)
        decompressed = raw_data

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(decompressed)
    logger.debug("Wrote %d bytes to %s", len(decompressed), output_path.name)


def parse_args(args: list[str] | None = None) -> argparse.ArgumentParser:
    """Create and return argument parser for resource decompression."""
    default_resources_dir = Path(__file__).resolve().parent.parent / "tests" / "resources"

    parser = argparse.ArgumentParser(
        description="Uncompress compressed resource files in the resources directory to .PML and .CSV files."
    )
    parser.add_argument(
        "--resources-dir",
        "-d",
        type=Path,
        default=default_resources_dir,
        help=f"Directory containing compressed resource files (default: {default_resources_dir}).",
    )
    parser.add_argument(
        "--output-dir",
        "-o",
        type=Path,
        default=None,
        help="Directory to write uncompressed files to (defaults to --resources-dir).",
    )
    parser.add_argument(
        "--files",
        "-f",
        nargs="+",
        type=Path,
        default=None,
        help="Specific file(s) to uncompress. If omitted, all compressed resource files in --resources-dir are uncompressed.",
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

    resources_dir = args.resources_dir.resolve()
    output_dir = args.output_dir.resolve() if args.output_dir else resources_dir

    if args.files:
        input_files = [f.resolve() for f in args.files]
    else:
        if not resources_dir.is_dir():
            logger.error("Resources directory does not exist: %s", resources_dir)
            return 1
        # Match all resource files that don't already have an extension or end with PML/CSV
        input_files = sorted(
            [f for f in resources_dir.iterdir() if f.is_file() and not f.name.endswith(".PML") and not f.name.endswith(".CSV")]
        )

    if not input_files:
        logger.warning("No files found to uncompress.")
        return 0

    logger.info("Found %d file(s) to uncompress", len(input_files))

    failed_files: list[str] = []
    for input_file in input_files:
        try:
            raw_data = input_file.read_bytes()
            try:
                decompressed = zlib.decompress(raw_data)
            except zlib.error:
                decompressed = raw_data

            target_filename = get_uncompressed_filename(input_file.name, decompressed)
            output_file = output_dir / target_filename

            output_file.parent.mkdir(parents=True, exist_ok=True)
            output_file.write_bytes(decompressed)
            logger.info("Uncompressed %s -> %s (%d bytes)", input_file.name, target_filename, len(decompressed))
        except Exception as e:
            logger.error("Failed to uncompress %s: %s", input_file.name, e)
            failed_files.append(input_file.name)

    if failed_files:
        logger.error("Failed to uncompress %d file(s): %s", len(failed_files), ", ".join(failed_files))
        return 1

    logger.info("All files uncompressed successfully.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
