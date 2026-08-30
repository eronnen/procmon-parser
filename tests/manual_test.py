import argparse
import contextlib
import glob
import time
from csv import DictReader
from itertools import chain

from procmon_parser import ProcmonLogsReader
from tests.test_logs_format import check_pml_equals_csv


def manual_test_pml_equals_csv_local(pml_path, csv_path, is_utc=False):
    start = time.time()
    logfile_paths = [pml_path, *glob.glob("{}-*.{}".format(*pml_path.rsplit('.', 1)))]
    with contextlib.ExitStack() as stack:
        csv_reader_local = DictReader(stack.enter_context(open(csv_path, encoding="utf-8-sig")))
        pml_readers = [
            ProcmonLogsReader(stack.enter_context(open(logfile_path, "rb"))) for logfile_path in logfile_paths
        ]

        loaded = time.time()
        print(f"Loading readers took {loaded - start} seconds")
        check_pml_equals_csv(csv_reader_local, chain(*pml_readers), is_utc)
        print(f"Reading events took {time.time() - loaded} seconds")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--pml-path", type=str, help="Path to PML file")
    parser.add_argument("--csv-path", type=str, help="Path to CSV file converted from the PML")
    parser.add_argument("--utc", action="store_true",
                        help="The CSV time strings are in UTC instead of the local timezone")
    args = parser.parse_args()
    manual_test_pml_equals_csv_local(args.pml_path, args.csv_path, args.utc)


if __name__ == "__main__":
    main()
