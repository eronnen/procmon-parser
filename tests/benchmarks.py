import argparse
import contextlib
import glob
import timeit
from csv import DictReader
from itertools import chain

from procmon_parser import ProcmonLogsReader


def read_pml_logs(pml_path):
    """Reads a pml, and linked PML files if exist
    """
    logfile_paths = [pml_path, *glob.glob("{}-*.{}".format(*pml_path.rsplit('.', 1)))]
    with contextlib.ExitStack() as stack:
        pml_readers = [
            ProcmonLogsReader(stack.enter_context(open(logfile_path, "rb")), should_get_stacktrace=False)
            for logfile_path in logfile_paths
        ]
        for _ in chain(*pml_readers):
            pass


def read_csv_logs(csv_path):
    with open(csv_path, encoding="utf-8-sig") as f:
        csv_reader = DictReader(f)
        for _ in csv_reader:
            pass


def benchmark(pml_path, csv_path):
    setup = "from __main__ import read_pml_logs, read_csv_logs"
    print(timeit.timeit(f"read_pml_logs(\"{pml_path}\")".replace('\\', '\\\\'), setup=setup, number=5))
    print(timeit.timeit(f"read_csv_logs(\"{csv_path}\")".replace('\\', '\\\\'), setup=setup, number=5))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--pml-path", type=str, help="Path to PML file")
    parser.add_argument("--csv-path", type=str, help="Path to CSV file converted from the PML")
    args = parser.parse_args()
    benchmark(args.pml_path, args.csv_path)


if __name__ == "__main__":
    main()
