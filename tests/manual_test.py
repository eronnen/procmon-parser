import argparse
import glob
import time
from csv import DictReader
from itertools import chain

from procmon_parser import ProcmonLogsReader
from tests.test_logs_format import check_pml_equals_csv


def manual_test_pml_equals_csv_local(pml_path, csv_path):
    start = time.time()
    csv_reader_local = DictReader(open(csv_path, encoding="utf-8-sig"))
    pml_readers = []
    for logfile_path in [pml_path] + glob.glob("{}-*.{}".format(*pml_path.rsplit('.', 1))):
        pml_readers.append(ProcmonLogsReader(open(logfile_path, "rb")))

    loaded = time.time()
    print(f"Loading readers took {loaded - start} seconds")
    pml_reader = chain(*pml_readers)
    check_pml_equals_csv(csv_reader_local, pml_reader)
    print(f"Reading events took {time.time() - loaded} seconds")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--pml-path", type=str, help="Path to PML file")
    parser.add_argument("--csv-path", type=str, help="Path to CSV file converted from the PML")
    args = parser.parse_args()
    manual_test_pml_equals_csv_local(args.pml_path, args.csv_path)


if __name__ == "__main__":
    main()
