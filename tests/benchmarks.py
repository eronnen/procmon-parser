import argparse
import glob
import io
import timeit

from six import PY2
if PY2:
    from unicodecsv import DictReader
    from codecs import BOM_UTF8
else:
    from csv import DictReader

from itertools import chain
from procmon_parser import ProcmonLogsReader


def read_pml_logs(pml_path):
    """Reads a pml, and linked PML files if exist
    """
    pml_readers = []
    for logfile_path in [pml_path] + glob.glob("{0}-*.{1}".format(*pml_path.rsplit('.', 1))):
        pml_readers.append(ProcmonLogsReader(open(logfile_path, "rb"), should_get_stacktrace=False))
    pml_reader = chain(*pml_readers)
    for _ in pml_reader:
        pass


def read_csv_logs(csv_path):
    if PY2:
        with io.open(csv_path, "rb") as f:
            bom = f.read(len(BOM_UTF8))
            assert bom == BOM_UTF8, "Unexpected Procmon csv encoding"
            csv_reader = DictReader(f, encoding='utf-8')

            for _ in csv_reader:
                pass
    else:
        with open(csv_path, "r", encoding="utf-8-sig") as f:
            csv_reader = DictReader(f)
            for _ in csv_reader:
                pass


def benchmark(pml_path, csv_path):
    setup = "from __main__ import read_pml_logs, read_csv_logs"
    print(timeit.timeit("read_pml_logs(\"{}\")".format(pml_path).replace('\\', '\\\\'), setup=setup, number=5))
    print(timeit.timeit("read_csv_logs(\"{}\")".format(csv_path).replace('\\', '\\\\'), setup=setup, number=5))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--pml-path", type=str, help="Path to PML file")
    parser.add_argument("--csv-path", type=str, help="Path to CSV file converted from the PML")
    args = parser.parse_args()
    benchmark(args.pml_path, args.csv_path)


if __name__ == "__main__":
    main()
