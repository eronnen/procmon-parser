import csv
from io import BytesIO, StringIO
from six.moves import zip_longest
from procmon_parser import ProcmonLogsReader
from procmon_parser.consts import Column, ColumnToOriginalName


SUPPORTED_COLUMNS = [
    #  Column.TIME_OF_DAY,
    Column.PID,
    Column.PROCESS_NAME,
    Column.OPERATION,
    Column.PATH,
]


def check_pml_equals_csv(csv_reader, pml_reader):
    first_event_date = None
    for i, (csv_record, pml_record) in enumerate(zip_longest(csv_reader, pml_reader)):
        assert csv_record is not None, "PML reader has read more events then the CSV reader after {} records.".format(i)
        assert pml_record is not None, "CSV reader has read more events then the PML reader after {} records.".format(i)

        first_event_date = first_event_date if first_event_date else pml_record.date
        pml_compatible_record = pml_record.get_compatible_csv_info(first_event_date)
        for column in SUPPORTED_COLUMNS:
            pml_value = pml_compatible_record[column]
            csv_value = csv_record[ColumnToOriginalName[column]]
            if pml_value != csv_value:
                if column == Column.OPERATION and csv_value == "<Unknown>":
                    continue  # TODO: why there is "<Unknown>" here???
                raise AssertionError("Event {}, Column {}: PMl=\"{}\", CSV=\"{}\"".format(
                    i+1, ColumnToOriginalName[column], pml_value, csv_value))


def test_pml_equals_csv_32bit(pml_logs_32bit, csv_logs_32bit):
    pml_stream = BytesIO(pml_logs_32bit)
    csv_stream = StringIO(csv_logs_32bit)
    pml_reader = ProcmonLogsReader(pml_stream)
    csv_reader = csv.DictReader(csv_stream)
    check_pml_equals_csv(csv_reader, pml_reader)


def test_pml_equals_csv_64bit(pml_logs_64bit, csv_logs_64bit):
    pml_stream = BytesIO(pml_logs_64bit)
    csv_stream = StringIO(csv_logs_64bit)
    pml_reader = ProcmonLogsReader(pml_stream)
    csv_reader = csv.DictReader(csv_stream)
    check_pml_equals_csv(csv_reader, pml_reader)
