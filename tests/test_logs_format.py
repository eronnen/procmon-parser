
from six import PY2
from six.moves import zip_longest
from procmon_parser.consts import Column, ColumnToOriginalName


SUPPORTED_COLUMNS = [
    Column.TIME_OF_DAY,
    Column.PID,
    Column.PROCESS_NAME,
    Column.OPERATION,
    Column.PATH,
    Column.RESULT,
    #Column.DURATION,
    Column.RELATIVE_TIME,
    #Column.DATE_AND_TIME,
    Column.COMMAND_LINE,
]


def check_pml_equals_csv(csv_reader, pml_reader):
    first_event_date = None
    for i, (csv_record, pml_record) in enumerate(zip_longest(csv_reader, pml_reader)):
        assert csv_record is not None, "PML reader has read more events then the CSV reader after {} records.".format(i)
        assert pml_record is not None, "CSV reader has read more events then the PML reader after {} records.".format(i)

        first_event_date = first_event_date if first_event_date else pml_record.date
        try:
            pml_compatible_record = pml_record.get_compatible_csv_info(first_event_date)
        except UnicodeEncodeError:
            if PY2:
                continue  # problem
            raise

        for column in SUPPORTED_COLUMNS:
            pml_value = pml_compatible_record[column]
            csv_value = csv_record[ColumnToOriginalName[column]]
            if pml_value != csv_value:
                if column == Column.OPERATION and csv_value == "<Unknown>":
                    continue  # TODO: why there is "<Unknown>" here by the original procmon???
                raise AssertionError("Event {}, Column {}: PMl=\"{}\", CSV=\"{}\"".format(
                    i+1, ColumnToOriginalName[column], pml_value, csv_value))


def test_pml_equals_csv_32bit(log_readers_32bit):
    csv_reader, pml_reader = log_readers_32bit
    check_pml_equals_csv(csv_reader, pml_reader)


def test_pml_equals_csv_64bit(log_readers_64bit):
    csv_reader, pml_reader = log_readers_64bit
    check_pml_equals_csv(csv_reader, pml_reader)
