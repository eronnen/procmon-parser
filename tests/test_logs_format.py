
import re
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
    Column.DURATION,
    Column.RELATIVE_TIME,
    Column.COMPLETION_TIME,
    Column.DATE_AND_TIME,
    Column.COMMAND_LINE,
    Column.SEQUENCE,
    Column.COMPANY,
    Column.DESCRIPTION,
    Column.USER,
    Column.IMAGE_PATH,
    Column.SESSION,
    Column.VERSION,
    Column.EVENT_CLASS,
    Column.VIRTUALIZED,
    Column.ARCHITECTURE,
    Column.AUTHENTICATION_ID,
    Column.PARENT_PID,
    #  Column.CATEGORY,
    #  Column.DETAIL,
]

PARTIAL_SUPPORTED_COLUMNS = {
    Column.DETAIL: [
        "TCP Unknown", "UDP Unknown",
        "TCP Other", "UDP Other",
        "TCP Send", "UDP Send",
        "TCP Receive", "UDP Receive",
        "TCP Accept", "UDP Accept",
        "TCP Connect", "UDP Connect",
        "TCP Disconnect", "UDP Disconnect",
        "TCP Reconnect", "UDP Reconnect",
        "TCP Retransmit", "UDP Retransmit",
        "TCP TCPCopy", "UDP TCPCopy",

        "Process Defined",
        "Process Create",
        "Process Start",
        "Thread Exit",
        "Load Image",

        "RegQueryValue",
        "RegEnumValue",
    ],

    Column.CATEGORY: [
        "RegQueryValue",
        "RegEnumValue",
    ]
}


def are_we_better_than_procmon(pml_record, csv_record, column_name, i):
    if pml_record["Operation"] != csv_record["Operation"]:
        return False

    if column_name == "Detail":
        if "Reg" in csv_record["Operation"]:
            if "Data: " in csv_record["Detail"] and "Type: REG_" in csv_record["Detail"]:
                pml_data = re.search("Data: (.*)", pml_record["Detail"]).group(1)
                csv_data = re.search("Data: (.*)", csv_record["Detail"]).group(1)
                pml_detail = pml_record["Detail"][:pml_record["Detail"].index(pml_data)]
                csv_detail = csv_record["Detail"][:csv_record["Detail"].index(csv_data)]
                if pml_detail != csv_detail:
                    return False

                # Sometimes they have an overflow reading registry data!
                return len(pml_data) > 0 and pml_data in csv_data
    return False


def check_pml_equals_csv(csv_reader, pml_reader):
    first_event_date = None
    i = 0
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
            column_name = ColumnToOriginalName[column]
            pml_value = pml_compatible_record[column_name]
            csv_value = csv_record[column_name]
            if column_name == "Operation" and csv_value == "<Unknown>":
                assert "<Unknown>" in pml_value  # Sometimes there are unknown sub operations
                continue
            if pml_value != csv_value:
                raise AssertionError(
                    "Event {}, Column {}: PMl=\"{}\", CSV=\"{}\".\n PML Event: {}\nCSV Event: {}".format(
                        i+1, column_name, pml_value, csv_value, repr(pml_record), csv_record))

        for column in PARTIAL_SUPPORTED_COLUMNS:
            column_name = ColumnToOriginalName[column]
            if csv_record["Operation"] != "<Unknown>":
                assert pml_compatible_record["Operation"] == csv_record["Operation"]
            if pml_compatible_record["Operation"] in PARTIAL_SUPPORTED_COLUMNS[column]:
                pml_value = pml_compatible_record[column_name]
                csv_value = csv_record[column_name]
                if pml_value != csv_value and not are_we_better_than_procmon(pml_compatible_record, csv_record,
                                                                             column_name, i):
                    raise AssertionError("Event {}, Column {}: PMl=\"{}\", CSV=\"{}\"".format(
                        i + 1, column_name, pml_value, csv_value))


def test_pml_equals_csv_32bit(csv_reader_windows7_32bit, pml_reader_windows7_32bit):
    check_pml_equals_csv(csv_reader_windows7_32bit, pml_reader_windows7_32bit)


def test_pml_equals_csv_64bit(csv_reader_windows10_64bit, pml_reader_windows10_64bit):
    check_pml_equals_csv(csv_reader_windows10_64bit, pml_reader_windows10_64bit)


def test_processes_windows_10_64bit(pml_reader_windows10_64bit):
    processes = pml_reader_windows10_64bit.processes()
    assert 25 == len(processes)
    explorer = next(p for p in processes if p.process_name.lower() == "explorer.exe")
    assert explorer.is_process_64bit
    assert explorer.session == 1
    assert explorer.integrity == "Medium"
    assert explorer.company == "Microsoft Corporation"


def test_windows_7_32bit_system_details(pml_reader_windows7_32bit):
    system_details = pml_reader_windows7_32bit.system_details()
    assert system_details["Computer Name"] == "WIN-5V8CQK0CP5H"
    assert system_details["Operating System"] == "Windows 7, Service Pack 1 (build 7601.2)"
    assert system_details["System Root"] == "C:\\Windows"
    assert system_details["Logical Processors"] == 1
    assert system_details["Memory (RAM)"] == "1.99 GB"
    assert system_details["System Type"] == "32-bit"


def test_windows_10_64bit_system_details(pml_reader_windows10_64bit):
    system_details = pml_reader_windows10_64bit.system_details()
    assert system_details["Computer Name"] == "DESKTOP-6PCIALL"
    assert system_details["Operating System"] == "Windows 10 (build 16299.2)"
    assert system_details["System Root"] == "C:\\Windows"
    assert system_details["Logical Processors"] == 2
    assert system_details["Memory (RAM)"] == "1.99 GB"
    assert system_details["System Type"] == "64-bit"
