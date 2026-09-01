
import re
from datetime import timedelta, timezone
from itertools import zip_longest

from dateutil.parser import parse

from procmon_parser.consts import (
    Column,
    ColumnToOriginalName,
    NetworkOperation,
    ProcessOperation,
    ProfilingOperation,
    RegistryOperation,
)
from tests.mismatch_report import print_mismatch

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
        "CloseFile",
        "QueryRemoteProtocolInformation",
        "QueryIdInformation",
        "CreateFile",
        "CreateFileMapping",
        "ReadFile",
        "WriteFile",
        "QueryDirectory",
        "NotifyChangeDirectory",
        "FilesystemControl",
        "DeviceIoControl",
        "InternalDeviceIoControl",
        "Shutdown",
        "SetDispositionInformationFile",
        "FlushBuffersFile",
        "QueryNameInformationFile",
        "CreatePipe",
    ] + ["TCP " + op.csv_name for op in NetworkOperation] + ["UDP " + op.csv_name for op in NetworkOperation] + \
        [op.csv_name for op in RegistryOperation] + [op.csv_name for op in ProcessOperation] + \
        [op.csv_name for op in ProfilingOperation],

    Column.CATEGORY: [
        "CloseFile",
        "QueryRemoteProtocolInformation",
        "QueryIdInformation",
        "CreateFile",
        "ReadFile",
        "WriteFile",
        "QueryDirectory",
        "NotifyChangeDirectory",
        "FilesystemControl",
        "DeviceIoControl",
        "InternalDeviceIoControl",
        "Shutdown",
        "SetDispositionInformationFile",
    ] + ["TCP " + op.csv_name for op in NetworkOperation] + ["UDP " + op.csv_name for op in NetworkOperation] + \
        [op.csv_name for op in RegistryOperation] + [op.csv_name for op in ProcessOperation] + \
        [op.csv_name for op in ProfilingOperation],
}

def are_we_better_than_procmon(pml_record, csv_record, column_name, pml_value, csv_value, i):
    if pml_record["Operation"] != csv_record["Operation"]:
        return False

    if column_name == "Detail":
        if csv_record["Event Class"] == "Registry":
            if "Data: " in csv_record["Detail"] and "Type: REG_" in csv_record["Detail"]:
                pml_data_match = re.search("Data: (.*)", pml_record["Detail"])
                csv_data_match = re.search("Data: (.*)", csv_record["Detail"])
                if pml_data_match is None or csv_data_match is None:
                    return False
                pml_data = pml_data_match.group(1)
                csv_data = csv_data_match.group(1)
                pml_detail = pml_record["Detail"][:pml_record["Detail"].index(pml_data)]
                csv_detail = csv_record["Detail"][:csv_record["Detail"].index(csv_data)]
                if pml_detail != csv_detail:
                    return False

                # Sometimes they have an overflow reading registry data!
                if len(pml_data) > 0 and pml_data in csv_data:
                    return True
                elif csv_data in pml_data and csv_data[:16] == pml_data[:16]:
                    return True
            elif csv_record["Operation"] == "RegEnumKey":
                # Sometimes they miss some of the details
                return csv_value in pml_value
        elif csv_record["Event Class"] == "File System":
            if csv_record["Operation"] == "QueryDirectory" and csv_value in pml_value:
                return True  # they don't write long directories sometimes
            elif csv_record["Operation"] == "CreateFileMapping" and "PageProtection" in pml_value \
                    and "PageProtection" in csv_value:
                # Procmon has a bug where they probably read the wrong struct field for PageProtection
                return pml_value[:pml_value.find("PageProtection")] == csv_value[:csv_value.find("PageProtection")]
        elif csv_record["Event Class"] == "Network" and csv_record["Operation"] == "TCP Connect":
            # Sometimes they miss some of the details
            return csv_value in pml_value
        elif csv_record["Event Class"] == "Process" and csv_record["Operation"] == "Process Start":
            # Sometimes they miss some of the command line when it's too long
            return csv_value in pml_value

    if (
        column_name == "Command Line"
        and csv_record["Event Class"] == "Profiling"
        and csv_record["Operation"] == "Process Profiling"
    ):
        # Sometimes they miss some of the command line when it's too long
        return csv_value in pml_value

    return False


def check_pml_equals_csv(csv_reader, pml_reader, is_utc=True):
    """Compares the events of a PML reader against the events of a CSV export of the same log.

    :param is_utc: True if the CSV time strings are in UTC, False if they are in the local timezone.
    """
    first_event_date = None
    i = 0
    for i, (csv_record, pml_record) in enumerate(zip_longest(csv_reader, pml_reader)):
        assert csv_record is not None, f"PML reader has read more events then the CSV reader after {i} records."
        assert pml_record is not None, f"CSV reader has read more events then the PML reader after {i} records."

        first_event_date = first_event_date if first_event_date else pml_record.date_filetime
        pml_compatible_record = pml_record.get_compatible_csv_info(first_event_date, is_utc)

        for column in SUPPORTED_COLUMNS:
            column_name = ColumnToOriginalName[column]
            pml_value = pml_compatible_record[column_name]
            csv_value = csv_record[column_name]
            if pml_value != csv_value and not are_we_better_than_procmon(pml_compatible_record, csv_record,
                                                                             column_name, pml_value, csv_value, i):
                print_mismatch(i + 1, column_name, pml_record, pml_compatible_record, csv_record, pml_value, csv_value)
                raise AssertionError(f"Event {i + 1}, Column {column_name} mismatch, see the printed diff above")

        for column in PARTIAL_SUPPORTED_COLUMNS:
            column_name = ColumnToOriginalName[column]
            if csv_record["Operation"] != "<Unknown>":
                assert pml_compatible_record["Operation"] == csv_record["Operation"]
            if pml_compatible_record["Operation"] in PARTIAL_SUPPORTED_COLUMNS[column]:
                pml_value = pml_compatible_record[column_name]
                csv_value = csv_record[column_name]
                if column_name == "Detail" and "Impersonating" in pml_record.details:
                    # For this detail procmon keeps the SID structure so we can't restore the SID resolved name,
                    # only the S-1-5-... form
                    pml_value = pml_value[:pml_value.index("Impersonating")]
                    csv_value = csv_value[:csv_value.index("Impersonating")]
                elif column_name == "Detail" and "FileInformationClass: " in pml_value:
                    # Field was added only in recent version
                    pml_detail = pml_value.split(", ")
                    pml_value = ", ".join([d for d in pml_detail if "FileInformationClass" not in d])
                    csv_detail = []

                    if "FileInformationClass: " in csv_value:
                        idx = 0
                        for detail in csv_value.split(", "):
                            if ":" not in detail or detail[:detail.index(":")].isnumeric():
                                idx += 1
                            if detail.startswith("FileInformationClass: "):
                                if idx == 2 and str(idx) in pml_record.details:
                                    # They stupid
                                    csv_detail.append(f"{idx!s}: {pml_record.details[str(idx)]}")
                            else:
                                csv_detail.append(detail)

                        csv_value = ", ".join(csv_detail)
                if pml_value != csv_value and not are_we_better_than_procmon(pml_compatible_record, csv_record,
                                                                             column_name, pml_value, csv_value, i):
                    print_mismatch(i + 1, column_name, pml_record, pml_compatible_record, csv_record, pml_value,
                                   csv_value)
                    raise AssertionError(f"Event {i + 1}, Column {column_name} mismatch, see the printed diff above")


def test_pml_equals_csv_32bit(csv_reader_windows7_32bit, pml_reader_windows7_32bit):
    check_pml_equals_csv(csv_reader_windows7_32bit, pml_reader_windows7_32bit)


def test_pml_equals_csv_64bit(csv_reader_windows10_64bit, pml_reader_windows10_64bit):
    check_pml_equals_csv(csv_reader_windows10_64bit, pml_reader_windows10_64bit)


def test_pml_equals_csv_specific_events(specific_events_logs_readers):
    check_pml_equals_csv(specific_events_logs_readers[0], specific_events_logs_readers[1])


def test_processes_windows_10_64bit(pml_reader_windows10_64bit):
    processes = pml_reader_windows10_64bit.processes()
    assert len(processes) == 25
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


def test_date_parsing(csv_reader_windows10_64bit, pml_reader_windows10_64bit):
    pml_date1 = next(pml_reader_windows10_64bit).date()
    csv_event1 = next(csv_reader_windows10_64bit)
    csv_date1 = parse(csv_event1["Date & Time"]).replace(tzinfo=timezone.utc) + timedelta(
        microseconds=parse(csv_event1["Time of Day"]).microsecond)
    assert pml_date1 == csv_date1
