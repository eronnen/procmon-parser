
import re
from dateutil.parser import parse
from datetime import timedelta
from six import PY2
from six.moves import zip_longest
from procmon_parser.consts import Column, ColumnToOriginalName, RegistryOperation, NetworkOperation, ProcessOperation


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
        "SetDispositionInformationFile"
    ] + ["TCP " + op.name for op in NetworkOperation] + ["UDP " + op.name for op in NetworkOperation] +
        [op.name for op in RegistryOperation] + [op.name for op in ProcessOperation],

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
    ] + ["TCP " + op.name for op in NetworkOperation] + ["UDP " + op.name for op in NetworkOperation] +
        [op.name for op in RegistryOperation] + [op.name for op in ProcessOperation]
}


def is_operation_not_unknown(operation):
    if operation in ["SetStorageReservedIdInformation", "QuerySatLxInformation",
                                   "QueryCaseSensitiveInformation", "QueryLinkInformationEx",
                                   "QueryLinkInfomraitonBypassAccessCheck", "QueryStorageReservedIdInformation",
                                   "QueryCaseSensitiveInformationForceAccessCheck"]:
        return True  # These operations were added in 3.60 and are not recognized by 3.53
    return False


def are_we_better_than_procmon(pml_record, csv_record, column_name, pml_value, csv_value, i):
    if pml_record["Operation"] != csv_record["Operation"]:
        return False

    if column_name == "Detail":
        if "Registry" == csv_record["Event Class"]:
            if "Data: " in csv_record["Detail"] and "Type: REG_" in csv_record["Detail"]:
                pml_data = re.search("Data: (.*)", pml_record["Detail"]).group(1)
                csv_data = re.search("Data: (.*)", csv_record["Detail"]).group(1)
                pml_detail = pml_record["Detail"][:pml_record["Detail"].index(pml_data)]
                csv_detail = csv_record["Detail"][:csv_record["Detail"].index(csv_data)]
                if pml_detail != csv_detail:
                    return False

                # Sometimes they have an overflow reading registry data!
                if len(pml_data) > 0 and pml_data in csv_data:
                    return True
                elif csv_data in pml_data and csv_data[:16] == pml_data[:16]:
                    return True
        elif "File System" == csv_record["Event Class"]:
            if "QueryDirectory" == csv_record["Operation"]:
                if csv_value in pml_value:
                    return True  # they don't write long directories sometimes
            elif "CreateFileMapping" == csv_record["Operation"]:
                if "PageProtection" in pml_value and "PageProtection" in csv_value:
                    if pml_value[:pml_value.find("PageProtection")] == csv_value[:csv_value.find("PageProtection")]:
                        # Procmon has a bug where they probably read the wrong struct field for PageProtection
                        return True
    return False


def check_pml_equals_csv(csv_reader, pml_reader):
    first_event_date = None
    i = 0
    for i, (csv_record, pml_record) in enumerate(zip_longest(csv_reader, pml_reader)):
        assert csv_record is not None, "PML reader has read more events then the CSV reader after {} records.".format(i)
        assert pml_record is not None, "CSV reader has read more events then the PML reader after {} records.".format(i)

        first_event_date = first_event_date if first_event_date else pml_record.date_filetime
        try:
            pml_compatible_record = pml_record.get_compatible_csv_info(first_event_date)
        except UnicodeEncodeError:
            if PY2:
                continue  # problem
            raise

        if csv_record["Operation"] == "<Unknown>" and pml_compatible_record["Operation"] != "<Unknown>":
            if is_operation_not_unknown(pml_compatible_record["Operation"]):
                continue

        for column in SUPPORTED_COLUMNS:
            column_name = ColumnToOriginalName[column]
            pml_value = pml_compatible_record[column_name]
            csv_value = csv_record[column_name]
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
                                    csv_detail.append("{}: {}".format(str(idx), pml_record.details[str(idx)]))
                            else:
                                csv_detail.append(detail)

                        csv_value = ", ".join(csv_detail)
                if pml_value != csv_value and not are_we_better_than_procmon(pml_compatible_record, csv_record,
                                                                             column_name, pml_value, csv_value, i):
                    print("In Event {}".format(repr(pml_record)))
                    raise AssertionError("Event {}, Column {}: PMl=\"{}\", CSV=\"{}\"".format(
                        i + 1, column_name, pml_value, csv_value))


def test_pml_equals_csv_32bit(csv_reader_windows7_32bit, pml_reader_windows7_32bit):
    check_pml_equals_csv(csv_reader_windows7_32bit, pml_reader_windows7_32bit)


def test_pml_equals_csv_64bit(csv_reader_windows10_64bit, pml_reader_windows10_64bit):
    check_pml_equals_csv(csv_reader_windows10_64bit, pml_reader_windows10_64bit)


def test_pml_equals_csv_specific_events(specific_events_logs_readers):
    check_pml_equals_csv(specific_events_logs_readers[0], specific_events_logs_readers[1])


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


def test_date_parsing(csv_reader_windows10_64bit, pml_reader_windows10_64bit):
    pml_date1 = next(pml_reader_windows10_64bit).date()
    csv_event1 = next(csv_reader_windows10_64bit)
    csv_date1 = parse(csv_event1["Date & Time"]) + timedelta(microseconds=parse(csv_event1["Time of Day"]).microsecond)
    assert pml_date1 == csv_date1
