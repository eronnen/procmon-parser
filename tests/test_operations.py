
import pytest

from procmon_parser.consts import (
    UNKNOWN_CSV_NAME,
    Column,
    ColumnToOriginalName,
    EventClass,
    FilesystemOperation,
    FilesystemSetInformationOperation,
    NetworkOperation,
    ProcessOperation,
    ProfilingOperation,
    RegistryOperation,
)
from procmon_parser.logs import Event, Process


def build_event(event_class, operation, **kwargs):
    process = Process(pid=4, parent_pid=0)
    return Event(process=process, tid=8, event_class=event_class, operation=operation, duration=0, date_filetime=0,
                 **kwargs)


def csv_operation_name(event):
    return event.get_compatible_csv_info()[ColumnToOriginalName[Column.OPERATION]]


@pytest.mark.parametrize("event_class, operation, csv_name", [
    (EventClass.Process, ProcessOperation.Load_Image, "Load Image"),
    (EventClass.Profiling, ProfilingOperation.Thread_Profiling, "Thread Profiling"),
    (EventClass.Registry, RegistryOperation.RegQueryValue, "RegQueryValue"),
    (EventClass.Network, NetworkOperation.Send, "Send"),
    (EventClass.File_System, FilesystemOperation.IRP_MJ_CLOSE, "IRP_MJ_CLOSE"),
    (EventClass.File_System, FilesystemOperation.FASTIO_MDL_READ_COMPLETE, "FASTIO_MDL_READ_COMPLETE"),
    (EventClass.File_System, FilesystemSetInformationOperation.SetDispositionInformationFile,
     "SetDispositionInformationFile"),
])
def test_operation_csv_name(event_class, operation, csv_name):
    assert operation.csv_name == csv_name
    assert csv_operation_name(build_event(event_class, operation)) == csv_name


def test_event_class_csv_name():
    assert EventClass.File_System.csv_name == "File System"
    assert EventClass.Registry.csv_name == "Registry"


def test_network_operation_csv_name_has_protocol():
    event = build_event(EventClass.Network, NetworkOperation.Send, network_protocol="TCP")
    assert csv_operation_name(event) == "TCP Send"


def test_unknown_sub_operation_csv_name():
    event = build_event(EventClass.File_System, FilesystemOperation.SetInformationFile, unknown_sub_operation=0xff)
    assert event.operation is FilesystemOperation.SetInformationFile
    assert csv_operation_name(event) == UNKNOWN_CSV_NAME


def test_operations_of_different_classes_are_not_equal():
    # both are 2, so comparing them by value would mistake one for the other
    assert ProcessOperation.Process_Exit == ProcessOperation.Process_Exit
    assert ProcessOperation.Process_Exit != ProfilingOperation.Debug_Output_Profiling
    assert ProcessOperation.Process_Exit not in [ProfilingOperation.Debug_Output_Profiling]
    assert ProcessOperation.Process_Exit == 2  # they are still the values of the PML format
