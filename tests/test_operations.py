
import pytest

from procmon_parser.consts import (
    UNKNOWN_CSV_NAME,
    EventClass,
    FilesystemOperation,
    FilesystemSetInformationOperation,
    NetworkOperation,
    ProcessOperation,
    ProfilingOperation,
    RegistryOperation,
)
from procmon_parser.logs import EventOperation


@pytest.mark.parametrize("operation, csv_name", [
    (ProcessOperation.Load_Image, "Load Image"),
    (ProfilingOperation.Thread_Profiling, "Thread Profiling"),
    (RegistryOperation.RegQueryValue, "RegQueryValue"),
    (NetworkOperation.Send, "Send"),
    (FilesystemOperation.IRP_MJ_CLOSE, "IRP_MJ_CLOSE"),
    (FilesystemOperation.FASTIO_MDL_READ_COMPLETE, "FASTIO_MDL_READ_COMPLETE"),
    (FilesystemSetInformationOperation.SetDispositionInformationFile, "SetDispositionInformationFile"),
])
def test_operation_csv_name(operation, csv_name):
    assert operation.csv_name == csv_name
    assert EventOperation(operation).csv_name == csv_name


def test_event_class_csv_name():
    assert EventClass.File_System.csv_name == "File System"
    assert EventClass.Registry.csv_name == "Registry"


def test_network_operation_csv_name_has_protocol():
    operation = EventOperation(NetworkOperation.Send, protocol="TCP")
    assert operation.csv_name == "TCP Send"
    assert operation == "TCP Send"


def test_unknown_sub_operation_csv_name():
    operation = EventOperation(FilesystemOperation.SetInformationFile, unknown_sub_operation=0xff)
    assert operation.is_unknown
    assert operation.csv_name == UNKNOWN_CSV_NAME
    assert operation.type is FilesystemOperation.SetInformationFile


def test_event_operation_keeps_the_typed_operation():
    operation = EventOperation(ProcessOperation.Load_Image)
    assert operation.type is ProcessOperation.Load_Image
    assert operation == "Load_Image"
    assert not operation.is_unknown


def test_operations_of_different_classes_are_not_equal():
    # both are 2, so comparing them by value would mistake one for the other
    assert ProcessOperation.Process_Exit == ProcessOperation.Process_Exit
    assert ProcessOperation.Process_Exit != ProfilingOperation.Debug_Output_Profiling
    assert ProcessOperation.Process_Exit not in [ProfilingOperation.Debug_Output_Profiling]
    assert ProcessOperation.Process_Exit == 2  # they are still the values of the PML format
