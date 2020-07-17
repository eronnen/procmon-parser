from collections import OrderedDict, namedtuple
from procmon_parser.kaitai_helper import duration_from_100nanosecs
from procmon_parser.consts import EventClass, NetworkOperation, RegistryOperation, FilesystemOperation, \
    ProcessOperation, ProfilingOperation, FilesystemQueryInformationOperation, FilesysemDirectoryControlOperation, \
    FilesystemSetInformationOperation, FilesystemPnpOperation, FilesystemQueryVolumeInformationOperation, \
    FilesystemSetVolumeInformationOperation, FilesystemLockUnlockOperation


__all__ = ['get_event_info', 'PmlMetadata']


PmlMetadata = namedtuple('PmlMetadata', ['str_idx', 'process_idx', 'hostname_idx', 'port_idx'])


class EventInfo(object):
    """Represent the information about the event that can be changed for specific operations and sub operations.
    """
    def __init__(self, operation=None, path=None, category=None, details=None):
        self.operation = operation
        self.path = path
        self.category = category
        self.details = details


def get_network_event_info(kaitai_event, pml_metadata):
    details = kaitai_event.details
    protocol = "TCP" if details.flags.is_tcp else "UDP"
    operation = protocol + " " + NetworkOperation(kaitai_event.operation).name

    path = "{}:{} -> {}:{}".format(pml_metadata.hostname_idx(details.source_host_ip, details.flags.is_source_ipv4),
                                   pml_metadata.port_idx(details.source_port, details.flags.is_tcp),
                                   pml_metadata.hostname_idx(details.dest_host_ip, details.flags.is_dest_ipv4),
                                   pml_metadata.port_idx(details.dest_port, details.flags.is_tcp))

    extra_details = OrderedDict([("Length", kaitai_event.details.packet_length)])
    for i in range(len(details.extra_details) // 2):
        extra_details[details.extra_details[i * 2]] = details.extra_details[i * 2 + 1]

    return EventInfo(operation=operation, path=path, category="", details=extra_details)


def get_registry_event_info(kaitai_event, pml_metadata):
    operation = RegistryOperation(kaitai_event.operation)
    path = kaitai_event.details.path.string
    return EventInfo(operation=operation.name, path=path, category="", details=OrderedDict())


def calculate_filesystem_directory_control_info(event_details, info):
    if info.operation == FilesysemDirectoryControlOperation.QueryDirectory.name \
            and event_details.extra_details.sub_operation_details.directory_name.string:
        dirname = event_details.extra_details.sub_operation_details.directory_name.string
        info.path = info.path + dirname if info.path[-1] == "\\" else info.path + "\\" + dirname
        info.details['Filter'] = dirname


FilesystemSpecificOperationHandler = {
    FilesystemOperation.DirectoryControl: calculate_filesystem_directory_control_info
}


FilesystemSubOperations = {
    FilesystemOperation.QueryVolumeInformation: FilesystemQueryVolumeInformationOperation,
    FilesystemOperation.SetVolumeInformation: FilesystemSetVolumeInformationOperation,
    FilesystemOperation.QueryInformationFile: FilesystemQueryInformationOperation,
    FilesystemOperation.SetInformationFile: FilesystemSetInformationOperation,
    FilesystemOperation.DirectoryControl: FilesysemDirectoryControlOperation,
    FilesystemOperation.PlugAndPlay: FilesystemPnpOperation,
    FilesystemOperation.LockUnlockFile: FilesystemLockUnlockOperation,
}


def get_filesystem_event_info(kaitai_event, pml_metadata):
    extra_details = OrderedDict()
    path = kaitai_event.details.path.string
    operation = FilesystemOperation(kaitai_event.operation)
    info = EventInfo(operation=operation.name, path=path, category="", details=extra_details)

    # fix specific info according to sub operation
    if kaitai_event.operation != 0 and operation in FilesystemSubOperations:
        try:
            info.operation = FilesystemSubOperations[operation](kaitai_event.details.sub_operation).name
        except ValueError:
            info.operation += " <Unknown>"
    FilesystemSpecificOperationHandler.get(operation, lambda _1, _2: None)(kaitai_event.details, info)

    return info


def calculate_process_created_info(event_details, info):
    info.path = event_details.extra_details.path.string
    info.details["PID"] = event_details.extra_details.created_pid
    info.details["Command line"] = event_details.extra_details.command_line.string


def calculate_process_started_info(event_details, info):
    info.details["Parent PID"] = event_details.extra_details.parent_pid
    info.details["Command line"] = event_details.extra_details.command_line.string
    info.details["Current directory"] = event_details.extra_details.current_directory.string
    info.details["Environment"] = event_details.extra_details.environment


def calculate_load_image_info(event_details, info):
    info.path = event_details.extra_details.path.string
    info.details["Image Base"] = event_details.extra_details.image_base.value
    info.details["Image Size"] = event_details.extra_details.image_size


def calculate_thread_exit_info(event_details, info):
    info.details["Thread ID"] = event_details._parent.thread_id
    info.details["User Time"] = duration_from_100nanosecs(event_details.extra_details.user_time)
    info.details["Kernel Time"] = duration_from_100nanosecs(event_details.extra_details.kernel_time)


ProcessSpecificOperationHandler = {
    ProcessOperation.Process_Defined: calculate_process_created_info,
    ProcessOperation.Process_Create: calculate_process_created_info,
    ProcessOperation.Thread_Exit: calculate_thread_exit_info,
    ProcessOperation.Load_Image: calculate_load_image_info,
    ProcessOperation.Process_Start: calculate_process_started_info,
}


def get_process_event_info(kaitai_event, pml_metadata):
    extra_details = OrderedDict()
    operation = ProcessOperation(kaitai_event.operation)
    info = EventInfo(operation=operation.name, path="", category="", details=extra_details)
    ProcessSpecificOperationHandler.get(operation, lambda _1, _2: None)(kaitai_event.details, info)
    return info


def get_profiling_event_info(kaitai_event, pml_metadata):
    operation = ProfilingOperation(kaitai_event.operation)
    return EventInfo(operation=operation.name, path="", category="", details=OrderedDict())


ClassHandler = {
    EventClass.Unknown: lambda: EventInfo("<Unknown>", "", "", OrderedDict()),
    EventClass.Process: get_process_event_info,
    EventClass.Registry: get_registry_event_info,
    EventClass.Network: get_network_event_info,
    EventClass.Profiling: get_profiling_event_info,
    EventClass.File_System: get_filesystem_event_info,
}


def get_event_info(kaitai_event, pml_metadata):
    """Return the event specific information:
    operation name, path, category and extra details
    """
    return ClassHandler[kaitai_event.event_class.value](kaitai_event, pml_metadata)

