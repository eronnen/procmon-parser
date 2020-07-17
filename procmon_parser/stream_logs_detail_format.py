from collections import namedtuple

from procmon_parser.consts import EventClass, ProcessOperation, RegistryOperation, FilesystemOperation, \
    FilesystemSubOperations, \
    FilesysemDirectoryControlOperation
from procmon_parser.stream_helper import read_u8, read_u16, read_u32, read_utf16, read_pvoid, read_duration, \
    read_utf16_multisz, sizeof_pvoid

PmlMetadata = namedtuple('PmlMetadata', ['is_64bit', 'str_idx', 'process_idx', 'hostname_idx', 'port_idx'])


def read_detail_string_info(io):
    """Reads the info field about a detail string (contains is_ascii and number of characters)
    """
    return read_u16(io)


def read_detail_string(io, string_info):
    """Reads a string in the details that has an info field declared before
    """
    is_ascii = string_info >> 15 == 1
    character_count = string_info & (2 ** 15 - 1)
    if is_ascii:
        return io.read(character_count).decode("ascii")
    else:
        return read_utf16(io, character_count * 2)


def get_profiling_event_details(io, metadata, event, extra_detail_io):
    pass


def get_network_event_details(io, metadata, event, extra_detail_io):
    flags = read_u16(io)
    is_source_ipv4 = flags & 1 != 0
    is_dest_ipv4 = flags & 2 != 0
    is_tcp = flags & 4 != 0

    protocol = "TCP" if is_tcp else "UDP"
    event.operation = protocol + " " + event.operation

    io.seek(2, 1)  # Unknown field
    event.details['Length'] = read_u32(io)
    source_ip = io.read(16)
    dest_ip = io.read(16)
    source_port = read_u16(io)
    dest_port = read_u16(io)

    event.path = "{}:{} -> {}:{}".format(
        metadata.hostname_idx(source_ip, is_source_ipv4), metadata.port_idx(source_port, is_tcp),
        metadata.hostname_idx(dest_ip, is_dest_ipv4), metadata.port_idx(dest_port, is_tcp))

    extra_details = read_utf16_multisz(io)
    for i in range(len(extra_details) // 2):
        event.details[extra_details[i * 2]] = extra_details[i * 2 + 1]


def get_registry_event_details(io, metadata, event, extra_detail_io):
    path_info = read_detail_string_info(io)
    if event.operation in [RegistryOperation.RegLoadKey.name, RegistryOperation.RegRenameKey.name]:
        io.seek(2, 1)  # Unknown field
    elif event.operation in [RegistryOperation.RegOpenKey.name, RegistryOperation.RegCreateKey.name]:
        io.seek(6, 1)  # Unknown field
    elif event.operation in [RegistryOperation.RegQueryKey.name, RegistryOperation.RegQueryValue.name]:
        io.seek(10, 1)  # Unknown field
    elif event.operation in [RegistryOperation.RegSetValue.name, RegistryOperation.RegEnumValue.name,
                             RegistryOperation.RegEnumKey.name, RegistryOperation.RegSetInfoKey.name]:
        io.seek(14, 1)  # Unknown field

    event.path = read_detail_string(io, path_info)


def get_filesystem_query_directory_extra_details(io, metadata, event, extra_detail_io):
    directory_name_info = read_detail_string_info(io)
    directory_name = read_detail_string(io, directory_name_info)
    if directory_name:
        event.path = event.path + directory_name if event.path[-1] == "\\" else event.path + "\\" + directory_name
        event.details['Filter'] = directory_name


FilesystemSubOperationHandler = {
    FilesysemDirectoryControlOperation.QueryDirectory.name: get_filesystem_query_directory_extra_details
}


def get_filesystem_event_details(io, metadata, event, extra_detail_io):
    sub_operation = read_u8(io)

    # fix operation name if there is more specific sub operation
    if 0 != sub_operation and FilesystemOperation[event.operation] in FilesystemSubOperations:
        try:
            event.operation = FilesystemSubOperations[FilesystemOperation[event.operation]](sub_operation).name
        except ValueError:
            event.operation += " <Unknown>"

    io.seek(1 + sizeof_pvoid(metadata.is_64bit) * 5 + 0x16, 1)  # Unknown fields
    path_info = read_detail_string_info(io)
    io.seek(2, 1)  # Unknown fields
    event.path = read_detail_string(io, path_info)
    if event.operation in FilesystemSubOperationHandler:
        FilesystemSubOperationHandler[event.operation](io, metadata, event, extra_detail_io)


def get_process_created_details(io, metadata, event, extra_detail_io):
    io.seek(4, 1)  # Unknown fields
    event.details["PID"] = read_u32(io)
    io.seek(0x24, 1)  # Unknown fields
    unknown_size1 = read_u8(io)
    unknown_size2 = read_u8(io)
    path_info = read_detail_string_info(io)
    command_line_info = read_detail_string_info(io)
    io.seek(2 + unknown_size1 + unknown_size2, 1)  # Unknown fields
    event.path = read_detail_string(io, path_info)
    event.details["Command line"] = read_detail_string(io, command_line_info)


def get_process_started_details(io, metadata, event, extra_detail_io):
    event.details["Parent PID"] = read_u32(io)
    command_line_info = read_detail_string_info(io)
    current_directory_info = read_detail_string_info(io)
    environment_character_count = read_u32(io)
    event.details["Command line"] = read_detail_string(io, command_line_info)
    event.details["Current directory"] = read_detail_string(io, current_directory_info)
    event.details["Environment"] = read_utf16_multisz(io, environment_character_count * 2)


def get_load_image_details(io, metadata, event, extra_detail_io):
    event.details["Image Base"] = read_pvoid(io, metadata.is_64bit)
    event.details["Image Size"] = read_u32(io)
    path_info = read_detail_string_info(io)
    io.seek(2, 1)  # Unknown field
    event.path = read_detail_string(io, path_info)


def get_thread_exit_details(io, metadata, event, extra_detail_io):
    event.details["Thread ID"] = event.tid
    io.seek(4, 1)  # Unknown fields
    kernel_time = read_duration(io)
    user_time = read_duration(io)
    event.details["User Time"] = user_time
    event.details["Kernel Time"] = kernel_time


ProcessSpecificOperationHandler = {
    ProcessOperation.Process_Defined.name: get_process_created_details,
    ProcessOperation.Process_Create.name: get_process_created_details,
    ProcessOperation.Thread_Exit.name: get_thread_exit_details,
    ProcessOperation.Load_Image.name: get_load_image_details,
    ProcessOperation.Process_Start.name: get_process_started_details,
}


def get_process_event_details(io, metadata, event, extra_detail_io):
    if event.operation in ProcessSpecificOperationHandler:
        ProcessSpecificOperationHandler[event.operation](io, metadata, event, extra_detail_io)


ClassEventDetailsHandler = {
    EventClass.Process: get_process_event_details,
    EventClass.Registry: get_registry_event_details,
    EventClass.File_System: get_filesystem_event_details,
    EventClass.Profiling: get_profiling_event_details,
    EventClass.Network: get_network_event_details
}


def get_event_details(detail_stream, metadata, event, extra_detail_stream):
    """Calculates the specific details of the event in the stream. The stream should be after the common
    information of the event.

    :param detail_stream: the stream of the details structure.
    :param metadata: metadata of the PML file.
    :param event: the event object to fill.
    :param extra_detail_stream: the stream of the extra details structure.
    """
    ClassEventDetailsHandler[event.event_class](detail_stream, metadata, event, extra_detail_stream)
