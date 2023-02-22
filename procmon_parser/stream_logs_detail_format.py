from collections import namedtuple
from io import BytesIO
from struct import error, unpack

from procmon_parser.consts import EventClass, ProcessOperation, RegistryOperation, FilesystemOperation, \
    FilesystemSubOperations, FilesysemDirectoryControlOperation, RegistryTypes, RegistryKeyValueInformationClass, \
    RegistryKeyInformationClass, get_registry_access_mask_string, RegistryDisposition, RegistryKeySetInformationClass, \
    FilesystemQueryInformationOperation, get_filesystem_access_mask_string, FilesystemDisposition, \
    get_filesysyem_create_options, get_filesysyem_create_attributes, get_filesysyem_create_share_mode, \
    FilesystemOpenResult, get_filesysyem_io_flags, FilesystemPriority, get_ioctl_name, FileInformationClass, \
    get_filesystem_notify_change_flags, FilesystemSetInformationOperation, get_filesystem_createfilemapping_synctype, \
    PageProtection
from procmon_parser.stream_helper import read_u8, read_u16, read_u32, read_utf16, read_duration, \
    read_utf16_multisz, read_u64, read_filetime, read_s64

PmlMetadata = namedtuple('PmlMetadata', ['str_idx', 'process_idx', 'hostname_idx', 'port_idx', 'read_pvoid',
                                         'sizeof_pvoid', 'should_get_stacktrace', 'should_get_details'])


def get_enum_name_or(enum, val, default):
    try:
        return enum(val).name
    except ValueError:
        return default


def get_sid_string(sid):
    revision = unpack('B', sid[0:1])[0]
    if revision != 1:
        return ''  # Not 1 doesn't exist yet
    count = unpack('B', sid[1:2])[0]
    authority = unpack(">Q", b"\x00\x00" + sid[2:8])[0]
    sid_string = 'S-{}-{}'.format(revision, authority)
    binary = sid[8:]
    if len(binary) != 4 * count:
        return ''
    for i in range(count):
        value = unpack('<L', binary[4 * i:4 * (i + 1)])[0]
        sid_string += '-{}'.format(value)
    return sid_string


def read_detail_string_info(io):
    """Reads the info field about a detail string (contains is_ascii and number of characters)
    """
    flags = read_u16(io)
    return flags >> 15 == 1, flags & (2 ** 15 - 1)  # is_ascii, char_count


def read_detail_string(io, string_info):
    """Reads a string in the details that has an info field declared before
    """
    is_ascii, character_count = string_info
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


def read_registry_data(io, reg_type_name, length=0):
    """Reads registry data (which is present in the Detail column in original Procmon) according to ``reg_type``
    """
    try:
        if reg_type_name == RegistryTypes.REG_DWORD.name:
            return read_u32(io)
        elif reg_type_name == RegistryTypes.REG_QWORD.name:
            return read_u64(io)
        elif reg_type_name == RegistryTypes.REG_EXPAND_SZ.name or reg_type_name == RegistryTypes.REG_SZ.name:
            return read_utf16(io)
        elif reg_type_name == RegistryTypes.REG_BINARY.name:
            # Assuming the stream ends at the end of the extra detail, so just read everything
            return io.read(length)
        elif reg_type_name == RegistryTypes.REG_MULTI_SZ.name:
            return read_utf16_multisz(io, length)
    except error:
        return ''

    return ''


def get_reg_type_name(reg_type_value):
    try:
        return RegistryTypes(reg_type_value).name
    except ValueError:
        return "<Unknown: {}>".format(reg_type_value)  # Don't know how to parse this


def get_registry_query_multiple_value_extra_details(metadata, event, extra_detail_io, details_info):
    event.category = "Read"


def get_registry_set_key_security_extra_details(metadata, event, extra_detail_io, details_info):
    event.category = "Write Metadata"


def get_registry_query_key_security_extra_details(metadata, event, extra_detail_io, details_info):
    event.category = "Read Metadata"


def get_registry_delete_key_or_value_extra_details(metadata, event, extra_detail_io, details_info):
    event.category = "Write"


def get_registry_load_or_rename_extra_details(metadata, event, extra_detail_io, details_info):
    new_path = read_detail_string(extra_detail_io, details_info["new_path_info"])
    if event.operation == RegistryOperation.RegLoadKey.name:
        event.details["Hive Path"] = new_path
    elif event.operation == RegistryOperation.RegRenameKey.name:
        event.category = "Write"
        event.details["New Name"] = new_path


def get_registry_query_or_enum_key_extra_details(metadata, event, extra_detail_io, details_info):
    event.category = "Read"  # RegQueryKey and RegEnumKey is always Read
    key_information_class = RegistryKeyInformationClass(details_info["information_class"])

    if event.operation == RegistryOperation.RegEnumKey.name:
        event.details["Index"] = details_info["index"]  # Only in enum
    elif event.operation == RegistryOperation.RegQueryKey.name:
        event.details["Query"] = key_information_class.name # Only in query

    if not extra_detail_io:
        #  There is no extra details
        event.details["Length"] = details_info["length"]
        return

    if key_information_class == RegistryKeyInformationClass.Name:
        # KEY_NAME_INFORMATION structure
        name_size = read_u32(extra_detail_io)
        event.details["Name"] = read_utf16(extra_detail_io, name_size)
    elif key_information_class == RegistryKeyInformationClass.HandleTags:
        event.details["HandleTags"] = read_u32(extra_detail_io)
    elif key_information_class == RegistryKeyInformationClass.Flags:
        event.details["UserFlags"] = read_u32(extra_detail_io)
    elif key_information_class == RegistryKeyInformationClass.Cached:
        # KEY_CACHED_INFORMATION structure
        event.details["LastWriteTime"] = read_filetime(extra_detail_io)
        event.details["TitleIndex"] = read_u32(extra_detail_io)
        event.details["SubKeys"] = read_u32(extra_detail_io)
        event.details["MaxNameLen"] = read_u32(extra_detail_io)
        event.details["Values"] = read_u32(extra_detail_io)
        event.details["MaxValueNameLen"] = read_u32(extra_detail_io)
        event.details["MaxValueDataLen"] = read_u32(extra_detail_io)
    elif key_information_class == RegistryKeyInformationClass.Basic:
        # KEY_BASIC_INFORMATION structure
        event.details["LastWriteTime"] = read_filetime(extra_detail_io)
        event.details["TitleIndex"] = read_u32(extra_detail_io)
        name_size = read_u32(extra_detail_io)
        event.details["Name"] = read_utf16(extra_detail_io, name_size)
    elif key_information_class == RegistryKeyInformationClass.Full:
        # KEY_FULL_INFORMATION structure
        event.details["LastWriteTime"] = read_filetime(extra_detail_io)
        event.details["TitleIndex"] = read_u32(extra_detail_io)
        event.details["ClassOffset"] = read_u32(extra_detail_io)
        event.details["ClassLength"] = read_u32(extra_detail_io)
        event.details["SubKeys"] = read_u32(extra_detail_io)
        event.details["MaxNameLen"] = read_u32(extra_detail_io)
        event.details["MaxClassLen"] = read_u32(extra_detail_io)
        event.details["Values"] = read_u32(extra_detail_io)
        event.details["MaxValueNameLen"] = read_u32(extra_detail_io)
        event.details["MaxValueDataLen"] = read_u32(extra_detail_io)
    elif key_information_class == RegistryKeyInformationClass.Node:
        # KEY_NODE_INFORMATION structure
        event.details["LastWriteTime"] = read_filetime(extra_detail_io)
        event.details["TitleIndex"] = read_u32(extra_detail_io)
        event.details["ClassOffset"] = read_u32(extra_detail_io)
        event.details["ClassLength"] = read_u32(extra_detail_io)
        name_size = read_u32(extra_detail_io)
        event.details["Name"] = read_utf16(extra_detail_io, name_size)


def get_registry_query_or_enum_value_extra_details(metadata, event, extra_detail_io, details_info):
    event.category = "Read"  # RegQueryValue and RegEnumValue are always Read
    key_value_information_class = RegistryKeyValueInformationClass(details_info["information_class"])

    if event.operation == RegistryOperation.RegEnumValue.name:
        event.details["Index"] = details_info["index"]  # Only in enum

    if not extra_detail_io:
        #  There is no extra details
        event.details["Length"] = details_info["length"]
        return

    extra_detail_io.seek(4, 1)  # Unknown field
    reg_type_name = get_reg_type_name(read_u32(extra_detail_io))

    if key_value_information_class == RegistryKeyValueInformationClass.KeyValueFullInformation:
        offset_to_data = read_u32(extra_detail_io)
        length_value = read_u32(extra_detail_io)
        name_size = read_u32(extra_detail_io)
        event.details["Name"] = read_utf16(extra_detail_io, name_size)
        extra_detail_io.seek(offset_to_data, 0)  # the stream starts at the start of the struct so the seek is good
    elif key_value_information_class == RegistryKeyValueInformationClass.KeyValuePartialInformation:
        length_value = read_u32(extra_detail_io)
    else:
        # Only KeyValuePartialInformation and KeyValueFullInformation have Data property
        event.details["Type"] = reg_type_name  # the Type is still known...
        return

    event.details["Type"] = reg_type_name  # I do this assignment here because "Name" comes before "Type"
    event.details["Length"] = length_value

    if length_value > 0:
        event.details["Data"] = read_registry_data(extra_detail_io, reg_type_name, length_value)


def get_registry_open_or_create_key_extra_details(metadata, event, extra_detail_io, details_info):
    event.category = "Read"
    if 0 == details_info["desired_access"]:
        return

    event.details["Desired Access"] = get_registry_access_mask_string(details_info["desired_access"])
    if not extra_detail_io:
        return

    if event.details["Desired Access"] == "Maximum Allowed":
        event.details["Granted Access"] = get_registry_access_mask_string(read_u32(extra_detail_io))
    else:
        extra_detail_io.seek(4, 1)

    disposition = read_u32(extra_detail_io)
    try:
        event.details["Disposition"] = RegistryDisposition(disposition).name
        if event.details["Disposition"] == RegistryDisposition.REG_CREATED_NEW_KEY.name:
            event.category = "Write"
    except ValueError:
        pass


def get_registry_set_info_key_extra_details(metadata, event, extra_detail_io, details_info):
    event.category = "Write Metadata"
    event.details["KeySetInformationClass"] = RegistryKeySetInformationClass.get(
        details_info["key_set_information_class"],
        "<Unknown: {}>".format(details_info["key_set_information_class"])
    )
    event.details["Length"] = details_info["length"]
    if details_info["length"] > 0:
        if event.details["KeySetInformationClass"] == "KeyWriteTimeInformation":
            event.details["LastWriteTime"] = read_filetime(extra_detail_io)
        elif event.details["KeySetInformationClass"] == "KeyWow64FlagsInformation":
            event.details["Wow64Flags"] = read_u32(extra_detail_io)
        elif event.details["KeySetInformationClass"] == "KeyWriteTimeInformation":
            event.details["HandleTags"] = read_u32(extra_detail_io)


def get_registry_set_value_extra_details(metadata, event, extra_detail_io, details_info):
    event.category = "Write"
    event.details["Type"] = get_reg_type_name(details_info["reg_type"])
    event.details["Length"] = details_info["length"]
    length = min(event.details["Length"], details_info["data_length"])
    if length > 0 and "Unknown" not in event.details["Type"]:
        event.details["Data"] = read_registry_data(extra_detail_io, event.details["Type"], length)


RegistryExtraDetailsHandler = {
    RegistryOperation.RegOpenKey.name: get_registry_open_or_create_key_extra_details,
    RegistryOperation.RegCreateKey.name: get_registry_open_or_create_key_extra_details,
    RegistryOperation.RegQueryKey.name: get_registry_query_or_enum_key_extra_details,
    RegistryOperation.RegSetValue.name: get_registry_set_value_extra_details,
    RegistryOperation.RegQueryValue.name: get_registry_query_or_enum_value_extra_details,
    RegistryOperation.RegEnumValue.name: get_registry_query_or_enum_value_extra_details,
    RegistryOperation.RegEnumKey.name: get_registry_query_or_enum_key_extra_details,
    RegistryOperation.RegSetInfoKey.name: get_registry_set_info_key_extra_details,
    RegistryOperation.RegDeleteKey.name: get_registry_delete_key_or_value_extra_details,
    RegistryOperation.RegDeleteValue.name: get_registry_delete_key_or_value_extra_details,
    RegistryOperation.RegLoadKey.name: get_registry_load_or_rename_extra_details,
    RegistryOperation.RegRenameKey.name: get_registry_load_or_rename_extra_details,
    RegistryOperation.RegQueryMultipleValueKey.name: get_registry_query_multiple_value_extra_details,
    RegistryOperation.RegSetKeySecurity.name: get_registry_set_key_security_extra_details,
    RegistryOperation.RegQueryKeySecurity.name: get_registry_query_key_security_extra_details,
}


def get_registry_event_details(io, metadata, event, extra_detail_io):
    path_info = read_detail_string_info(io)
    details_info = dict()  # information that is needed by the extra details structure

    if event.operation in [RegistryOperation.RegLoadKey.name, RegistryOperation.RegRenameKey.name]:
        details_info["new_path_info"] = read_detail_string_info(io)
        extra_detail_io = io  # the new path is a part of the details structure
    elif event.operation in [RegistryOperation.RegOpenKey.name, RegistryOperation.RegCreateKey.name]:
        io.seek(2, 1)  # Unknown field
        details_info["desired_access"] = read_u32(io)
    elif event.operation in [RegistryOperation.RegQueryKey.name, RegistryOperation.RegQueryValue.name]:
        io.seek(2, 1)  # Unknown field
        details_info["length"] = read_u32(io)
        details_info["information_class"] = read_u32(io)
    elif event.operation in [RegistryOperation.RegEnumValue.name, RegistryOperation.RegEnumKey.name]:
        io.seek(2, 1)  # Unknown field
        details_info["length"] = read_u32(io)
        details_info["index"] = read_u32(io)
        details_info["information_class"] = read_u32(io)
    elif event.operation == RegistryOperation.RegSetInfoKey.name:
        io.seek(2, 1)  # Unknown field
        details_info["key_set_information_class"] = read_u32(io)
        io.seek(4, 1)  # Unknown field
        details_info["length"] = read_u16(io)
        io.seek(2, 1)  # Unknown field
        extra_detail_io = io  # For RegSetInfoKey the data is in the details structure
    elif event.operation == RegistryOperation.RegSetValue.name:
        io.seek(2, 1)  # Unknown field
        details_info["reg_type"] = read_u32(io)
        details_info["length"] = read_u32(io)
        details_info["data_length"] = read_u32(io)
        extra_detail_io = io  # For RegSetValue the data is in the details structure

    event.path = read_detail_string(io, path_info)

    # Get the extra details structure
    if metadata.should_get_details and event.operation in RegistryExtraDetailsHandler:
        RegistryExtraDetailsHandler[event.operation](metadata, event, extra_detail_io, details_info)


def get_filesystem_read_metadata_details(io, metadata, event, details_io, extra_detail_io):
    event.category = "Read Metadata"


def get_filesystem_query_directory_details(io, metadata, event, details_io, extra_detail_io):
    event.category = "Read Metadata"
    directory_name_info = read_detail_string_info(io)
    directory_name = read_detail_string(io, directory_name_info)
    if directory_name:
        event.path = event.path + directory_name if event.path[-1] == "\\" else event.path + "\\" + directory_name
        event.details['Filter'] = directory_name

    details_io.seek(0x10, 1)
    if metadata.sizeof_pvoid == 8:
        details_io.seek(4, 1)  # Padding for 64 bit
    details_io.seek(0x4, 1)
    if metadata.sizeof_pvoid == 8:
        details_io.seek(4, 1)  # Padding for 64 bit

    file_information_class = FileInformationClass(read_u32(details_io))
    event.details["FileInformationClass"] = file_information_class.name

    if extra_detail_io and file_information_class in [FileInformationClass.FileDirectoryInformation,
                                                      FileInformationClass.FileFullDirectoryInformation,
                                                      FileInformationClass.FileBothDirectoryInformation,
                                                      FileInformationClass.FileNamesInformation,
                                                      FileInformationClass.FileIdBothDirectoryInformation,
                                                      FileInformationClass.FileIdFullDirectoryInformation]:
        extra_detail_length = len(extra_detail_io.getvalue())
        next_entry_offset = -1  # hack so the first iteration won't exit
        current_entry_offset = 1

        i = 0 if directory_name else -1
        while True:
            i += 1
            if next_entry_offset == 0 or (current_entry_offset + next_entry_offset) > extra_detail_length:
                break  # No more structures

            extra_detail_io.seek(current_entry_offset + next_entry_offset, 0)
            current_entry_offset = extra_detail_io.tell()
            next_entry_offset = read_u32(extra_detail_io)
            file_index = read_u32(extra_detail_io)
            if file_information_class == FileInformationClass.FileNamesInformation:
                # FILE_NAMES_INFORMATION structure
                file_name_length = read_u32(extra_detail_io)
                event.details[str(i)] = read_utf16(extra_detail_io, file_name_length)
                continue
            creation_time = read_filetime(extra_detail_io)
            last_access_time = read_filetime(extra_detail_io)
            last_write_time = read_filetime(extra_detail_io)
            change_time = read_filetime(extra_detail_io)
            end_of_file = read_u64(extra_detail_io)
            allocation_size = read_u64(extra_detail_io)
            file_attributes = read_u32(extra_detail_io)
            file_name_length = read_u32(extra_detail_io)
            if file_information_class == FileInformationClass.FileDirectoryInformation:
                # FILE_DIRECTORY_INFORMATION structure
                event.details[str(i)] = read_utf16(extra_detail_io, file_name_length)
                continue
            ea_size = read_u32(extra_detail_io)
            if file_information_class == FileInformationClass.FileFullDirectoryInformation:
                # FILE_FULL_DIR_INFORMATION structure
                event.details[str(i)] = read_utf16(extra_detail_io, file_name_length)
                continue
            if file_information_class == FileInformationClass.FileIdFullDirectoryInformation:
                # FILE_ID_FULL_DIR_INFORMATION structure
                file_id = read_u64(extra_detail_io)
                event.details[str(i)] = read_utf16(extra_detail_io, file_name_length)
                continue
            short_name_length = read_u8(extra_detail_io)
            extra_detail_io.seek(1, 1)  # Padding
            short_name = extra_detail_io.read(12 * 2)
            if file_information_class == FileInformationClass.FileBothDirectoryInformation:
                # FILE_BOTH_DIR_INFORMATION structure
                event.details[str(i)] = read_utf16(extra_detail_io, file_name_length)
                continue

            # FILE_ID_BOTH_DIR_INFORMATION structure
            extra_detail_io.seek(2, 1)  # Padding
            file_id = read_u64(extra_detail_io)
            event.details[str(i)] = read_utf16(extra_detail_io, file_name_length)
            continue


def get_filesystem_notify_change_directory_details(io, metadata, event, details_io, extra_detail_io):
    event.category = "Read Metadata"

    details_io.seek(0x10, 1)
    if metadata.sizeof_pvoid == 8:
        details_io.seek(4, 1)  # Padding for 64 bit

    event.details["Filter"] = get_filesystem_notify_change_flags(read_u32(details_io))


def get_filesystem_create_file_details(io, metadata, event, details_io, extra_detail_io):
    event.details["Desired Access"] = get_filesystem_access_mask_string(read_u32(io))
    impersonating_sid_length = read_u8(io)
    io.seek(0x3, 1)  # padding

    details_io.seek(0x10, 1)
    if metadata.sizeof_pvoid == 8:
        details_io.seek(4, 1)  # Padding for 64 bit

    disposition_and_options = read_u32(details_io)
    disposition = disposition_and_options >> 0x18
    options = disposition_and_options & 0xffffff
    if metadata.sizeof_pvoid == 8:
        details_io.seek(4, 1)  # Padding for 64 bit
    attributes = read_u16(details_io)
    share_mode = read_u16(details_io)

    event.details["Disposition"] = get_enum_name_or(FilesystemDisposition, disposition, "<unknown>")
    event.details["Options"] = get_filesysyem_create_options(options)
    event.details["Attributes"] = get_filesysyem_create_attributes(attributes)
    event.details["ShareMode"] = get_filesysyem_create_share_mode(share_mode)

    details_io.seek(0x4 + metadata.sizeof_pvoid * 2, 1)
    allocation = read_u32(details_io)
    allocation_value = allocation if disposition in [FilesystemDisposition.Supersede, FilesystemDisposition.Create,
                                                     FilesystemDisposition.OpenIf,
                                                     FilesystemDisposition.OverwriteIf] else "n/a"
    event.details["AllocationSize"] = allocation_value

    if impersonating_sid_length:
        event.details["Impersonating"] = get_sid_string(io.read(impersonating_sid_length))

    open_result = None
    if extra_detail_io:
        open_result = read_u32(extra_detail_io)
        event.details["OpenResult"] = get_enum_name_or(FilesystemOpenResult, open_result, "<unknown>")

    if open_result in [FilesystemOpenResult.Superseded, FilesystemOpenResult.Created, FilesystemOpenResult.Overwritten]:
        event.category = "Write"
    elif open_result in [FilesystemOpenResult.Opened, FilesystemOpenResult.Exists, FilesystemOpenResult.DoesNotExist]:
        pass
    elif event.details["Disposition"] in ["Open", "<unknown>"]:
        pass
    else:
        event.category = "Write"


def get_filesystem_create_file_mapping(io, metadata, event, details_io, extra_detail_io):
    """Get detailed information about a FileSystem CreateFileMapping event.

    Notes:
         The CreateFileMapping event is basically the results of the IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION IRP, but
         without the FS_FILTER_SECTION_SYNC_OUTPUT output information. Only SyncType and PageProtection are available.
         See: https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/flt-parameters-for-irp-mj-acquire-for-section-synchronization
    """
    # Only two fields are read from the details (there's also the detail string which is already read in the caller, see
    # get_filesystem_event_details() function). Besides those, all other fields seem to be completely ignored.
    details_io.seek(0x0C, 1)  # skip 0xC bytes from the beginning of details.
    sync_type = read_u32(details_io)  # note: asm uses 'movsxd', so it's signed with sign extension.
    page_protection = read_u32(details_io)
    event.details["SyncType"] = get_filesystem_createfilemapping_synctype(sync_type)

    if page_protection & PageProtection.PAGE_READONLY:
        event.details["PageProtection"] = PageProtection.PAGE_READONLY.name
    elif page_protection & PageProtection.PAGE_READWRITE:
        event.details["PageProtection"] = PageProtection.PAGE_READWRITE.name
    elif page_protection & PageProtection.PAGE_WRITECOPY:
        event.details["PageProtection"] = PageProtection.PAGE_WRITECOPY.name
    elif page_protection & PageProtection.PAGE_EXECUTE:
        event.details["PageProtection"] = PageProtection.PAGE_EXECUTE.name
    elif page_protection & PageProtection.PAGE_EXECUTE_READ:
        event.details["PageProtection"] = PageProtection.PAGE_EXECUTE_READ.name
    elif page_protection & PageProtection.PAGE_EXECUTE_READWRITE:
        event.details["PageProtection"] = PageProtection.PAGE_EXECUTE_READWRITE.name

    if page_protection & PageProtection.PAGE_NOCACHE and "PageProtection" in event.details:
        event.details["PageProtection"] += "|PAGE_NOCACHE"


def get_filesystem_read_write_file_details(io, metadata, event, details_io, extra_detail_io):
    event.category = "Read" if event.operation == "ReadFile" else "Write"
    details_io.seek(0x4, 1)
    io_flags_and_priority = read_u32(details_io)
    io_flags = io_flags_and_priority & 0xe000ff
    priority = (io_flags_and_priority >> 0x11) & 7
    details_io.seek(0x4, 1)
    length = read_u32(details_io)
    if metadata.sizeof_pvoid == 8:
        details_io.seek(4, 1)  # Padding for 64 bit
    details_io.seek(0x4, 1)
    if metadata.sizeof_pvoid == 8:
        details_io.seek(4, 1)  # Padding for 64 bit
    offset = read_s64(details_io)

    event.details["Offset"] = offset
    if extra_detail_io:
        length = read_u32(extra_detail_io)
    event.details["Length"] = length

    if io_flags != 0:
        event.details["I/O Flags"] = get_filesysyem_io_flags(io_flags)

    if priority != 0:
        event.details["Priority"] = FilesystemPriority.get(priority, "0x{:x}".format(priority))


def get_filesystem_ioctl_details(io, metadata, event, details_io, extra_detail_io):
    details_io.seek(0x8, 1)
    write_length = read_u32(details_io)
    read_length = read_u32(details_io)
    if metadata.sizeof_pvoid == 8:
        details_io.seek(4, 1)  # Padding for 64 bit

    details_io.seek(0x4, 1)
    if metadata.sizeof_pvoid == 8:
        details_io.seek(4, 1)  # Padding for 64 bit

    ioctl = read_u32(details_io)
    event.details["Control"] = get_ioctl_name(ioctl)
    if event.details["Control"] in ["FSCTL_OFFLOAD_READ", "FSCTL_GET_REPARSE_POINT", "FSCTL_READ_RAW_ENCRYPTED"]:
        event.category = "Read"
    elif event.details["Control"] in ["FSCTL_OFFLOAD_WRITE", "FSCTL_MOVE_FILE", "FSCTL_DELETE_REPARSE_POINT",
                                      "FSCTL_WRITE_RAW_ENCRYPTED", "FSCTL_PIPE_TRANSCEIVE",
                                      "FSCTL_PIPE_INTERNAL_TRANSCEIVE"]:
        event.category = "Write"
    elif event.details["Control"] in ["FSCTL_SET_COMPRESSION", "FSCTL_WRITE_PROPERTY_DATA", "FSCTL_SET_OBJECT_ID",
                                      "FSCTL_DELETE_OBJECT_ID", "FSCTL_SET_REPARSE_POINT", "FSCTL_SET_SPARSE",
                                      "FSCTL_SET_ENCRYPTION", "FSCTL_CREATE_USN_JOURNAL",
                                      "FSCTL_WRITE_USN_CLOSE_RECORD", "FSCTL_EXTEND_VOLUME",
                                      "FSCTL_DELETE_USN_JOURNAL"]:
        event.category = "Write Metadata"
    elif event.details["Control"] in ["FSCTL_QUERY_RETRIEVAL_POINTERS", "FSCTL_GET_COMPRESSION",
                                      "FSCTL_QUERY_FAT_BPB", "FSCTL_QUERY_FAT_BPB",
                                      "FSCTL_FILESYSTEM_GET_STATISTICS", "FSCTL_GET_NTFS_VOLUME_DATA",
                                      "FSCTL_GET_NTFS_FILE_RECORD", "FSCTL_GET_VOLUME_BITMAP",
                                      "FSCTL_GET_RETRIEVAL_POINTERS", "FSCTL_IS_VOLUME_DIRTY",
                                      "FSCTL_READ_PROPERTY_DATA", "FSCTL_FIND_FILES_BY_SID", "FSCTL_GET_OBJECT_ID",
                                      "FSCTL_READ_USN_JOURNAL", "FSCTL_SET_OBJECT_ID_EXTENDED",
                                      "FSCTL_CREATE_OR_GET_OBJECT_ID", "FSCTL_READ_FILE_USN_DATA",
                                      "FSCTL_QUERY_USN_JOURNAL"]:
        event.category = "Read Metadata"

    if event.operation == "FileSystemControl":
        if event.details["Control"] == "FSCTL_PIPE_INTERNAL_WRITE":
            event.details["Length"] = write_length
        elif event.details["Control"] == "FSCTL_OFFLOAD_READ":
            details_io.seek(0x8, 1)
            event.details["Offset"] = read_s64(io)
            event.details["Length"] = read_u64(io)
        elif event.details["Control"] == "FSCTL_OFFLOAD_WRITE":
            event.details["Offset"] = read_s64(io)
            event.details["Length"] = read_u64(io)
        elif event.details["Control"] == "FSCTL_PIPE_INTERNAL_READ":
            event.details["Length"] = read_length
        elif event.details["Control"] in ["FSCTL_PIPE_TRANSCEIVE", "FSCTL_PIPE_INTERNAL_TRANSCEIVE"]:
            event.details["WriteLength"] = write_length
            event.details["ReadLength"] = read_length


def get_filesystem_setdispositioninformation_details(io, metadata, event, details_io, extra_detail_io):
    is_delete = bool(read_u8(io))
    io.seek(3, 1)  # Padding

    if is_delete:
        event.details["Delete"] = "True"
        event.category = "Write"
    else:
        event.details["Delete"] = "False"


FilesystemSubOperationHandler = {
    FilesystemOperation.CreateFile.name: get_filesystem_create_file_details,
    FilesystemOperation.ReadFile.name: get_filesystem_read_write_file_details,
    FilesystemOperation.WriteFile.name: get_filesystem_read_write_file_details,
    FilesystemOperation.FileSystemControl.name: get_filesystem_ioctl_details,
    FilesysemDirectoryControlOperation.QueryDirectory.name: get_filesystem_query_directory_details,
    FilesysemDirectoryControlOperation.NotifyChangeDirectory.name: get_filesystem_notify_change_directory_details,
    FilesystemOperation.DeviceIoControl.name: get_filesystem_ioctl_details,
    FilesystemQueryInformationOperation.QueryIdInformation.name: get_filesystem_read_metadata_details,
    FilesystemQueryInformationOperation.QueryRemoteProtocolInformation.name: get_filesystem_read_metadata_details,
    FilesystemSetInformationOperation.SetDispositionInformationFile.name:
        get_filesystem_setdispositioninformation_details,
    FilesystemOperation.CreateFileMapping.name: get_filesystem_create_file_mapping,
}


def get_filesystem_event_details(io, metadata, event, extra_detail_io):
    sub_operation = read_u8(io)
    io.seek(0x3, 1)  # padding

    # fix operation name if there is more specific sub operation
    if 0 != sub_operation and FilesystemOperation[event.operation] in FilesystemSubOperations:
        try:
            event.operation = FilesystemSubOperations[FilesystemOperation[event.operation]](sub_operation).name
        except ValueError:
            event.operation += " <Unknown>"

    details_io = BytesIO(io.read(metadata.sizeof_pvoid * 5 + 0x14))
    path_info = read_detail_string_info(io)
    io.seek(2, 1)  # Padding
    event.path = read_detail_string(io, path_info)
    if metadata.should_get_details and event.operation in FilesystemSubOperationHandler:
        FilesystemSubOperationHandler[event.operation](io, metadata, event, details_io, extra_detail_io)


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


def get_process_exit_details(io, metadata, event, extra_details_io):
    event.details["Exit Status"] = read_u32(io)
    kernel_time = read_duration(io)
    user_time = read_duration(io)
    working_set = read_u64(io)
    peak_working_set = read_u64(io)
    private_bytes = read_u64(io)
    peak_private_bytes = read_u64(io)

    event.details["User Time"] = user_time
    event.details["Kernel Time"] = kernel_time
    event.details["Private Bytes"] = private_bytes
    event.details["Peak Private Bytes"] = peak_private_bytes
    event.details["Working Set"] = working_set
    event.details["Peak Working Set"] = peak_working_set


def get_load_image_details(io, metadata, event, extra_detail_io):
    event.details["Image Base"] = metadata.read_pvoid(io)
    event.details["Image Size"] = read_u32(io)
    path_info = read_detail_string_info(io)
    io.seek(2, 1)  # Unknown field
    event.path = read_detail_string(io, path_info)


def get_thread_create_details(io, metadata, event, extra_detail_io):
    event.details["Thread ID"] = read_u32(io)


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
    ProcessOperation.Process_Exit.name: get_process_exit_details,
    ProcessOperation.Thread_Create.name: get_thread_create_details,
    ProcessOperation.Thread_Exit.name: get_thread_exit_details,
    ProcessOperation.Load_Image.name: get_load_image_details,
    ProcessOperation.Process_Start.name: get_process_started_details,
    ProcessOperation.Process_Statistics.name: get_process_exit_details,
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
