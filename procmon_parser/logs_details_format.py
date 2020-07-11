"""
Definitions For specific event details in process monitor logs
"""

from collections import namedtuple, OrderedDict
from construct import Int8ul, Int32ul, Struct, PaddedString, FlagsEnum, IfThenElse, Computed, Int16ul, Adapter, Bytes, \
    Switch, Enum, ExprAdapter, Pass, Array, BitStruct, BitsInteger, Bit, ByteSwapped, SymmetricAdapter
from six import string_types
from ipaddress import IPv4Address, IPv6Address

from procmon_parser.construct_helper import PVoid, UTF16MultiSz, SizedUTF16MultiSz, Duration
from procmon_parser.consts import ProcessOperation, RegistryOperation, FilesystemOperation, \
    FilesystemQueryInformationOperation, FilesysemDirectoryControlOperation, \
    FilesystemSetInformationOperation, FilesystemPnpOperation, FilesystemQueryVolumeInformationOperation, \
    FilesystemSetVolumeInformationOperation, FilesystemLockUnlockOperation


__all__ = ['EventDetails', 'NetworkDetails', 'RegistryDetails', 'FilesystemDetails', 'ProcessDetails']


EventDetails = namedtuple("EventDetails", ['path', 'category', 'details'])


class HostnameString(SymmetricAdapter):
    def __init__(self, is_ipv4_func):
        super(HostnameString, self).__init__(Bytes(16))
        self.is_ipv4_func = is_ipv4_func

    def _decode(self, obj, context, path):
        if obj in context.hosts_table:
            if context.hosts_table[obj]:
                return context.hosts_table[obj]
        if self.is_ipv4_func(context):
            return str(IPv4Address(obj[:4]))
        return str(IPv6Address(obj))


PortString = ExprAdapter(
    Struct("port_number" / Int16ul),
    lambda obj, ctx: ctx.ports_table.get((obj.port_number, bool(ctx.flags.is_tcp)), str(obj.port_number)),
    lambda obj, ctx: ctx.ports_table.index(obj))


FilesystemQueryVolumeInformationOperationType = Enum(Int8ul, FilesystemQueryVolumeInformationOperation)
FilesystemSetVolumeInformationOperationType = Enum(Int8ul, FilesystemSetVolumeInformationOperation)
FilesystemQueryInformationOperationType = Enum(Int8ul, FilesystemQueryInformationOperation)
FilesystemDirectoryControlOperationType = Enum(Int8ul, FilesysemDirectoryControlOperation)
FilesystemSetInformationOperationType = Enum(Int8ul, FilesystemSetInformationOperation)
FilesystemPnpOperationType = Enum(Int8ul, FilesystemPnpOperation)
FilesystemLockUnlockOperationType = Enum(Int8ul, FilesystemLockUnlockOperation)
NetworkOperationFlags = FlagsEnum(Int16ul, is_source_ipv4=1, is_dest_ipv4=2, is_tcp=4)
DetailStringInfo = ByteSwapped(BitStruct("is_ascii" / Bit, "char_count" / BitsInteger(15)))


def DetailString(detail_info_func):
    """Strings in the specific detail structure are described by a flags field and a length field
    """
    return IfThenElse(lambda ctx: detail_info_func(ctx).is_ascii,
                      PaddedString(lambda ctx: detail_info_func(ctx).char_count, "ascii"),
                      PaddedString(lambda ctx: detail_info_func(ctx).char_count * 2, "UTF_16_le"))


def fix_network_event_operation_name(obj, ctx):
    """Fixes the operation name according to the protocol type
    """
    protocol = "TCP" if obj.is_tcp else "UDP"
    ctx._.operation = protocol + " " + ctx._.operation


RawNetworkDetailsStruct = """
The structure that holds the specific network events details
""" * Struct(
    "hosts_table" / Computed(lambda ctx: ctx._._.hosts_table),  # keep a reference to the hosts table
    "ports_table" / Computed(lambda ctx: ctx._._.ports_table),  # keep a reference to the ports table
    "flags" / NetworkOperationFlags * fix_network_event_operation_name,
    "reserved1" / Int16ul * "!!Unknown field!!",
    "packet_length" / Int32ul,
    "source_host" / HostnameString(lambda ctx: ctx.flags.is_source_ipv4),
    "dest_host" / HostnameString(lambda ctx: ctx.flags.is_dest_ipv4),
    "source_port" / PortString,
    "dest_port" / PortString,
    "extra_details" / UTF16MultiSz
)


class NetworkDetailsAdapter(Adapter):
    def _decode(self, obj, context, path):
        details = OrderedDict([("Length", obj.packet_length)])
        for i in range(len(obj.extra_details) // 2):
            details[obj.extra_details[i*2]] = obj.extra_details[i*2+1]
        return EventDetails(
            path="{}:{} -> {}:{}".format(obj.source_host, obj.source_port, obj.dest_host, obj.dest_port),
            category='',
            details=details
        )

    def _encode(self, obj, context, path):
        raise NotImplementedError("building network detail structure is not supported yet")


NetworkDetails = NetworkDetailsAdapter(RawNetworkDetailsStruct)
RawRegistryDetailsStruct = """
The structure that holds the specific registry events details
""" * Struct(
    "path_info" / DetailStringInfo,
    "reserved" / Bytes(
        lambda ctx: 0 if ctx._.operation in [RegistryOperation.RegCloseKey.name, RegistryOperation.RegDeleteKey.name,
                                             RegistryOperation.RegDeleteValue.name, RegistryOperation.RegFlushKey.name,
                                             RegistryOperation.RegUnloadKey.name,
                                             RegistryOperation.RegQueryMultipleValueKey.name,
                                             RegistryOperation.RegSetKeySecurity.name,
                                             RegistryOperation.RegQueryKeySecurity.name]
        else 2 if ctx._.operation in [RegistryOperation.RegLoadKey.name, RegistryOperation.RegRenameKey.name]
        else 6 if ctx._.operation in [RegistryOperation.RegOpenKey.name, RegistryOperation.RegCreateKey.name]
        else 10 if ctx._.operation in [RegistryOperation.RegQueryKey.name, RegistryOperation.RegQueryValue.name]
        else 14 if ctx._.operation in [RegistryOperation.RegSetValue.name, RegistryOperation.RegEnumValue.name,
                                       RegistryOperation.RegEnumKey.name, RegistryOperation.RegSetInfoKey.name]
        else 0,
    ) * "!!Unknown field!!",
    "path" / DetailString(lambda this: this.path_info)
)


RegistryDetails = ExprAdapter(
    RawRegistryDetailsStruct,
    lambda obj, ctx: EventDetails(path=obj.path, category='', details={}),
    lambda obj, ctx: None  # building registry detail structure is not supported yet
)


def fix_query_directory_path(obj, ctx):
    """for some QueryDirectory operations the path is concatenated to the relevant directory
    """
    if obj:
        ctx._.path = ctx._.path + obj if ctx._.path[-1] == "\\" else ctx._.path + "\\" + obj


QueryDirectoryDetailsStruct = Struct(
    "directory_name_info" / DetailStringInfo,
    "directory_name" / DetailString(lambda this: this.directory_name_info) * fix_query_directory_path,
)


QueryDirectoryDetails = ExprAdapter(
    QueryDirectoryDetailsStruct,
    lambda obj, ctx: OrderedDict([('Filter', obj.directory_name)]) if obj.directory_name else {},
    lambda obj, ctx: None  # building file system detail structure is not supported yet
)


def fix_filesystem_event_operation_name(obj, ctx):
    """Fixes the operation name if there is a sub operation
    """
    if isinstance(obj, string_types):
        ctx._.operation = obj


RawFilesystemDetailsStruct = """
The structure that holds the specific file system events details
""" * Struct(
    "is_64bit" / Computed(lambda ctx: ctx._.is_64bit),  # we keep this in order to use PVoid
    "sub_operation" / Switch(lambda ctx: ctx._.operation, {
        FilesystemOperation.QueryVolumeInformation.name: FilesystemQueryVolumeInformationOperationType,
        FilesystemOperation.SetVolumeInformation.name: FilesystemSetVolumeInformationOperationType,
        FilesystemOperation.QueryInformationFile.name: FilesystemQueryInformationOperationType,
        FilesystemOperation.SetInformationFile.name: FilesystemSetInformationOperationType,
        FilesystemOperation.DirectoryControl.name: FilesystemDirectoryControlOperationType,
        FilesystemOperation.PlugAndPlay.name: FilesystemPnpOperationType,
        FilesystemOperation.LockUnlockFile.name: FilesystemLockUnlockOperationType,
    }, Int8ul) * fix_filesystem_event_operation_name,
    "reserved1" / Int8ul * "!!Unknown field!!",
    "reserved2" / Array(5, PVoid) * "!!Unknown field!!",
    "reserved3" / Bytes(0x16) * "!!Unknown field!!",
    "path_info" / DetailStringInfo,
    "reserved3" / Int16ul,
    "path" / DetailString(lambda this: this.path_info),
    "operation_detail" / Switch(lambda ctx: ctx._.operation, {
        FilesysemDirectoryControlOperation.QueryDirectory.name: QueryDirectoryDetails
    }, Pass),

    "path" / Computed(lambda ctx: ctx.path),  # The path might be changed because of the specific file operation
)


FilesystemDetails = ExprAdapter(
    RawFilesystemDetailsStruct,
    lambda obj, ctx: EventDetails(path=obj.path, category='', details=obj.operation_detail or {}),
    lambda obj, ctx: None  # building file system detail structure is not supported yet
)


RawLoadImageDetailsStruct = Struct(
    "is_64bit" / Computed(lambda ctx: ctx._._.is_64bit),  # we keep this in order to use PVoid
    "image_base" / PVoid,
    "image_size" / Int32ul,
    "path_info" / DetailStringInfo,
    "reserved1" / Int16ul * "!!Unknown field!!",
    "path" / DetailString(lambda this: this.path_info)
)


LoadImageDetails = ExprAdapter(
    RawLoadImageDetailsStruct,
    lambda obj, ctx: EventDetails(path=obj.path, category='',
                                  details=OrderedDict([("Image Base", obj.image_base),
                                                       ("Image Size", obj.image_size)])),
    lambda obj, ctx: None  # building load image detail structure is not supported yet
)


RawThreadExitDetails = Struct(
    "reserved1" / Int32ul * "!!Unknown field!!",
    "kernel_time" / Duration,
    "user_time" / Duration,
)

ThreadExitDetails = ExprAdapter(
    RawThreadExitDetails,
    lambda obj, ctx: EventDetails(path='', category='',
                                  details=OrderedDict([("Thread ID", ctx._.thread_id), ("User Time", obj.user_time),
                                                       ("Kernel Time", obj.kernel_time)])),
    lambda obj, ctx: None  # building load image detail structure is not supported yet
)


RawProcessCreateDetailsStruct = Struct(
    "reserved1" / Int32ul * "!!Unknown field!!",
    "pid" / Int32ul,
    "reserved2" / Bytes(0x24) * "!!Unknown field!!",
    "size1" / Int8ul * "!!Unknown field!!",
    "size2" / Int8ul * "!!Unknown field!!",
    "path_info" / DetailStringInfo,
    "command_line_info" / DetailStringInfo,
    "reserved3" / Int16ul * "!!Unknown field!!",
    "reserved4" / Bytes(lambda ctx: ctx.size1 + ctx.size2) * "!!Unknown field!!",
    "path" / DetailString(lambda this: this.path_info),
    "command_line" / DetailString(lambda this: this.command_line_info),
)

ProcessCreateDetails = ExprAdapter(
    RawProcessCreateDetailsStruct,
    lambda obj, ctx: EventDetails(path=obj.path, category='',
                                  details=OrderedDict([("PID", obj.pid), ("Command line", obj.command_line)])),
    lambda obj, ctx: None  # building process create detail structure is not supported yet
)


RawProcessStartDetailsStruct = Struct(
    "parent_pid" / Int32ul,
    "command_line_info" / DetailStringInfo,
    "current_directory_info" / DetailStringInfo,
    "environment_size" / Int32ul,
    "command_line" / DetailString(lambda this: this.command_line_info),
    "current_directory" / DetailString(lambda this: this.current_directory_info),
    "environment" / SizedUTF16MultiSz(lambda this: this.environment_size),
)

ProcessStartDetails = ExprAdapter(
    RawProcessStartDetailsStruct,
    lambda obj, ctx: EventDetails(path='', category='',
                                  details=OrderedDict([("Parent PID", obj.parent_pid),
                                                       ("Command line", obj.command_line),
                                                       ("Current directory", obj.current_directory),
                                                       ("Environment", "\r\n;\t" + "\r\n;\t".join(obj.environment))])),
    lambda obj, ctx: None  # building process create detail structure is not supported yet
)


RawProcessDetailsStruct = """
The structure that holds the specific process events details
""" * Struct(
    "info" / Switch(lambda ctx: ctx._.operation, {
        ProcessOperation.Process_Defined.name: ProcessCreateDetails,
        ProcessOperation.Process_Create.name: ProcessCreateDetails,
        ProcessOperation.Process_Exit.name: Pass,
        ProcessOperation.Thread_Create.name: Pass,
        ProcessOperation.Thread_Exit.name: ThreadExitDetails,
        ProcessOperation.Load_Image.name: LoadImageDetails,
        ProcessOperation.Thread_Profile.name: Pass,
        ProcessOperation.Process_Start.name: ProcessStartDetails,
        ProcessOperation.Process_Statistics.name: Pass,
        ProcessOperation.System_Statistics.name: Pass,
    })
)

ProcessDetails = ExprAdapter(
    RawProcessDetailsStruct,
    lambda obj, ctx: obj.info if obj.info else EventDetails(path='', category='', details={}),
    lambda obj, ctx: None
)
