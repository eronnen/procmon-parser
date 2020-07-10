"""
Definitions For the process monitor logs file formats.
"""

from collections import namedtuple
from construct import Struct, Const, Validator, Int32ul, Int64ul, PaddedString, Bytes, Check, Array, PrefixedArray, \
    Pointer, Tell, Switch, Error, Int16ul, IfThenElse, Byte, Computed, Int8ul, ExprAdapter, Adapter, Rebuild, \
    FlagsEnum, RepeatUntil, CString, Pass, Enum , If
from six import string_types
from procmon_parser.construct_helper import FixedNullTerminatedUTF16String, OriginalEnumAdapter, Filetime, ListAdapter
from procmon_parser.logs import EventClass, ProcessOperation, RegistryOperation, NetworkOperation, ProfilingOperation, \
    FilesystemOperation, FilesystemQueryInformationOperation, FilesysemDirectoryControlOperation, \
    FilesystemSetInformationOperation, FilesystemPnpOperation, Architecture, Process, Event

EventClassType = OriginalEnumAdapter(Int32ul, EventClass)
ProcessOperationType = Enum(Int16ul, ProcessOperation)
RegistryOperationType = Enum(Int16ul, RegistryOperation)
NetworkOperationType = Enum(Int16ul, NetworkOperation)
ProfilingOperationType = Enum(Int16ul, ProfilingOperation)
FilesystemOperationType = Enum(Int16ul, FilesystemOperation)
FilesystemQueryInformationOperationType = Enum(Int8ul, FilesystemQueryInformationOperation)
FilesystemDirectoryControlOperationType = Enum(Int8ul, FilesysemDirectoryControlOperation)
FilesystemSetInformationOperationType = Enum(Int8ul, FilesystemSetInformationOperation)
FilesystemPnpOperationType = Enum(Int8ul, FilesystemPnpOperation)
NetworkOperationFlags = FlagsEnum(Int16ul, has_hostname=1, reserved=2, is_tcp=4)
ArchitectureType = OriginalEnumAdapter(Int32ul, Architecture)
StringIndex = ExprAdapter(Struct("string_index" / Int32ul), lambda obj, ctx: ctx._.strings_table[obj.string_index],
                          lambda obj, ctx: ctx._.strings_table.index(obj))
ProcessIndex = ExprAdapter(Struct("process_index" / Int32ul), lambda obj, ctx: ctx._.process_table[obj.process_index],
                           lambda obj, ctx: ctx._.process_table.index(obj))
HostnameIndex = ExprAdapter(Struct("host_index" / Int32ul), lambda obj, ctx: ctx.hosts_table[obj.host_index],
                            lambda obj, ctx: ctx._.hosts_table.index(obj))
PortIndex = ExprAdapter(Struct("port_index" / Int32ul), lambda obj, ctx: ctx.ports_table[obj.port_index],
                        lambda obj, ctx: ctx._.ports_table.index(obj))
PVoid = IfThenElse(lambda ctx: ctx.is_64bit, Int64ul, Int32ul)


class PMLVersionNumberValidator(Validator):
    def _validate(self, obj, context, path):
        return obj in [9]


Header = """
The header of the PML file.
""" * Struct(
    "signature" / Const(b"PML_"),
    "version" / PMLVersionNumberValidator(Int32ul),
    "is_64bit" / Int32ul,
    "host_name" / PaddedString(0x20, "UTF_16_le"),
    "windows_path" / PaddedString(0x208, "UTF_16_le"),
    "number_of_events" / Int32ul,
    "reserved1" / Int64ul * "!!Unknown field!!",
    "events_offset" / Int64ul,
    "events_offsets_array_offset" / Int64ul,
    "process_table_offset" / Int64ul,
    "strings_table_offset" / Int64ul,
    "unknown_table_offset" / Int64ul,
    "reserved2" / Int64ul * "!!Unknown field!!",
    "reserved3" / Bytes(0x46) * "!!Unknown field!!",
    "reserved4" / Bytes(0xd6) * "!!Unknown field!!",
    "reserved5" / Int32ul * "!!Unknown field!!",
    "reserved6" / Int64ul * "!!Unknown field!!",
    "header_size" / Int64ul,
    "hosts_and_ports_tables_offset" / Int64ul,

    Check(lambda this: this.events_offset == this.header_size),
    Check(lambda this:
          0 != this.events_offset and 0 != this.events_offsets_array_offset and 0 != this.process_table_offset and
          0 != this.strings_table_offset and 0 != this.hosts_and_ports_tables_offset and 0 != this.unknown_table_offset)
)

StringsTable = """
The table of all the strings needed for the logs.
""" * Struct(
    "table_offset" / Tell,
    "strings" / PrefixedArray(
        Int32ul,
        Struct(
            "offset" / Int32ul,
            "string" / Pointer(
                lambda this: this._._.table_offset + this.offset,
                FixedNullTerminatedUTF16String
            )
        )
    )
)

RawProcessStruct = """
Struct that describes a process.
""" * Struct(
    "strings_table" / Computed(lambda ctx: ctx._.strings_table),  # keep the reference to the strings table
    "process_index" / Int32ul,
    "process_id" / Int32ul,
    "parent_process_id" / Int32ul,
    "reserved1" / Int32ul * "!!Unknown field!!",
    "authentication_id" / Int32ul,
    "reserved2" / Int32ul * "!!Unknown field!!",
    "session" / Int32ul,
    "reserved3" / Array(5, Int32ul) * "!!Unknown field!!",
    "virtualized" / Int32ul,
    "architecture" / ArchitectureType,
    "integrity" / StringIndex,
    "user" / StringIndex,
    "process_name" / StringIndex,
    "image_path" / StringIndex,
    "command_line" / StringIndex,
    "company" / StringIndex,
    "version" / StringIndex,
    "description" / StringIndex,
    "reserved4" / Array(5, Int32ul) * "!!Unknown field!!",
)


class ProcessStructAdapter(Adapter):
    def _decode(self, obj, context, path):
        return obj.process_index, Process(pid=obj.process_id, parent_pid=obj.parent_process_id,
                                          authentication_id=obj.authentication_id, session=obj.session,
                                          virtualized=obj.virtualized, architecture=obj.architecture,
                                          integrity=obj.integrity, user=obj.user, process_name=obj.process_name,
                                          image_path=obj.image_path, command_line=obj.command_line, company=obj.company,
                                          version=obj.version, description=obj.description)

    def _encode(self, obj, context, path):
        return {"process_index": obj[0], "process_id": obj[1].pid, "parent_process_id": obj[1].parent_process_id,
                "authentication_id": obj[1].authentication_id, "session": obj[1].session, "integrity": obj[1].integrity,
                "user": obj[1].user, "process_name": obj[1].process_name, "image_path": obj[1].image_path,
                "command_line": obj[1].command_line, "company": obj[1].company, "version": obj[1].version,
                "description": obj[1].description}


ProcessStruct = ProcessStructAdapter(RawProcessStruct)
ProcessTable = """
The table of all the processes that the events in the logs come from.
""" * Struct(
    "table_offset" / Tell,
    "count" / Int32ul,
    "process_indexes" / Array(lambda this: this.count, Int32ul),
    "processes" / Array(
        lambda this: this.count,
        Struct(
            "strings_table" / Computed(lambda ctx: ctx._._.strings_table),  # keep the reference to the string table
            "offset" / Int32ul,
            "process" / Pointer(lambda this: this._.table_offset + this.offset, ProcessStruct)
        ),
    ),
    Check(lambda this: all(i == p.process[0] for i, p in zip(this.process_indexes, this.processes)))
)

HostsAndPortsTable = """
Tables for the host names and port names used by network events.
""" * Struct(
    "hosts" / PrefixedArray(
        Int32ul,
        Struct(
            "hostname_index" / Int32ul,
            "reserved1" / Bytes(0xc) * "!!Unknown field!!",
            "hostname" / FixedNullTerminatedUTF16String,
        )
    ),
    "ports" / PrefixedArray(
        Int32ul,
        Struct(
            "port_index" / Int32ul,
            "port" / FixedNullTerminatedUTF16String,
        )
    ),
)


def EventsOffsetArray(number_of_events):
    return Array(number_of_events, Struct("offset" / Int32ul, "flags" / Byte))


EventDetails = namedtuple("EventDetails", ['path', 'category', 'details'], defaults=['', '', {}])
PathFlags = FlagsEnum(Int8ul, is_ascii=0x80)


def Path(path_size_func, path_flags_func):
    return IfThenElse(lambda ctx: path_flags_func(ctx).is_ascii, PaddedString(path_size_func, "ascii"),
                      PaddedString(path_size_func, "UTF_16_le"))


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
    "reserved1" / Int16ul,
    "packet_length" / Int32ul,
    "source_host" / HostnameIndex,
    "reserved2" / Bytes(0xc) * "!!Unknown field!!",
    "dest_host" / HostnameIndex,
    "reserved3" / Bytes(0xc) * "!!Unknown field!!",
    "source_port" / Int16ul,
    "dest_port" / Int16ul,
    "extra_details" / RepeatUntil(lambda x, lst, ctx: not x, CString("UTF_16_le"))
)


class NetworkDetailsAdapter(Adapter):
    def _decode(self, obj, context, path):
        details = {"Length": obj.packet_length}
        for i in range(len(obj.extra_details) // 2):
            details[obj.extra_details[i*2]] = obj.extra_details[i*2+1]
        return EventDetails(
            path="{}:{} -> {}:{}".format(obj.source_host, obj.source_port, obj.dest_host, obj.dest_port),
            category="",
            details=details
        )

    def _encode(self, obj, context, path):
        raise NotImplementedError("building network detail structure is not supported yet")


NetworkDetails = NetworkDetailsAdapter(RawNetworkDetailsStruct)
RawRegistryDetailsStruct = """
The structure that holds the specific registry events details
""" * Struct(
    "path_length" / Int8ul,
    "path_flags" / PathFlags,
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
    "path" / Path(lambda this: this.path_length, lambda this: this.path_flags)
)


class RegistryDetailsAdapter(Adapter):
    def _decode(self, obj, context, path):
        return EventDetails(path=obj.path, category="", details={})

    def _encode(self, obj, context, path):
        raise NotImplementedError("building registry detail structure is not supported yet")


RegistryDetails = RegistryDetailsAdapter(RawRegistryDetailsStruct)


def fix_filesystem_event_operation_name(obj, ctx):
    """Fixes the operation name if there is a sub operation
    """
    if isinstance(obj.sub_operation, string_types):
        ctx._.operation = obj.sub_operation


RawFilesystemDetailsStruct = """
The structure that holds the specific file system events details
""" * Struct(
    "sub_operation" / Switch(lambda ctx: ctx._.operation, {
        FilesystemOperation.QueryInformationFile: FilesystemQueryInformationOperationType,
        FilesystemOperation.SetInformationFile: FilesystemSetInformationOperationType,
        FilesystemOperation.DirectoryControl: FilesystemDirectoryControlOperationType,
        FilesystemOperation.PlugAndPlay: FilesystemPnpOperationType,
    }, Int8ul),
    "reserved1" / Int8ul * "!!Unknown field!!",
    "reserved2" / Bytes(0x3e) * "!!Unknown field!!",
    "path_length" / Int8ul,
    "path_flags" / PathFlags,
    "reserved3" / Int16ul,
    "path" / Path(lambda this: this.path_length, lambda this: this.path_flags)
)


class FilesystemDetailsAdapter(Adapter):
    def _decode(self, obj, context, path):
        return EventDetails(path=obj.path, category="", details={})

    def _encode(self, obj, context, path):
        raise NotImplementedError("building file system detail structure is not supported yet")


FilesystemDetails = FilesystemDetailsAdapter(RawFilesystemDetailsStruct)
RawEventStruct = """
The generic structure that represents a single event of every event class 
""" * Struct(
    "is_64bit" / Computed(lambda ctx: ctx._.is_64bit),  # we keep this in order to use PVoid
    "process_table" / Computed(lambda ctx: ctx._.process_table),  # keep reference to processes table
    "process" / ProcessIndex,
    "thread_id" / Int32ul,
    "event_class" / EventClassType,
    "operation" / Switch(lambda this: this.event_class, {
        EventClass.PROCESS: ProcessOperationType,
        EventClass.REGISTRY: RegistryOperationType,
        EventClass.NETWORK: NetworkOperationType,
        EventClass.PROFILING: ProfilingOperationType,
        EventClass.FILESYSTEM: FilesystemOperationType,
    }, Error),
    "reserved1" / Int16ul * "!!Unknown field!!",
    "reserved2" / Int32ul * "!!Unknown field!!",
    "duration_100_nanosec" / Int64ul,
    "date" / Filetime,
    "result" / Int32ul,
    "stacktrace_depth" / Rebuild(Int16ul, lambda this: len(this.stacktrace)),
    Check(lambda this: this.stacktrace_depth <= 0x100),
    "reserved3" / Int16ul * "!!Unknown field!!",
    "detail_size" / Int32ul,
    "detail_offset" / Int32ul,
    "stacktrace" / ListAdapter(Array(lambda this: this.stacktrace_depth, PVoid)),
    "details" / Switch(lambda this: this.event_class, {
        EventClass.PROCESS: Pass,
        EventClass.REGISTRY: RegistryDetails,
        EventClass.NETWORK: NetworkDetails,
        EventClass.PROFILING: Pass,
        EventClass.FILESYSTEM: FilesystemDetails,
    }),

    "operation" / Computed(lambda ctx: ctx.operation),  # The operation might be changed because of the specific details
)


class EventStructAdapter(Adapter):
    def _decode(self, obj, context, path):
        category = obj.details.category if obj.details else ''
        path = obj.details.path if obj.details else ''
        details = obj.details.details if obj.details else {}
        return Event(process=obj.process, tid=obj.thread_id, event_class=obj.event_class, operation=obj.operation,
                     duration_100_nanosec=obj.duration_100_nanosec, date=obj.date, result=obj.result,
                     stacktrace=obj.stacktrace, category=category, path=path, details=details)

    def _encode(self, obj, context, path):
        return {"process": obj.process, "thread_id": obj.tid, "event_class": obj.event_class,
                "operation": obj.operation, "duration_100_nanosec": obj.duration_100_nanosec,
                "date": obj.date, "result": obj.result, "stacktrace": obj.stacktrace, "category": obj.category,
                "path": obj.path, "detail": obj.detail}


EventStruct = EventStructAdapter(RawEventStruct)
