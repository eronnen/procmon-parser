"""
Definitions For the process monitor logs file formats.
"""

from construct import Struct, Const, SymmetricAdapter, Int32ul, Int64ul, PaddedString, Bytes, Array, PrefixedArray, \
    Pointer, Tell, Switch, Error, Int16ul, Byte, Computed, ExprAdapter, Adapter, Rebuild, Pass, Enum, \
    ExprSymmetricAdapter
from procmon_parser.construct_helper import FixedNullTerminatedUTF16String, OriginalEnumAdapter, Filetime, \
    ListAdapter, PVoid, Duration, CheckCustom
from procmon_parser.logs_details_format import NetworkDetails, RegistryDetails, FilesystemDetails, ProcessDetails
from procmon_parser.consts import EventClass, ProcessOperation, RegistryOperation, NetworkOperation, ProfilingOperation, \
    FilesystemOperation
from procmon_parser.logs import Module, Process, Event

EventClassType = OriginalEnumAdapter(Int32ul, EventClass)
ProcessOperationType = Enum(Int16ul, ProcessOperation)
RegistryOperationType = Enum(Int16ul, RegistryOperation)
NetworkOperationType = Enum(Int16ul, NetworkOperation)
ProfilingOperationType = Enum(Int16ul, ProfilingOperation)
FilesystemOperationType = Enum(Int16ul, FilesystemOperation)
StringIndex = ExprAdapter(Struct("string_index" / Int32ul), lambda obj, ctx: ctx.strings_table[obj.string_index],
                          lambda obj, ctx: ctx.strings_table.index(obj))
ProcessIndex = ExprAdapter(Struct("process_index" / Int32ul), lambda obj, ctx: ctx.process_table[obj.process_index],
                           lambda obj, ctx: ctx.process_table.index(obj))

SUPPORTED_VERSIONS = [9]


class PMLVersionNumberValidator(SymmetricAdapter):
    def _decode(self, obj, context, path):
        if obj not in SUPPORTED_VERSIONS:
            raise RuntimeError("PML is version {} while only versions {} are supported", obj, SUPPORTED_VERSIONS)


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
    "unknown_table_offset" / Int64ul * "!!Unknown field!!",
    "reserved2" / Int64ul * "!!Unknown field!!",
    "reserved3" / Bytes(0x46) * "!!Unknown field!!",
    "reserved4" / Bytes(0xd6) * "!!Unknown field!!",
    "reserved5" / Int32ul * "!!Unknown field!!",
    "reserved6" / Int64ul * "!!Unknown field!!",
    "header_size" / Int64ul,
    "hosts_and_ports_tables_offset" / Int64ul,

    CheckCustom(lambda this: this.events_offset == this.header_size,
                RuntimeError, "events offset is not like header size."),
    CheckCustom(lambda this:
                0 != this.events_offset and 0 != this.events_offsets_array_offset and 0 != this.process_table_offset and
                0 != this.strings_table_offset and 0 != this.hosts_and_ports_tables_offset and 0 != this.unknown_table_offset,
                RuntimeError, "Procmon was probably not closed properly.")
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


RawModuleStruct = """
Struct that describes a loaded module in a process (or system process)
""" * Struct(
    "offset" / Tell,
    "is_64bit" / Computed(lambda ctx: ctx._._.is_64bit),  # keep this in order to use PVoid
    "strings_table" / Computed(lambda ctx: ctx._._.strings_table),  # keep the reference to the strings table
    "reserved1" / PVoid * "!!Unknown field!!",
    "base_address" / PVoid,
    "size" / Int32ul,
    "path" / StringIndex,
    "version" / StringIndex,
    "company" / StringIndex,
    "description" / StringIndex,
    "timestamp" / Int32ul,
    "reserved2" / Int64ul * "!!Unknown field!!",
    "reserved3" / Int64ul * "!!Unknown field!!",
    "unknown_time" / Filetime * "!!Unknown field!!",
)


ModuleStruct = ExprSymmetricAdapter(
    RawModuleStruct,
    lambda obj, ctx: Module(base_address=obj.base_address, size=obj.size, path=obj.path, version=obj.version,
                            company=obj.company, description=obj.company, timestamp=obj.timestamp))

RawProcessStruct = """
Struct that describes a process.
""" * Struct(
    "is_64bit" / Computed(lambda ctx: ctx._.is_64bit),  # keep this in order to use PVoid
    "strings_table" / Computed(lambda ctx: ctx._.strings_table),  # keep the reference to the strings table
    "process_index" / Int32ul,
    "process_id" / Int32ul,
    "parent_process_id" / Int32ul,
    "reserved1" / Int32ul * "!!Unknown field!!",
    "authentication_id" / Int64ul,
    "session" / Int32ul,
    "reserved3" / Int32ul * "!!Unknown field!!",
    "start_time" / Filetime,
    "end_time" / Filetime,
    "virtualized" / Int32ul,
    "is_process_64bit" / Int32ul,
    "integrity" / StringIndex,
    "user" / StringIndex,
    "process_name" / StringIndex,
    "image_path" / StringIndex,
    "command_line" / StringIndex,
    "company" / StringIndex,
    "version" / StringIndex,
    "description" / StringIndex,
    "reserved4" / PVoid * "!!Unknown field!!",
    "reserved5" / Int64ul * "!!Unknown field!!",
    "modules" / PrefixedArray(Int32ul, ModuleStruct)
)


class ProcessStructAdapter(SymmetricAdapter):
    def _decode(self, obj, context, path):
        return obj.process_index, Process(pid=obj.process_id, parent_pid=obj.parent_process_id,
                                          authentication_id=obj.authentication_id, session=obj.session,
                                          virtualized=obj.virtualized, is_process_64bit=obj.is_process_64bit,
                                          integrity=obj.integrity, user=obj.user, process_name=obj.process_name,
                                          image_path=obj.image_path, command_line=obj.command_line, company=obj.company,
                                          version=obj.version, description=obj.description, start_time=obj.start_time,
                                          end_time=obj.end_time, modules=obj.modules)


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
            "is_64bit" / Computed(lambda ctx: ctx._._.is_64bit),  # keep this in order to use PVoid
            "strings_table" / Computed(lambda ctx: ctx._._.strings_table),  # keep the reference to the string table
            "offset" / Int32ul,
            "process" / Pointer(lambda this: this._.table_offset + this.offset, ProcessStruct)
        ),
    ),
    CheckCustom(lambda this: all(i == p.process[0] for i, p in zip(this.process_indexes, this.processes)),
                RuntimeError, "found mismatching process indexes")
)

HostsAndPortsTable = """
Tables for the host names and port names used by network events.
""" * Struct(
    "hosts" / PrefixedArray(
        Int32ul,
        Struct(
            "host_ip" / Bytes(16),
            "hostname" / FixedNullTerminatedUTF16String,
        )
    ),
    "ports" / PrefixedArray(
        Int32ul,
        Struct(
            "port_number" / Int16ul,
            "is_tcp" / Int16ul,
            "port" / FixedNullTerminatedUTF16String,
        )
    ),
)


def EventsOffsetArray(number_of_events):
    return Array(number_of_events, Struct("offset" / Int32ul, "flags" / Byte))


RawEventStruct = """
The generic structure that represents a single event of every event class 
""" * Struct(
    "offset" / Tell,
    "is_64bit" / Computed(lambda ctx: ctx._.is_64bit),  # keep this in order to use PVoid
    "process_table" / Computed(lambda ctx: ctx._.process_table),  # keep reference to processes table
    "process" / ProcessIndex,
    "thread_id" / Int32ul,
    "event_class" / EventClassType,
    "operation" / Switch(lambda this: this.event_class, {
        EventClass.Process: ProcessOperationType,
        EventClass.Registry: RegistryOperationType,
        EventClass.Network: NetworkOperationType,
        EventClass.Profiling: ProfilingOperationType,
        EventClass.File_System: FilesystemOperationType,
    }, Error),
    "reserved1" / Int16ul * "!!Unknown field!!",
    "reserved2" / Int32ul * "!!Unknown field!!",
    "duration" / Duration,
    "date" / Filetime,
    "result" / Int32ul,
    "stacktrace_depth" / Rebuild(Int16ul, lambda this: len(this.stacktrace)),
    CheckCustom(lambda this: this.stacktrace_depth <= 0x100, RuntimeError, "stack trace is unreasonably big"),
    "reserved3" / Int16ul * "!!Unknown field!!",
    "detail_size" / Int32ul,
    "detail_offset" / Int32ul,
    "stacktrace" / ListAdapter(Array(lambda this: this.stacktrace_depth, PVoid)),
    "details" / Switch(lambda this: this.event_class, {
        EventClass.Process: ProcessDetails,
        EventClass.Registry: RegistryDetails,
        EventClass.Network: NetworkDetails,
        EventClass.Profiling: Pass,
        EventClass.File_System: FilesystemDetails,
    }),

    "operation" / Computed(lambda ctx: ctx.operation),  # The operation might be changed because of the specific details
)


class EventStructAdapter(Adapter):
    def _decode(self, obj, context, path):
        category = obj.details.category if obj.details else ''
        path = obj.details.path if obj.details else ''
        details = obj.details.details if obj.details else {}
        return Event(process=obj.process, tid=obj.thread_id, event_class=obj.event_class, operation=obj.operation,
                     duration=obj.duration, date=obj.date, result=obj.result,
                     stacktrace=obj.stacktrace, category=category, path=path, details=details, file_offset=obj.offset)

    def _encode(self, obj, context, path):
        return {"process": obj.process, "thread_id": obj.tid, "event_class": obj.event_class,
                "operation": obj.operation, "duration": obj.duration,
                "date": obj.date, "result": obj.result, "stacktrace": obj.stacktrace, "category": obj.category,
                "path": obj.path, "detail": obj.detail}


EventStruct = EventStructAdapter(RawEventStruct)
