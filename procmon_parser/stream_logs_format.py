from collections import OrderedDict
from io import BytesIO
from struct import Struct
from ipaddress import IPv4Address, IPv6Address

from procmon_parser.consts import EventClass, EventClassOperation
from procmon_parser.logs import PMLStructReader, Module, Process, Event, PMLError
from procmon_parser.stream_helper import read_u8, read_u16, read_u32, read_u64, read_utf16, read_filetime, \
    get_pvoid_reader, get_pvoid_size
from procmon_parser.stream_logs_detail_format import PmlMetadata, get_event_details


class Header(object):
    SIZE = 0x3a8

    def __init__(self, io):
        stream = BytesIO(io.read(self.SIZE))
        self.signature = stream.read(4)
        if self.signature != b"PML_":
            raise PMLError("not a Process Monitor backing file (signature missing).")
        self.version = read_u32(stream)
        if self.version not in [9]:
            raise NotImplementedError("Not supporting PML version {}".format(self.version))
        self.is_64bit = read_u32(stream)
        self.computer_name = read_utf16(stream, 0x20)
        self.system_root = read_utf16(stream, 0x208)
        self.number_of_events = read_u32(stream)

        stream.seek(8, 1)  # Unknown field
        self.events_offset = read_u64(stream)
        self.events_offsets_array_offset = read_u64(stream)
        self.process_table_offset = read_u64(stream)
        self.strings_table_offset = read_u64(stream)

        # currently not being parsed because I don't know how to show icons in python.
        # Docs of this table's layout are in "docs\PML Format.md"
        self.icon_table_offset = read_u64(stream)

        stream.seek(12, 1)  # Unknown fields
        self.windows_major_number = read_u32(stream)
        self.windows_minor_number = read_u32(stream)
        self.windows_build_number = read_u32(stream)
        self.windows_build_number_after_decimal_point = read_u32(stream)

        self.service_pack_name = read_utf16(stream, 0x32)

        stream.seek(0xd6, 1)  # Unknown field
        self.number_of_logical_processors = read_u32(stream)
        self.ram_memory_size = read_u64(stream)
        self.header_size = read_u64(stream)
        self.hosts_and_ports_tables_offset = read_u64(stream)

        if self.events_offset == 0 or self.events_offsets_array_offset == 0 or self.process_table_offset == 0 or self.strings_table_offset == 0 or self.icon_table_offset == 0:
            raise PMLError("PML was not closed cleanly during capture and is corrupt.")

        if self.header_size != self.SIZE or self.hosts_and_ports_tables_offset == 0:
            raise PMLError("PML is corrupt and cannot be opened.")


class EventOffsetsArray(list):
    def __init__(self, io, total_size, number_of_events):
        super(EventOffsetsArray, self).__init__()
        stream = BytesIO(io.read(total_size))
        offsets = [0] * number_of_events
        for i in range(number_of_events):
            offsets[i] = read_u32(stream)
            _ = read_u8(stream)  # Unknown flags
        self.extend(offsets)


class StringsTable(list):
    def __init__(self, io):
        super(StringsTable, self).__init__()
        string_table_start = io.tell()
        number_of_strings = read_u32(io)

        strings_offsets_array = [read_u32(io) for _ in range(number_of_strings)]

        strings = [''] * number_of_strings
        for i, offset in enumerate(strings_offsets_array):
            io.seek(string_table_start + offset, 0)
            string_size = read_u32(io)
            strings[i] = read_utf16(io, string_size)
        self.extend(strings)


class ProcessTable(dict):
    def __init__(self, io, read_pvoid, strings_table):
        super(ProcessTable, self).__init__()
        self._read_pvoid = read_pvoid
        self._strings_table = strings_table
        process_table_start = io.tell()
        number_of_processes = read_u32(io)

        # The array of process indexes is not essential becuase they appear in the process structure itself.
        # process_index_array = [read_u32(io) for _ in range(number_of_processes)]
        io.seek(number_of_processes * 4, 1)  # jump over the process indexes array

        process_offsets_array = [read_u32(io) for _ in range(number_of_processes)]
        for offset in process_offsets_array:
            io.seek(process_table_start + offset, 0)
            process_index, process = self.__read_process(io)
            self[process_index] = process

    def __read_process(self, stream):
        process_index = read_u32(stream)
        pid = read_u32(stream)
        parent_pid = read_u32(stream)

        stream.seek(4, 1)  # Unknown field
        authentication_id = read_u64(stream)
        session = read_u32(stream)

        stream.seek(4, 1)  # Unknown field
        start_time = read_filetime(stream)
        end_time = read_filetime(stream)
        virtualized = read_u32(stream)
        is_process_64bit = read_u32(stream)

        integrity = self._strings_table[read_u32(stream)]
        user = self._strings_table[read_u32(stream)]
        process_name = self._strings_table[read_u32(stream)]
        image_path = self._strings_table[read_u32(stream)]
        command_line = self._strings_table[read_u32(stream)]
        company = self._strings_table[read_u32(stream)]
        version = self._strings_table[read_u32(stream)]
        description = self._strings_table[read_u32(stream)]

        icon_index_small = read_u32(stream)
        icon_index_big = read_u32(stream)
        _ = self._read_pvoid(stream)  # Unknown field
        number_of_modules = read_u32(stream)
        modules = [self.__read_module(stream) for _ in range(number_of_modules)]
        return process_index, Process(pid=pid, parent_pid=parent_pid, authentication_id=authentication_id,
                                      session=session, virtualized=virtualized, is_process_64bit=is_process_64bit,
                                      integrity=integrity, user=user, process_name=process_name, image_path=image_path,
                                      command_line=command_line, company=company, version=version,
                                      description=description, start_time=start_time, end_time=end_time,
                                      modules=modules)

    def __read_module(self, stream):
        _ = self._read_pvoid(stream)  # Unknown field
        base_address = self._read_pvoid(stream)
        size = read_u32(stream)
        image_path = self._strings_table[read_u32(stream)]
        version = self._strings_table[read_u32(stream)]
        company = self._strings_table[read_u32(stream)]
        description = self._strings_table[read_u32(stream)]
        timestamp = read_u32(stream)
        stream.seek(0x18, 1)  # Unknown field
        return Module(base_address=base_address, size=size, path=image_path, version=version, company=company,
                      description=description, timestamp=timestamp)


class HostnamesTable(dict):
    def __init__(self, io):
        super(HostnamesTable, self).__init__()
        number_of_hostnames = read_u32(io)
        for _ in range(number_of_hostnames):
            ip = io.read(16)
            hostname_len = read_u32(io)
            hostname = read_utf16(io, hostname_len)
            self[ip] = hostname


class PortsTable(dict):
    def __init__(self, io):
        super(PortsTable, self).__init__()
        number_of_ports = read_u32(io)
        for _ in range(number_of_ports):
            port_value = read_u16(io)
            is_tcp = bool(read_u16(io))
            port_len = read_u32(io)
            port_name = read_utf16(io, port_len)
            self[(port_value, is_tcp)] = port_name


CommonEventStruct = Struct("<IIIHHIQQIHHII")


def read_event(io, metadata):
    """Reads the event that the stream points to.

    :param io: the stream.
    :param metadata: metadata of the PML file.
    :return: Event object.
    """
    process_idx, tid, event_class_val, operation_val, _, _, duration, date, result, stacktrace_depth, _, \
        details_size, extra_details_offset = CommonEventStruct.unpack(io.read(CommonEventStruct.size))

    process = metadata.process_idx(process_idx)
    event_class = EventClass(event_class_val)
    operation = EventClassOperation[event_class](operation_val)

    sizeof_stacktrace = stacktrace_depth * metadata.sizeof_pvoid
    if metadata.should_get_stacktrace:
        stream = BytesIO(io.read(sizeof_stacktrace))
        stacktrace = [metadata.read_pvoid(stream) for _ in range(stacktrace_depth)]
    else:
        io.seek(sizeof_stacktrace, 1)
        stacktrace = []

    details = OrderedDict()
    event = Event(process=process, tid=tid, event_class=event_class, operation=operation, duration=duration,
                  date_filetime=date, result=result, stacktrace=stacktrace, category='', path='', details=details)

    details_stream = BytesIO(io.read(details_size))
    extra_details_stream = None
    if extra_details_offset > 0:
        # The extra details structure surprisingly can be separated from the event structure
        extra_details_offset -= \
            (CommonEventStruct.size + details_size + sizeof_stacktrace)
        assert extra_details_offset >= 0

        current_offset = io.tell()
        io.seek(extra_details_offset, 1)
        extra_details_stream_size = read_u16(io)
        extra_details_stream = BytesIO(io.read(extra_details_stream_size))
        io.seek(current_offset, 0)
    get_event_details(details_stream, metadata, event, extra_details_stream)
    return event


class PMLStreamReader(PMLStructReader):
    def __init__(self, f, should_get_stacktrace=True, should_get_details=True):
        self._stream = f
        self._header = Header(self._stream)
        self._read_pvoid = get_pvoid_reader(self.header.is_64bit)

        self._stream.seek(self.header.events_offsets_array_offset)
        self._events_offsets = EventOffsetsArray(
            self._stream, self.header.process_table_offset - self.header.events_offsets_array_offset,
            self.header.number_of_events)

        self._stream.seek(self.header.strings_table_offset)
        self._strings_table = StringsTable(self._stream)
        self._stream.seek(self.header.process_table_offset)
        self._process_table = ProcessTable(self._stream, read_pvoid=self._read_pvoid, strings_table=self._strings_table)
        self._stream.seek(self.header.hosts_and_ports_tables_offset)

        hostnames_and_ports_tables_stream = BytesIO(self._stream.read())  # this is the end of the file
        self._hostnames_table = HostnamesTable(hostnames_and_ports_tables_stream)
        self._ports_table = PortsTable(hostnames_and_ports_tables_stream)
        self._metadata = PmlMetadata(self.__str_idx, self.__process_idx, self.__hostname_idx, self.__port_idx,
                                     self._read_pvoid, get_pvoid_size(self.header.is_64bit),
                                     should_get_stacktrace, should_get_details)

    def __str_idx(self, string_index):
        """Get the actual string from a string index
        """
        return self._strings_table[string_index]

    def __process_idx(self, process_index):
        """Get the actual process from a process index
        """
        return self._process_table[process_index]

    def __hostname_idx(self, hostname_ip, is_ipv4):
        """Get the actual hostname from hostname ip
        """
        if self._hostnames_table.get(hostname_ip, '') != '':
            return self._hostnames_table[hostname_ip]
        if is_ipv4:
            return str(IPv4Address(hostname_ip[:4]))

        # remove leading zeroes in ipv6 like procmon does...
        return ':'.join(['{:x}'.format(int(i, 16)) for i in IPv6Address(hostname_ip).exploded.split(':')])

    def __port_idx(self, port, is_tcp):
        """Get the actual port name from port value
        """
        return self._ports_table.get((port, is_tcp), str(port))

    @property
    def header(self):
        return self._header

    @property
    def events_offsets(self):
        return self._events_offsets

    def processes(self):
        """Return a list of all the known processes in the log file
        """
        return list(self._process_table.values())

    def get_event_at_offset(self, offset):
        self._stream.seek(offset)
        event = read_event(self._stream, self._metadata)
        return event
