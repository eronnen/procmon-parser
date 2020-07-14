from collections import OrderedDict
from io import BytesIO
from six import PY2
from construct import StreamError
from procmon_parser.configuration_format import Record
from procmon_parser.logs_format import Header, StringsTable, ProcessTable, HostsAndPortsTable, EventsOffsetArray, \
    EventStruct
from procmon_parser.configuration import *
from procmon_parser.logs import *

__all__ = [
    'load_configuration', 'loads_configuration', 'dump_configuration', 'dumps_configuration', 'ProcmonLogsReader',
]


def load_configuration(stream):
    """Deserialize ``stream`` (a ``.read()``-supporting file-like object) which contains PMC formatted data,
    to a Python dictionary with the parsed configuration records.
    """
    records = []
    while True:
        try:
            name, data = Record.parse_stream(stream)
            records.append((name, data))
        except StreamError:
            break
    return OrderedDict(records)


def loads_configuration(data):
    """Deserialize ``data`` (a ``bytes`` object), which contains PMC formatted data,
    to a Python dictionary with the parsed configuration records.
    """
    stream = BytesIO(data)
    return load_configuration(stream)


def dump_configuration(records, stream):
    """Serialize ``records``, a dictionary of procmon configuration records, to ``stream`` (a
    ``.write()``-supporting file-like object that returns the length written (for python2 use the io module)),
    in the format of PMC.
    """
    for name, data in records.items():
        Record.build_stream((name, data), stream)


def dumps_configuration(records):
    """Serialize ``records``, a dictionary of procmon configuration records, to ``bytes`` in the format of PMC.
    """
    stream = BytesIO()
    dump_configuration(records, stream)
    return stream.getvalue()


class ProcmonLogsReader(object):
    """Reads procmon logs from a stream which in the PML format
    """
    def __init__(self, f):
        """Build a ProcmonLogsReader object from ``f`` (a `.read()``-supporting file-like object)
        """
        self._stream = f
        self._header = Header.parse_stream(f)
        self._events_offsets = self.__read_events_offsets()
        self._strings_table = self.__read_strings_table()
        self._process_table = self.__read_process_table()
        self._hosts_table, self._ports_table = self.__read_hosts_and_ports_table()
        self._current_event_index = 0
        self._number_of_events = self._header.number_of_events

    def __read_events_offsets(self):
        self._stream.seek(self._header.events_offsets_array_offset)
        raw_event_offsets_array = EventsOffsetArray(self._header.number_of_events).parse_stream(self._stream)
        return [o.offset for o in raw_event_offsets_array]

    def __read_strings_table(self):
        self._stream.seek(self._header.strings_table_offset)
        raw_strings_table = StringsTable.parse_stream(self._stream)
        return [s.string.string for s in raw_strings_table.strings]

    def __read_process_table(self):
        self._stream.seek(self._header.process_table_offset)
        raw_process_table = ProcessTable.parse_stream(self._stream, is_64bit=self._header.is_64bit,
                                                      strings_table=self._strings_table)
        return dict([element.process for element in raw_process_table.processes])

    def __read_hosts_and_ports_table(self):
        self._stream.seek(self._header.hosts_and_ports_tables_offset)
        raw_hosts_and_ports_table = HostsAndPortsTable.parse_stream(self._stream)
        return {h.host_ip: h.hostname.string for h in raw_hosts_and_ports_table.hosts}, \
               {(p.port_number, bool(p.is_tcp)): p.port.string for p in raw_hosts_and_ports_table.ports}

    def __iter__(self):
        return self

    def __next__(self):
        if self._current_event_index >= self._number_of_events:
            raise StopIteration
        current_index = self._current_event_index
        self._current_event_index += 1
        self._stream.seek(self._events_offsets[current_index])
        return EventStruct.parse_stream(self._stream, is_64bit=self._header.is_64bit, process_table=self._process_table,
                                        hosts_table=self._hosts_table, ports_table=self._ports_table)

    if PY2:
        next = __next__

    def __len__(self):
        return self._number_of_events

    def _get_os_name(self):
        windows_names = {
            (6, 0): "Windows Vista",
            (6, 1): "Windows 7",
            (6, 2): "Windows 8",
            (6, 3): "Windows 8.1",
            (10, 0): "Windows 10",
        }

        windows_name = windows_names[(self._header.windows_major_number, self._header.windows_minor_number)]
        if self._header.service_pack_name:
            windows_name += ", {}".format(self._header.service_pack_name)

        return "{} (build {}.{})".format(windows_name, self._header.windows_build_number,
                                         self._header.windows_build_number_after_decimal_point)

    def processes(self):
        """Return a list of all the known processes in the log file
        """
        return list(self._process_table.values())

    def system_details(self):
        """Return the system details of the computer which captured the logs (like Tools -> System Details in Procmon)
        """
        return {
            "Computer Name": self._header.computer_name,
            "Operating System": self._get_os_name(),
            "System Root": self._header.system_root,
            "Logical Processors": self._header.number_of_logical_processors,
            "Memory (RAM)": "{} GB".format((self._header.ram_memory_size / (1024.0 ** 3)) // 0.01 / 100),
            "System Type": "64-bit" if self._header.is_64bit else "32-bit"
        }
