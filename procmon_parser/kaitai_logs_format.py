from kaitaistruct import KaitaiStream
from ipaddress import IPv4Address, IPv6Address

from procmon_parser.kaitai_helper import filetime_to_datetime64, duration_from_100nanosecs
from procmon_parser.kaitai_generated.pml import Pml
from procmon_parser.kaitai_generated.pml_event import PmlEvent
from procmon_parser.kaitai_logs_details_format import get_event_info, PmlMetadata
from procmon_parser.consts import EventClass
from procmon_parser.logs import PMLStructReader, Module, Process, Event


class PMLKaitaiReader(PMLStructReader):
    def __init__(self, f):
        super(PMLKaitaiReader, self).__init__(f)
        self._pml = Pml.from_io(f)
        self._events_offsets = [o.offset for o in self._pml.events_offsets_table]
        self._process_table = {k.process_index: self.__to_process(k) for k in self._pml.process_table.processes}
        self._hostnames_table = {h.ip: h.name.string for h in self._pml.network_tables.hostnames_table.hostnames}
        self._ports_table = {(p.port, bool(p.is_tcp)): p.name.string for p in
                             self._pml.network_tables.ports_table.ports}
        self._metadata = PmlMetadata(str_idx=self.__str_idx, process_idx=self.__process_idx,
                                     hostname_idx=self.__hostname_idx, port_idx=self.__port_idx)

    def __str_idx(self, string_index):
        """Get the actual string from a string index
        """
        return self._pml.strings_table.strings[string_index].string

    def __process_idx(self, process_index):
        """Get the actual process from a process index
        """
        return self._process_table[process_index]

    def __hostname_idx(self, hostname_ip, is_ipv4):
        if self._hostnames_table.get(hostname_ip, '') != '':
            return self._hostnames_table[hostname_ip]
        if is_ipv4:
            return str(IPv4Address(hostname_ip[:4]))
        return str(IPv6Address(hostname_ip))

    def __port_idx(self, port, is_tcp):
        return self._ports_table.get((port, is_tcp), str(port))

    def __to_module(self, kaitai_module):
        return Module(base_address=kaitai_module.base_address.value, size=kaitai_module.size,
                      path=self.__str_idx(kaitai_module.path_string_index),
                      version=self.__str_idx(kaitai_module.version_string_index),
                      company=self.__str_idx(kaitai_module.company_string_index),
                      description=self.__str_idx(kaitai_module.description_string_index),
                      timestamp=kaitai_module.timestamp)

    def __to_process(self, kaitai_process):
        return Process(pid=kaitai_process.process_id, parent_pid=kaitai_process.parent_process_id,
                       authentication_id=kaitai_process.authentication_id, session=kaitai_process.session,
                       virtualized=kaitai_process.virtualized, is_process_64bit=kaitai_process.is_process_64bit,
                       integrity=self.__str_idx(kaitai_process.integrity_string_index),
                       user=self.__str_idx(kaitai_process.user_string_index),
                       process_name=self.__str_idx(kaitai_process.process_name_string_index),
                       image_path=self.__str_idx(kaitai_process.image_path_string_index),
                       command_line=self.__str_idx(kaitai_process.command_line_string_index),
                       company=self.__str_idx(kaitai_process.company_string_index),
                       version=self.__str_idx(kaitai_process.version_string_index),
                       description=self.__str_idx(kaitai_process.description_string_index),
                       start_time=filetime_to_datetime64(kaitai_process.start_time),
                       end_time=filetime_to_datetime64(kaitai_process.end_time),
                       modules=[self.__to_module(m) for m in kaitai_process.modules])

    def __to_event(self, kaitai_event):
        event_info = get_event_info(kaitai_event, self._metadata)
        return Event(process=self.__process_idx(kaitai_event.process_index), tid=kaitai_event.thread_id,
                     event_class=EventClass(kaitai_event.event_class.value), operation=event_info.operation,
                     duration=duration_from_100nanosecs(kaitai_event.duration),
                     date=filetime_to_datetime64(kaitai_event.date), result=kaitai_event.result,
                     stacktrace=kaitai_event.stacktrace, category=event_info.category, path=event_info.path,
                     details=event_info.details)

    @property
    def header(self):
        return self._pml.header

    @property
    def events_offsets(self):
        return self._events_offsets

    def get_event_at_offset(self, offset):
        before = self._stream.tell()
        self._stream.seek(offset)
        event = self.__to_event(PmlEvent(self.header.is_64bit, KaitaiStream(self._stream)))
        self._stream.seek(before)
        return event

    def processes(self):
        """Return a list of all the known processes in the log file
        """
        return list(self._process_table.values())
