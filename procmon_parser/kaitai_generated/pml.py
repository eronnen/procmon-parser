# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

from pkg_resources import parse_version
import kaitaistruct
from kaitaistruct import KaitaiStruct, KaitaiStream, BytesIO


if parse_version(kaitaistruct.__version__) < parse_version('0.9'):
    raise Exception("Incompatible Kaitai Struct Python API: 0.9 or later is required, but you have %s" % (kaitaistruct.__version__))

from procmon_parser.kaitai_types import utf16_string
class Pml(KaitaiStruct):
    """
    .. seealso::
       Source - https://github.com/eronnen/procmon-parser/blob/master/docs/PML%20Format.md
    """
    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._read()

    def _read(self):
        self.header = Pml.PmlHeader(self._io, self, self._root)

    class Pvoid(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            _on = self._root.header.is_64bit
            if _on == 0:
                self.value = self._io.read_u4le()
            elif _on == 1:
                self.value = self._io.read_u8le()


    class PmlPort(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.port = self._io.read_u2le()
            self.is_tcp = self._io.read_u2le()
            self.name = Pml.SizedUtf16Cstring(self._io, self, self._root)


    class PmlNetworkTables(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.hostnames_table = Pml.PmlHostnamesTable(self._io, self, self._root)
            self.ports_table = Pml.PmlPortsTable(self._io, self, self._root)


    class PmlProcess(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.process_index = self._io.read_u4le()
            self.process_id = self._io.read_u4le()
            self.parent_process_id = self._io.read_u4le()
            self.reserved1 = self._io.read_u4le()
            self.authentication_id = self._io.read_u8le()
            self.session = self._io.read_u4le()
            self.reserved3 = self._io.read_u4le()
            self.start_time = self._io.read_u8le()
            self.end_time = self._io.read_u8le()
            self.virtualized = self._io.read_u4le()
            self.is_process_64bit = self._io.read_u4le()
            self.integrity_string_index = self._io.read_u4le()
            self.user_string_index = self._io.read_u4le()
            self.process_name_string_index = self._io.read_u4le()
            self.image_path_string_index = self._io.read_u4le()
            self.command_line_string_index = self._io.read_u4le()
            self.company_string_index = self._io.read_u4le()
            self.version_string_index = self._io.read_u4le()
            self.description_string_index = self._io.read_u4le()
            self.reserved4 = Pml.Pvoid(self._io, self, self._root)
            self.reserved5 = self._io.read_u8le()
            self.number_of_modules = self._io.read_u4le()
            self.modules = [None] * (self.number_of_modules)
            for i in range(self.number_of_modules):
                self.modules[i] = Pml.PmlModule(self._io, self, self._root)



    class PmlStringsTable(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.number_of_strings = self._io.read_u4le()
            self.string_offsets = [None] * (self.number_of_strings)
            for i in range(self.number_of_strings):
                self.string_offsets[i] = self._io.read_u4le()

            self.strings = [None] * (self.number_of_strings)
            for i in range(self.number_of_strings):
                self.strings[i] = Pml.SizedUtf16Cstring(self._io, self, self._root)



    class PmlProcessTable(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.number_of_processes = self._io.read_u4le()
            self.process_indexes = [None] * (self.number_of_processes)
            for i in range(self.number_of_processes):
                self.process_indexes[i] = self._io.read_u4le()

            self.process_offsets = [None] * (self.number_of_processes)
            for i in range(self.number_of_processes):
                self.process_offsets[i] = self._io.read_u4le()

            self.processes = [None] * (self.number_of_processes)
            for i in range(self.number_of_processes):
                self.processes[i] = Pml.PmlProcess(self._io, self, self._root)



    class PmlPortsTable(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.number_of_ports = self._io.read_u4le()
            self.ports = [None] * (self.number_of_ports)
            for i in range(self.number_of_ports):
                self.ports[i] = Pml.PmlPort(self._io, self, self._root)



    class SizedUtf16Cstring(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.len = self._io.read_u4le()
            self.string = utf16_string.Utf16String(self.len, self._io)


    class PmlModule(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.reserved1 = Pml.Pvoid(self._io, self, self._root)
            self.base_address = Pml.Pvoid(self._io, self, self._root)
            self.size = self._io.read_u4le()
            self.path_string_index = self._io.read_u4le()
            self.version_string_index = self._io.read_u4le()
            self.company_string_index = self._io.read_u4le()
            self.description_string_index = self._io.read_u4le()
            self.timestamp = self._io.read_u4le()
            self.reserved2 = self._io.read_u8le()
            self.reserved3 = self._io.read_u8le()
            self.reserved4 = self._io.read_u8le()


    class PmlHostnamesTable(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.number_of_hostnames = self._io.read_u4le()
            self.hostnames = [None] * (self.number_of_hostnames)
            for i in range(self.number_of_hostnames):
                self.hostnames[i] = Pml.PmlHostname(self._io, self, self._root)



    class PmlHostname(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.ip = self._io.read_bytes(16)
            self.name = Pml.SizedUtf16Cstring(self._io, self, self._root)


    class PmlHeader(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.signature = self._io.read_bytes(4)
            if not self.signature == b"\x50\x4D\x4C\x5F":
                raise kaitaistruct.ValidationNotEqualError(b"\x50\x4D\x4C\x5F", self.signature, self._io, u"/types/pml_header/seq/0")
            self.version = self._io.read_u4le()
            self.is_64bit = self._io.read_u4le()
            self.desktop_name = (self._io.read_bytes(32)).decode(u"UTF-16LE")
            self.system_root = (self._io.read_bytes(520)).decode(u"UTF-16LE")
            self.number_of_events = self._io.read_u4le()
            self.reserved1 = self._io.read_u8le()
            self.events_offset = self._io.read_u8le()
            self.events_offsets_array_offset = self._io.read_u8le()
            self.process_table_offset = self._io.read_u8le()
            self.strings_table_offset = self._io.read_u8le()
            self.unknown_table_offset = self._io.read_u8le()
            self.reserved2 = self._io.read_u8le()
            self.reserved3 = self._io.read_u4le()
            self.windows_major_number = self._io.read_u4le()
            self.windows_minor_number = self._io.read_u4le()
            self.windows_build_number = self._io.read_u4le()
            self.windows_build_number_after_decimal_point = self._io.read_u4le()
            self.service_pack_name = (self._io.read_bytes(50)).decode(u"UTF-16LE")
            self.reserved4 = self._io.read_bytes(214)
            self.number_of_logical_processors = self._io.read_u4le()
            self.ram_memory_size = self._io.read_u8le()
            self.header_size = self._io.read_u8le()
            self.hosts_and_ports_tables_offset = self._io.read_u8le()


    class PmlEventOffset(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.offset = self._io.read_u4le()
            self.flags = self._io.read_u1()


    @property
    def events_offsets_table(self):
        if hasattr(self, '_m_events_offsets_table'):
            return self._m_events_offsets_table if hasattr(self, '_m_events_offsets_table') else None

        _pos = self._io.pos()
        self._io.seek(self.header.events_offsets_array_offset)
        self._m_events_offsets_table = [None] * (self.header.number_of_events)
        for i in range(self.header.number_of_events):
            self._m_events_offsets_table[i] = Pml.PmlEventOffset(self._io, self, self._root)

        self._io.seek(_pos)
        return self._m_events_offsets_table if hasattr(self, '_m_events_offsets_table') else None

    @property
    def strings_table(self):
        if hasattr(self, '_m_strings_table'):
            return self._m_strings_table if hasattr(self, '_m_strings_table') else None

        _pos = self._io.pos()
        self._io.seek(self.header.strings_table_offset)
        self._m_strings_table = Pml.PmlStringsTable(self._io, self, self._root)
        self._io.seek(_pos)
        return self._m_strings_table if hasattr(self, '_m_strings_table') else None

    @property
    def process_table(self):
        if hasattr(self, '_m_process_table'):
            return self._m_process_table if hasattr(self, '_m_process_table') else None

        _pos = self._io.pos()
        self._io.seek(self.header.process_table_offset)
        self._m_process_table = Pml.PmlProcessTable(self._io, self, self._root)
        self._io.seek(_pos)
        return self._m_process_table if hasattr(self, '_m_process_table') else None

    @property
    def network_tables(self):
        if hasattr(self, '_m_network_tables'):
            return self._m_network_tables if hasattr(self, '_m_network_tables') else None

        _pos = self._io.pos()
        self._io.seek(self.header.hosts_and_ports_tables_offset)
        self._m_network_tables = Pml.PmlNetworkTables(self._io, self, self._root)
        self._io.seek(_pos)
        return self._m_network_tables if hasattr(self, '_m_network_tables') else None


