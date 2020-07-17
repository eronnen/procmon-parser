# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

from pkg_resources import parse_version
import kaitaistruct
from kaitaistruct import KaitaiStruct, KaitaiStream, BytesIO
from enum import Enum


if parse_version(kaitaistruct.__version__) < parse_version('0.9'):
    raise Exception("Incompatible Kaitai Struct Python API: 0.9 or later is required, but you have %s" % (kaitaistruct.__version__))

from procmon_parser.kaitai_types import utf16_string
from procmon_parser.kaitai_types import ascii_string
from procmon_parser.kaitai_types import sized_utf16_multisz
from procmon_parser.kaitai_types import utf16_multisz
class PmlEvent(KaitaiStruct):
    """
    .. seealso::
       Source - https://github.com/eronnen/procmon-parser/blob/master/docs/PML%20Format.md
    """

    class PmlFilesystemQueryVolumeInformationOperation(Enum):
        query_information_volume = 1
        query_label_information_volume = 2
        query_size_information_volume = 3
        query_device_information_volume = 4
        query_attribute_information_volume = 5
        query_control_information_volume = 6
        query_full_size_information_volume = 7
        query_object_id_information_volume = 8

    class PmlRegistryOperation(Enum):
        reg_open_key = 0
        reg_create_key = 1
        reg_close_key = 2
        reg_query_key = 3
        reg_set_value = 4
        reg_query_value = 5
        reg_enum_value = 6
        reg_enum_key = 7
        reg_set_info_key = 8
        reg_delete_key = 9
        reg_delete_value = 10
        reg_flush_key = 11
        reg_load_key = 12
        reg_unload_key = 13
        reg_rename_key = 14
        reg_query_multiple_value_key = 15
        reg_set_key_security = 16
        reg_query_key_security = 17

    class PmlFilesystemPnpOperation(Enum):
        start_device = 0
        query_remove_device = 1
        remove_device = 2
        cancel_remove_device = 3
        stop_device = 4
        query_stop_device = 5
        cancel_stop_device = 6
        query_device_relations = 7
        query_interface = 8
        query_capabilities = 9
        query_resources = 10
        query_resource_requirements = 11
        query_device_text = 12
        filter_resource_requirements = 13
        read_config = 15
        write_config = 16
        eject = 17
        set_lock = 18
        query_id2 = 19
        query_pnp_device_state = 20
        query_bus_information = 21
        device_usage_notification = 22
        surprise_removal = 23
        query_legacy_bus_information = 24

    class PmlEventClass(Enum):
        unknown = 0
        process = 1
        registry = 2
        filesystem = 3
        profiling = 4
        network = 5

    class PmlFilesystemQueryFileInformationOperation(Enum):
        query_basic_information_file = 4
        query_standard_information_file = 5
        query_file_internal_information_file = 6
        query_ea_information_file = 7
        query_name_information_file = 9
        query_position_information_file = 14
        query_all_information_file = 18
        query_end_of_file = 20
        query_stream_information_file = 22
        query_compression_information_file = 28
        query_id = 29
        query_move_cluster_information_file = 31
        query_network_open_information_file = 34
        query_attribute_tag_file = 35
        query_id_both_directory = 37
        query_valid_data_length = 39
        query_short_name_information_file = 40
        query_io_piority_hint = 43
        query_links = 46
        query_normalized_name_information_file = 48
        query_network_physical_name_information_file = 49
        query_id_global_tx_directory_information = 50
        query_is_remote_device_information = 51
        query_attribute_cache_information = 52
        query_numa_node_information = 53
        query_standard_link_information = 54
        query_remote_protocol_information = 55
        query_rename_information_bypass_access_check = 56
        query_link_information_bypass_access_check = 57
        query_volume_name_information = 58
        query_id_information = 59
        query_id_extd_directory_information = 60
        query_hard_link_full_id_information = 62
        query_id_extd_both_directory_information = 63
        query_desired_storage_class_information = 67
        query_stat_information = 68
        query_memory_partition_information = 69

    class PmlFilesystemSetFileInformationOperation(Enum):
        set_basic_information_file = 4
        set_rename_information_file = 10
        set_link_information_file = 11
        set_disposition_information_file = 13
        set_position_information_file = 14
        set_allocation_information_file = 19
        set_end_of_file_information_file = 20
        set_file_stream_information = 22
        set_pipe_information = 23
        set_valid_data_length_information_file = 39
        set_short_name_information = 40
        set_replace_completion_information = 61
        set_disposition_information_ex = 64
        set_rename_information_ex = 65
        set_rename_information_ex_bypass_access_check = 66

    class PmlFilesystemDirectoryControlOperation(Enum):
        query_directory = 1
        notify_change_directory = 2

    class PmlFilesystemLockUnlockOperation(Enum):
        lock_file = 1
        unlock_file_single = 2
        unlock_file_all = 3
        unlock_file_by_key = 4

    class PmlFilesystemOperation(Enum):
        volume_dismount = 0
        volume_mount = 1
        fastio_mdl_write_complete = 2
        write_file2 = 3
        fastio_mdl_read_complete = 4
        read_file2 = 5
        query_open = 6
        fastio_check_if_possible = 7
        irp_mj_12 = 8
        irp_mj_11 = 9
        irp_mj_10 = 10
        irp_mj_9 = 11
        irp_mj_8 = 12
        fastio_notify_stream_fo_creation = 13
        fastio_release_for_cc_flush = 14
        fastio_acquire_for_cc_flush = 15
        fastio_release_for_mod_write = 16
        fastio_acquire_for_mod_write = 17
        fastio_release_for_section_synchronization = 18
        create_file_mapping = 19
        create_file = 20
        create_pipe = 21
        irp_mj_close = 22
        read_file = 23
        write_file = 24
        query_information_file = 25
        set_information_file = 26
        query_e_a_file = 27
        set_e_a_file = 28
        flush_buffers_file = 29
        query_volume_information = 30
        set_volume_information = 31
        directory_control = 32
        file_system_control = 33
        device_io_control = 34
        internal_device_io_control = 35
        shutdown = 36
        lock_unlock_file = 37
        close_file = 38
        create_mail_slot = 39
        query_security_file = 40
        set_security_file = 41
        power = 42
        system_control = 43
        device_change = 44
        query_file_quota = 45
        set_file_quota = 46
        plug_and_play = 47

    class PmlFilesystemSetVolumeInformationOperation(Enum):
        set_control_information_volume = 1
        set_label_information_volume = 2
        set_object_id_information_volume = 8

    class PmlProcessOperation(Enum):
        process_defined = 0
        process_create = 1
        process_exit = 2
        thread_create = 3
        thread_exit = 4
        load_image = 5
        thread_profile = 6
        process_start = 7
        process_statistics = 8
        system_statistics = 9

    class PmlNetworkOperation(Enum):
        unknown = 0
        other = 1
        send = 2
        receive = 3
        accept = 4
        connect = 5
        disconnect = 6
        reconnect = 7
        retransmit = 8
        tcp_copy = 9

    class PmlProfilingOperation(Enum):
        thread_profiling = 0
        process_profiling = 1
        debug_output_profiling = 2
    def __init__(self, is_64bit, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self.is_64bit = is_64bit
        self._read()

    def _read(self):
        self.process_index = self._io.read_u4le()
        self.thread_id = self._io.read_u4le()
        self.event_class = KaitaiStream.resolve_enum(PmlEvent.PmlEventClass, self._io.read_u4le())
        self.operation = self._io.read_u2le()
        self.reserved1 = self._io.read_u2le()
        self.reserved2 = self._io.read_u4le()
        self.duration = self._io.read_u8le()
        self.date = self._io.read_u8le()
        self.result = self._io.read_u4le()
        self.stacktrace_depth = self._io.read_u2le()
        self.reserved3 = self._io.read_u2le()
        self.details_size = self._io.read_u4le()
        self.reserved4 = self._io.read_u4le()
        self.stacktrace = [None] * (self.stacktrace_depth)
        for i in range(self.stacktrace_depth):
            self.stacktrace[i] = PmlEvent.Pvoid(self.is_64bit, self._io, self, self._root)

        _on = self.event_class
        if _on == PmlEvent.PmlEventClass.filesystem:
            self.details = PmlEvent.PmlFilesystemDetails(self._io, self, self._root)
        elif _on == PmlEvent.PmlEventClass.process:
            self.details = PmlEvent.PmlProcessDetails(self._io, self, self._root)
        elif _on == PmlEvent.PmlEventClass.network:
            self.details = PmlEvent.PmlNetworkDetails(self._io, self, self._root)
        elif _on == PmlEvent.PmlEventClass.profiling:
            self.details = PmlEvent.PmlProfilingDetails(self._io, self, self._root)
        elif _on == PmlEvent.PmlEventClass.registry:
            self.details = PmlEvent.PmlRegistryDetails(self._io, self, self._root)

    class PmlFilesystemDirectoryControlDetails(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            _on = self._parent.sub_operation
            if _on == PmlEvent.PmlFilesystemDirectoryControlOperation.query_directory.value:
                self.sub_operation_details = PmlEvent.PmlFilesystemQueryDirectoryDetails(self._io, self, self._root)
            else:
                self.sub_operation_details = PmlEvent.Dummy(self._io, self, self._root)


    class PmlProcessDetails(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            _on = self._parent.operation
            if _on == PmlEvent.PmlProcessOperation.thread_profile.value:
                self.extra_details = PmlEvent.Dummy(self._io, self, self._root)
            elif _on == PmlEvent.PmlProcessOperation.process_start.value:
                self.extra_details = PmlEvent.PmlProcessStartedDetails(self._io, self, self._root)
            elif _on == PmlEvent.PmlProcessOperation.process_statistics.value:
                self.extra_details = PmlEvent.Dummy(self._io, self, self._root)
            elif _on == PmlEvent.PmlProcessOperation.process_create.value:
                self.extra_details = PmlEvent.PmlProcessCreatedDetails(self._io, self, self._root)
            elif _on == PmlEvent.PmlProcessOperation.system_statistics.value:
                self.extra_details = PmlEvent.Dummy(self._io, self, self._root)
            elif _on == PmlEvent.PmlProcessOperation.process_defined.value:
                self.extra_details = PmlEvent.PmlProcessCreatedDetails(self._io, self, self._root)
            elif _on == PmlEvent.PmlProcessOperation.process_exit.value:
                self.extra_details = PmlEvent.Dummy(self._io, self, self._root)
            elif _on == PmlEvent.PmlProcessOperation.thread_exit.value:
                self.extra_details = PmlEvent.PmlThreadExitDetails(self._io, self, self._root)
            elif _on == PmlEvent.PmlProcessOperation.load_image.value:
                self.extra_details = PmlEvent.PmlLoadImageDetails(self._io, self, self._root)
            elif _on == PmlEvent.PmlProcessOperation.thread_create.value:
                self.extra_details = PmlEvent.Dummy(self._io, self, self._root)
            else:
                self.extra_details = PmlEvent.Dummy(self._io, self, self._root)


    class Pvoid(KaitaiStruct):
        def __init__(self, is_64bit, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self.is_64bit = is_64bit
            self._read()

        def _read(self):
            _on = self.is_64bit
            if _on == 0:
                self.value = self._io.read_u4le()
            elif _on == 1:
                self.value = self._io.read_u8le()


    class DetailString(KaitaiStruct):
        def __init__(self, is_ascii, char_count, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self.is_ascii = is_ascii
            self.char_count = char_count
            self._read()

        def _read(self):
            _on = self.is_ascii
            if _on == 0:
                self.string = utf16_string.Utf16String((self.char_count * 2), self._io)
            elif _on == 1:
                self.string = ascii_string.AsciiString(self.char_count, self._io)


    class PmlRegistryDetailsLoadRename(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.reserved = self._io.read_bytes(2)


    class PmlRegistryDetailsQuery(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.reserved = self._io.read_bytes(10)


    class PmlThreadExitDetails(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.reserved1 = self._io.read_u4le()
            self.kernel_time = self._io.read_u8le()
            self.user_time = self._io.read_u8le()


    class PmlLoadImageDetails(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.image_base = PmlEvent.Pvoid(self._root.is_64bit, self._io, self, self._root)
            self.image_size = self._io.read_u4le()
            self.path_info = PmlEvent.DetailStringInfo(self._io, self, self._root)
            self.reserved1 = self._io.read_u2le()
            self.path = PmlEvent.DetailString(self.path_info.is_ascii, self.path_info.char_count, self._io, self, self._root)


    class PmlProcessStartedDetails(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.parent_pid = self._io.read_u4le()
            self.command_line_info = PmlEvent.DetailStringInfo(self._io, self, self._root)
            self.current_directory_info = PmlEvent.DetailStringInfo(self._io, self, self._root)
            self.environment_size = self._io.read_u4le()
            self.command_line = PmlEvent.DetailString(self.command_line_info.is_ascii, self.command_line_info.char_count, self._io, self, self._root)
            self.current_directory = PmlEvent.DetailString(self.current_directory_info.is_ascii, self.current_directory_info.char_count, self._io, self, self._root)
            self.environment = sized_utf16_multisz.SizedUtf16Multisz((self.environment_size * 2), self._io)


    class Dummy(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            pass


    class PmlRegistryDetails(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.path_info = PmlEvent.DetailStringInfo(self._io, self, self._root)
            _on = self._parent.operation
            if _on == PmlEvent.PmlRegistryOperation.reg_enum_value.value:
                self.extra_details = PmlEvent.PmlRegistryDetailsSetEnum(self._io, self, self._root)
            elif _on == PmlEvent.PmlRegistryOperation.reg_query_key.value:
                self.extra_details = PmlEvent.PmlRegistryDetailsQuery(self._io, self, self._root)
            elif _on == PmlEvent.PmlRegistryOperation.reg_set_value.value:
                self.extra_details = PmlEvent.PmlRegistryDetailsSetEnum(self._io, self, self._root)
            elif _on == PmlEvent.PmlRegistryOperation.reg_rename_key.value:
                self.extra_details = PmlEvent.PmlRegistryDetailsLoadRename(self._io, self, self._root)
            elif _on == PmlEvent.PmlRegistryOperation.reg_set_info_key.value:
                self.extra_details = PmlEvent.PmlRegistryDetailsSetEnum(self._io, self, self._root)
            elif _on == PmlEvent.PmlRegistryOperation.reg_load_key.value:
                self.extra_details = PmlEvent.PmlRegistryDetailsLoadRename(self._io, self, self._root)
            elif _on == PmlEvent.PmlRegistryOperation.reg_create_key.value:
                self.extra_details = PmlEvent.PmlRegistryDetailsOpenCreate(self._io, self, self._root)
            elif _on == PmlEvent.PmlRegistryOperation.reg_open_key.value:
                self.extra_details = PmlEvent.PmlRegistryDetailsOpenCreate(self._io, self, self._root)
            elif _on == PmlEvent.PmlRegistryOperation.reg_query_value.value:
                self.extra_details = PmlEvent.PmlRegistryDetailsQuery(self._io, self, self._root)
            elif _on == PmlEvent.PmlRegistryOperation.reg_enum_key.value:
                self.extra_details = PmlEvent.PmlRegistryDetailsSetEnum(self._io, self, self._root)
            else:
                self.extra_details = PmlEvent.Dummy(self._io, self, self._root)
            self.path = PmlEvent.DetailString(self.path_info.is_ascii, self.path_info.char_count, self._io, self, self._root)


    class PmlNetworkFlags(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.flags = self._io.read_u2le()

        @property
        def is_source_ipv4(self):
            if hasattr(self, '_m_is_source_ipv4'):
                return self._m_is_source_ipv4 if hasattr(self, '_m_is_source_ipv4') else None

            self._m_is_source_ipv4 = (self.flags & 1) != 0
            return self._m_is_source_ipv4 if hasattr(self, '_m_is_source_ipv4') else None

        @property
        def is_dest_ipv4(self):
            if hasattr(self, '_m_is_dest_ipv4'):
                return self._m_is_dest_ipv4 if hasattr(self, '_m_is_dest_ipv4') else None

            self._m_is_dest_ipv4 = (self.flags & 2) != 0
            return self._m_is_dest_ipv4 if hasattr(self, '_m_is_dest_ipv4') else None

        @property
        def is_tcp(self):
            if hasattr(self, '_m_is_tcp'):
                return self._m_is_tcp if hasattr(self, '_m_is_tcp') else None

            self._m_is_tcp = (self.flags & 4) != 0
            return self._m_is_tcp if hasattr(self, '_m_is_tcp') else None


    class PmlFilesystemDetails(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.sub_operation = self._io.read_u1()
            self.reserved1 = self._io.read_u1()
            self.reserved2 = [None] * (5)
            for i in range(5):
                self.reserved2[i] = PmlEvent.Pvoid(self._root.is_64bit, self._io, self, self._root)

            self.reserved3 = self._io.read_bytes(22)
            self.path_info = PmlEvent.DetailStringInfo(self._io, self, self._root)
            self.reserved4 = self._io.read_u2le()
            self.path = PmlEvent.DetailString(self.path_info.is_ascii, self.path_info.char_count, self._io, self, self._root)
            _on = self._parent.operation
            if _on == PmlEvent.PmlFilesystemOperation.directory_control.value:
                self.extra_details = PmlEvent.PmlFilesystemDirectoryControlDetails(self._io, self, self._root)
            else:
                self.extra_details = PmlEvent.Dummy(self._io, self, self._root)


    class PmlFilesystemQueryDirectoryDetails(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.directory_name_info = PmlEvent.DetailStringInfo(self._io, self, self._root)
            self.directory_name = PmlEvent.DetailString(self.directory_name_info.is_ascii, self.directory_name_info.char_count, self._io, self, self._root)


    class DetailStringInfo(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.info = self._io.read_u2le()

        @property
        def is_ascii(self):
            if hasattr(self, '_m_is_ascii'):
                return self._m_is_ascii if hasattr(self, '_m_is_ascii') else None

            self._m_is_ascii = (self.info >> 15)
            return self._m_is_ascii if hasattr(self, '_m_is_ascii') else None

        @property
        def char_count(self):
            if hasattr(self, '_m_char_count'):
                return self._m_char_count if hasattr(self, '_m_char_count') else None

            self._m_char_count = (self.info & 32767)
            return self._m_char_count if hasattr(self, '_m_char_count') else None


    class PmlRegistryDetailsSetEnum(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.reserved = self._io.read_bytes(14)


    class PmlNetworkDetails(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.flags = PmlEvent.PmlNetworkFlags(self._io, self, self._root)
            self.reserved2 = self._io.read_u2le()
            self.packet_length = self._io.read_u4le()
            self.source_host_ip = self._io.read_bytes(16)
            self.dest_host_ip = self._io.read_bytes(16)
            self.source_port = self._io.read_u2le()
            self.dest_port = self._io.read_u2le()
            self.extra_details = utf16_multisz.Utf16Multisz(self._io)


    class PmlProcessCreatedDetails(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.reserved1 = self._io.read_u4le()
            self.created_pid = self._io.read_u4le()
            self.reserved2 = self._io.read_bytes(36)
            self.size1 = self._io.read_u1()
            self.size2 = self._io.read_u1()
            self.path_info = PmlEvent.DetailStringInfo(self._io, self, self._root)
            self.command_line_info = PmlEvent.DetailStringInfo(self._io, self, self._root)
            self.reserved3 = self._io.read_u2le()
            self.reserved4 = self._io.read_bytes((self.size1 + self.size2))
            self.path = PmlEvent.DetailString(self.path_info.is_ascii, self.path_info.char_count, self._io, self, self._root)
            self.command_line = PmlEvent.DetailString(self.command_line_info.is_ascii, self.command_line_info.char_count, self._io, self, self._root)


    class PmlRegistryDetailsOpenCreate(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.reserved = self._io.read_bytes(6)


    class PmlProfilingDetails(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.bytes = self._io.read_bytes(self._parent.details_size)



