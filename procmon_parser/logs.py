"""
Python types that procmon logs use
"""

import enum
from six import string_types


class EventClass(enum.IntEnum):
    UNKNOWN = 0
    PROCESS = 1
    REGISTRY = 2
    FILESYSTEM = 3
    PROFILING = 4
    NETWORK = 5


class ProcessOperation(enum.IntEnum):
    Process_Defined = 0
    Process_Create = 1
    Process_Exit = 2
    Thread_Create = 3
    Thread_Exit = 4
    Load_Image = 5
    Thread_Profile = 6
    Process_Start = 7
    Process_Statistics = 8
    System_Statistics = 9


class RegistryOperation(enum.IntEnum):
    RegOpenKey = 0
    RegCreateKey = 1
    RegCloseKey = 2
    RegQueryKey = 3
    RegSetValue = 4
    RegQueryValue = 5
    RegEnumValue = 6
    RegEnumKey = 7
    RegSetInfoKey = 8
    RegDeleteKey = 9
    RegDeleteValue = 10
    RegFlushKey = 11
    RegLoadKey = 12
    RegUnloadKey = 13
    RegRenameKey = 14
    RegQueryMultipleValueKey = 15
    RegSetKeySecurity = 16
    RegQueryKeySecurity = 17


class NetworkOperation(enum.IntEnum):
    Unknown = 0
    Other = 1
    Send = 2
    Receive = 3
    Accept = 4
    Connect = 5
    Disconnect = 6
    Reconnect = 7
    Retransmit = 8
    TCPCopy = 9


class ProfilingOperation(enum.IntEnum):
    Thread_Profiling = 0
    Process_Profiling = 1
    Debug_Output_Profiling = 2


class FilesystemOperation(enum.IntEnum):
    VolumeDismount = 0  # IRP_MJ_VOLUME_DISMOUNT
    VolumeMount = 1  # IRP_MJ_VOLUME_MOUNT
    FASTIO_MDL_WRITE_COMPLETE = 2  # FASTIO_MDL_WRITE_COMPLETE
    WriteFile2 = 3  # FASTIO_PREPARE_MDL_WRITE
    FASTIO_MDL_READ_COMPLETE = 4  # FASTIO_MDL_READ_COMPLETE
    ReadFile2 = 5  # FASTIO_MDL_READ
    QueryOpen = 6  # FASTIO_NETWORK_QUERY_OPEN
    FASTIO_CHECK_IF_POSSIBLE = 7  # FASTIO_CHECK_IF_POSSIBLE
    IRP_MJ_12 = 8  # IRP_MJ_12
    IRP_MJ_11 = 9  # IRP_MJ_11
    IRP_MJ_10 = 10  # IRP_MJ_10
    IRP_MJ_9 = 11  # IRP_MJ_9
    IRP_MJ_8 = 12  # IRP_MJ_8
    FASTIO_NOTIFY_STREAM_FO_CREATION = 13  # FASTIO_NOTIFY_STREAM_FO_CREATION
    FASTIO_RELEASE_FOR_CC_FLUSH = 14  # FASTIO_RELEASE_FOR_CC_FLUSH
    FASTIO_ACQUIRE_FOR_CC_FLUSH = 15  # FASTIO_ACQUIRE_FOR_CC_FLUSH
    FASTIO_RELEASE_FOR_MOD_WRITE = 16  # FASTIO_RELEASE_FOR_MOD_WRITE
    FASTIO_ACQUIRE_FOR_MOD_WRITE = 17  # FASTIO_ACQUIRE_FOR_MOD_WRITE
    FASTIO_RELEASE_FOR_SECTION_SYNCHRONIZATION = 18  # FASTIO_RELEASE_FOR_SECTION_SYNCHRONIZATION
    CreateFileMapping = 19  # FASTIO_ACQUIRE_FOR_SECTION_SYNCHRONIZATION
    CreateFile = 20  # IRP_MJ_CREATE
    CreatePipe = 21  # IRP_MJ_CREATE_NAMED_PIPE
    IRP_MJ_CLOSE = 22  # IRP_MJ_CLOSE
    ReadFile = 23  # IRP_MJ_READ
    WriteFile = 24  # IRP_MJ_WRITE
    QueryInformationFile = 25  # IRP_MJ_QUERY_INFORMATION
    SetInformationFile = 26  # IRP_MJ_SET_INFORMATION
    QueryEAFile = 27  # IRP_MJ_QUERY_EA
    SetEAFile = 28  # IRP_MJ_SET_EA
    FlushBuffersFile = 29  # IRP_MJ_FLUSH_BUFFERS
    QueryVolumeInformation = 30  # IRP_MJ_QUERY_VOLUME_INFORMATION
    SetVolumeInformation = 31  # IRP_MJ_SET_VOLUME_INFORMATION
    DirectoryControl = 32  # IRP_MJ_DIRECTORY_CONTROL
    FileSystemControl = 33  # IRP_MJ_FILE_SYSTEM_CONTROL
    DeviceIoControl = 34  # IRP_MJ_DEVICE_CONTROL
    InternalDeviceIoControl = 35  # IRP_MJ_INTERNAL_DEVICE_CONTROL
    Shutdown = 36  # IRP_MJ_SHUTDOWN
    LockUnlockFile = 37  # IRP_MJ_LOCK_CONTROL
    CloseFile = 38  # IRP_MJ_CLEANUP
    CreateMailSlot = 39  # IRP_MJ_CREATE_MAILSLOT
    QuerySecurityFile = 40  # IRP_MJ_QUERY_SECURITY
    SetSecurityFile = 41  # IRP_MJ_SET_SECURITY
    Power = 42  # IRP_MJ_POWER
    SystemControl = 43  # IRP_MJ_SYSTEM_CONTROL
    DeviceChange = 44  # IRP_MJ_DEVICE_CHANGE
    QueryFileQuota = 45  # IRP_MJ_QUERY_QUOTA
    SetFileQuota = 46  # IRP_MJ_SET_QUOTA
    PlugAndPlay = 47  # IRP_MJ_PNP


class FilesystemQueryInformationOperation(enum.IntEnum):
    QueryBasicInformationFile = 0x4
    QueryStandardInformationFile = 0x5
    QueryFileInternalInformationFile = 0x6
    QueryEaInformationFile = 0x7
    QueryNameInformationFile = 0x9
    QueryPositionInformationFile = 0xe
    QueryAllInformationFile = 0x12
    QueryEndOfFile = 0x14
    QueryStreamInformationFile = 0x16
    QueryCompressionInformationFile = 0x1c
    QueryId = 0x1d
    QueryMoveClusterInformationFile = 0x1f
    QueryNetworkOpenInformationFile = 0x22
    # QueryAttributeTag = 0x23
    QueryAttributeTagFile = 0x23
    QueryIdBothDirectory = 0x25
    QueryValidDataLength = 0x27
    QueryShortNameInformationFile = 0x28
    QueryIoPiorityHint = 0x2b
    QueryLinks = 0x2e
    QueryNormalizedNameInformationFile = 0x30
    QueryNetworkPhysicalNameInformationFile = 0x31
    QueryIdGlobalTxDirectoryInformation = 0x32
    QueryIsRemoteDeviceInformation = 0x33
    QueryAttributeCacheInformation = 0x34
    QueryNumaNodeInformation = 0x35
    QueryStandardLinkInformation = 0x36
    QueryRemoteProtocolInformation = 0x37
    QueryRenameInformationBypassAccessCheck = 0x38
    QueryLinkInformationBypassAccessCheck = 0x39
    QueryVolumeNameInformation = 0x3a
    QueryIdInformation = 0x3b
    QueryIdExtdDirectoryInformation = 0x3c
    QueryHardLinkFullIdInformation = 0x3e
    QueryIdExtdBothDirectoryInformation = 0x3f
    QueryDesiredStorageClassInformation = 0x43
    QueryStatInformation = 0x44
    QueryMemoryPartitionInformation = 0x45


class FilesystemSetInformationOperation(enum.IntEnum):
    SetBasicInformationFile = 0x4
    SetRenameInformationFile = 0xa
    SetLinkInformationFile = 0xb
    SetDispositionInformationFile = 0xd
    SetPositionInformationFile = 0xe
    SetAllocationInformationFile = 0x13
    SetEndOfFileInformationFile = 0x14
    SetFileStreamInformation = 0x16
    SetPipeInformation = 0x17
    SetValidDataLengthInformationFile = 0x27
    SetShortNameInformation = 0x28
    SetReplaceCompletionInformation = 0x3d
    SetDispositionInformationEx = 0x40
    SetRenameInformationEx = 0x41
    SetRenameInformationExBypassAccessCheck = 0x42


class FilesysemDirectoryControlOperation(enum.IntEnum):
    QueryDirectory = 0x1,
    NotifyChangeDirectory = 0x2,


class FilesystemPnpOperation(enum.IntEnum):
    StartDevice = 0x0
    QueryRemoveDevice = 0x1
    RemoveDevice = 0x2
    CancelRemoveDevice = 0x3
    StopDevice = 0x4
    QueryStopDevice = 0x5
    CancelStopDevice = 0x6
    QueryDeviceRelations = 0x7
    QueryInterface = 0x8
    QueryCapabilities = 0x9
    QueryResources = 0xa
    QueryResourceRequirements = 0xb
    QueryDeviceText = 0xc
    FilterResourceRequirements = 0xd
    ReadConfig = 0xf
    WriteConfig = 0x10
    Eject = 0x11
    SetLock = 0x12
    QueryId2 = 0x13
    QueryPnpDeviceState = 0x14
    QueryBusInformation = 0x15
    DeviceUsageNotification = 0x16
    SurpriseRemoval = 0x17
    QueryLegacyBusInformation = 0x18


Architecture = enum.IntEnum(value='Architecture', names=[('32-bit', 0), ('64-bit', 1)])


class Process(object):
    """Information about a process in the system
    """

    def __init__(self, pid=0, parent_pid=0, authentication_id=0, session=0, virtualized=0, architecture=0, integrity="",
                 user="", process_name="", image_path="", command_line="", company="", version="", description=""):
        self.pid = pid
        self.parent_pid = parent_pid
        self.authentication_id = authentication_id
        self.session = session
        self.virtualized = bool(virtualized)
        self.architecture = \
            Architecture[architecture] if isinstance(architecture, string_types) else Architecture(architecture)
        self.integrity = integrity
        self.user = user
        self.process_name = process_name
        self.image_path = image_path
        self.command_line = command_line
        self.company = company
        self.version = version
        self.description = description

    def __eq__(self, other):
        if type(other) is type(self):
            return self.__dict__ == other.__dict__
        return False

    def __ne__(self, other):
        return not self.__eq__(other)

    def __str__(self):
        return "{}, {}".format(self.process_name, self.pid)

    def __repr__(self):
        return "Process({}, {}, {}, {}, {}, \"{}\", \"{}\", \"{}\", \"{}\", \"{}\", \"{}\", \"{}\", \"{}\", \"{}\")"\
            .format(self.pid, self.parent_pid, self.authentication_id, self.session, self.virtualized,
                    self.architecture.name, self.integrity, self.user, self.process_name, self.image_path,
                    self.command_line, self.company, self.version, self.description)


class Event(object):
    def __init__(self, process=None, tid=0, event_class=None, operation=None, duration_100_nanosec=0, date=None, result=0,
                 stacktrace=None, category=None, path=None, details=None, file_offset=0):
        self.process = process
        self.tid = tid
        self.event_class = EventClass[event_class] if isinstance(event_class, string_types) else EventClass(event_class)
        self.operation = operation
        self.duration_100_nanosec = duration_100_nanosec
        self.date = date
        self.result = result
        self.stacktrace = stacktrace
        self.category = category
        self.path = path
        self.details = details
        self._file_offset = file_offset

    def __eq__(self, other):
        if type(other) is type(self):
            return self.__dict__ == other.__dict__
        return False

    def __ne__(self, other):
        return not self.__eq__(other)

    def __str__(self):
        return "File offset=0x{:x}, Process Name={}, Pid={}, Operation={}, Path=\"{}\", Details={}".format(
            self._file_offset, self.process.process_name, self.process.pid, self.operation, self.path, self.details)

    def __repr__(self):
        return "Event({}, {}, \"{}\", \"{}\", {}, {}, {}, \"{}\", \"{}\", {})" \
            .format(self.process, self.tid, self.event_class.name, self.operation, self.duration_100_nanosec,
                    self.date, self.result, self.category, self.path, self.details)


