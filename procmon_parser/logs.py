"""
Python types that procmon logs use
"""

import datetime
import enum
from six import string_types
from numpy import timedelta64
from procmon_parser.configuration import Column


class EventClass(enum.IntEnum):
    Unknown = 0
    Process = 1
    Registry = 2
    File_System = 3
    Profiling = 4
    Network = 5


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


ErrorCodeMessages = {
    0: 'SUCCESS',
    0x103: '',
    0x104: 'REPARSE',
    0x105: 'MORE ENTRIES',
    0x108: 'OPLOCK BREAK IN PROGRESS',
    0x10b: 'NOTIFY CLEANUP',
    0x10c: 'NOTIFY ENUM DIR',
    0x12a: 'FILE LOCKED WITH ONLY READERS',
    0x12b: 'FILE LOCKED WITH WRITERS',
    0x215: 'OPLOCK SWITCHED TO NEW HANDLE',
    0x216: 'OPLOCK HANDLE CLOSED',
    0x367: 'WAIT FOR OPLOCK',
    0x40000016: 'PREDEFINED HANDLE',
    0xc0000001: 'UNSUCCESSFUL',
    0x80000015: 'INVALID_EA_FLAG',
    0x80000002: 'DATATYPE_MISALIGNMENT',
    0x80000005: 'BUFFER_OVERFLOW',
    0x80000006: 'NO_MORE_FILES',
    0x8000001a: 'NO_MORE_ENTRIES',
    0xc0000101: 'NOT EMPTY',
    0xc0000002: 'NOT IMPLEMENTED',
    0xc0000003: 'INVALID INFO CLASS',
    0xc0000004: 'INFO LENGTH MISMATCH',
    0xc0000005: 'ACCESS VIOLATION',
    0xc0000006: 'IN PAGE ERROR',
    0xc0000008: 'INVALID HANDLE',
    0xc000000d: 'INVALID PARAMETER',
    0xc000000e: 'NO SUCH DEVICE',
    0xc000000f: 'NO SUCH FILE',
    0xc0000010: 'INVALID DEVICE REQUEST',
    0xc0000011: 'END OF FILE',
    0xc0000012: 'WRONG VOLUME',
    0xc0000013: 'NO MEDIA',
    0xc0000015: 'NONEXISTENT SECTOR',
    0xc0000017: 'NO MEMORY',
    0xc0000021: 'ALREADY COMMITED',
    0xc0000022: 'ACCESS DENIED',
    0xc0000023: 'ALREADY COMMITED',
    0xc0000024: 'BUFFER TO SMALL',
    0xc0000032: 'DISK CORRUPT',
    0xc0000033: 'NAME INVALID',
    0xc0000034: 'NAME NOT FOUND',
    0xc0000035: 'NAME COLLISION',
    0xc0000039: 'OBJECT PATH INVALID',
    0xc000003a: 'PATH NOT FOUND',
    0xc000003b: 'PATH SYNTAX BAD',
    0xc000003c: 'DATA OVERRUN',
    0xc000003f: 'CRC ERROR',
    0xc0000043: 'SHARING VIOLATION',
    0xc0000044: 'QUOTA EXCEEDED',
    0xc000004f: 'EAS NOT SUPPORTED',
    0xc0000050: 'EA TOO LARGE',
    0xc0000051: 'NONEXISTENT EA ENTRY',
    0xc0000052: 'NO EAS ON FILE',
    0xc0000053: 'EA CORRUPTED ERROR',
    0xc0000054: 'FILE LOCK CONFLICT',
    0xc0000055: 'NOT GRANTED',
    0xc0000056: 'DELETE PENDING',
    0xc0000061: 'PRIVILEGE NOT HELD',
    0xc000006d: 'LOGON FAILURE',
    0xc000007e: 'RANGE NOT LOCKED',
    0xc000007f: 'DISK FULL',
    0xc0000098: 'FILE INVALID',
    0xc000009a: 'INSUFFICIENT RESOURCES',
    0xc000009c: 'DEVICE DATA ERROR',
    0xc000009d: 'DEVICE NOT CONNECTED',
    0xc00000a2: 'MEDIA WRITE PROTECTED',
    0xc00000a5: 'BAD IMPERSONATION',
    0xc00000ab: 'INSTANCE NOT AVAILABLE',
    0xc00000ac: 'PIPE NOT AVAILABLE',
    0xc00000ad: 'INVALID PIPE STATE',
    0xc00000ae: 'PIPE BUSY',
    0xc00000b0: 'PIPE DISCONNECTED',
    0xc00000b1: 'PIPE CLOSING',
    0xc00000b2: 'PIPE CONNECTED',
    0xc00000b3: 'PIPE LISTENING',
    0xc00000b4: 'INVALID READ MODE',
    0xc00000b5: 'IO TIMEOUT',
    0xc00000ba: 'IS DIRECTORY',
    0xc00000bb: 'NOT SUPPORTED',
    0xc00000bd: 'DUPLICATE NAME',
    0xc00000be: 'BAD NETWORK PATH',
    0xc00000c1: 'BAD NETWORK PATH',
    0xc00000c3: 'INVALID NETWORK RESPONSE',
    0xc00000c4: 'NETWORK ERROR',
    0xc00000cc: 'BAD NETWORK NAME',
    0xc00000d4: 'BAD NETWORK NAME',
    0xc00000d8: 'CANT WAIT',
    0xc00000d9: 'PIPE EMPTY',
    0xc00000db: 'CSC OBJECT PATH NOT FOUND',
    0xc00000e2: 'OPLOCK NOT GRANTED',
    0xc00000ef: 'INVALID PARAMETER 1',
    0xc00000f0: 'INVALID PARAMETER 2',
    0xc00000f1: 'INVALID PARAMETER 3',
    0xc00000f2: 'INVALID PARAMETER 4',
    0xc00000fb: 'REDIRECTOR NOT STARTED',
    0xc0000102: 'FILE CORRUPT',
    0xc0000103: 'NOT A DIRECTORY',
    0xc0000107: 'FILES OPEN',
    0xc000010d: 'CANNOT IMPERSONATE',
    0xc0000120: 'CANCELLED',
    0xc0000121: 'CANNOT DELETE',
    0xc0000123: 'FILE DELETED',
    0xc0000128: 'FILE CLOSED',
    0xc000012a: 'THREAD NOT IN PROCESS',
    0xc0000148: 'INVALID LEVEL',
    0xc000014b: 'PIPE BROKEN',
    0xc000014c: 'REGISTRY CORRUPT',
    0xc000014d: 'IO FAILED',
    0xc000017c: 'KEY DELETED',
    0xc0000181: 'CHILD MUST BE VOLATILE',
    0xc0000184: 'INVALID DEVICE STATE',
    0xc0000185: 'IO DEVICE ERROR',
    0xc0000188: 'LOG FILE FULL',
    0xc000019c: 'FS DRIVER REQUIRED',
    0xc0000205: 'INSUFFICIENT SERVER RESOURCES',
    0xc0000207: 'INVALID ADDRESS COMPONENT',
    0xc000020c: 'DISCONNECTED',
    0xc0000225: 'NOT FOUND',
    0xc0000243: 'USER MAPPED FILE',
    0xc0000248: 'LOGIN WKSTA RESTRICTION',
    0xc0000257: 'PATH NOT COVERED',
    0xc000026d: 'DFS UNAVAILABLE',
    0xc0000273: 'NO MORE MATCHES',
    0xc0000275: 'NOT REPARSE POINT',
    0xc00002ea: 'CANNOT MAKE',
    0xc00002f0: 'OBJECTID NOT FOUND',
    0xc0000388: 'DOWNGRADE DETECTED',
    0xc0190044: 'CANNOT EXECUTE FILE IN TRANSACTION',
    0xc0000425: 'HIVE UNLOADED',
    0xc0000427: 'FILE SYSTEM LIMITATION',
    0xc0000463: 'DEVICE FEATURE NOT SUPPORTED',
    0xc000046d: 'OBJECT NOT EXTERNALLY BACKED',
    0xc0000909: 'CANNOT BREAK OPLOCK',
    0xc000a2a1: 'STATUS_OFFLOAD_READ_FLT_NOT_SUPPORTED',
    0xc000a2a2: 'STATUS_OFFLOAD_WRITE_FLT_NOT_SUPPORTED',
    0xc0190001: 'TRANSACTIONAL CONFLICT',
    0xc0190002: 'INVALID TRANSACTION',
    0xc0190003: 'TRANSACTION_NOT_ACTIVE',
    0xc019003e: 'EFS NOT ALLOWED IN TRANSACTION',
    0xc019003f: 'TRANSACTIONAL OPEN NOT ALLOWED',
    0xc0190040: 'TRANSACTED MAPPING UNSUPPORTED REMOTE',
    0xc000a2a3: 'OFFLOAD READ FILE NOT SUPPORTED',
    0xc000a2a4: 'OFFLOAD READ FILE NOT SUPPORTED',
    0xc0190049: 'SPARSE NOT ALLOWED IN TRANSACTION',
    0xc01c0004: 'FAST IO DISALLOWED',
}


class Process(object):
    """Information about a process in the system
    """

    def __init__(self, pid=0, parent_pid=0, authentication_id=0, session=0, virtualized=0, is_64bit=False, integrity="",
                 user="", process_name="", image_path="", command_line="", company="", version="", description=""):
        self.pid = pid
        self.parent_pid = parent_pid
        self.authentication_id = authentication_id
        self.session = session
        self.virtualized = bool(virtualized)
        self.is_64bit = bool(is_64bit)
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
                    self.is_64bit, self.integrity, self.user, self.process_name, self.image_path,
                    self.command_line, self.company, self.version, self.description)


class Event(object):
    def __init__(self, process=None, tid=0, event_class=None, operation=None, duration=timedelta64(0, 'ns'), date=None,
                 result=0, stacktrace=None, category=None, path=None, details=None, file_offset=0):
        self.process = process
        self.tid = tid
        self.event_class = EventClass[event_class] if isinstance(event_class, string_types) else EventClass(event_class)
        self.operation = operation
        self.duration = duration
        self.date = date
        self.result = result
        self.stacktrace = stacktrace
        self.category = category
        self.path = path
        self.details = details
        self._file_offset = file_offset  # for debugging purposes :)

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
            .format(self.process, self.tid, self.event_class.name, self.operation, self.duration,
                    self.date, self.result, self.category, self.path, self.details)

    @staticmethod
    def _strftime_date(date, full_date=True):
        nanoseconds = int(date.astype('O') % int(1e9))
        d = datetime.datetime.utcfromtimestamp(date.astype('O') / 1e9)
        time_of_day = d.strftime("%I:%M:%S.{:07d} %p").lstrip('0').format(nanoseconds // 100)
        if not full_date:
            return time_of_day
        day = d.strftime("%m/%d/%Y ").lstrip('0').replace('/0', '/')
        return day + time_of_day

    @staticmethod
    def _strftime_relative_time(delta_nanosecs):
        secs = int(delta_nanosecs // int(1e9))
        nanosecs = int(delta_nanosecs % int(1e9))
        return "{:02d}:{:02d}:{:02d}.{:07d}".format(secs // 3600, (secs // 60) % 60, secs % 60, nanosecs // 100)

    @staticmethod
    def _strftime_duration(duration_nanosecs):
        secs = int(duration_nanosecs // int(1e9))
        nanosecs = int(duration_nanosecs % int(1e9))
        return "{}.{:07d}".format(secs, nanosecs // 100)

    def get_compatible_csv_info(self, first_event_date=None):
        """Returns data for every Procmon column in compatible format to the exported csv by procmon
        """
        return {Column.DATE_AND_TIME: Event._strftime_date(self.date),
                Column.PROCESS_NAME: self.process.process_name,
                Column.PID: self.process.pid,
                Column.OPERATION: self.operation.replace('_', ' '),
                Column.RESULT: ErrorCodeMessages.get(self.result, hex(self.result)),
                Column.DETAIL: ", ".join("{}: {}".format(k, v) for k, v in self.details.items()),
                Column.SEQUENCE: 'n/a',
                Column.COMPANY: self.process.company,
                Column.DESCRIPTION: self.process.description,
                Column.COMMAND_LINE: self.process.command_line,
                Column.USER: self.process.user,
                Column.IMAGE_PATH: self.process.image_path,
                Column.SESSION: self.process.session,
                Column.PATH: self.path,
                Column.TID: self.tid,
                Column.RELATIVE_TIME: Event._strftime_relative_time(
                    (self.date - first_event_date).astype('O') if first_event_date else 0),
                Column.DURATION: Event._strftime_duration(self.duration.astype('O')),
                Column.TIME_OF_DAY: Event._strftime_date(self.date, False),
                Column.VERSION: self.process.version,
                Column.EVENT_CLASS: self.event_class.name.replace('_', ' '),
                Column.AUTHENTICATION_ID: self.process.authentication_id,
                Column.VIRTUALIZED: self.process.virtualized,
                Column.INTEGRITY: self.process.integrity,
                Column.CATEGORY: self.category,
                Column.PARENT_PID: self.process.parent_pid,
                Column.ARCHITECTURE: "64-bit" if self.process.is_64bit else "32-bit",
                Column.COMPLETION_TIME: Event._strftime_date(self.date + self.duration, False),
                }
