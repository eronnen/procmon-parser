"""
Python types for constant values in Procmon
"""

import enum
from collections import OrderedDict


class RuleAction(enum.IntEnum):
    EXCLUDE = 0
    INCLUDE = 1


class RuleRelation(enum.IntEnum):
    IS = 0
    IS_NOT = 1
    LESS_THAN = 2
    MORE_THAN = 3
    BEGINS_WITH = 4
    ENDS_WITH = 5
    CONTAINS = 6
    EXCLUDES = 7


class Column(enum.IntEnum):
    NONE = 0
    DATE_AND_TIME = 40052
    PROCESS_NAME = 40053
    PID = 40054
    OPERATION = 40055
    RESULT = 40056
    DETAIL = 40057
    SEQUENCE = 40058
    COMPANY = 40064
    DESCRIPTION = 40065
    COMMAND_LINE = 40066
    USER = 40067
    IMAGE_PATH = 40068
    SESSION = 40069
    PATH = 40071
    TID = 40072
    RELATIVE_TIME = 40076
    DURATION = 40077
    TIME_OF_DAY = 40078
    VERSION = 40081
    EVENT_CLASS = 40082
    AUTHENTICATION_ID = 40083
    VIRTUALIZED = 40084
    INTEGRITY = 40085
    CATEGORY = 40086
    PARENT_PID = 40087
    ARCHITECTURE = 40088
    COMPLETION_TIME = 40164


ColumnToOriginalName = {
    Column.DATE_AND_TIME: "Date & Time",
    Column.PROCESS_NAME: "Process Name",
    Column.PID: "PID",
    Column.OPERATION: "Operation",
    Column.RESULT: "Result",
    Column.DETAIL: "Detail",
    Column.SEQUENCE: "Sequence",
    Column.COMPANY: "Company",
    Column.DESCRIPTION: "Description",
    Column.COMMAND_LINE: "Command Line",
    Column.USER: "User",
    Column.IMAGE_PATH: "Image Path",
    Column.SESSION: "Session",
    Column.PATH: "Path",
    Column.TID: "TID",
    Column.RELATIVE_TIME: 'Relative Time',
    Column.DURATION: "Duration",
    Column.TIME_OF_DAY: "Time of Day",
    Column.VERSION: "Version",
    Column.EVENT_CLASS: "Event Class",
    Column.AUTHENTICATION_ID: "Authentication ID",
    Column.VIRTUALIZED: "Virtualized",
    Column.INTEGRITY: "Integrity",
    Column.CATEGORY: "Category",
    Column.PARENT_PID: "Parent PID",
    Column.ARCHITECTURE: "Architecture",
    Column.COMPLETION_TIME: "Completion Time",
}


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


EventClassOperation = {
    EventClass.Process: ProcessOperation,
    EventClass.Registry: RegistryOperation,
    EventClass.File_System: FilesystemOperation,
    EventClass.Profiling: ProfilingOperation,
    EventClass.Network: NetworkOperation
}


class FilesystemQueryVolumeInformationOperation(enum.IntEnum):
    QueryInformationVolume = 0x1
    QueryLabelInformationVolume = 0x2
    QuerySizeInformationVolume = 0x3
    QueryDeviceInformationVolume = 0x4
    QueryAttributeInformationVolume = 0x5
    QueryControlInformationVolume = 0x6
    QueryFullSizeInformationVolume = 0x7
    QueryObjectIdInformationVolume = 0x8


class FilesystemSetVolumeInformationOperation(enum.IntEnum):
    SetControlInformationVolume = 0x1
    SetLabelInformationVolume = 0x2
    SetObjectIdInformationVolume = 0x8


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


class FilesystemLockUnlockOperation(enum.IntEnum):
    LockFile = 0x1  # IRP_MJ_LOCK_CONTROL, FASTIO_LOCK
    UnlockFileSingle = 0x2  # IRP_MJ_LOCK_CONTROL, FASTIO_UNLOCK_SINGLE
    UnlockFileAll = 0x3  # IRP_MJ_LOCK_CONTROL, FASTIO_UNLOCK_ALL
    UnlockFileByKey = 0x4  # IRP_MJ_LOCK_CONTROL, FASTIO_UNLOCK_ALL_BY_KEY


FilesystemSubOperations = {
    FilesystemOperation.QueryVolumeInformation: FilesystemQueryVolumeInformationOperation,
    FilesystemOperation.SetVolumeInformation: FilesystemSetVolumeInformationOperation,
    FilesystemOperation.QueryInformationFile: FilesystemQueryInformationOperation,
    FilesystemOperation.SetInformationFile: FilesystemSetInformationOperation,
    FilesystemOperation.DirectoryControl: FilesysemDirectoryControlOperation,
    FilesystemOperation.PlugAndPlay: FilesystemPnpOperation,
    FilesystemOperation.LockUnlockFile: FilesystemLockUnlockOperation,
}

_ErrorCodeMessages = {
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
    0x80000015: 'INVALID EA FLAG',
    0x80000002: 'DATATYPE MISALIGNMENT',
    0x80000005: 'BUFFER OVERFLOW',
    0x80000006: 'NO MORE FILES',
    0x8000001a: 'NO MORE ENTRIES',
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
    0xc0000023: 'BUFFER TOO SMALL',
    0xc0000024: 'OBJECT TYPE MISMATCH',
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


def get_error_message(error_value):
    return _ErrorCodeMessages.get(error_value, "0x{:X}".format(error_value))


def _get_mask_string(mask, mask_strings, seperator):
    strings = []
    for value, string in mask_strings.items():
        if mask & value == value:
            strings.append(string)
            mask &= ~value

    if len(strings) == 0:
        return ''
    return seperator.join(strings)


COMMON_ACCESS_MASK_STRINGS = OrderedDict([
    (0x10000, "Delete"),
    (0x20000, "Read Control"),
    (0x40000, "Write DAC"),
    (0x80000, "Write Owner"),
    (0x100000, "Synchronize"),
    (0x1000000, "Access System Security"),
    (0x2000000, "Maximum Allowed"),
])


REGISTRY_ACCESS_MASK_MAPPING = [0x20019, 0x20006, 0x20019, 0xf003f]  # used in MapGenericMask
REGISTRY_ACCESS_MASK_STRINGS = OrderedDict([
    (0xf003f, "All Access"),
    (0x2001f, "Read/Write"),
    (0x20019, "Read"),
    (0x20006, "Write"),
    (0x1, "Query Value"),
    (0x2, "Set Value"),
    (0x4, "Create Sub Key"),
    (0x8, "Enumerate Sub Keys"),
    (0x10, "Notify"),
    (0x20, "Create Link"),
    (0x300, "WOW64_Res"),
    (0x200, "WOW64_32Key"),
    (0x100, "WOW64_64Key"),
])
REGISTRY_ACCESS_MASK_STRINGS.update(COMMON_ACCESS_MASK_STRINGS)


FILESYSTEM_ACCESS_MASK_MAPPING = [0x120089, 0x120116, 0x1200a0, 0x1f01ff]  # used in MapGenericMask
FILESYSTEM_ACCESS_MASK_STRINGS = OrderedDict([
    (0x1f01ff, "All Access"),
    (0x1201bf, "Generic Read/Write/Execute"),
    (0x12019f, "Generic Read/Write"),
    (0x1200a9, "Generic Read/Execute"),
    (0x1201b6, "Generic Write/Execute"),
    (0x120089, "Generic Read"),
    (0x120116, "Generic Write"),
    (0x1200a0, "Generic Execute"),
    (0x1, "Read Data/List Directory"),
    (0x2, "Write Data/Add File"),
    (0x4, "Append Data/Add Subdirectory/Create Pipe Instance"),
    (0x8, "Read EA"),
    (0x10, "Write EA"),
    (0x20, "Execute/Traverse"),
    (0x40, "Delete Child"),
    (0x80, "Read Attributes"),
    (0x100, "Write Attributes"),
])
FILESYSTEM_ACCESS_MASK_STRINGS.update(COMMON_ACCESS_MASK_STRINGS)


def _get_access_mask_string(access_mask, mappings, access_strings):
    """Return a string that describes the access mask.
    :param access_mask: the access mask value
    :param mappings: the mapping that is given to MapGenericMask
    :param access_strings: the string for every mask option
    """
    if access_mask & 0x80000000:
        access_mask |= mappings[0]
    if access_mask & 0x40000000:
        access_mask |= mappings[1]
    if access_mask & 0x20000000:
        access_mask |= mappings[2]
    if access_mask & 0x10000000:
        access_mask |= mappings[3]

    string = _get_mask_string(access_mask, access_strings, ", ")
    if string == '':
        return "None 0x{:x}".format(access_mask)
    return string


def get_registry_access_mask_string(access_mask):
    return _get_access_mask_string(access_mask, REGISTRY_ACCESS_MASK_MAPPING, REGISTRY_ACCESS_MASK_STRINGS)


def get_filesystem_access_mask_string(access_mask):
    return _get_access_mask_string(access_mask, FILESYSTEM_ACCESS_MASK_MAPPING, FILESYSTEM_ACCESS_MASK_STRINGS)


FILESYSTEM_CREATE_OPTIONS = OrderedDict([
    (0x1, "Directory"),
    (0x2, "Write Through"),
    (0x4, "Sequential Access"),
    (0x8, "No Buffering"),
    (0x10, "Synchronous IO Alert"),
    (0x20, "Synchronous IO Non-Alert"),
    (0x40, "Non-Directory File"),
    (0x80, "Create Tree Connection"),
    (0x100, "Complete If Oplocked"),
    (0x200, "No EA Knowledge"),
    (0x400, "Open for Recovery"),
    (0x800, "Random Access"),
    (0x1000, "Delete On Close"),
    (0x2000, "Open By ID"),
    (0x4000, "Open For Backup"),
    (0x8000, "No Compression"),
    (0x100000, "Reserve OpFilter"),
    (0x200000, "Open Reparse Point"),
    (0x400000, "Open No Recall"),
    (0x800000, "Open For Free Space Query"),
    (0x10000, "Open Requiring Oplock"),
    (0x20000, "Disallow Exclusive"),
])


def get_filesysyem_create_options(options_mask):
    return _get_mask_string(options_mask, FILESYSTEM_CREATE_OPTIONS, ", ")


FilesystemCreateAttributes = OrderedDict([
    (0x1, "R"),
    (0x2, "H"),
    (0x4, "S"),
    (0x10, "D"),
    (0x20, "A"),
    (0x40, "D"),
    (0x80, "N"),
    (0x100, "T"),
    (0x200, "SF"),
    (0x400, "RP"),
    (0x800, "C"),
    (0x1000, "O"),
    (0x2000, "NCI"),
    (0x4000, "E"),
    (0x10000, "V"),
])


def get_filesysyem_create_attributes(create_mask):
    if 0 == create_mask:
        return "n/a"
    return _get_mask_string(create_mask, FilesystemCreateAttributes, "")


FilesystemCreateShareMode = OrderedDict([
    (0x1, "Read"),
    (0x2, "Write"),
    (0x4, "Delete"),
])


def get_filesysyem_create_share_mode(share_mask):
    if 0 == share_mask:
        return "None"
    return _get_mask_string(share_mask, FilesystemCreateShareMode, ", ")


FilesystemIoFlags = OrderedDict([
    (0x10, "Buffered"),
    (0x1, "Non-cached"),
    (0x2, "Paging I/O"),
    (0x4, "Synchronous"),
    (0x40, "Synchronous Paging I/O"),
    (0x400000, "Write Through"),
])


def get_filesysyem_io_flags(flags):
    return _get_mask_string(flags, FilesystemIoFlags, ", ")


FilesystemPriority = {
    0: '',
    1: 'Very Low',
    2: 'Low',
    3: 'Normal',
    4: 'High',
    5: 'Critical',
}



class RegistryTypes(enum.IntEnum):
    REG_NONE = 0  # No value type
    REG_SZ = 1  # Unicode nul terminated string
    REG_EXPAND_SZ = 2  # Unicode nul terminated string
    REG_BINARY = 3  # Free form binary
    REG_DWORD = 4  # 32-bit number
    REG_DWORD_LITTLE_ENDIAN = 4  # 32-bit number (same as REG_DWORD)
    REG_DWORD_BIG_ENDIAN = 5  # 32-bit number
    REG_LINK = 6  # Symbolic Link (unicode)
    REG_MULTI_SZ = 7  # Multiple Unicode strings
    REG_RESOURCE_LIST = 8  # Resource list in the resource map
    REG_FULL_RESOURCE_DESCRIPTOR = 9  # Resource list in the hardware description
    REG_RESOURCE_REQUIREMENTS_LIST = 10
    REG_QWORD = 11  # 64-bit number
    REG_QWORD_LITTLE_ENDIAN = 11  # 64-bit number (same as REG_QWORD)


class RegistryKeyValueInformationClass(enum.IntEnum):
    KeyValueBasicInformation = 0,
    KeyValueFullInformation = 1,
    KeyValuePartialInformation = 2
    KeyValueFullInformationAlign64 = 3,
    KeyValuePartialInformationAlign64 = 4,
    KeyValueLayerInformation = 5,


class RegistryKeyInformationClass(enum.IntEnum):
    Basic = 0
    Node = 1
    Full = 2
    Name = 3
    Cached = 4
    Flags = 5
    Virtualization = 6
    HandleTags = 7
    Trust = 8
    Layer = 9


RegistryKeySetInformationClass = {
    0: "KeyWriteTimeInformation",
    1: "KeyWow64FlagsInformation",
    5: "KeySetHandleTagsInformation",
}


class RegistryDisposition(enum.IntEnum):
    REG_CREATED_NEW_KEY = 1
    REG_OPENED_EXISTING_KEY = 2


class FilesystemDisposition(enum.IntEnum):
    Supersede = 0
    Open = 1
    Create = 2
    OpenIf = 3
    Overwrite = 4
    OverwriteIf = 5


class FilesystemOpenResult(enum.IntEnum):
    Superseded = 0
    Opened = 1
    Created = 2
    Overwritten = 3
    Exists = 4
    DoesNotExist = 5
