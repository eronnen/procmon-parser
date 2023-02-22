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
    QuerySatLxInformation = 0x46
    QueryCaseSensitiveInformation = 0x47
    QueryLinkInformationEx = 0x48
    QueryLinkInfomraitonBypassAccessCheck = 0x49
    QueryStorageReservedIdInformation = 0x4a
    QueryCaseSensitiveInformationForceAccessCheck = 0x4b


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
    SetStorageReservedIdInformation = 0x4a


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
    0x103: '',  # NO MORE DATA
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


_IoctlConsts = {
    0x24058: "IOCTL_CDROM_GET_CONFIGURATION",
    0x24800: "IOCTL_CDROM_CHECK_VERIFY",
    0x24804: "IOCTL_CDROM_MEDIA_REMOVAL",
    0x24808: "IOCTL_CDROM_EJECT_MEDIA",
    0x2480c: "IOCTL_CDROM_LOAD_MEDIA",
    0x41018: "IOCTL_SCSI_GET_ADDRESS",
    0x41020: "IOCTL_SCSI_GET_DUMP_POINTERS",
    0x41024: "IOCTL_SCSI_FREE_DUMP_POINTERS",
    0x4d004: "IOCTL_SCSI_PASS_THROUGH",
    0x4d014: "IOCTL_SCSI_PASS_THROUGH_DIRECT",
    0x60198: "FSCTL_DFS_REPORT_INCONSISTENCY",
    0x60190: "FSCTL_DFS_TRANSLATE_PATH",
    0x60194: "FSCTL_DFS_GET_REFERRALS",
    0x6019c: "FSCTL_DFS_IS_SHARE_IN_DFS",
    0x601a0: "FSCTL_DFS_IS_ROOT",
    0x601a4: "FSCTL_DFS_GET_VERSION",
    0x70000: "IOCTL_DISK_GET_DRIVE_GEOMETRY",
    0x70014: "IOCTL_DISK_VERIFY",
    0x70020: "IOCTL_DISK_PERFORMANCE",
    0x70024: "IOCTL_DISK_IS_WRITABLE",
    0x70028: "IOCTL_DISK_LOGGING",
    0x70030: "IOCTL_DISK_HISTOGRAM_STRUCTURE",
    0x70034: "IOCTL_DISK_HISTOGRAM_DATA",
    0x70038: "IOCTL_DISK_HISTOGRAM_RESET",
    0x7003c: "IOCTL_DISK_REQUEST_STRUCTURE",
    0x70040: "IOCTL_DISK_REQUEST_DATA",
    0x70048: "IOCTL_DISK_GET_PARTITION_INFO_EX",
    0x70050: "IOCTL_DISK_GET_DRIVE_LAYOUT_EX",
    0x70060: "IOCTL_DISK_PERFORMANCE_OFF",
    0x700a0: "IOCTL_DISK_GET_DRIVE_GEOMETRY_EX",
    0x700f0: "IOCTL_DISK_GET_DISK_ATTRIBUTES",
    0x70140: "IOCTL_DISK_UPDATE_PROPERTIES",
    0x70214: "IOCTL_DISK_GET_CLUSTER_INFO",
    0x70c00: "IOCTL_DISK_GET_MEDIA_TYPES",
    0x74004: "IOCTL_DISK_GET_PARTITION_INFO",
    0x7400c: "IOCTL_DISK_GET_DRIVE_LAYOUT",
    0x7405c: "IOCTL_DISK_GET_LENGTH_INFO",
    0x74080: "SMART_GET_VERSION",
    0x740d4: "IOCTL_DISK_GET_CACHE_INFORMATION",
    0x74800: "IOCTL_DISK_CHECK_VERIFY",
    0x74804: "IOCTL_DISK_MEDIA_REMOVAL",
    0x74808: "IOCTL_DISK_EJECT_MEDIA",
    0x7480c: "IOCTL_DISK_LOAD_MEDIA",
    0x74810: "IOCTL_DISK_RESERVE",
    0x74814: "IOCTL_DISK_RELEASE",
    0x74818: "IOCTL_DISK_FIND_NEW_DEVICES",
    0x7c008: "IOCTL_DISK_SET_PARTITION_INFO",
    0x7c010: "IOCTL_DISK_SET_DRIVE_LAYOUT",
    0x7c018: "IOCTL_DISK_FORMAT_TRACKS",
    0x7c01c: "IOCTL_DISK_REASSIGN_BLOCKS",
    0x7c02c: "IOCTL_DISK_FORMAT_TRACKS_EX",
    0x7c04c: "IOCTL_DISK_SET_PARTITION_INFO_EX",
    0x7c054: "IOCTL_DISK_SET_DRIVE_LAYOUT_EX",
    0x7c058: "IOCTL_DISK_CREATE_DISK",
    0x7c084: "SMART_SEND_DRIVE_COMMAND",
    0x7c088: "SMART_RCV_DRIVE_DATA",
    0x7c0a4: "IOCTL_DISK_REASSIGN_BLOCKS_EX",
    0x7c0c8: "IOCTL_DISK_UPDATE_DRIVE_SIZE",
    0x7c0d0: "IOCTL_DISK_GROW_PARTITION",
    0x7c0d8: "IOCTL_DISK_SET_CACHE_INFORMATION",
    0x7c0f4: "IOCTL_DISK_SET_DISK_ATTRIBUTES",
    0x7c218: "IOCTL_DISK_SET_CLUSTER_INFO",
    0x90100: "FSCTL_SIS_COPYFILE",
    0x90000: "FSCTL_REQUEST_OPLOCK_LEVEL_1",
    0x90004: "FSCTL_REQUEST_OPLOCK_LEVEL_2",
    0x90008: "FSCTL_REQUEST_BATCH_OPLOCK",
    0x9000c: "FSCTL_OPLOCK_BREAK_ACKNOWLEDGE",
    0x90010: "FSCTL_OPBATCH_ACK_CLOSE_PENDING",
    0x90014: "FSCTL_OPLOCK_BREAK_NOTIFY",
    0x90018: "FSCTL_LOCK_VOLUME",
    0x9001c: "FSCTL_UNLOCK_VOLUME",
    0x90020: "FSCTL_DISMOUNT_VOLUME",
    0x90028: "FSCTL_IS_VOLUME_MOUNTED",
    0x9002c: "FSCTL_IS_PATHNAME_VALID",
    0x90030: "FSCTL_MARK_VOLUME_DIRTY",
    0x9003b: "FSCTL_QUERY_RETRIEVAL_POINTERS",
    0x9003c: "FSCTL_GET_COMPRESSION",
    0x90050: "FSCTL_OPLOCK_BREAK_ACK_NO_2",
    0x90058: "FSCTL_QUERY_FAT_BPB",
    0x9005c: "FSCTL_REQUEST_FILTER_OPLOCK",
    0x90060: "FSCTL_FILESYSTEM_GET_STATISTICS",
    0x90064: "FSCTL_GET_NTFS_VOLUME_DATA",
    0x90068: "FSCTL_GET_NTFS_FILE_RECORD",
    0x9006f: "FSCTL_GET_VOLUME_BITMAP",
    0x90073: "FSCTL_GET_RETRIEVAL_POINTERS",
    0x90074: "FSCTL_MOVE_FILE",
    0x90078: "FSCTL_IS_VOLUME_DIRTY",
    0x90083: "FSCTL_ALLOW_EXTENDED_DASD_IO",
    0x90087: "FSCTL_READ_PROPERTY_DATA",
    0x9008b: "FSCTL_WRITE_PROPERTY_DATA",
    0x9008f: "FSCTL_FIND_FILES_BY_SID",
    0x90097: "FSCTL_DUMP_PROPERTY_DATA",
    0x90098: "FSCTL_SET_OBJECT_ID",
    0x9009c: "FSCTL_GET_OBJECT_ID",
    0x900a0: "FSCTL_DELETE_OBJECT_ID",
    0x900a4: "FSCTL_SET_REPARSE_POINT",
    0x900a8: "FSCTL_GET_REPARSE_POINT",
    0x900ac: "FSCTL_DELETE_REPARSE_POINT",
    0x900b3: "FSCTL_ENUM_USN_DATA",
    0x900bb: "FSCTL_READ_USN_JOURNAL",
    0x900bc: "FSCTL_SET_OBJECT_ID_EXTENDED",
    0x900c0: "FSCTL_CREATE_OR_GET_OBJECT_ID",
    0x900c4: "FSCTL_SET_SPARSE",
    0x900d7: "FSCTL_SET_ENCRYPTION",
    0x900db: "FSCTL_ENCRYPTION_FSCTL_IO",
    0x900df: "FSCTL_WRITE_RAW_ENCRYPTED",
    0x900e3: "FSCTL_READ_RAW_ENCRYPTED",
    0x900e7: "FSCTL_CREATE_USN_JOURNAL",
    0x900eb: "FSCTL_READ_FILE_USN_DATA",
    0x900ef: "FSCTL_WRITE_USN_CLOSE_RECORD",
    0x900f0: "FSCTL_EXTEND_VOLUME",
    0x900f4: "FSCTL_QUERY_USN_JOURNAL",
    0x900f8: "FSCTL_DELETE_USN_JOURNAL",
    0x900fc: "FSCTL_MARK_HANDLE",
    0x90120: "FSCTL_FILE_PREFETCH",
    0x901af: "CSC_FSCTL_OPERATION_QUERY_HANDLE",
    0x901f0: "FSCTL_QUERY_DEPENDENT_VOLUME",
    0x90230: "FSCTL_GET_BOOT_AREA_INFO",
    0x90240: "FSCTL_REQUEST_OPLOCK",
    0x90244: "FSCTL_CSV_TUNNEL_REQUEST",
    0x9024c: "FSCTL_QUERY_FILE_SYSTEM_RECOGNITION",
    0x90254: "FSCTL_CSV_GET_VOLUME_NAME_FOR_VOLUME_MOUNT_POINT",
    0x90258: "FSCTL_CSV_GET_VOLUME_PATH_NAMES_FOR_VOLUME_NAME",
    0x9025c: "FSCTL_IS_FILE_ON_CSV_VOLUME",
    0x90260: "FSCTL_CORRUPTION_HANDLING",
    0x90270: "FSCTL_SET_PURGE_FAILURE_MODE",
    0x90277: "FSCTL_QUERY_FILE_LAYOUT",
    0x90278: "FSCTL_IS_VOLUME_OWNED_BYCSVFS",
    0x9027c: "FSCTL_GET_INTEGRITY_INFORMATION",
    0x90284: "FSCTL_QUERY_FILE_REGIONS",
    0x902b0: "FSCTL_SCRUB_DATA",
    0x902b8: "FSCTL_DISABLE_LOCAL_BUFFERING",
    0x9030c: "FSCTL_SET_EXTERNAL_BACKING",
    0xc4003: "FSCTL_MAILSLOT_PEEK",
    0x980d0: "FSCTL_ENABLE_UPGRADE",
    0x941e4: "FSCTL_TXFS_LIST_TRANSACTIONS",
    0x90310: "FSCTL_GET_EXTERNAL_BACKING",
    0x940b7: "FSCTL_SECURITY_ID_CHECK",
    0x940cf: "FSCTL_QUERY_ALLOCATED_RANGES",
    0x94264: "FSCTL_OFFLOAD_READ",
    0x980c8: "FSCTL_SET_ZERO_DATA",
    0x9c104: "FSCTL_SIS_LINK_FILES",
    0x98208: "FSCTL_FILE_LEVEL_TRIM",
    0x98268: "FSCTL_OFFLOAD_WRITE",
    0x9c040: "FSCTL_SET_COMPRESSION",
    0x9c108: "FSCTL_HSM_MSG",
    0x9c2b4: "FSCTL_REPAIR_COPIES",
    0x110020: "FSCTL_PIPE_SET_CLIENT_PROCESS",
    0x110000: "FSCTL_PIPE_ASSIGN_EVENT",
    0x110004: "FSCTL_PIPE_DISCONNECT",
    0x110008: "FSCTL_PIPE_LISTEN",
    0x110010: "FSCTL_PIPE_QUERY_EVENT",
    0x110018: "FSCTL_PIPE_WAIT",
    0x11001c: "FSCTL_PIPE_IMPERSONATE",
    0x119ff8: "FSCTL_PIPE_INTERNAL_WRITE",
    0x110024: "FSCTL_QUERY_CLIENT_PROCESS",
    0x11400c: "FSCTL_PIPE_PEEK",
    0x116000: "FSCTL_PIPE_INTERNAL_READ",
    0x11c017: "FSCTL_PIPE_TRANSCEIVE",
    0x11dfff: "FSCTL_PIPE_INTERNAL_TRANSCEIVE",
    0x140191: "FSCTL_LMR_START",
    0x140193: "IOCTL_SMBMRX_START",
    0x140194: "FSCTL_LMR_STOP",
    0x140197: "IOCTL_SMBMRX_STOP",
    0x140198: "IOCTL_SMBMRX_GETSTATE",
    0x140199: "FSCTL_NETWORK_SET_CONFIGURATION_INFO",
    0x14019e: "FSCTL_NETWORK_GET_CONFIGURATION_INFO",
    0x1401a3: "FSCTL_NETWORK_GET_CONNECTION_INFO",
    0x1401a7: "FSCTL_NETWORK_ENUMERATE_CONNECTIONS",
    0x1401ab: "FSCTL_LMR_FORCE_DISCONNECT",
    0x1401ac: "FSCTL_NETWORK_DELETE_CONNECTION",
    0x1401b0: "FSCTL_LMR_BIND_TO_TRANSPORT",
    0x1401b4: "FSCTL_LMR_UNBIND_FROM_TRANSPORT",
    0x1401bb: "FSCTL_LMR_ENUMERATE_TRANSPORTS",
    0x1401c4: "FSCTL_LMR_GET_HINT_SIZE",
    0x1401c8: "FSCTL_LMR_TRANSACT",
    0x1401cc: "FSCTL_LMR_ENUMERATE_PRINT_INFO",
    0x1401d0: "FSCTL_NETWORK_GET_STATISTICS",
    0x1401d4: "FSCTL_LMR_START_SMBTRACE",
    0x1401d8: "FSCTL_LMR_END_SMBTRACE",
    0x1401dc: "FSCTL_LMR_START_RBR",
    0x1401e0: "FSCTL_NETWORK_SET_DOMAIN_NAME",
    0x1401e4: "FSCTL_LMR_SET_SERVER_GUID",
    0x1401e8: "FSCTL_LMR_QUERY_TARGET_INFO",
    0x1401ec: "FSCTL_LMR_QUERY_DEBUG_INFO",
    0x1401f4: "IOCTL_SMBMRX_ADDCONN",
    0x1401f8: "IOCTL_SMBMRX_DELCONN",
    0x140fdb: "IOCTL_SHADOW_END_REINT",
    0x140378: "IOCTL_UMRX_RELEASE_THREADS",
    0x14037e: "IOCTL_UMRX_GET_REQUEST",
    0x140382: "IOCTL_UMRX_RESPONSE_AND_REQUEST",
    0x140386: "IOCTL_UMRX_RESPONSE",
    0x140388: "IOCTL_UMRX_GET_LOCK_OWNER",
    0x14038c: "IOCTL_LMR_QUERY_REMOTE_SERVER_NAME",
    0x140390: "IOCTL_LMR_DISABLE_LOCAL_BUFFERING",
    0x140394: "IOCTL_UMRX_PREPARE_QUEUE",
    0x140397: "IOCTL_LMR_LWIO_POSTIO",
    0x14039b: "IOCTL_LMR_LWIO_PREIO",
    0x1403e8: "FSCTL_NETWORK_REMOTE_BOOT_INIT_SCRT",
    0x2d0c00: "IOCTL_STORAGE_GET_MEDIA_TYPES",
    0x140fff: "IOCTL_GETSHADOW",
    0x2d0800: "IOCTL_STORAGE_CHECK_VERIFY2",
    0x2d080c: "IOCTL_STORAGE_LOAD_MEDIA2",
    0x2d0940: "IOCTL_STORAGE_EJECTION_CONTROL",
    0x2d0944: "IOCTL_STORAGE_MCN_CONTROL",
    0x2d0c04: "IOCTL_STORAGE_GET_MEDIA_TYPES_EX",
    0x2d0c10: "IOCTL_STORAGE_GET_MEDIA_SERIAL_NUMBER",
    0x2d0c14: "IOCTL_STORAGE_GET_HOTPLUG_INFO",
    0x2d1080: "IOCTL_STORAGE_GET_DEVICE_NUMBER",
    0x2d1100: "IOCTL_STORAGE_PREDICT_FAILURE",
    0x2d1400: "IOCTL_STORAGE_QUERY_PROPERTY",
    0x530190: "IOCTL_VOLSNAP_QUERY_ORIGINAL_VOLUME_NAME",
    0x2d5004: "IOCTL_STORAGE_RESET_DEVICE",
    0x2d4800: "IOCTL_STORAGE_CHECK_VERIFY",
    0x2d4804: "IOCTL_STORAGE_MEDIA_REMOVAL",
    0x2d4808: "IOCTL_STORAGE_EJECT_MEDIA",
    0x2d480c: "IOCTL_STORAGE_LOAD_MEDIA",
    0x2d4810: "IOCTL_STORAGE_RESERVE",
    0x2d4814: "IOCTL_STORAGE_RELEASE",
    0x2d4818: "IOCTL_STORAGE_FIND_NEW_DEVICES",
    0x2d5000: "IOCTL_STORAGE_RESET_BUS",
    0x2d518c: "IOCTL_STORAGE_QUERY_DEPENDENT_DISK",
    0x2d5014: "IOCTL_STORAGE_BREAK_RESERVATION",
    0x2d5018: "IOCTL_STORAGE_PERSISTENT_RESERVE_IN",
    0x2d5140: "IOCTL_STORAGE_READ_CAPACITY",
    0x2dcc18: "IOCTL_STORAGE_SET_HOTPLUG_INFO",
    0x2dd01c: "IOCTL_STORAGE_PERSISTENT_RESERVE_OUT",
    0x38a813: "IOCTL_CHANNEL_GET_SNDCHANNEL",
    0x530018: "IOCTL_VOLSNAP_QUERY_NAMES_OF_SNAPSHOTS",
    0x4d0000: "IOCTL_MOUNTDEV_QUERY_UNIQUE_ID",
    0x4d0004: "IOCTL_MOUNTDEV_UNIQUE_ID_CHANGE_NOTIFY",
    0x4d0008: "IOCTL_MOUNTDEV_QUERY_DEVICE_NAME",
    0x4d000c: "IOCTL_MOUNTDEV_QUERY_SUGGESTED_LINK_NAME",
    0x4d0010: "IOCTL_MOUNTDEV_LINK_CREATED",
    0x4d0014: "IOCTL_MOUNTDEV_LINK_DELETED",
    0x530024: "IOCTL_VOLSNAP_QUERY_DIFF_AREA",
    0x53002c: "IOCTL_VOLSNAP_QUERY_DIFF_AREA_SIZES",
    0x530034: "IOCTL_VOLSNAP_AUTO_CLEANUP",
    0x53003c: "IOCTL_VOLSNAP_QUERY_REVERT",
    0x530040: "IOCTL_VOLSNAP_REVERT_CLEANUP",
    0x530048: "IOCTL_VOLSNAP_QUERY_REVERT_PROGRESS",
    0x53004c: "IOCTL_VOLSNAP_CANCEL_REVERT",
    0x530050: "IOCTL_VOLSNAP_QUERY_EPIC",
    0x53005e: "IOCTL_VOLSNAP_QUERY_COPY_FREE_BITMAP",
    0x534054: "IOCTL_VOLSNAP_QUERY_OFFLINE",
    0x53019c: "IOCTL_VOLSNAP_QUERY_CONFIG_INFO",
    0x5301a0: "IOCTL_VOLSNAP_HAS_CHANGED",
    0x5301a4: "IOCTL_VOLSNAP_SET_SNAPSHOT_PRIORITY",
    0x5301a8: "IOCTL_VOLSNAP_QUERY_SNAPSHOT_PRIORITY",
    0x5301ae: "IOCTL_VOLSNAP_QUERY_DELTA_BITMAP",
    0x5301b2: "IOCTL_VOLSNAP_QUERY_SNAPSHOT_SUPPLEMENTAL",
    0x5301b6: "IOCTL_VOLSNAP_QUERY_COPIED_BITMAP",
    0x5301b8: "IOCTL_VOLSNAP_QUERY_MOVE_LIST",
    0x5301be: "IOCTL_VOLSNAP_QUERY_PRE_COPIED_BITMAP",
    0x5301c2: "IOCTL_VOLSNAP_QUERY_USED_PRE_COPIED_BITMAP",
    0x5301c6: "IOCTL_VOLSNAP_QUERY_DEFRAG_PRE_COPIED_BITMAP",
    0x5301ca: "IOCTL_VOLSNAP_QUERY_FREESPACE_PRE_COPIED_BITMAP",
    0x5301ce: "IOCTL_VOLSNAP_QUERY_HOTBLOCKS_PRE_COPIED_BITMAP",
    0x5301d0: "IOCTL_VOLSNAP_QUERY_DIFF_AREA_FILE_SIZES",
    0x53c000: "IOCTL_VOLSNAP_FLUSH_AND_HOLD_WRITES",
    0x534058: "IOCTL_VOLSNAP_QUERY_DIFF_AREA_MINIMUM_SIZE",
    0x534064: "IOCTL_VOLSNAP_BLOCK_DELETE_IN_THE_MIDDLE",
    0x534070: "IOCTL_VOLSNAP_QUERY_APPLICATION_FLAGS",
    0x534080: "IOCTL_VOLSNAP_QUERY_PERFORMANCE_COUNTERS",
    0x534088: "IOCTL_VOLSNAP_QUERY_PRE_COPY_AMOUNTS",
    0x53408c: "IOCTL_VOLSNAP_QUERY_DEFAULT_PRE_COPY_AMOUNTS",
    0x53c198: "IOCTL_VOLSNAP_SET_APPLICATION_INFO",
    0x53c004: "IOCTL_VOLSNAP_RELEASE_WRITES",
    0x53c008: "IOCTL_VOLSNAP_PREPARE_FOR_SNAPSHOT",
    0x53c00c: "IOCTL_VOLSNAP_ABORT_PREPARED_SNAPSHOT",
    0x53c010: "IOCTL_VOLSNAP_COMMIT_SNAPSHOT",
    0x53c014: "IOCTL_VOLSNAP_END_COMMIT_SNAPSHOT",
    0x53c01c: "IOCTL_VOLSNAP_CLEAR_DIFF_AREA",
    0x53c020: "IOCTL_VOLSNAP_ADD_VOLUME_TO_DIFF_AREA",
    0x53c028: "IOCTL_VOLSNAP_SET_MAX_DIFF_AREA_SIZE",
    0x53c030: "IOCTL_VOLSNAP_DELETE_OLDEST_SNAPSHOT",
    0x53c038: "IOCTL_VOLSNAP_DELETE_SNAPSHOT",
    0x53c044: "IOCTL_VOLSNAP_REVERT",
    0x53c068: "IOCTL_VOLSNAP_SET_MAX_DIFF_AREA_SIZE_TEMP",
    0x53c06c: "IOCTL_VOLSNAP_SET_APPLICATION_FLAGS",
    0x53c07c: "IOCTL_VOLSNAP_SET_BC_FAILURE_MODE",
    0x53c084: "IOCTL_VOLSNAP_SET_PRE_COPY_AMOUNTS",
    0x53c090: "IOCTL_VOLSNAP_PRE_EXPOSE_DEVICES",
    0x560000: "IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS",
    0x560038: "IOCTL_VOLUME_GET_GPT_ATTRIBUTES",
    0x700010: "IOCTL_DISK_QUERY_DEVICE_STATE",
    0x704008: "IOCTL_DISK_QUERY_DISK_SIGNATURE",
}


def get_ioctl_name(ioctl):
    try:
        return _IoctlConsts[ioctl]
    except KeyError:
        return "0x{:x} (Device:0x{:x} Function:{} Method: {})".format(
            ioctl, ioctl >> 0x10, (ioctl >> 2) & 0xfff, ioctl & 3)


class FileInformationClass(enum.IntEnum):
    Unknown = 0,
    FileDirectoryInformation = 1,
    FileFullDirectoryInformation = 2,
    FileBothDirectoryInformation = 3,
    FileBasicInformation = 4,
    FileStandardInformation = 5,
    FileInternalInformation = 6,
    FileEaInformation = 7,
    FileAccessInformation = 8,
    FileNameInformation = 9,
    FileRenameInformation = 10,
    FileLinkInformation = 11,
    FileNamesInformation = 12,
    FileDispositionInformation = 13,
    FilePositionInformation = 14,
    FileFullEaInformation = 15,
    FileModeInformation = 16,
    FileAlignmentInformation = 17,
    FileAllInformation = 18,
    FileAllocationInformation = 19,
    FileEndOfFileInformation = 20,
    FileAlternateNameInformation = 21,
    FileStreamInformation = 22,
    FilePipeInformation = 23,
    FilePipeLocalInformation = 24,
    FilePipeRemoteInformation = 25,
    FileMailslotQueryInformation = 26,
    FileMailslotSetInformation = 27,
    FileCompressionInformation = 28,
    FileObjectIdInformation = 29,
    FileCompletionInformation = 30,
    FileMoveClusterInformation = 31,
    FileQuotaInformation = 32,
    FileReparsePointInformation = 33,
    FileNetworkOpenInformation = 34,
    FileAttributeTagInformation = 35,
    FileTrackingInformation = 36,
    FileIdBothDirectoryInformation = 37,
    FileIdFullDirectoryInformation = 38,
    FileValidDataLengthInformation = 39,
    FileShortNameInformation = 40,
    FileIoCompletionNotificationInformation = 41,
    FileIoStatusBlockRangeInformation = 42,
    FileIoPriorityHintInformation = 43,
    FileSfioReserveInformation = 44,
    FileSfioVolumeInformation = 45,
    FileHardLinkInformation = 46,
    FileProcessIdsUsingFileInformation = 47,
    FileNormalizedNameInformation = 48,
    FileNetworkPhysicalNameInformation = 49,
    FileIdGlobalTxDirectoryInformation = 50,
    FileIsRemoteDeviceInformation = 51,
    FileUnusedInformation = 52,
    FileNumaNodeInformation = 53,
    FileStandardLinkInformation = 54,
    FileRemoteProtocolInformation = 55,
    FileRenameInformationBypassAccessCheck = 56,
    FileLinkInformationBypassAccessCheck = 57,
    FileVolumeNameInformation = 58,
    FileIdInformation = 59,
    FileIdExtdDirectoryInformation = 60,
    FileReplaceCompletionInformation = 61,
    FileHardLinkFullIdInformation = 62,
    FileIdExtdBothDirectoryInformation = 63,
    FileDispositionInformationEx = 64,
    FileRenameInformationEx = 65,
    FileRenameInformationExBypassAccessCheck = 66,
    FileDesiredStorageClassInformation = 67,
    FileStatInformation = 68,
    FileMemoryPartitionInformation = 69,
    FileMaximumInformation = 70,
    SeShutdownPrivilege = 71,
    SeChangeNotifyPrivilege = 72,
    SeUndockPrivilege = 73,
    SeIncreaseWorkingSetPrivilege = 74,
    SeTimeZonePrivilege = 75,


FilesystemNotifyChangeFlags = OrderedDict([
    (0x1, 'FILE_NOTIFY_CHANGE_FILE_NAME'),
    (0x2, 'FILE_NOTIFY_CHANGE_DIR_NAME'),
    (0x3, 'FILE_NOTIFY_CHANGE_NAME'),
    (0x4, 'FILE_NOTIFY_CHANGE_ATTRIBUTES'),
    (0x8, 'FILE_NOTIFY_CHANGE_SIZE'),
    (0x10, 'FILE_NOTIFY_CHANGE_LAST_WRITE'),
    (0x20, 'FILE_NOTIFY_CHANGE_LAST_ACCESS'),
    (0x40, 'FILE_NOTIFY_CHANGE_CREATION'),
    (0x80, 'FILE_NOTIFY_CHANGE_EA'),
    (0x100, 'FILE_NOTIFY_CHANGE_SECURITY'),
    (0x200, 'FILE_NOTIFY_CHANGE_STREAM_NAME'),
    (0x400, 'FILE_NOTIFY_CHANGE_STREAM_SIZE'),
    (0x800, 'FILE_NOTIFY_CHANGE_STREAM_WRITE'),
])


def get_filesystem_notify_change_flags(flags):
    return _get_mask_string(flags, FilesystemNotifyChangeFlags, ", ")


# Used for CreateFileMapping operation details (SyncType)
FileSystemCreateFileMappingSyncType = OrderedDict([
    (0x0, "SyncTypeOther"),
    (0x1, "SyncTypeCreateSection"),
    # 'Unknown' is everything else.
])


def get_filesystem_createfilemapping_synctype(synctype_value):
    # type: (int) -> str
    return FileSystemCreateFileMappingSyncType.get(synctype_value, "Unknown: {:#x}".format(synctype_value))


class PageProtection(enum.IntEnum):
    """Memory protection constants. Used for FilesystemOperation.CreateFileMapping event details.

    See Also:
        https://learn.microsoft.com/en-us/windows/win32/memory/memory-protection-constants
    """
    # PAGE_NOACCESS = 0x01 --> Not supported by CreateFileMapping, hence not used
    PAGE_READONLY = 0x02
    PAGE_READWRITE = 0x04
    PAGE_WRITECOPY = 0x08
    PAGE_EXECUTE = 0x10
    PAGE_EXECUTE_READ = 0x20
    PAGE_EXECUTE_READWRITE = 0x40
    # PAGE_EXECUTE_WRITECOPY = 0x80 --> seems to be not used by ProcMon, but is supported by CreateFileMapping
    # PAGE_GUARD = 0x100  --> Not supported by CreateFileMapping, hence not used
    PAGE_NOCACHE = 0x200
    # PAGE_WRITECOMBINE = 0x400 --> seems to be not used by ProcMon, but is supported by CreateFileMapping
