#pragma endian little
#pragma author "eronnen"
#pragma description "Sysinternals Process Monitor Log (PML) File Pattern"
#pragma file_format "pml"
#pragma MIME "application/x-procmon-log"
#pragma array_limit 2000000
#pragma pattern_limit 20971520

#include <std/sys.pat>
#include <std/mem.pat>
#include <std/time.pat>
#include <std/io.pat>
#include <std/string.pat>

/* =========================================================================
 * Formatter Functions & Helper Types
 * ========================================================================= */

struct IPAddress {
    u8 octets[16];
};

fn format_filetime(u64 ft) {
    if (ft == 0) return "0 (None)";
    // 116444736000000000 = difference between Windows epoch (1601) and Unix epoch (1970) in 100ns units
    if (ft < 116444736000000000) return "Pre-Unix Epoch";
    u64 unix_sec = (ft - 116444736000000000) / 10000000;
    return std::time::format(std::time::to_utc(unix_sec), "%Y-%m-%d %H:%M:%S UTC");
};

fn format_duration(u64 d) {
    u64 sec = d / 10000000;
    u64 fraction = d % 10000000;
    return std::format("{}.{:07d} s", sec, fraction);
};

fn format_auth_id(u64 id) {
    return std::format("{:08X}:{:08X}", u32(id >> 32), u32(id & 0xFFFFFFFF));
};

fn format_ram_size(u64 ram) {
    double gb = double(ram) / (1024.0 * 1024.0 * 1024.0);
    return std::format("{:.2f} GB ({:d} bytes)", gb, ram);
};

fn format_bitness(u32 b) {
    if (b == 1) return "64-bit";
    if (b == 0) return "32-bit (x86)";
    return std::format("Unknown ({:d})", b);
};

fn format_hex32(u32 val) {
    return std::format("0x{:08X}", val);
};

fn format_hex64(u64 val) {
    return std::format("0x{:016X}", val);
};

fn format_ip(IPAddress ip) {
    bool is_ipv4 = true;
    u32 i = 4;
    while (i < 16) {
        if (ip.octets[i] != 0) {
            is_ipv4 = false;
            break;
        }
        i = i + 1;
    }
    if (is_ipv4) {
        return std::format("{}.{}.{}.{}", ip.octets[0], ip.octets[1], ip.octets[2], ip.octets[3]);
    } else {
        return std::format("{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}",
            ip.octets[0], ip.octets[1], ip.octets[2], ip.octets[3], ip.octets[4], ip.octets[5], ip.octets[6], ip.octets[7],
            ip.octets[8], ip.octets[9], ip.octets[10], ip.octets[11], ip.octets[12], ip.octets[13], ip.octets[14], ip.octets[15]);
    }
};

fn format_ntstatus(u32 status) {
    match (status) {
        (0x00000000): return "SUCCESS (0x00000000)";
        (0x00000103): return "NO MORE DATA (0x00000103)";
        (0x00000104): return "REPARSE (0x00000104)";
        (0x00000105): return "MORE ENTRIES (0x00000105)";
        (0x00000108): return "OPLOCK BREAK IN PROGRESS (0x00000108)";
        (0x0000010B): return "NOTIFY CLEANUP (0x0000010B)";
        (0x0000010C): return "NOTIFY ENUM DIR (0x0000010C)";
        (0x0000012A): return "FILE LOCKED WITH ONLY READERS (0x0000012A)";
        (0x0000012B): return "FILE LOCKED WITH WRITERS (0x0000012B)";
        (0x00000215): return "OPLOCK SWITCHED TO NEW HANDLE (0x00000215)";
        (0x00000216): return "OPLOCK HANDLE CLOSED (0x00000216)";
        (0x00000367): return "WAIT FOR OPLOCK (0x00000367)";
        (0x40000016): return "PREDEFINED HANDLE (0x40000016)";
        (0x80000002): return "DATATYPE MISALIGNMENT (0x80000002)";
        (0x80000005): return "BUFFER OVERFLOW (0x80000005)";
        (0x80000006): return "NO MORE FILES (0x80000006)";
        (0x80000015): return "INVALID EA FLAG (0x80000015)";
        (0x8000001A): return "NO MORE ENTRIES (0x8000001A)";
        (0xC0000001): return "UNSUCCESSFUL (0xC0000001)";
        (0xC0000002): return "NOT IMPLEMENTED (0xC0000002)";
        (0xC0000003): return "INVALID INFO CLASS (0xC0000003)";
        (0xC0000004): return "INFO LENGTH MISMATCH (0xC0000004)";
        (0xC0000005): return "ACCESS VIOLATION (0xC0000005)";
        (0xC0000006): return "IN PAGE ERROR (0xC0000006)";
        (0xC0000008): return "INVALID HANDLE (0xC0000008)";
        (0xC000000D): return "INVALID PARAMETER (0xC000000D)";
        (0xC000000E): return "NO SUCH DEVICE (0xC000000E)";
        (0xC000000F): return "NO SUCH FILE (0xC000000F)";
        (0xC0000010): return "INVALID DEVICE REQUEST (0xC0000010)";
        (0xC0000011): return "END OF FILE (0xC0000011)";
        (0xC0000012): return "WRONG VOLUME (0xC0000012)";
        (0xC0000013): return "NO MEDIA (0xC0000013)";
        (0xC0000015): return "NONEXISTENT SECTOR (0xC0000015)";
        (0xC0000017): return "NO MEMORY (0xC0000017)";
        (0xC0000021): return "ALREADY COMMITTED (0xC0000021)";
        (0xC0000022): return "ACCESS DENIED (0xC0000022)";
        (0xC0000023): return "BUFFER TOO SMALL (0xC0000023)";
        (0xC0000024): return "OBJECT TYPE MISMATCH (0xC0000024)";
        (0xC0000032): return "DISK CORRUPT (0xC0000032)";
        (0xC0000033): return "NAME INVALID (0xC0000033)";
        (0xC0000034): return "NAME NOT FOUND (0xC0000034)";
        (0xC0000035): return "NAME COLLISION (0xC0000035)";
        (0xC0000039): return "OBJECT PATH INVALID (0xC0000039)";
        (0xC000003A): return "PATH NOT FOUND (0xC000003A)";
        (0xC000003B): return "PATH SYNTAX BAD (0xC000003B)";
        (0xC000003C): return "DATA OVERRUN (0xC000003C)";
        (0xC000003F): return "CRC ERROR (0xC000003F)";
        (0xC0000043): return "SHARING VIOLATION (0xC0000043)";
        (0xC0000044): return "QUOTA EXCEEDED (0xC0000044)";
        (0xC000004F): return "EAS NOT SUPPORTED (0xC000004F)";
        (0xC0000050): return "EA TOO LARGE (0xC0000050)";
        (0xC0000051): return "NONEXISTENT EA ENTRY (0xC0000051)";
        (0xC0000052): return "NO EAS ON FILE (0xC0000052)";
        (0xC0000053): return "EA CORRUPTED ERROR (0xC0000053)";
        (0xC0000054): return "FILE LOCK CONFLICT (0xC0000054)";
        (0xC0000055): return "NOT GRANTED (0xC0000055)";
        (0xC0000056): return "DELETE PENDING (0xC0000056)";
        (0xC0000061): return "PRIVILEGE NOT HELD (0xC0000061)";
        (0xC000006D): return "LOGON FAILURE (0xC000006D)";
        (0xC000007E): return "RANGE NOT LOCKED (0xC000007E)";
        (0xC000007F): return "DISK FULL (0xC000007F)";
        (0xC0000098): return "FILE INVALID (0xC0000098)";
        (0xC000009A): return "INSUFFICIENT RESOURCES (0xC000009A)";
        (0xC000009C): return "DEVICE DATA ERROR (0xC000009C)";
        (0xC000009D): return "DEVICE NOT CONNECTED (0xC000009D)";
        (0xC00000A2): return "MEDIA WRITE PROTECTED (0xC00000A2)";
        (0xC00000A5): return "BAD IMPERSONATION (0xC00000A5)";
        (0xC00000AB): return "INSTANCE NOT AVAILABLE (0xC00000AB)";
        (0xC00000AC): return "PIPE NOT AVAILABLE (0xC00000AC)";
        (0xC00000AD): return "INVALID PIPE STATE (0xC00000AD)";
        (0xC00000AE): return "PIPE BUSY (0xC00000AE)";
        (0xC00000B0): return "PIPE DISCONNECTED (0xC00000B0)";
        (0xC00000B1): return "PIPE CLOSING (0xC00000B1)";
        (0xC00000B2): return "PIPE CONNECTED (0xC00000B2)";
        (0xC00000B3): return "PIPE LISTENING (0xC00000B3)";
        (0xC00000B4): return "INVALID READ MODE (0xC00000B4)";
        (0xC00000B5): return "IO TIMEOUT (0xC00000B5)";
        (0xC00000BA): return "IS DIRECTORY (0xC00000BA)";
        (0xC00000BB): return "NOT SUPPORTED (0xC00000BB)";
        (0xC00000BD): return "DUPLICATE NAME (0xC00000BD)";
        (0xC00000BE): return "BAD NETWORK PATH (0xC00000BE)";
        (0xC00000C1): return "BAD NETWORK PATH (0xC00000C1)";
        (0xC00000C3): return "INVALID NETWORK RESPONSE (0xC00000C3)";
        (0xC00000C4): return "NETWORK ERROR (0xC00000C4)";
        (0xC00000CC): return "BAD NETWORK NAME (0xC00000CC)";
        (0xC00000D4): return "BAD NETWORK NAME (0xC00000D4)";
        (0xC00000D8): return "CANT WAIT (0xC00000D8)";
        (0xC00000D9): return "PIPE EMPTY (0xC00000D9)";
        (0xC00000DB): return "CSC OBJECT PATH NOT FOUND (0xC00000DB)";
        (0xC00000E2): return "OPLOCK NOT GRANTED (0xC00000E2)";
        (0xC0000101): return "NOT EMPTY (0xC0000101)";
        (0xC0000102): return "FILE CORRUPT (0xC0000102)";
        (0xC0000103): return "NOT A DIRECTORY (0xC0000103)";
        (0xC0000107): return "FILES OPEN (0xC0000107)";
        (0xC000010D): return "CANNOT IMPERSONATE (0xC000010D)";
        (0xC0000120): return "CANCELLED (0xC0000120)";
        (0xC0000121): return "CANNOT DELETE (0xC0000121)";
        (0xC0000123): return "FILE DELETED (0xC0000123)";
        (0xC0000128): return "FILE CLOSED (0xC0000128)";
        (0xC0000148): return "INVALID LEVEL (0xC0000148)";
        (0xC000014B): return "PIPE BROKEN (0xC000014B)";
        (0xC000014C): return "REGISTRY CORRUPT (0xC000014C)";
        (0xC000014D): return "IO FAILED (0xC000014D)";
        (0xC000017C): return "KEY DELETED (0xC000017C)";
        (0xC0000185): return "IO DEVICE ERROR (0xC0000185)";
        (0xC0000188): return "LOG FILE FULL (0xC0000188)";
        (0xC000020C): return "DISCONNECTED (0xC000020C)";
        (0xC0000225): return "NOT FOUND (0xC0000225)";
        (0xC0000243): return "USER MAPPED FILE (0xC0000243)";
        (0xC0000273): return "NO MORE MATCHES (0xC0000273)";
        (0xC0000275): return "NOT REPARSE POINT (0xC0000275)";
        (_): return std::format("0x{:08X}", status);
    }
};

/* =========================================================================
 * Enums and Bitfields
 * ========================================================================= */

enum EventClass : u32 {
    Unknown = 0,
    Process = 1,
    Registry = 2,
    File_System = 3,
    Profiling = 4,
    Network = 5,
    Ipc = 6
};

enum ProcessOperation : u16 {
    Process_Defined = 0,
    Process_Create = 1,
    Process_Exit = 2,
    Thread_Create = 3,
    Thread_Exit = 4,
    Load_Image = 5,
    Thread_Profile = 6,
    Process_Start = 7,
    Process_Statistics = 8,
    System_Statistics = 9
};

enum RegistryOperation : u16 {
    RegOpenKey = 0,
    RegCreateKey = 1,
    RegCloseKey = 2,
    RegQueryKey = 3,
    RegSetValue = 4,
    RegQueryValue = 5,
    RegEnumValue = 6,
    RegEnumKey = 7,
    RegSetInfoKey = 8,
    RegDeleteKey = 9,
    RegDeleteValue = 10,
    RegFlushKey = 11,
    RegLoadKey = 12,
    RegUnloadKey = 13,
    RegRenameKey = 14,
    RegQueryMultipleValueKey = 15,
    RegSetKeySecurity = 16,
    RegQueryKeySecurity = 17
};

enum NetworkOperation : u16 {
    Unknown = 0,
    Other = 1,
    Send = 2,
    Receive = 3,
    Accept = 4,
    Connect = 5,
    Disconnect = 6,
    Reconnect = 7,
    Retransmit = 8,
    TCPCopy = 9
};

enum ProfilingOperation : u16 {
    Thread_Profiling = 0,
    Process_Profiling = 1,
    Debug_Output_Profiling = 2
};

enum FilesystemOperation : u16 {
    VolumeDismount = 0,
    VolumeMount = 1,
    FASTIO_MDL_WRITE_COMPLETE = 2,
    WriteFile2 = 3,
    FASTIO_MDL_READ_COMPLETE = 4,
    ReadFile2 = 5,
    QueryOpen = 6,
    FASTIO_CHECK_IF_POSSIBLE = 7,
    IRP_MJ_12 = 8,
    IRP_MJ_11 = 9,
    IRP_MJ_10 = 10,
    IRP_MJ_9 = 11,
    IRP_MJ_8 = 12,
    FASTIO_NOTIFY_STREAM_FO_CREATION = 13,
    FASTIO_RELEASE_FOR_CC_FLUSH = 14,
    FASTIO_ACQUIRE_FOR_CC_FLUSH = 15,
    FASTIO_RELEASE_FOR_MOD_WRITE = 16,
    FASTIO_ACQUIRE_FOR_MOD_WRITE = 17,
    FASTIO_RELEASE_FOR_SECTION_SYNCHRONIZATION = 18,
    CreateFileMapping = 19,
    CreateFile = 20,
    CreatePipe = 21,
    IRP_MJ_CLOSE = 22,
    ReadFile = 23,
    WriteFile = 24,
    QueryInformationFile = 25,
    SetInformationFile = 26,
    QueryEAFile = 27,
    SetEAFile = 28,
    FlushBuffersFile = 29,
    QueryVolumeInformation = 30,
    SetVolumeInformation = 31,
    DirectoryControl = 32,
    FileSystemControl = 33,
    DeviceIoControl = 34,
    InternalDeviceIoControl = 35,
    Shutdown = 36,
    LockUnlockFile = 37,
    CloseFile = 38,
    CreateMailSlot = 39,
    QuerySecurityFile = 40,
    SetSecurityFile = 41,
    Power = 42,
    SystemControl = 43,
    DeviceChange = 44,
    QueryFileQuota = 45,
    SetFileQuota = 46,
    PlugAndPlay = 47
};

enum RegistryType : u32 {
    REG_NONE = 0,
    REG_SZ = 1,
    REG_EXPAND_SZ = 2,
    REG_BINARY = 3,
    REG_DWORD = 4,
    REG_DWORD_BIG_ENDIAN = 5,
    REG_LINK = 6,
    REG_MULTI_SZ = 7,
    REG_RESOURCE_LIST = 8,
    REG_FULL_RESOURCE_DESCRIPTOR = 9,
    REG_RESOURCE_REQUIREMENTS_LIST = 10,
    REG_QWORD = 11
};

enum RegistryKeyInformationClass : u32 {
    KeyBasicInformation = 0,
    KeyNodeInformation = 1,
    KeyFullInformation = 2,
    KeyNameInformation = 3,
    KeyCachedInformation = 4,
    KeyFlagsInformation = 5,
    KeyVirtualizationInformation = 6,
    KeyHandleTagsInformation = 7,
    KeyTrustInformation = 8,
    KeyLayerInformation = 9
};

enum RegistryKeyValueInformationClass : u32 {
    KeyValueBasicInformation = 0,
    KeyValueFullInformation = 1,
    KeyValuePartialInformation = 2,
    KeyValueFullInformationAlign64 = 3,
    KeyValuePartialInformationAlign64 = 4,
    KeyValueLayerInformation = 5
};

enum RegistryKeySetInformationClass : u32 {
    KeyWriteTimeInformation = 0,
    KeyWow64FlagsInformation = 1,
    KeySetHandleTagsInformation = 5
};

enum RegistryDisposition : u32 {
    REG_CREATED_NEW_KEY = 1,
    REG_OPENED_EXISTING_KEY = 2
};

enum FilesystemDisposition : u8 {
    Supersede = 0,
    Open = 1,
    Create = 2,
    OpenIf = 3,
    Overwrite = 4,
    OverwriteIf = 5
};

enum FilesystemOpenResult : u32 {
    Superseded = 0,
    Opened = 1,
    Created = 2,
    Overwritten = 3,
    Exists = 4,
    DoesNotExist = 5
};

enum FileInformationClass : u32 {
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
    FileMaximumInformation = 70
};

enum ProductType : u8 {
    Workstation = 1,
    DomainController = 2,
    Server = 3
};

bitfield SuiteMask {
    smallbusiness : 1;
    enterprise : 1;
    backoffice : 1;
    communications : 1;
    terminal : 1;
    smallbusiness_restricted : 1;
    embeddednt : 1;
    datacenter : 1;
    singleuserts : 1;
    personal : 1;
    blade : 1;
    embedded_restricted : 1;
    security_appliance : 1;
    storage_server : 1;
    compute_server : 1;
    wh_server : 1;
};

bitfield FileAccessMask {
    read_data : 1;
    write_data : 1;
    append_data : 1;
    read_ea : 1;
    write_ea : 1;
    execute : 1;
    delete_child : 1;
    read_attributes : 1;
    write_attributes : 1;
    padding : 7;
    delete_access : 1;
    read_control : 1;
    write_dac : 1;
    write_owner : 1;
    synchronize : 1;
    padding2 : 3;
    access_system_security : 1;
    maximum_allowed : 1;
    padding3 : 2;
    generic_all : 1;
    generic_execute : 1;
    generic_write : 1;
    generic_read : 1;
};

bitfield RegistryAccessMask {
    query_value : 1;
    set_value : 1;
    create_sub_key : 1;
    enumerate_sub_keys : 1;
    notify : 1;
    create_link : 1;
    padding : 2;
    wow64_64key : 1;
    wow64_32key : 1;
    padding2 : 6;
    delete_access : 1;
    read_control : 1;
    write_dac : 1;
    write_owner : 1;
    synchronize : 1;
    padding3 : 3;
    access_system_security : 1;
    maximum_allowed : 1;
    padding4 : 2;
    generic_all : 1;
    generic_execute : 1;
    generic_write : 1;
    generic_read : 1;
};

bitfield FilesystemCreateOptions {
    directory_file : 1;
    write_through : 1;
    sequential_only : 1;
    no_intermediate_buffering : 1;
    synchronous_io_alert : 1;
    synchronous_io_nonalert : 1;
    non_directory_file : 1;
    create_tree_connection : 1;
    complete_if_oplocked : 1;
    no_ea_knowledge : 1;
    open_for_recovery : 1;
    random_access : 1;
    delete_on_close : 1;
    open_by_file_id : 1;
    open_for_backup_intent : 1;
    no_compression : 1;
    open_requiring_oplock : 1;
    disallow_exclusive : 1;
    padding : 2;
    reserve_opfilter : 1;
    open_reparse_point : 1;
    open_no_recall : 1;
    open_for_free_space_query : 1;
    padding2 : 8;
};

bitfield FilesystemCreateAttributes {
    readonly : 1;
    hidden : 1;
    system : 1;
    padding : 1;
    directory : 1;
    archive : 1;
    device : 1;
    normal : 1;
    temporary : 1;
    sparse_file : 1;
    reparse_point : 1;
    compressed : 1;
    offline : 1;
    not_content_indexed : 1;
    encrypted : 1;
    padding2 : 1;
};

bitfield FilesystemShareAccess {
    share_read : 1;
    share_write : 1;
    share_delete : 1;
    padding : 13;
};

bitfield FilesystemIoFlags {
    non_cached : 1;
    paging_io : 1;
    synchronous : 1;
    padding : 1;
    buffered : 1;
    padding2 : 1;
    synchronous_paging_io : 1;
    padding3 : 15;
    write_through : 1;
    padding4 : 9;
};

bitfield PageProtectionFlags {
    padding : 1;
    readonly : 1;
    readwrite : 1;
    writecopy : 1;
    execute : 1;
    execute_read : 1;
    execute_readwrite : 1;
    execute_writecopy : 1;
    guard : 1;
    nocache : 1;
    writecombine : 1;
    padding2 : 21;
};

bitfield FilesystemNotifyChangeFlags {
    file_name : 1;
    dir_name : 1;
    name : 1;
    attributes : 1;
    size : 1;
    last_write : 1;
    last_access : 1;
    creation : 1;
    ea : 1;
    security : 1;
    stream_name : 1;
    stream_size : 1;
    stream_write : 1;
    padding : 19;
};

/* =========================================================================
 * PML Header (0x3A8 bytes)
 * ========================================================================= */

struct Header {
    char magic[4] [[comment("PML file signature: PML_")]];
    u32 version [[comment("PML version (expected 9)")]];
    u32 is_64bit [[comment("System architecture: 1 for 64-bit, 0 for 32-bit"), format("format_bitness")]];
    char16 computer_name[16] [[comment("Computer name that captured the logs")]];
    char16 system_root[260] [[comment("System root path (e.g. C:\\Windows)")]];
    u32 number_of_events [[comment("Total number of captured events in file")]];
    u64 reserved_238 [[comment("Unused / Reserved")]];
    u64 events_offset [[comment("File offset to the start of events data"), format("format_hex64")]];
    u64 events_offsets_array_offset [[comment("File offset to array of event offsets"), format("format_hex64")]];
    u64 process_table_offset [[comment("File offset to the Process Table"), format("format_hex64")]];
    u64 strings_table_offset [[comment("File offset to the Strings Table"), format("format_hex64")]];
    u64 icon_table_offset [[comment("File offset to the Icon Table"), format("format_hex64")]];
    u64 max_application_address [[comment("SYSTEM_INFO.lpMaximumApplicationAddress")]];
    u32 os_version_info_size [[comment("sizeof(OSVERSIONINFOEXW) (284 bytes)")]];
    u32 os_major_version [[comment("Operating system major version")]];
    u32 os_minor_version [[comment("Operating system minor version")]];
    u32 os_build_number [[comment("Operating system build number")]];
    u32 os_build_number_decimal [[comment("Build number after decimal point / platform ID")]];
    char16 csd_version[128] [[comment("Service pack / CSD version string")]];
    u16 service_pack_major [[comment("Service pack major version")]];
    u16 service_pack_minor [[comment("Service pack minor version")]];
    SuiteMask suite_mask [[comment("Product suite mask")]];
    ProductType product_type [[comment("OS Product Type")]];
    u8 reserved_38b [[comment("Reserved")]];
    u32 number_of_processors [[comment("Number of logical processors")]];
    u64 total_phys_memory [[comment("Total physical RAM in bytes"), format("format_ram_size")]];
    u64 header_size [[comment("Header size (expected 0x3A8)")]] ;
    u64 hosts_and_ports_tables_offset [[comment("File offset to Hosts & Ports tables"), format("format_hex64")]];
};

/* =========================================================================
 * Strings Table
 * ========================================================================= */

struct StringEntry {
    u32 size [[comment("Size of string in bytes")]];
    char16 string[size / 2] [[comment("UTF-16LE string")]];
};

struct StringsTable {
    u32 count [[comment("Number of strings in table")]];
    u32 offsets[count] [[comment("Offsets relative to Strings Table start")]];
    StringEntry strings[count] [[comment("Contiguous UTF-16LE strings")]];
};

/* =========================================================================
 * Process Table
 * ========================================================================= */

struct Module {
    if (header.is_64bit) {
        u64 unknown_00;
        u64 base_address [[comment("Module base address"), format("format_hex64")]];
    } else {
        u32 unknown_00;
        u32 base_address [[comment("Module base address"), format("format_hex32")]];
    }
    u32 size [[comment("Module size in bytes")]];
    u32 image_path_string_index [[comment("Strings Table index: Image Path")]];
    u32 version_string_index [[comment("Strings Table index: Version")]];
    u32 company_string_index [[comment("Strings Table index: Company")]];
    u32 description_string_index [[comment("Strings Table index: Description")]];
    u32 timestamp [[comment("PE Header Timestamp / TimeDateStamp")]];
    u8 unknown_28[0x18] [[comment("Reserved / Unknown")]];
};

struct Process {
    u32 process_index [[comment("Process index (referenced by events)")]];
    u32 process_id [[comment("Process ID (PID)")]];
    u32 parent_process_id [[comment("Parent Process ID (PPID)")]];
    u32 parent_process_index [[comment("Parent Process index")]];
    u64 authentication_id [[comment("Authentication ID (LUID)"), format("format_auth_id")]];
    u32 session_id [[comment("Terminal Services Session ID")]];
    u32 unknown_1c;
    u64 start_time [[comment("Process start time"), format("format_filetime")]];
    u64 end_time [[comment("Process end time"), format("format_filetime")]];
    u32 is_virtualized [[comment("1 if process is virtualized, 0 otherwise")]];
    u32 is_64bit [[comment("1 if 64-bit, 0 if WOW64 / 32-bit"), format("format_bitness")]];
    u32 integrity_string_index [[comment("Strings Table index: Integrity")]];
    u32 user_string_index [[comment("Strings Table index: User")]];
    u32 process_name_string_index [[comment("Strings Table index: Process Name")]];
    u32 image_path_string_index [[comment("Strings Table index: Image Path")]];
    u32 command_line_string_index [[comment("Strings Table index: Command Line")]];
    u32 company_string_index [[comment("Strings Table index: Company")]];
    u32 version_string_index [[comment("Strings Table index: Version")]];
    u32 description_string_index [[comment("Strings Table index: Description")]];
    u32 icon_index_small [[comment("Small icon index (16x16)")]];
    u32 icon_index_big [[comment("Big icon index (32x32)")]];

    if (header.is_64bit) {
        u64 unknown_pvoid;
    } else {
        u32 unknown_pvoid;
    }

    u32 num_modules [[comment("Number of loaded modules")]];
    Module modules[num_modules] [[comment("Loaded modules array")]];
};

struct ProcessTable {
    u32 count [[comment("Number of processes in table")]];
    u32 process_indices[count] [[comment("Array of process indices")]];
    u32 offsets[count] [[comment("Offsets relative to Process Table start")]];
    Process processes[count] [[comment("Process records")]];
};

/* =========================================================================
 * Icons Table
 * ========================================================================= */

struct IconEntry {
    u32 cx_cy_desired [[comment("Desired icon dimensions (0x10=16x16, 0x20=32x32)")]];
    u32 size [[comment("Icon data size in bytes")]];
    u8 data[size] [[comment("Raw icon / resource image data")]];
};

struct IconTable {
    u32 count [[comment("Number of icons in table")]];
    u32 offsets[count] [[comment("Offsets relative to Icon Table start")]];
    IconEntry icons[count] [[comment("Icon records")]];
};

/* =========================================================================
 * Hosts and Ports Table
 * ========================================================================= */

struct HostEntry {
    IPAddress ip [[comment("IP address bytes (IPv4 in first 4 bytes or IPv6)"), format("format_ip")]];
    u32 hostname_length [[comment("Hostname length in bytes")]];
    char16 hostname[hostname_length / 2] [[comment("Resolved hostname")]];
};

struct PortEntry {
    u16 port [[comment("Port number")]];
    u16 is_tcp [[comment("1 for TCP, 0 for UDP")]];
    u32 port_name_length [[comment("Port name length in bytes")]];
    char16 port_name[port_name_length / 2] [[comment("Service name (e.g. http, https)")]];
};

struct HostsAndPortsTable {
    u32 num_hosts [[comment("Number of cached hostnames")]];
    HostEntry hosts[num_hosts] [[comment("Cached hostnames")]];
    u32 num_ports [[comment("Number of cached port names")]];
    PortEntry ports[num_ports] [[comment("Cached port names")]];
};

/* =========================================================================
 * Event Offsets Array
 * ========================================================================= */

struct EventOffsetEntry {
    u32 offset [[comment("Absolute file offset to the event"), format("format_hex32")]];
    u8 flags [[comment("Event flags / reserved")]];
};

/* =========================================================================
 * Detail Helper Structs
 * ========================================================================= */

struct DetailString {
    u16 flags;
    bool is_ascii = (flags & 0x8000) != 0;
    u16 char_count = flags & 0x7FFF;
    if (is_ascii) {
        char string[char_count];
    } else {
        char16 string[char_count];
    }
};

struct ProcessExitDetails {
    u32 exit_status [[comment("Process exit status / NTSTATUS code"), format("format_ntstatus")]];
    u64 kernel_time [[comment("Kernel CPU time (100ns units)"), format("format_duration")]];
    u64 user_time [[comment("User CPU time (100ns units)"), format("format_duration")]];
    u64 working_set [[comment("Working set size in bytes")]];
    u64 peak_working_set [[comment("Peak working set size in bytes")]];
    u64 private_bytes [[comment("Private bytes")]];
    u64 peak_private_bytes [[comment("Peak private bytes")]];
};

struct ThreadCreateDetails {
    u32 thread_id [[comment("Created Thread ID")]];
};

struct ThreadExitDetails {
    u32 unknown_00;
    u64 kernel_time [[comment("Kernel CPU time (100ns units)"), format("format_duration")]];
    u64 user_time [[comment("User CPU time (100ns units)"), format("format_duration")]];
};

struct NetworkDetails {
    u16 flags [[comment("Bit 0: Src IPv4, Bit 1: Dst IPv4, Bit 2: TCP")]];
    u16 unknown_02;
    u32 length [[comment("Network packet length")]];
    IPAddress source_ip [[comment("Source IP address"), format("format_ip")]];
    IPAddress dest_ip [[comment("Destination IP address"), format("format_ip")]];
    u16 source_port [[comment("Source port")]];
    u16 dest_port [[comment("Destination port")]];
};

/* =========================================================================
 * Event Structure
 * ========================================================================= */

struct Event {
    u32 process_index [[comment("Index into Process Table")]];
    u32 thread_id [[comment("Thread ID (TID)")]];
    EventClass event_class [[comment("Event Class")]];
    u16 operation [[comment("Operation Code")]];
    u16 unknown_0e;
    u32 unknown_10;
    u64 duration_100ns [[comment("Duration in 100ns units"), format("format_duration")]];
    u64 date_filetime [[comment("Event timestamp (FILETIME)"), format("format_filetime")]];
    u32 result [[comment("Result / NTSTATUS code"), format("format_ntstatus")]];
    u16 stacktrace_depth [[comment("Number of stack frames")]];
    u16 unknown_2a;
    u32 details_size [[comment("Size of detail payload in bytes")]];
    u32 extra_details_offset [[comment("Offset to extra details from start of event")]];

    if (header.is_64bit) {
        u64 stacktrace[stacktrace_depth] [[comment("Stack frame return addresses")]];
    } else {
        u32 stacktrace[stacktrace_depth] [[comment("Stack frame return addresses")]];
    }

    if (details_size > 0) {
        if (event_class == EventClass::Process && (operation == 2 || operation == 8) && details_size == sizeof(ProcessExitDetails)) {
            ProcessExitDetails process_exit [[inline, name("Process Exit Details")]];
        } else if (event_class == EventClass::Process && operation == 3 && details_size == sizeof(ThreadCreateDetails)) {
            ThreadCreateDetails thread_create [[inline, name("Thread Create Details")]];
        } else if (event_class == EventClass::Process && operation == 4 && details_size == sizeof(ThreadExitDetails)) {
            ThreadExitDetails thread_exit [[inline, name("Thread Exit Details")]];
        } else if (event_class == EventClass::Network && details_size >= sizeof(NetworkDetails)) {
            NetworkDetails network [[inline, name("Network Details")]];
            if (details_size > sizeof(NetworkDetails)) {
                u8 network_extra_multisz[details_size - sizeof(NetworkDetails)] [[name("Multi-SZ Details")]];
            }
        } else {
            u8 details[details_size] [[comment("Detail Payload"), color("98FB98")]];
        }
    }

    if (extra_details_offset > 0) {
        u16 extra_details_size [[comment("Size of extra details payload")]];
        u8 extra_details[extra_details_size] [[comment("Extra details data"), color("DDA0DD")]];
    }
};

/* =========================================================================
 * Top-level File Layout
 * ========================================================================= */

Header header @ 0x00;
EventOffsetEntry event_offsets[header.number_of_events] @ header.events_offsets_array_offset;
StringsTable strings_table @ header.strings_table_offset;
ProcessTable process_table @ header.process_table_offset;
IconTable icon_table @ header.icon_table_offset;
HostsAndPortsTable hosts_and_ports @ header.hosts_and_ports_tables_offset;

// Preview the first events block (capped to prevent evaluation performance degradation on huge 50k+ logs)
u32 preview_event_count = header.number_of_events < 5000 ? header.number_of_events : 5000;
Event events_preview[preview_event_count] @ header.events_offset;