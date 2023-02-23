# PML File Format

PML (Process Monitor Log file) is the file format which Procmon uses to save the logs it has captured to the disk. There is no official documentation of this format so everything here was reverse engineered, and there are a lot of unknown fields.

This file contains information about the operating system, the running processes, their modules, and of course the captured events themselves.

The file starts with a header:

**PML Header**

| Offset | Data Type      | Size (bytes) | Description                                                                                                                                                      |
| ------ | -------------- |--------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| 0x000  | char[4]        | 4            | Magic Signature - `'PML_'`.                                                                                                                                      |
| 0x004  | uint32         | 4            | Version of the PML file. `9` in the current version.                                                                                                             |
| 0x008  | uint32         | 4            | System bitness: 1 if the system is 64 bit, 0 otherwise.                                                                                                          |
| 0x00C  | wchar_t[0x10]  | 32           | Name of the computer (that did the capture).                                                                                                                     |
| 0x02C  | wchar_t[0x104] | 512          | System root path (e.g. "C:\Windows").                                                                                                                            |
| 0x234  | uint32         | 4            | Total number of events in the log file.                                                                                                                          |
| 0x238  | uint64         | 8            | ?  (seems to be unused)                                                                                                                                          |
| 0x240  | uint64         | 8            | File offset to the start of the events array.                                                                                                                    |
| 0x248  | uint64         | 8            | File offset to an array of offsets to all the events.                                                                                                            |
| 0x250  | uint64         | 8            | File offset to the array of processes.                                                                                                                           |
| 0x258  | uint64         | 8            | File offset to the array of strings.                                                                                                                             |
| 0x260  | uint64         | 8            | File offset to the icons array.                                                                                                                                  |
| 0x268  | uint64         | 8            | [`SYSTEM_INFO`](https://docs.microsoft.com/en-us/windows/win32/api/sysinfoapi/ns-sysinfoapi-system_info)`.lpMaximumApplicationAddress`: Maximum User Address     |
| 0x270  | uint32         | 4            | [`OSVERSIONINFOEXW`](https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-osversioninfoexw)`.dwOSVersionInfoSize`: `sizeof(OSVERSIONINFOEXW)`       |
| 0x274  | uint32         | 8            | `OSVERSIONINFOEXW.dwMajorVersion`: Major version number of the operating system.                                                                                 |
| 0x278  | uint32         | 8            | `OSVERSIONINFOEXW.dwMinorVersion`: Minor version number of the operating system.                                                                                 |
| 0x27C  | uint32         | 8            | `OSVERSIONINFOEXW.dwBuildNumber`: Build number of the operating system.                                                                                          |
| 0x280  | uint32         | 8            | `OSVERSIONINFOEXW.dwPlatformId`: Operating system platform.                                                                                                      |
| 0x284  | wchar_t[0x100] | 512          | `OSVERSIONINFOEXW.szCSDVersion`: Indicates the latest Service Pack installed.                                                                                    |
| 0x384  | uint16         | 2            | `OSVERSIONINFOEXW.wServicePackMajor`:  Major version number of the latest Service Pack.                                                                          |
| 0x386  | uint16         | 2            | `OSVERSIONINFOEXW.wServicePackMinor`:  Minor version number of the latest Service Pack.                                                                          |
| 0x388  | uint16         | 2            | `OSVERSIONINFOEXW.wSuiteMask`: Bit mask that identifies the product suites available.                                                                            |
| 0x38A  | uint8          | 1            | `OSVERSIONINFOEXW.wProductType`: Additional information about the system.                                                                                        |
| 0x38B  | uint8          | 1            | `OSVERSIONINFOEXW.wReserved`: Reserved for future use.                                                                                                           |
| 0x38C  | uint32         | 4            | [`SYSTEM_INFO`](https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/ns-sysinfoapi-system_info)`.dwNumberOfProcessors`: Number of logical processors.  |
| 0x390  | uint64         | 8            | [`MEMORYSTATUSEX`](https://docs.microsoft.com/en-us/windows/win32/api/sysinfoapi/ns-sysinfoapi-memorystatusex)`.ullTotalPhys`: Total physical memory (in bytes). |
| 0x398  | uint64         | 8            | File offset to the start of the events array (again).                                                                                                            |
| 0x3A0  | uint64         | 8            | File offset to hosts and ports arrays.                                                                                                                           |

The header has file pointers to 5 important arrays:

**Strings Array**

This is an array of strings, which allows other parts of the file to refer to strings by their index in this array. Every String is represented by the struct:

```cpp
typedef struct {
    uint32_t size;
    wchar_t string[size / sizeof(wchar_t)];
} String;
```

The array itself is represented by:

| Offset | Data Type | Description                                             |
| ------ | --------- | ------------------------------------------------------- |
| 0x0    | UInt32    | The number of strings in the array.                     |
| 0x4    | Uint32[]  | Array of relative offsets to every string in the array. |
| 0x4+n  | String[]  | The array of the strings itself.                        |

**Process Array**

The array of processes, which allows every event to have the process as an index in the array. 

| Offset | Data Type | Description                                             |
| ------ | --------- | ------------------------------------------------------- |
| 0x0    | UInt32    | The number of strings in the array.                     |
| 0x4    | Uint32[]  | Array of the process indexes.                           |
| 0x4+n  | Uint32[]  | Array of relative offsets to every string in the array. |
| 0x4+2n | Process[] | The array of the processes.                             |

A process is represented by:

| Offset    | Data Type | Description                                                         |
|-----------| --------- |---------------------------------------------------------------------|
| 0x0       | Uint32    | The process index (for events to use as a reference to the process) |
| 0x4       | Uint32    | Process id                                                          |
| 0x8       | Uint32    | Parent process id                                                   |
| 0xC       | Uint32    | Parent Process index.                                               |
| 0x10      | Uint64    | Authentication id                                                   |
| 0x18      | Uint32    | Session number                                                      |
| 0x1C      | Uint32    | Unknown                                                             |
| 0x20      | FILETIME  | The startinig time of the process.                                  |
| 0x28      | FILETIME  | The ending time of the process.                                     |
| 0x30      | Uint32    | 1 if the process is virtualized, 0 otherwise.                       |
| 0x34      | Uint32    | 1 if this process is 64 bit, 0 if WOW64.                            |
| 0x38      | Uint32    | Integrity - as a string index                                       |
| 0x3C      | Uint32    | the user - as a string index                                        |
| 0x40      | Uint32    | the process name - as a string index                                |
| 0x44      | Uint32    | the image path - as a string index                                  |
| 0x48      | Uint32    | the command line - as a string index                                |
| 0x4C      | Uint32    | company of the executable - as a string index                       |
| 0x50      | Uint32    | version of the executable - as a string index                       |
| 0x54      | Uint32    | description of the executable - as a string index                   |
| 0x58      | Uint32    | Icon index small (0x10 pixels)                                      |
| 0x5C      | Uint32    | Icon index big (0x20 pixels)                                        |
| 0x60      | PVoid     | Unknown                                                             |
| 0x64/0x68 | Uint32    | number of modules in the process                                    |
| 0x68/0x6C | Module[]  | Array of the modules loaded in the process.                         |

A module is represented by:

| Offset | Data Type | Description                                       |
| ------ | --------- | ------------------------------------------------- |
| 0x0    | Pvoid     | Unknown                                           |
| 0x8    | Pvoid     | Base address of the module.                       |
| 0x10   | Uint32    | Size of the module.                               |
| 0x14   | Uint32    | image path \- as a string index                   |
| 0x18   | Uint32    | version of the executable - as a string index     |
| 0x1C   | Uint32    | company of the executable - as a string index     |
| 0x20   | Uint32    | description of the executable - as a string index |
| 0x24   | Uint32    | timestamp of the executable                       |
| 0x28   | Uint64[3] | Unknown                                           |

**Hosts and Ports array**

All the hosts and ports names for the network events are cached in these arrays:

| Data Type | Description                           |
| --------- | ------------------------------------- |
| Uint32    | Number of elements in the hosts array |
| Host[]    | The hosts                             |
| Uint32    | Number of elements in the ports array |
| Port[]    | The ports                             |

where hosts and ports are represented by:

```cpp
typedef struct {
    char ip[16]; // the bytes of the ip, either IPv6 or IPv4 (only first 4 bytes used for IPv4)
    String host; // the name of the host as a string
} Host;

typedef struct {
    uint16_t port_number; // the number of the port
    uint16_t is_tcp; // true if this port is for TCP, false for UDP.
    String port_name; // the string value of the port name (for example http for TCP,80)
} Port;
```

**Icon Array**

Icons of captured process are stored in this array in the following format:

| Offset | Data Type | Description                                           |
| ------ | --------- | ----------------------------------------------------- |
| 0x0    | UInt32    | The number of icons in the array.                     |
| 0x4    | Uint32[]  | Array of relative offsets to every icon in the array. |
| 0x4+n  | Icon[]    | The array of the icons itself.                        |

The icons are being shown in the GUI with `CreateIconFromResourceEx`. Every icon is represented in the file by:

| Offset | Data Type | Description                     |
| ------ | --------- | ------------------------------- |
| 0x0    | Uint32    | the `cxDesired` and `cyDesired` |
| 0x4    | Uint32    | the size of the icon in bytes.  |
| 0x8    | ICONIMAGE | the icon itself.                |

**Events Array**

This is the array of all the captured events. Each event has the information needed for all the columns, regardless of the selected columns in the configuration. Every event start at an offset from the event offsets array, in the following layout:

| Offset | Data Type | Description                                                  |
| ------ | --------- | ------------------------------------------------------------ |
| 0x0    | Uint32    | The index to the process of the event.                       |
| 0x4    | Uint32    | Thread Id.                                                   |
| 0x8    | Uint32    | Event class - see ```class EventClass(enum.IntEnum)``` in [consts.py](../procmon_parser/consts.py) |
| 0xC    | Uint16    | Operation type - see `ProcessOperation`, `RegistryOperation`, `NetworkOperation`, `FilesystemOperation` in [consts.py](../procmon_parser/consts.py) |
| 0xE    | Byte[6]   | Unknown.                                                     |
| 0x14   | Uint64    | Duration of the operation in 100 nanoseconds interval.       |
| 0x1C   | FILETIME  | The time when the event was captured.                        |
| 0x24   | Uint32    | The value of the event result.                               |
| 0x28   | Uint16    | The depth of the captured stack trace.                       |
| 0x2A   | Uint16    | Unknown                                                      |
| 0x2C   | Uint32    | The size of the specific **detail** structure (contains path and other details) |
| 0x30   | Uint32    | The offset from the start of the event to **extra detail** structure (not necessarily continuous with this structure). |
| 0x34   | PVoid[]   | Array of the addresses of the stack frames.                  |
| 0x34+n | Byte[]    | A **detail** structure based on the operation type.          |

### Detail Structures

Every event has a different **detail** structure at the end of the structure, based on the operation. The detail structure contains the *path* column, the *category* column and the *detail* column of the event. There are something like 50+ operation and sub operation types so most of them are still unknown.  
In addition, an event can have an **extra detail** event, which can contain even more detail values. The extra detail structure doesn't necessarily comes after the event structure, so there is an offset field relative to the event structure.



All of the detail structures that are known are described in [stream_logs_details_format.py](../procmon_parser/stream_logs_details_format.py).

#### Network

#### Process

##### Process Create

##### Process Exit

##### Thread Create

##### Thread Exit

##### Load Image

##### Process Start

#### Registry



#### File system
