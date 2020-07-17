# PML File Format

PML (Process Monitor Log file) is the file format which Procmon uses to save the logs it has captured to the disk. There is no official documentation of this format so everything here was reverse engineered, and there are a lot of unknown fields.

This file contains information about the operating system, the running processes, their modules, and of course the captured events themselves.

The file starts with a header:

**PML Header**

| Offset | Data Type      | Description                                           |
| ------ | -------------- | ----------------------------------------------------- |
| 0x0    | char[4]        | Signature - "PML_"                                    |
| 0x4    | Uint32         | The version of the PML file. I assume its 9           |
| 0x8    | Uint32         | 1 if the system is 64 bit, 0 otherwise                |
| 0xC    | Wchar_t[0x10]  | The computer name                                     |
| 0x2C   | Wchar_t[0x104] | The system root path (like "C:\Windows")              |
| 0x234  | Uint32         | The total number of events in the log file            |
| 0x238  | Uint64         | Unknown                                               |
| 0x240  | Uint64         | File offset to the start of the events array.         |
| 0x248  | Uint64         | File offset to an array of offsets to all the events. |
| 0x250  | Uint64         | File offset to the array of processes.                |
| 0x258  | Uint64         | File offset to the array of strings.                  |
| 0x260  | Byte[0x14]     | Unknown                                               |
| 0x274  | Uint32         | Windows version major number                          |
| 0x278  | Uint32         | Windows version minor number                          |
| 0x27C  | Uint32         | Windows build number                                  |
| 0x280  | Uint32         | Windows build number after the decimal point          |
| 0x284  | Wchar_t[0x32]  | The name of the service pack (optional)               |
| 0x2A6  | Byte[0xd6]     | Unknown                                               |
| 0x38C  | Uint32         | Number of logical processors                          |
| 0x390  | Uint64         | The size of the RAM                                   |
| 0x398  | Uint64         | File offset to the start of the events array (again). |
| 0x3A0  | Uint64         | File offset to hosts and ports arrays.                |

The header has file pointers to 4 important arrays:

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

| Offset    | Data Type | Description                                                  |
| --------- | --------- | ------------------------------------------------------------ |
| 0x0       | Uint32    | The process index (for events to use as a reference to the process) |
| 0x4       | Uint32    | Process id                                                   |
| 0x8       | Uint32    | Parent process id                                            |
| 0xC       | Uint32    | Unknown                                                      |
| 0x10      | Uint64    | Authentication id                                            |
| 0x18      | Uint32    | Session number                                               |
| 0x1C      | Uint32    | Unknown                                                      |
| 0x20      | FILETIME  | The startinig time of the process.                           |
| 0x28      | FILETIME  | The ending time of the process.                              |
| 0x30      | Uint32    | 1 if the process is virtualized, 0 otherwise.                |
| 0x34      | Uint32    | 1 if this process is 64 bit, 0 if WOW64.                     |
| 0x38      | Uint32    | Integrity - as a string index                                |
| 0x3C      | Uint32    | the user - as a string index                                 |
| 0x40      | Uint32    | the process name - as a string index                         |
| 0x44      | Uint32    | the image path - as a string index                           |
| 0x48      | Uint32    | the command line - as a string index                         |
| 0x4C      | Uint32    | company of the executable - as a string index                |
| 0x50      | Uint32    | version of the executable - as a string index                |
| 0x54      | Uint32    | description of the executable - as a string index            |
| 0x58      | Pvoid     | Unknown                                                      |
| 0x5C/0x60 | Uint64    | Unknown                                                      |
| 0x64/0x68 | Uint32    | number of modules in the process                             |
| 0x68/0x6C | Module[]  | Array of the modules loaded in the process.                  |

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
| 0x2C   | Uint32    | The size of the specific detail structure (contains path and other details) |
| 0x30   | Uint32    | The offset from the start of the event to extra detail structure. |
| 0x34   | PVoid[]   | Array of the addresses of the stack frames.                  |

#### Detail Structures

Every event has a different detail structure, based on the operation. The detail structure contains the *path* value, the *category* value and the *detail* value of the event. There are something like 100+ operation and sub operation types so most of them are still unknown. 

All of the detail structures that are known are described in [construct_logs_details_format.py](../procmon_parser/construct_logs_details_format.py).

