"""
Python types that procmon logs use
"""

from __future__ import annotations

import binascii
import datetime

from procmon_parser.consts import (
    UNKNOWN_CSV_NAME,
    Column,
    ColumnToOriginalName,
    EventClass,
    FilesystemOperation,
    Operation,
    ProcessOperation,
    ProfilingOperation,
    RegistryOperation,
    get_error_message,
)

__all__ = ['Event', 'Module', 'PMLError', 'PMLStructReader', 'Process']


EPOCH_AS_FILETIME = 116444736000000000  # January 1, 1970 as MS file time
HUNDREDS_OF_NANOSECONDS = 10000000


class PMLError(RuntimeError):
    pass


class Module:
    """Information about a loaded module in a process or in the kernel
    """

    def __init__(self, base_address=0, size=0, path="", version="", company="", description="", timestamp=0):
        self.base_address = base_address
        self.size = size
        self.path = path
        self.version = version
        self.company = company
        self.description = description
        self.timestamp = timestamp

    def __eq__(self, other):
        if type(other) is type(self):
            return self.__dict__ == other.__dict__
        return False

    def __ne__(self, other):
        return not self.__eq__(other)

    def __str__(self):
        return "\"{}\", address={}, size={}".format(
            self.path, f"0x{self.base_address:x}", f"0x{self.size:x}")

    def __repr__(self):
        return f"Module({self.base_address}, {self.size}, \"{self.path}\", \"{self.version}\", " \
               f"\"{self.company}\", \"{self.description}\", {self.timestamp})"

    def __hash__(self):
        return hash((self.base_address, self.size, self.path, self.timestamp))


class Process:
    """Information about a process in the system
    """

    def __init__(self, pid=0, parent_pid=0, authentication_id=0, session=0, virtualized=0, is_process_64bit=False,
                 integrity="", user="", process_name="", image_path="", command_line="", company="", version="",
                 description="", start_time=None, end_time=None, modules=None):
        self.pid = pid
        self.parent_pid = parent_pid
        self.authentication_id = authentication_id
        self.session = session
        self.virtualized = virtualized
        self.is_process_64bit = bool(is_process_64bit)
        self.integrity = integrity
        self.user = user
        self.process_name = process_name
        self.image_path = image_path
        self.command_line = command_line
        self.company = company
        self.version = version
        self.description = description
        self.start_time = start_time
        self.end_time = end_time
        self.modules = modules or []

    def __eq__(self, other):
        if type(other) is type(self):
            return self.__dict__ == other.__dict__
        return False

    def __ne__(self, other):
        return not self.__eq__(other)

    def __str__(self):
        return f"\"{self.image_path}\", {self.pid}"

    def __repr__(self):
        return f"Process({self.pid}, {self.parent_pid}, {self.authentication_id}, {self.session}, " \
               f"{self.virtualized}, \"{self.is_process_64bit}\", \"{self.integrity}\", \"{self.user}\", " \
               f"\"{self.process_name}\", \"{self.image_path}\", \"{self.command_line}\", \"{self.company}\", " \
               f"\"{self.version}\", \"{self.description}\")"

    def __hash__(self):
        return hash((self.pid, self.parent_pid, self.image_path, self.command_line, self.start_time, self.end_time))


class Event:
    def __init__(self, process: Process, tid: int, event_class: EventClass | str | int,
                 operation: Operation, duration: int, date_filetime: int, result: int = 0,
                 stacktrace: list | None = None, category: str = "", path: str = "", details: dict | None = None,
                 network_protocol: str = "", unknown_sub_operation: int | None = None):
        self.process = process
        self.tid = tid
        self.event_class = EventClass[event_class] if isinstance(event_class, str) else EventClass(event_class)
        self.operation = operation
        self.network_protocol = network_protocol  # Procmon prints it before the name of a network operation
        self.unknown_sub_operation = unknown_sub_operation  # the raw sub operation, if it isn't a known one
        self.date_filetime = date_filetime
        self.result = result
        self.duration = duration
        self.stacktrace = stacktrace
        self.category = category
        self.path = path
        self.details = details

    def __eq__(self, other):
        if type(other) is type(self):
            return self.__dict__ == other.__dict__
        return False

    def __ne__(self, other):
        return not self.__eq__(other)

    def __str__(self):
        return f"Process Name={self.process.process_name}, Pid={self.process.pid}, Operation={self.operation.name}, " \
               f"Path=\"{self.path}\", Time={self._strftime_date(self.date_filetime, True, True)}"

    def __repr__(self):
        return f"Event({self.process}, {self.tid}, \"{self.event_class.name}\", \"{self.operation.name}\", " \
               f"{self.duration}, {self.date_filetime}, {self.result}, \"{self.category}\", \"{self.path}\", " \
               f"{self.details})"

    def __hash__(self):
        return hash((self.process.pid, self.tid, self.operation, self.date_filetime))

    def date(self, is_utc=True):
        """The timezone aware date of the event, in UTC or in the local timezone
        """
        date = datetime.datetime.fromtimestamp(
            (self.date_filetime - EPOCH_AS_FILETIME) // HUNDREDS_OF_NANOSECONDS,
            datetime.timezone.utc) + datetime.timedelta(
            microseconds=((self.date_filetime % HUNDREDS_OF_NANOSECONDS) // 10))
        return date if is_utc else date.astimezone()

    @staticmethod
    def _strftime_date(date_filetime, show_day=True, show_nanoseconds=False, is_utc=True):
        # Procmon prints the time in the timezone of the machine which exported the logs
        hundred_nanoseconds = (date_filetime % HUNDREDS_OF_NANOSECONDS)
        d = datetime.datetime.fromtimestamp((date_filetime - EPOCH_AS_FILETIME) // HUNDREDS_OF_NANOSECONDS,
                                            datetime.timezone.utc)
        if not is_utc:
            d = d.astimezone()

        if show_nanoseconds:
            time_of_day = d.strftime("%I:%M:%S.{:07d} %p").lstrip('0').format(hundred_nanoseconds)
        else:
            time_of_day = d.strftime("%I:%M:%S %p").lstrip('0')

        if not show_day:
            return time_of_day
        day = d.strftime("%m/%d/%Y ").lstrip('0').replace('/0', '/')
        return day + time_of_day

    @staticmethod
    def _strftime_relative_time(delta_hundred_nanosecs):
        secs = delta_hundred_nanosecs // HUNDREDS_OF_NANOSECONDS
        hundred_nanosecs = delta_hundred_nanosecs % HUNDREDS_OF_NANOSECONDS
        return f"{secs // 3600:02d}:{(secs // 60) % 60:02d}:{secs % 60:02d}.{hundred_nanosecs:07d}"

    @staticmethod
    def _strftime_duration(duration_hundred_nanosecs):
        secs = duration_hundred_nanosecs // HUNDREDS_OF_NANOSECONDS
        hundred_nanosecs = duration_hundred_nanosecs % HUNDREDS_OF_NANOSECONDS
        return f"{secs}.{hundred_nanosecs:07d}"

    @staticmethod
    def _get_bool_str(b):
        if isinstance(b, bool):
            return str(b)
        if b == 0:
            return str(False)
        elif b == 1:
            return str(True)
        return "n/a"

    def _get_compatible_csv_operation_name(self):
        """Returns the operation name as Procmon prints it in the Operation column of the exported csv.
        """
        if self.unknown_sub_operation is not None:
            return UNKNOWN_CSV_NAME
        if self.network_protocol:
            return f"{self.network_protocol} {self.operation.csv_name}"
        return self.operation.csv_name

    def _get_compatible_csv_detail_column(self, is_utc=True):
        """Returns the detail column as a string which is compatible to Procmon's detail format in the exported csv.
        """
        if not self.details:
            return ""
        details = self.details.copy()
        operation = self.operation
        if operation is ProcessOperation.Load_Image:
            details["Image Base"] = "0x{:x}".format(details["Image Base"])
            details["Image Size"] = "0x{:x}".format(details["Image Size"])
        elif operation is ProcessOperation.Thread_Exit:
            details["User Time"] = Event._strftime_duration(details["User Time"])
            details["Kernel Time"] = Event._strftime_duration(details["Kernel Time"])
        elif operation in [
            ProcessOperation.Process_Exit,
            ProcessOperation.Process_Statistics,
            ProfilingOperation.Process_Profiling,
        ]:
            if "Exit Status" in details and details["Exit Status"] >= 0x80000000:
                details["Exit Status"] = details["Exit Status"] - 0x100000000
            if "User Time" in details:
                details["User Time"] = f"{Event._strftime_duration(details['User Time'])} seconds"
            if "Kernel Time" in details:
                details["Kernel Time"] = f"{Event._strftime_duration(details['Kernel Time'])} seconds"
            commas_formatted_keys = ["Private Bytes", "Peak Private Bytes", "Working Set", "Peak Working Set"]
            for key in commas_formatted_keys:
                if key in details:
                    details[key] = f"{details[key]:,}"
        elif operation is ProcessOperation.Process_Start:
            details["Environment"] = "\r;\t" + "\r;\t".join(details["Environment"])
        elif EventClass.Registry == self.event_class:
            commas_formatted_keys = ["Length", "SubKeys", "Values", "Index"]
            for key in commas_formatted_keys:
                if key in details:
                    details[key] = f'{details[key]:,}'

            hexa_formatted_keys = ["HandleTags", "UserFlags", "Wow64Flags"]
            for key in hexa_formatted_keys:
                if key in details:
                    details[key] = f"0x{details[key]:x}"

            removed_keys = ["TitleIndex", "MaxNameLen", "MaxValueNameLen", "MaxValueDataLen",
                            "ClassOffset", "ClassLength", "MaxClassLen"]
            for key in removed_keys:
                if key in details:
                    del details[key]
            if "LastWriteTime" in details:
                if operation is RegistryOperation.RegSetInfoKey:
                    details["LastWriteTime"] = self._strftime_date(details["LastWriteTime"], is_utc=is_utc)
                else:
                    del details["LastWriteTime"]

            if details.get("Type", '') == "REG_BINARY" and "Data" in details:
                binary_ascii = binascii.b2a_hex(details["Data"]).decode('ascii').upper()
                binary_ascii_formatted = ' '.join(binary_ascii[i:i+2] for i in range(0, len(binary_ascii), 2))
                details["Data"] = binary_ascii_formatted
            elif details.get("Type", '') == "REG_QWORD" and "Data" in details:
                details["Data"] = ''  # Procmon doesnt print qword in csv, I don't know why
            elif details.get("Type", '') == "REG_MULTI_SZ" and "Data" in details:
                details["Data"] = ', '.join(details["Data"])
            elif "Data" in details and isinstance(details["Data"], str):
                details["Data"] = "\n;".join(details["Data"].split('\r\n'))  # They add ; before a new line

            if operation is RegistryOperation.RegQueryValue and "Name" in details:
                del details["Name"]
            elif operation is RegistryOperation.RegQueryKey and details["Query"] == "Name" and "Name" in details:
                del details["Name"]
        elif self.event_class in [EventClass.File_System, EventClass.IPC]:
            commas_formatted_keys = ["AllocationSize", "Offset", "Length"]
            for key in commas_formatted_keys:
                if key in details and type(details[key]) is int:
                    details[key] = f'{details[key]:,}'

        if operation is FilesystemOperation.CreatePipe:
            for key in details:
                if type(details[key]) is int:
                    details[key] = f"0x{details[key]:x}"

        return ", ".join(f"{k}: {v}" for k, v in details.items())

    def get_compatible_csv_info(self, first_event_date_filetime=None, is_utc=True):
        """Returns data for every Procmon column in compatible format to the exported csv by procmon

        :param first_event_date_filetime: the date of the first event in the log, for the relative time column.
        :param is_utc: True if the time strings should be in UTC, False if they should be in the local timezone.
        """
        first_event_date_filetime = first_event_date_filetime if first_event_date_filetime else self.date_filetime
        record = {
            Column.DATE_AND_TIME: Event._strftime_date(self.date_filetime, True, False, is_utc),
            Column.PROCESS_NAME: self.process.process_name,
            Column.PID: str(self.process.pid),
            Column.OPERATION: self._get_compatible_csv_operation_name(),
            Column.RESULT: get_error_message(self.result),
            Column.DETAIL: self._get_compatible_csv_detail_column(is_utc),
            Column.SEQUENCE: 'n/a',  # They do it too
            Column.COMPANY: self.process.company,
            Column.DESCRIPTION: self.process.description,
            Column.COMMAND_LINE: self.process.command_line,
            Column.USER: self.process.user,
            Column.IMAGE_PATH: self.process.image_path,
            Column.SESSION: str(self.process.session),
            Column.PATH: self.path,
            Column.TID: str(self.tid),
            Column.RELATIVE_TIME: Event._strftime_relative_time(self.date_filetime - first_event_date_filetime),
            Column.DURATION:
                Event._strftime_duration(self.duration) if get_error_message(self.result) != "" else "",
            Column.TIME_OF_DAY: Event._strftime_date(self.date_filetime, False, True, is_utc),
            Column.VERSION: self.process.version,
            Column.EVENT_CLASS: self.event_class.csv_name,
            Column.AUTHENTICATION_ID:
                f"{self.process.authentication_id >> 32:08x}:{self.process.authentication_id & 0xFFFFFFFF:08x}",
            Column.VIRTUALIZED: Event._get_bool_str(self.process.virtualized),
            Column.INTEGRITY: self.process.integrity,
            Column.CATEGORY: self.category,
            Column.PARENT_PID: str(self.process.parent_pid),
            Column.ARCHITECTURE: "64-bit" if self.process.is_process_64bit else "32-bit",
            Column.COMPLETION_TIME:
                Event._strftime_date(self.date_filetime + self.duration, False, True, is_utc)
                if get_error_message(self.result) != "" else "",
        }

        compatible_record = {ColumnToOriginalName[k]: v for k, v in record.items()}
        return compatible_record


class PMLStructReader:
    @property
    def header(self):
        raise NotImplementedError()

    @property
    def events_offsets(self):
        raise NotImplementedError()

    def get_event_at_offset(self, offset):
        raise NotImplementedError()

    @property
    def number_of_events(self):
        return self.header.number_of_events

    def processes(self):
        """Return a list of all the known processes in the log file
        """
        raise NotImplementedError()

    def __iter__(self):
        for offset in self.events_offsets:
            yield self.get_event_at_offset(offset)

    def __getitem__(self, index):
        if isinstance(index, slice):
            return [self.get_event_at_offset(offset) for offset in self.events_offsets[index]]
        elif isinstance(index, int):
            return self.get_event_at_offset(self.events_offsets[index])

        raise TypeError("Bad index")

    def _get_os_name(self):
        windows_names = {
            (6, 0): "Windows Vista",
            (6, 1): "Windows 7",
            (6, 2): "Windows 8",
            (6, 3): "Windows 8.1",
            (10, 0): "Windows 10",
        }

        windows_name = windows_names[(self.header.windows_major_number, self.header.windows_minor_number)]
        if self.header.service_pack_name:
            windows_name += f", {self.header.service_pack_name}"

        return f"{windows_name} (build {self.header.windows_build_number}." \
               f"{self.header.windows_build_number_after_decimal_point})"

    def system_details(self):
        """Return the system details of the computer which captured the logs (like Tools -> System Details in Procmon)
        """
        return {
            "Computer Name": self.header.computer_name,
            "Operating System": self._get_os_name(),
            "System Root": self.header.system_root,
            "Logical Processors": self.header.number_of_logical_processors,
            "Memory (RAM)": f"{(self.header.ram_memory_size / (1024.0 ** 3)) // 0.01 / 100} GB",
            "System Type": "64-bit" if self.header.is_64bit else "32-bit"
        }
