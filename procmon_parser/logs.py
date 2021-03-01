"""
Python types that procmon logs use
"""

import binascii
import datetime
import enum

from six import string_types

from procmon_parser.consts import Column, EventClass, get_error_message, ProcessOperation, ColumnToOriginalName

__all__ = ['PMLError', 'Module', 'Process', 'Event', 'PMLStructReader']


EPOCH_AS_FILETIME = 116444736000000000  # January 1, 1970 as MS file time
HUNDREDS_OF_NANOSECONDS = 10000000


class PMLError(RuntimeError):
    pass


class Module(object):
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
            self.path, "0x{:x}".format(self.base_address), "0x{:x}".format(self.size))

    def __repr__(self):
        return "Module({}, {}, \"{}\", \"{}\", \"{}\", \"{}\", {})" \
            .format(self.base_address, self.size, self.path, self.version, self.company,
                    self.description, self.timestamp)

    def __hash__(self):
        return hash((self.base_address, self.size, self.path, self.timestamp))


class Process(object):
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
        return "\"{}\", {}".format(self.image_path, self.pid)

    def __repr__(self):
        return "Process({}, {}, {}, {}, {}, \"{}\", \"{}\", \"{}\", \"{}\", \"{}\", \"{}\", \"{}\", \"{}\", \"{}\")" \
            .format(self.pid, self.parent_pid, self.authentication_id, self.session, self.virtualized,
                    self.is_process_64bit, self.integrity, self.user, self.process_name, self.image_path,
                    self.command_line, self.company, self.version, self.description)

    def __hash__(self):
        return hash((self.pid, self.parent_pid, self.image_path, self.command_line, self.start_time, self.end_time))


class Event(object):
    def __init__(self, process=None, tid=0, event_class=None, operation=None, duration=0,
                 date_filetime=None, result=0, stacktrace=None, category=None, path=None, details=None):
        self.process = process
        self.tid = tid
        self.event_class = EventClass[event_class] if isinstance(event_class, string_types) else EventClass(event_class)
        self.operation = operation.name if isinstance(operation, enum.IntEnum) else operation
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
        return "Process Name={}, Pid={}, Operation={}, Path=\"{}\", Time={}".format(
            self.process.process_name, self.process.pid, self.operation, self.path,
            self._strftime_date(self.date_filetime, True, True))

    def __repr__(self):
        return "Event({}, {}, \"{}\", \"{}\", {}, {}, {}, \"{}\", \"{}\", {})" \
            .format(self.process, self.tid, self.event_class.name, self.operation, self.duration,
                    self.date_filetime, self.result, self.category, self.path, self.details)

    def __hash__(self):
        return hash((self.process.pid, self.tid, self.operation, self.date_filetime))

    def date(self, is_utc=True):
        if self.date_filetime is not None:
            from_timestamp = datetime.datetime.utcfromtimestamp if is_utc else datetime.datetime.fromtimestamp
            return from_timestamp(
                (self.date_filetime - EPOCH_AS_FILETIME) // HUNDREDS_OF_NANOSECONDS) + datetime.timedelta(
                microseconds=((self.date_filetime % HUNDREDS_OF_NANOSECONDS) // 10))
        else:
            return None

    @staticmethod
    def _strftime_date(date_filetime, show_day=True, show_nanoseconds=False):
        # Actually Procmon prints it in local time instead of UTC
        hundred_nanoseconds = (date_filetime % HUNDREDS_OF_NANOSECONDS)
        d = datetime.datetime.utcfromtimestamp((date_filetime - EPOCH_AS_FILETIME) // HUNDREDS_OF_NANOSECONDS)

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
        return "{:02d}:{:02d}:{:02d}.{:07d}".format(secs // 3600, (secs // 60) % 60, secs % 60, hundred_nanosecs)

    @staticmethod
    def _strftime_duration(duration_hundred_nanosecs):
        secs = duration_hundred_nanosecs // HUNDREDS_OF_NANOSECONDS
        hundred_nanosecs = duration_hundred_nanosecs % HUNDREDS_OF_NANOSECONDS
        return "{}.{:07d}".format(secs, hundred_nanosecs)

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
        if "<Unknown>" in self.operation:
            return "<Unknown>"
        if EventClass.Process == self.event_class:
            return self.operation.replace('_', ' ')
        return self.operation

    def _get_compatible_csv_detail_column(self):
        """Returns the detail column as a string which is compatible to Procmon's detail format in the exported csv.
        """
        if not self.details:
            return ""
        details = self.details.copy()
        if self.operation == ProcessOperation.Load_Image.name:
            details["Image Base"] = "0x{:x}".format(details["Image Base"])
            details["Image Size"] = "0x{:x}".format(details["Image Size"])
        elif self.operation == ProcessOperation.Thread_Exit.name:
            details["User Time"] = Event._strftime_duration(details["User Time"])
            details["Kernel Time"] = Event._strftime_duration(details["Kernel Time"])
        elif self.operation == ProcessOperation.Process_Start.name:
            details["Environment"] = "\n;\t" + "\n;\t".join(details["Environment"])
        elif EventClass.Registry == self.event_class:
            commas_formatted_keys = ["Length", "SubKeys", "Values", "Index"]
            for key in commas_formatted_keys:
                if key in details:
                    details[key] = '{:,}'.format(details[key])

            hexa_formatted_keys = ["HandleTags", "UserFlags", "Wow64Flags"]
            for key in hexa_formatted_keys:
                if key in details:
                    details[key] = "0x{:x}".format(details[key])

            removed_keys = ["TitleIndex", "MaxNameLen", "MaxValueNameLen", "MaxValueDataLen",
                            "ClassOffset", "ClassLength", "MaxClassLen"]
            for key in removed_keys:
                if key in details:
                    del details[key]
            if "LastWriteTime" in details:
                if self.operation == "RegSetInfoKey":
                    details["LastWriteTime"] = self._strftime_date(details["LastWriteTime"])
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
            elif "Data" in details and isinstance(details["Data"], string_types):
                details["Data"] = "\n;".join(details["Data"].split('\r\n'))  # They add ; before a new line

            if self.operation == "RegQueryValue" and "Name" in details:
                del details["Name"]
            elif self.operation == "RegQueryKey" and details["Query"] == "Name" and "Name" in details:
                del details["Name"]
        elif EventClass.File_System == self.event_class:
            commas_formatted_keys = ["AllocationSize", "Offset", "Length"]
            for key in commas_formatted_keys:
                if key in details and int == type(details[key]):
                    details[key] = '{:,}'.format(details[key])

        return ", ".join("{}: {}".format(k, v) for k, v in details.items())

    def get_compatible_csv_info(self, first_event_date_filetime=None):
        """Returns data for every Procmon column in compatible format to the exported csv by procmon
        """
        first_event_date_filetime = first_event_date_filetime if first_event_date_filetime else self.date_filetime
        record = {
            Column.DATE_AND_TIME: Event._strftime_date(self.date_filetime, True, False),
            Column.PROCESS_NAME: self.process.process_name,
            Column.PID: str(self.process.pid),
            Column.OPERATION: self._get_compatible_csv_operation_name(),
            Column.RESULT: get_error_message(self.result),
            Column.DETAIL: self._get_compatible_csv_detail_column(),
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
            Column.TIME_OF_DAY: Event._strftime_date(self.date_filetime, False, True),
            Column.VERSION: self.process.version,
            Column.EVENT_CLASS: self.event_class.name.replace('_', ' '),
            Column.AUTHENTICATION_ID:
                "{:08x}:{:08x}".format(self.process.authentication_id >> 32,
                                       self.process.authentication_id & 0xFFFFFFFF),
            Column.VIRTUALIZED: Event._get_bool_str(self.process.virtualized),
            Column.INTEGRITY: self.process.integrity,
            Column.CATEGORY: self.category,
            Column.PARENT_PID: str(self.process.parent_pid),
            Column.ARCHITECTURE: "64-bit" if self.process.is_process_64bit else "32-bit",
            Column.COMPLETION_TIME:
                Event._strftime_date(self.date_filetime + self.duration, False, True)
                if get_error_message(self.result) != "" else "",
        }

        compatible_record = {ColumnToOriginalName[k]: v for k, v in record.items()}
        return compatible_record


class PMLStructReader(object):
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
            windows_name += ", {}".format(self.header.service_pack_name)

        return "{} (build {}.{})".format(windows_name, self.header.windows_build_number,
                                         self.header.windows_build_number_after_decimal_point)

    def system_details(self):
        """Return the system details of the computer which captured the logs (like Tools -> System Details in Procmon)
        """
        return {
            "Computer Name": self.header.computer_name,
            "Operating System": self._get_os_name(),
            "System Root": self.header.system_root,
            "Logical Processors": self.header.number_of_logical_processors,
            "Memory (RAM)": "{} GB".format((self.header.ram_memory_size / (1024.0 ** 3)) // 0.01 / 100),
            "System Type": "64-bit" if self.header.is_64bit else "32-bit"
        }
