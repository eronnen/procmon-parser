"""
Python types that procmon logs use
"""

import datetime
from six import string_types
from numpy import timedelta64
from procmon_parser.consts import Column, EventClass, get_error_message, ProcessOperation


__all__ = ['Module', 'Process', 'Event']


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
        return "\"{}\", address={}, size={}".format(self.path, hex(self.base_address), hex(self.size))

    def __repr__(self):
        return "Module({}, {}, \"{}\", \"{}\", \"{}\", \"{}\", {})" \
            .format(self.base_address, self.size, self.path, self.version, self.company,
                    self.description, self.timestamp)


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
        return "Process({}, {}, {}, {}, {}, \"{}\", \"{}\", \"{}\", \"{}\", \"{}\", \"{}\", \"{}\", \"{}\", \"{}\")"\
            .format(self.pid, self.parent_pid, self.authentication_id, self.session, self.virtualized,
                    self.is_process_64bit, self.integrity, self.user, self.process_name, self.image_path,
                    self.command_line, self.company, self.version, self.description)


class Event(object):
    def __init__(self, process=None, tid=0, event_class=None, operation=None, duration=timedelta64(0, 'ns'), date=None,
                 result=0, stacktrace=None, category=None, path=None, details=None, file_offset=0):
        self.process = process
        self.tid = tid
        self.event_class = EventClass[event_class] if isinstance(event_class, string_types) else EventClass(event_class)
        self.operation = operation
        self.date = date
        self.result = result
        self.duration = duration
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
    def _strftime_date(date, show_day=True, show_nanoseconds=False):
        nanoseconds = int(date.astype('O') % int(1e9))
        d = datetime.datetime.utcfromtimestamp(date.astype('O') / int(1e9))  # Procmon prints it in local time actually

        if show_nanoseconds:
            time_of_day = d.strftime("%I:%M:%S.{:07d} %p").lstrip('0').format(nanoseconds // 100)
        else:
            time_of_day = d.strftime("%I:%M:%S %p").lstrip('0')

        if not show_day:
            return time_of_day
        day = d.strftime("%m/%d/%Y ").lstrip('0').replace('/0', '/')
        return day + time_of_day

    @staticmethod
    def _strftime_relative_time(delta_nanosecs):
        secs = int(delta_nanosecs // int(1e9))
        nanosecs = int(delta_nanosecs % int(1e9))
        return "{:02d}:{:02d}:{:02d}.{:07d}".format(secs // 3600, (secs // 60) % 60, secs % 60, nanosecs // 100)

    @staticmethod
    def _strftime_duration(duration):
        duration_nanosecs = duration.astype('O')
        secs = int(duration_nanosecs // int(1e9))
        nanosecs = int(duration_nanosecs % int(1e9))
        return "{}.{:07d}".format(secs, nanosecs // 100)

    @staticmethod
    def _get_bool_str(b):
        if isinstance(b, bool):
            return str(b)
        if b == 0:
            return str(False)
        elif b == 1:
            return str(True)
        return "n/a"

    def _get_compatible_csv_detail_column(self):
        """Returns the detail column as a string which is compatible to Procmon's detail format in the exported csv.
        """
        if not self.details:
            return ""
        details = self.details
        if self.operation == ProcessOperation.Load_Image.name:
            details["Image Base"] = hex(details["Image Base"])
            details["Image Size"] = hex(details["Image Size"])
        elif self.operation == ProcessOperation.Thread_Exit.name:
            details["User Time"] = Event._strftime_duration(details["User Time"])
            details["Kernel Time"] = Event._strftime_duration(details["Kernel Time"])
        elif self.operation == ProcessOperation.Process_Start.name:
            details["Environment"] = "\n;\t" + "\n;\t".join(details["Environment"])
        return ", ".join("{}: {}".format(k, v) for k, v in details.items())

    def get_compatible_csv_info(self, first_event_date=None):
        """Returns data for every Procmon column in compatible format to the exported csv by procmon
        """
        first_event_date = first_event_date if first_event_date else self.date
        return {
            Column.DATE_AND_TIME: Event._strftime_date(self.date, True, False),
            Column.PROCESS_NAME: self.process.process_name,
            Column.PID: str(self.process.pid),
            Column.OPERATION: self.operation.replace('_', ' '),
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
            Column.RELATIVE_TIME: Event._strftime_relative_time((self.date - first_event_date).astype('O')),
            Column.DURATION:
                Event._strftime_duration(self.duration) if get_error_message(self.result) != "" else "",
            Column.TIME_OF_DAY: Event._strftime_date(self.date, False, True),
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
                Event._strftime_date(self.date + self.duration, False, True)
                if get_error_message(self.result) != "" else "",
        }
