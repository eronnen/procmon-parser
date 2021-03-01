from six import PY2

from procmon_parser.configuration import *
from procmon_parser.configuration_format import load_configuration, loads_configuration, dump_configuration, \
    dumps_configuration
from procmon_parser.logs import *
from procmon_parser.stream_logs_format import PMLStreamReader

__all__ = [
    'ProcmonLogsReader', 'load_configuration', 'loads_configuration', 'dump_configuration', 'dumps_configuration',
    'Rule', 'Column', 'RuleAction', 'RuleRelation', 'PMLError'
]


class ProcmonLogsReader(object):
    """Reads procmon logs from a stream which in the PML format
    """

    def __init__(self, f, should_get_stacktrace=True, should_get_details=True):
        """Build a ProcmonLogsReader object from ``f`` (a `.read()``-supporting file-like object).
        :param f: ``read`` supporting file-like object
        :param should_get_stacktrace: True if the parser should parse the stack traces
        :param should_get_details: True if the parser should parse the Detail column information of the event.
        """
        self._struct_readear = PMLStreamReader(f, should_get_stacktrace, should_get_details)
        self._current_event_index = 0

    def __iter__(self):
        return self

    def __next__(self):
        if self._current_event_index >= self.__len__():
            raise StopIteration
        current_index = self._current_event_index
        self._current_event_index += 1
        return self[current_index]

    if PY2:
        next = __next__

    def __getitem__(self, index):
        return self._struct_readear[index]

    def __len__(self):
        return self._struct_readear.number_of_events

    def processes(self):
        """Return a list of all the known processes in the log file
        """
        return self._struct_readear.processes()

    def system_details(self):
        """Return the system details of the computer which captured the logs (like Tools -> System Details in Procmon)
        """
        return self._struct_readear.system_details()


def read_all_events_from_pml(file):
    """
    Helper function that reads all the events from a PML file.
    :param file: the path to the PML file or an open file object.
    :return: a list of Event objects from the file.
    """
    if not hasattr(file, 'read'):
        with open(file, "rb") as f:
            pml_reader = PMLStreamReader(f)
            return list(pml_reader)
    else:
        pml_reader = PMLStreamReader(file)
        return list(pml_reader)
