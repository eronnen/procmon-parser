from collections import OrderedDict
from io import BytesIO
from construct import StreamError
from procmon_parser.configuration_format import Record
from procmon_parser.configuration import *

__all__ = [
    'load_configuration', 'loads_configuration', 'dump_configuration', 'dumps_configuration',
    'RuleAction', 'RuleRelation', 'Column', 'Rule', 'Font'
]


def load_configuration(stream):
    """Deserialize ``stream`` (a ``.read()``-supporting file-like object) which contains PMC formatted data,
    to a Python dictionary with the parsed configuration records.
    """
    records = []
    while True:
        try:
            name, data = Record.parse_stream(stream)
            records.append((name, data))
        except StreamError:
            break
    return OrderedDict(records)


def loads_configuration(data):
    """Deserialize ``data`` (a ``bytes`` object), which contains PMC formatted data,
    to a Python dictionary with the parsed configuration records.
    """
    stream = BytesIO(data)
    return load_configuration(stream)


def dump_configuration(records, stream):
    """Serialize ``records``, a dictionary of procmon configuration records, to ``stream`` (a
    ``.write()``-supporting file-like object that returns the length written (for python2 use the io module)),
    in the format of PMC.
    """
    for name, data in records.items():
        Record.build_stream((name, data), stream)


def dumps_configuration(records):
    """Serialize ``records``, a dictionary of procmon configuration records, to ``bytes`` in the format of PMC.
    """
    stream = BytesIO()
    dump_configuration(records, stream)
    return stream.getvalue()
