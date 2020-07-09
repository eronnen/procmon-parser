from procmon_parser.configuration_format import ProcmonConfiguration

__all__ = [
    'load_configuration', 'loads_configuration', 'dump_configuration', 'dumps_configuration'
]


def load_configuration(stream):
    """Deserialize ``stream`` (a ``.write()``-supporting file-like object) which contains PMC formatted data,
    to a Python dictionary with the parsed configuration records.
    """
    return ProcmonConfiguration.parse_stream(stream)


def loads_configuration(data):
    """Deserialize ``data`` (a ``bytes`` object), which contains PMC formatted data,
    to a Python dictionary with the parsed configuration records.
    """
    return ProcmonConfiguration.parse(data)


def dump_configuration(records, stream):
    """Serialize ``records``, a dictionary of procmon configuration records, to ``stream`` (a
    ``.write()``-supporting file-like object), in the format of PMC.
    """
    return ProcmonConfiguration.build_stream(records, stream)


def dumps_configuration(records):
    """Serialize ``records``, a dictionary of procmon configuration records, to ``bytes`` in the format of PMC.
    """
    return ProcmonConfiguration.build(records)
