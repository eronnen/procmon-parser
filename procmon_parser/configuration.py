from procmon_parser.format_definitions import ProcmonConfigurationStruct

__all__ = [
    'load_configuration', 'loads_configuration'
]


def load_configuration(stream):
    return ProcmonConfigurationStruct.parse_stream(stream)


def loads_configuration(data):
    return ProcmonConfigurationStruct.parse(data)


def dump_configuration(obj, stream):
    return ProcmonConfigurationStruct.build_stream(obj, stream)


def dumps_configuration(obj):
    return ProcmonConfigurationStruct.build(obj)
