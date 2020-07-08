from io import BytesIO
from construct import Array, Int16ul, Int32ul, PaddedString, GreedyRange, Adapter
from procmon_parser.format_definitions import ListAdapter, ColumnType, FontStruct, RulesStruct, Record

__all__ = [
    'load_configuration', 'loads_configuration'
]


ConfigRecordDecodeTypes = {
    "Columns": lambda length: ListAdapter(Array(length // Int16ul.sizeof(), Int16ul)),
    "ColumnCount": lambda length: Int32ul,
    "ColumnMap": lambda length: ListAdapter(Array(length // ColumnType.sizeof(), ColumnType)),
    "DbgHelpPath": lambda length: PaddedString(length, "UTF_16_le"),
    "Logfile": lambda length: PaddedString(length, "UTF_16_le"),
    "HighlightFG": lambda length: Int32ul,
    "HighlightBG": lambda length: Int32ul,
    "LogFont": lambda length: FontStruct,
    "BoookmarkFont": lambda length: FontStruct,  # they have typo in "BoookmarkFont"
    "AdvancedMode": lambda length: Int32ul,
    "Autoscroll": lambda length: Int32ul,
    "HistoryDepth": lambda length: Int32ul,
    "Profiling": lambda length: Int32ul,
    "DestructiveFilter": lambda length: Int32ul,
    "AlwaysOnTop": lambda length: Int32ul,
    "ResolveAddresses": lambda length: Int32ul,
    "SourcePath": lambda length: PaddedString(length, "UTF_16_le"),
    "SymbolPath": lambda length: PaddedString(length, "UTF_16_le"),
    "FilterRules": lambda length: RulesStruct,
    "HighlightRules": lambda length: RulesStruct,
}


def load_configuration(stream):
    generic_records = GreedyRange(Record).parse_stream(stream)
    records = {}
    for config_name, config_data in generic_records:
        records[config_name] = ConfigRecordDecodeTypes[config_name](len(config_data)).parse(config_data)
    return records


def loads_configuration(data):
    return load_configuration(BytesIO(data))
