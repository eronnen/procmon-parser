"""
Definitions For the process monitor configuration file formats.
"""
from collections import OrderedDict
from io import BytesIO

from construct import Struct, Int8ul, Int16ul, Int32ul, Bytes, PaddedString, Array, Const, Switch, Tell, Adapter, \
    Rebuild, Default, Pointer, StreamError

from procmon_parser.configuration import Column, RuleAction, RuleRelation, Rule, Font
from procmon_parser.construct_helper import OriginalEnumAdapter, FixedUTF16String, FixedUTF16CString, FixedArray, \
    FixedBytes, CheckCustom

# ===============================================================================
# Procmon configuration file definitions
# ===============================================================================
RuleActionType = OriginalEnumAdapter(Int8ul, RuleAction)
RuleRelationType = OriginalEnumAdapter(Int32ul, RuleRelation)
ColumnType = OriginalEnumAdapter(Int32ul, Column)

LOGFONTW = """
see https://docs.microsoft.com/en-us/windows/win32/api/wingdi/ns-wingdi-logfontw for documentation.
""" * Struct(
    "lfHeight" / Int32ul,
    "lfWidth" / Int32ul,
    "lfEscapement" / Int32ul,
    "lfOrientation" / Int32ul,
    "lfWeight" / Int32ul,
    "lfItalic" / Int8ul,
    "lfUnderline" / Int8ul,
    "lfStrikeOut" / Int8ul,
    "lfCharSet" / Int8ul,
    "lfOutPrecision" / Int8ul,
    "lfClipPrecision" / Int8ul,
    "lfQuality" / Int8ul,
    "lfPitchAndFamily" / Int8ul,
    "lfFaceName" / PaddedString(32 * 2, "UTF_16_le"),
)


class FontStructAdapter(Adapter):
    def _decode(self, obj, context, path):
        return Font(height=obj["lfHeight"], width=obj["lfWidth"], escapement=obj["lfEscapement"],
                    orientation=obj["lfOrientation"], weight=obj["lfWeight"], italic=obj["lfItalic"],
                    underline=obj["lfUnderline"], strikeout=obj["lfStrikeOut"], char_set=obj["lfCharSet"],
                    out_precision=obj["lfOutPrecision"], clip_precision=obj["lfClipPrecision"],
                    quality=obj["lfQuality"], pitch_and_family=obj["lfPitchAndFamily"], face_name=obj["lfFaceName"])

    def _encode(self, obj, context, path):
        return {"lfHeight": obj.height, "lfWidth": obj.width, "lfEscapement": obj.escapement,
                "lfOrientation": obj.orientation, "lfWeight": obj.weight, "lfItalic": obj.italic,
                "lfUnderline": obj.underline, "lfStrikeOut": obj.strikeout, "lfCharSet": obj.char_set,
                "lfOutPrecision": obj.out_precision, "lfClipPrecision": obj.clip_precision, "lfQuality": obj.quality,
                "lfPitchAndFamily": obj.pitch_and_family, "lfFaceName": obj.face_name}


FontStruct = FontStructAdapter(LOGFONTW)


def get_rule_integer_value(column, value):
    if value.isdigit():
        return int(value)

    if column == Column.ARCHITECTURE:
        return 32 if "32" in value else 64

    return 0


RawRuleStruct = """
Struct that contains a single rule which can be applied on the process monitor events.
""" * Struct(
    "column" / ColumnType,
    "relation" / RuleRelationType,
    "action" / RuleActionType,
    "value_offset" / Tell,  # NOT IN THE REAL FORMAT - USED FOR BUILDING ONLY
    "value_length" / Default(Int32ul, 0),
    "before_value_offset" / Tell,  # NOT IN THE REAL FORMAT - USED FOR BUILDING ONLY
    "value" / FixedUTF16CString(lambda this: this.value_length, "value"),
    "after_value_offset" / Tell,  # NOT IN THE REAL FORMAT - USED FOR BUILDING ONLY
    "int_value" / Rebuild(Int32ul, lambda this: get_rule_integer_value(this.column, this.value)),
    "reserved" / Default(Int32ul, 0) * "!!Unknown field!!",

    # NOT IN THE REAL FORMAT - used to calculate value string in build time
    "value_length" / Pointer(lambda this: this.value_offset,
                             Default(Int32ul, lambda this: this.after_value_offset - this.before_value_offset))
)


class RuleStructAdapter(Adapter):
    def _decode(self, obj, context, path):
        return Rule(column=obj["column"], relation=obj["relation"], value=obj["value"], action=obj["action"])

    def _encode(self, obj, context, path):
        return {"column": obj.column, "relation": obj.relation, "action": obj.action, "value": obj.value}


RuleStruct = RuleStructAdapter(RawRuleStruct)

RawRulesStruct = """
Struct that contains a list of procmon rules.
""" * Struct(
    "reserved" / Const(1, Int8ul) * "!!Unknown field!!",
    "rules_count" / Rebuild(Int32ul, lambda this: len(this.rules)),
    "rules" / Array(lambda this: this.rules_count, RuleStruct),
)


class RulesStructAdapter(Adapter):
    def _decode(self, obj, context, path):
        return list(obj["rules"])

    def _encode(self, obj, context, path):
        return {"rules": obj}


RulesStruct = RulesStructAdapter(RawRulesStruct)
RawRecordStruct = """
Struct that contains generic procmon configuration option.
""" * Struct(
    "record_size_offset" / Tell,  # NOT IN THE REAL FORMAT - USED FOR BUILDING ONLY
    "record_size" / Default(Int32ul, 0x10),
    "record_header_size" / Const(0x10, Int32ul),
    "record_header_and_name_size_offset" / Tell,  # NOT IN THE REAL FORMAT - USED FOR BUILDING ONLY
    "record_header_and_name_size" / Default(Int32ul, 0x10),
    "data_size_offset" / Tell,  # NOT IN THE REAL FORMAT - USED FOR BUILDING ONLY
    "data_size" / Default(Int32ul, 0),
    "before_name_offset" / Tell,  # NOT IN THE REAL FORMAT - USED FOR BUILDING ONLY
    "name" / FixedUTF16CString(lambda this: this.record_header_and_name_size - this.record_header_size, "name"),
    "after_name_offset" / Tell,  # NOT IN THE REAL FORMAT - USED FOR BUILDING ONLY
    "data" / Switch(lambda this: this.name, {
        "Columns": FixedArray(lambda this: this.data_size, Int16ul),
        "ColumnCount": Int32ul,
        "ColumnMap": FixedArray(lambda this: this.data_size, ColumnType),
        "DbgHelpPath": FixedUTF16String(lambda this: this.data_size),
        "Logfile": FixedUTF16String(lambda this: this.data_size),
        "HighlightFG": Int32ul,
        "HighlightBG": Int32ul,
        "LogFont": FontStruct,
        "BoookmarkFont": FontStruct,  # they have typo in "BoookmarkFont" lol
        "AdvancedMode": Int32ul,
        "Autoscroll": Int32ul,
        "HistoryDepth": Int32ul,
        "Profiling": Int32ul,
        "DestructiveFilter": Int32ul,
        "AlwaysOnTop": Int32ul,
        "ResolveAddresses": Int32ul,
        "SourcePath": FixedUTF16CString(lambda this: this.data_size, "data"),
        "SymbolPath": FixedUTF16CString(lambda this: this.data_size, "data"),
        "FilterRules": RulesStruct,
        "HighlightRules": RulesStruct
    }, FixedBytes(lambda this: this.data_size)),
    "after_data_offset" / Tell,  # NOT IN THE REAL FORMAT - USED FOR BUILDING ONLY


    # For computing sizes only after we built the known types
    "record_header_and_name_size" / Pointer(
        lambda this: this.record_header_and_name_size_offset,
        Default(Int32ul, lambda this: this.record_header_size + this.after_name_offset - this.before_name_offset)
    ),

    "data_size" / Pointer(
        lambda this: this.data_size_offset,
        Default(Int32ul, lambda this: this.after_data_offset - this.after_name_offset)
    ),

    "record_size" / Pointer(
        lambda this: this.record_size_offset,
        Default(Int32ul, lambda this: this.record_header_and_name_size + this.data_size)
    ),

    CheckCustom(lambda this: this.record_size == this.record_header_and_name_size + this.data_size,
                RuntimeError, "Record size is not valid")
)


class RecordStructAdapter(Adapter):
    def _decode(self, obj, context, path):
        return obj["name"], obj["data"]

    def _encode(self, obj, context, path):
        return {"name": obj[0], "data": obj[1]}


Record = RecordStructAdapter(RawRecordStruct)


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
