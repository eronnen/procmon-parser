"""
Definitions For the process monitor configuration file formats
"""

from construct import Struct, Int8ul, Int16ul, Int32ul, Bytes, PaddedString, CString, Enum, Array, Const, Switch, \
    Tell, Adapter, FixedSized, GreedyRange, Rebuild, GreedyString, Default, If, IfThenElse, Pointer, Check
from procmon_parser.configuration import Column, RuleAction, RuleRelation, Rule, Font

__all__ = ['RuleRelationType', 'ColumnType', 'FontStruct', 'RuleStruct', 'RulesStruct', 'Record']


# ===============================================================================
# Classes for construct
# ===============================================================================
class OriginalEnumAdapter(Enum):
    """Used to decode the original enum type instead of EnumIntegerString
    """
    def __init__(self, subcon, enum_class, *arg, **kwargs):
        super(OriginalEnumAdapter, self).__init__(subcon, enum_class, *arg, **kwargs)
        self.original_enum = enum_class

    def _decode(self, obj, context, path):
        return self.original_enum[super(OriginalEnumAdapter, self)._decode(obj, context, path)]


class ListAdapter(Adapter):
    """Used to decode regular python list instead of ListContainer
    """
    def _decode(self, obj, context, path):
        return list(obj)

    def _encode(self, obj, context, path):
        return obj


def FixedUTF16String(size_func):
    """At parse time parses a UTF16 string with a known size, and at build time builds the string with its given size.
    """
    return IfThenElse(lambda ctx: ctx._parsing, PaddedString(size_func, "UTF_16_le"), GreedyString("UTF_16_le"))


def FixedUTF16CString(size_func, ctx_str_name):
    """At parse time parses a UTF16 string terminated with null byte with a known size, and at build time builds
    the string with its given size.
    If the given string is empty at build time, then build nothing instead of a single null character.
    """
    return IfThenElse(lambda ctx: ctx._parsing, PaddedString(size_func, "UTF_16_le"),
                      If(lambda ctx: ctx[ctx_str_name], CString("UTF_16_le")))


def FixedArray(size_func, subcon):
    """At parse time parses a fixed sized array, and at build time builds the array with its given size.
    """
    return ListAdapter(
        IfThenElse(lambda this: this._parsing, FixedSized(size_func, GreedyRange(subcon)), GreedyRange(subcon)))


# ===============================================================================
# Procmon configuration file definitions
# ===============================================================================
RuleActionType = OriginalEnumAdapter(Int8ul, RuleAction)
RuleRelationType = OriginalEnumAdapter(Int32ul, RuleRelation)
ColumnType = OriginalEnumAdapter(Int32ul, Column)

LOGFONTW = """
see https://docs.microsoft.com/en-us/windows/win32/api/wingdi/ns-wingdi-logfontw for documentation
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

RawRuleStruct = """
Struct that contains a single rule which can be applied on the process monitor events.
""" * Struct(
    "reserved1" / Default(Bytes(3), 0) * "!!Unknown field!!",
    "column" / ColumnType,
    "relation" / RuleRelationType,
    "action" / RuleActionType,
    "value_offset" / Tell,  # NOT IN THE REAL FORMAT - USED FOR BUILDING ONLY
    "value_length" / Default(Int32ul, 0),
    "before_value_offset" / Tell,  # NOT IN THE REAL FORMAT - USED FOR BUILDING ONLY
    "value" / FixedUTF16CString(lambda this: this.value_length, "value"),
    "after_value_offset" / Tell,  # NOT IN THE REAL FORMAT - USED FOR BUILDING ONLY
    "reserved2" / Default(Bytes(5), 0) * "!!Unknown field!!",

    # To calculate value string in build time
    "value_length" / Pointer(lambda this: this.value_offset,
                             Default(Int32ul, lambda this: this.after_value_offset - this.before_value_offset))
)


class RuleStructAdapter(Adapter):
    def _decode(self, obj, context, path):
        return Rule(column=obj["column"], relation=obj["relation"], action=obj["action"], value=obj["value"])

    def _encode(self, obj, context, path):
        return {"column": obj.column, "relation": obj.relation, "action": obj.action, "value": obj.value}


RuleStruct = RuleStructAdapter(RawRuleStruct)

RawRulesStruct = """
Struct that contains a list of procmon rules.
""" * Struct(
    "reserved1" / Const(1, Int8ul) * "!!Unknown field!!",
    "rules_count" / Rebuild(Int8ul, lambda this: len(this.rules)),
    "rules" / Array(lambda this: this.rules_count, RuleStruct),
    "reserved1" / Default(Bytes(3), 0) * "!!Unknown field!!",
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
    }),
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

    Check(lambda this: this.record_size == this.record_header_and_name_size + this.data_size)
)


class RecordStructAdapter(Adapter):
    def _decode(self, obj, context, path):
        return obj["name"], obj["data"]

    def _encode(self, obj, context, path):
        return {"name": obj[0], "data": obj[1]}


Record = RecordStructAdapter(RawRecordStruct)
