"""
Definitions For the process monitor file formats
"""

from construct import Struct, Int8ul, Int32ul, Bytes, PaddedString, Enum, Array, Const, Adapter
from procmon_parser.definitions import Column, RuleAction, RuleRelation, Rule, Font

__all__ = ['RuleRelationType', 'ColumnType', 'FontStruct', 'RuleStruct', 'RulesStruct', 'Record']

class OriginalEnumAdapter(Enum):
    def __init__(self, subcon, enum_class, *arg, **kwargs):
        super(OriginalEnumAdapter, self).__init__(subcon, enum_class, *arg, **kwargs)
        self.original_enum = enum_class

    def _decode(self, obj, context, path):
        return self.original_enum[super(OriginalEnumAdapter, self)._decode(obj, context, path)]


class ListAdapter(Adapter):
    def _decode(self, obj, context, path):
        return list(obj)


RuleActionType = OriginalEnumAdapter(Int8ul, RuleAction)
RuleRelationType = OriginalEnumAdapter(Int32ul, RuleRelation)
ColumnType = OriginalEnumAdapter(Int32ul, Column)

LOGFONTW = Struct(
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

RawRuleStruct = Struct(
    "reserved1" / Bytes(3),
    "column" / ColumnType,
    "relation" / RuleRelationType,
    "action" / RuleActionType,
    "value_length" / Int32ul,
    "value" / PaddedString(lambda this: this.value_length, "UTF_16_le"),
    "reserved2" / Bytes(5),
)


class RuleStructAdapter(Adapter):
    def _decode(self, obj, context, path):
        return Rule(column=obj["column"], relation=obj["relation"], action=obj["action"], value=obj["value"])

    def _encode(self, obj, context, path):
        return {"reserved1": 0}


RuleStruct = RuleStructAdapter(RawRuleStruct)

RawRulesStruct = Struct(
    "unknown" / Const(1, Int8ul),
    "rules_count" / Int8ul,
    "rules" / Array(lambda this: this.rules_count, RuleStruct),
)


class RulesStructAdapter(Adapter):
    def _decode(self, obj, context, path):
        return list(obj["rules"])

    def _encode(self, obj, context, path):
        return {"unknown": 1, "rules_count": len(obj), "rules": obj}


RulesStruct = RulesStructAdapter(RawRulesStruct)

RawRecordStruct = Struct(
    "record_size" / Int32ul,  # TODO: record_size == record_header_and_name_size + data_size
    "record_header_size" / Int32ul,
    "record_header_and_name_size" / Int32ul,
    "data_size" / Int32ul,
    "name" / PaddedString(lambda this: this.record_header_and_name_size - this.record_header_size, "UTF_16_le"),
    "data" / Bytes(lambda this: this.data_size),
)


class RecordStructAdapter(Adapter):
    def _decode(self, obj, context, path):
        return obj["name"], obj["data"]

    def _encode(self, obj, context, path):
        header_size = 0x10
        header_and_name_size = header_size + len(obj[0])

        return {"record_size": header_and_name_size + len(obj[1]), "record_header_size": header_size,
                "record_header_and_name_size": header_and_name_size, "data_size": len(obj[1]), "name": obj[0],
                "data": obj[1]}


Record = RecordStructAdapter(RawRecordStruct)
