import datetime
from construct import Enum, Adapter, IfThenElse, PaddedString, CString, GreedyString, FixedSized, GreedyRange, Bytes, \
    GreedyBytes, If, Struct, Int32ul, Int64ul


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


def FixedBytes(size_func):
    """At parse time parses a fixed sized byte array, and at build time builds the byte array with its given size.
    """
    return IfThenElse(lambda this: this._parsing, Bytes(size_func), GreedyBytes)


FixedNullTerminatedUTF16String = Struct(  # I don't use PascalString because it's a null terminated string.
   "string_size" / Int32ul,
   "string" / PaddedString(lambda this: this.string_size, "UTF_16_le")
)


class FiletimeAdapter(Adapter):
    def _decode(self, obj, context, path):
        return datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=obj / 10)

    def _encode(self, obj, context, path):
        return int((obj - datetime.datetime(1601, 1, 1)).total_seconds() * (10 ** 7))


Filetime = FiletimeAdapter(Int64ul)
