from construct import Enum, Adapter, IfThenElse, PaddedString, CString, GreedyString, FixedSized, GreedyRange, Bytes, \
    GreedyBytes, If, Check, CheckError
from six import text_type, string_types


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


class UnicodeStringAdapter(Adapter):
    def _decode(self, obj, context, path):
        return obj

    def _encode(self, obj, context, path):
        if not isinstance(obj, string_types):
            raise TypeError("Expected string, got {}".format(type(obj)))
        return text_type(obj)


def FixedUTF16String(size_func):
    """At parse time parses a UTF16 string with a known size, and at build time builds the string with its given size.
    """
    return UnicodeStringAdapter(
        IfThenElse(lambda ctx: ctx._parsing, PaddedString(size_func, "UTF_16_le"), GreedyString("UTF_16_le"))
    )


def FixedUTF16CString(size_func, ctx_str_name):
    """At parse time parses a UTF16 string terminated with null byte with a known size, and at build time builds
    the string with its given size.
    If the given string is empty at build time, then build nothing instead of a single null character.
    """
    return UnicodeStringAdapter(
        IfThenElse(lambda ctx: ctx._parsing, PaddedString(size_func, "UTF_16_le"),
                   If(lambda ctx: ctx[ctx_str_name], CString("UTF_16_le")))
    )


def FixedArray(size_func, subcon):
    """At parse time parses a fixed sized array, and at build time builds the array with its given size.
    """
    return ListAdapter(
        IfThenElse(lambda this: this._parsing, FixedSized(size_func, GreedyRange(subcon)), GreedyRange(subcon)))


def FixedBytes(size_func):
    """At parse time parses a fixed sized byte array, and at build time builds the byte array with its given size.
    """
    return IfThenElse(lambda this: this._parsing, Bytes(size_func), GreedyBytes)


class CheckCustom(Check):
    def __init__(self, func, exc_type, msg):
        super(CheckCustom, self).__init__(func)
        self.exc_type = exc_type
        self.msg = msg

    def _build(self, obj, stream, context, path):
        try:
            super(CheckCustom, self)._build(obj, stream, context, path)
        except CheckError:
            raise self.exc_type(self.msg)

    def _parse(self, stream, context, path):
        try:
            super(CheckCustom, self)._parse(stream, context, path)
        except CheckError:
            raise self.exc_type(self.msg)
