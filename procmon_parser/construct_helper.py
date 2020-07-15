from numpy import datetime64, timedelta64, uint64
from construct import Enum, Adapter, IfThenElse, PaddedString, CString, GreedyString, FixedSized, GreedyRange, Bytes, \
    GreedyBytes, If, Struct, Int32ul, Int64ul, Check, CheckError, RepeatUntil, ExprAdapter, NullTerminated, Computed, \
    NullStripped


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


class UTF16EncodedBestEffort(Adapter):
    def _decode(self, obj, context, path):
        return obj.decode("UTF-16le", "replace")

    def _encode(self, obj, context, path):
        if obj == u"":
            return b""
        return obj.encode("UTF-16le", "replace")


def PaddedUTF16StringBestEffort(length):
    return UTF16EncodedBestEffort(FixedSized(length, NullStripped(GreedyBytes, pad="\x00\x00")))


FixedNullTerminatedUTF16String = Struct(  # I don't use PascalString because it's a null terminated string.
   "string_size" / Int32ul,
   "string" / IfThenElse(
       lambda this: this.string_size,
       FixedSized(lambda this: this.string_size, NullTerminated(GreedyString("UTF_16_le"),
                                                                term="\x00".encode("utf-16le"))),
       Computed(''))
)


class FiletimeAdapter(Adapter):
    def _decode(self, obj, context, path):
        if 0 == obj:
            return None  # 0 is not really a date
        secs = int(obj // int(1e7))
        nanosecs = int(obj - int(secs * int(1e7))) * 100

        # I use numpy's datetime64 instead of datetime.datetime because filetime have 100 nanoseconds precision.
        return datetime64('1601-01-01') + timedelta64(secs, 's') + timedelta64(nanosecs, 'ns')

    def _encode(self, obj, context, path):
        return int(uint64((obj - datetime64('1601-01-01')).astype('O'))) // 100


Filetime = FiletimeAdapter(Int64ul)


class DurationAdapter(Adapter):
    def _decode(self, obj, context, path):
        secs = obj // (10 ** 7)
        nanosecs = (obj - secs * (10 ** 7)) * 100
        return timedelta64(secs, 's') + timedelta64(nanosecs, 'ns')

    def _encode(self, obj, context, path):
        return int(uint64(obj.astype('O')))


Duration = DurationAdapter(Int64ul)
PVoid = IfThenElse(lambda ctx: ctx.is_64bit, Int64ul, Int32ul)


UTF16MultiSz = ExprAdapter(
    RepeatUntil(lambda x, lst, ctx: not x, CString("UTF_16_le")),
    lambda obj, ctx: list(obj[:-1]),  # last element is the null
    lambda obj, ctx: obj + ['']
)


def SizedUTF16MultiSz(size_func):
    return ExprAdapter(
        FixedSized(size_func, GreedyRange(CString("UTF_16_le"))),
        lambda obj, ctx: list(obj),  # last element is already removed by GreedyRange
        lambda obj, ctx: obj + ['']
    )


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
