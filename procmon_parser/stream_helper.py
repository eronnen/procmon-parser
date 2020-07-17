import struct

from numpy import datetime64, timedelta64

packer_u8 = struct.Struct('B')
packer_u16 = struct.Struct('<H')
packer_u32 = struct.Struct('<I')
packer_u64 = struct.Struct('<Q')


def read_u8(io):
    return packer_u8.unpack(io.read(1))[0]


def read_u16(io):
    return packer_u16.unpack(io.read(2))[0]


def read_u32(io):
    return packer_u32.unpack(io.read(4))[0]


def read_u64(io):
    return packer_u64.unpack(io.read(8))[0]


def read_pvoid(io, is_64bit):
    return packer_u64.unpack(io.read(8))[0] if is_64bit else packer_u32.unpack(io.read(4))[0]


def sizeof_pvoid(is_64bit):
    return 8 if is_64bit else 4


def read_utf16(io, size=-1):
    raw = b""
    i = 0
    while size == -1 or i < size:
        wchar = io.read(2)
        i += 2
        if wchar == b"" or wchar == b"\x00\x00":
            break
        raw += wchar
    if i < size:
        io.seek(size - i, 1)

    return raw.decode("UTF-16le", "replace")


def read_utf16_multisz(io, size=-1):
    i = 0
    multisz = []
    current = b""
    is_word_done = False
    while size == -1 or i < size:
        wchar = io.read(2)
        i += 2
        if wchar == b"" or wchar == b"\x00\x00":
            if is_word_done:
                break
            is_word_done = True
            multisz.append(current.decode("UTF-16le", "replace"))
            current = b""
        else:
            is_word_done = False
            current += wchar
    if current:
        multisz.append(current.decode("UTF-16le", "replace"))

    if i < size:
        io.seek(size - i, 1)

    return multisz


def read_filetime(io):
    return filetime_to_datetime64(packer_u64.unpack(io.read(8))[0])


def read_duration(io):
    return duration_from_100nanosecs(packer_u64.unpack(io.read(8))[0])


def filetime_to_datetime64(ft):
    """Convert filetime unsigned 64 bit value to a numpy.datetime64 type.
    """
    if 0 == ft:
        return None
    secs = int(ft // int(1e7))
    nanosecs = int(ft - int(secs * int(1e7))) * 100
    # I use numpy's datetime64 instead of datetime.datetime because filetime have 100 nanoseconds precision.
    return datetime64('1601-01-01') + timedelta64(secs, 's') + timedelta64(nanosecs, 'ns')


def duration_from_100nanosecs(n):
    """Convert 100 nano seconds unsigned 64 bit value to a numpy.timedelta64 type.
    """
    secs = n // (10 ** 7)
    nanosecs = (n - secs * (10 ** 7)) * 100
    return timedelta64(secs, 's') + timedelta64(nanosecs, 'ns')
