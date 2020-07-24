import struct

unpacker_u8 = struct.Struct('B').unpack
unpacker_u16 = struct.Struct('<H').unpack
unpacker_u32 = struct.Struct('<I').unpack
unpacker_u64 = struct.Struct('<Q').unpack
unpacker_s64 = struct.Struct('<q').unpack


def read_u8(io):
    return unpacker_u8(io.read(1))[0]


def read_u16(io):
    return unpacker_u16(io.read(2))[0]


def read_u32(io):
    return unpacker_u32(io.read(4))[0]


def read_u64(io):
    return unpacker_u64(io.read(8))[0]


def read_s64(io):
    return unpacker_s64(io.read(8))[0]


def get_pvoid_size(is_64bit):
    return 8 if is_64bit else 4


def get_pvoid_reader(is_64bit):
    return read_u64 if is_64bit else read_u32


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
    return unpacker_u64(io.read(8))[0]


def read_duration(io):
    return unpacker_u64(io.read(8))[0]
