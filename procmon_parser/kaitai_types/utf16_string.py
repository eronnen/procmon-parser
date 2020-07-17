def Utf16String(size, _io):
    raw = b""
    i = 0
    while i < size:
        wchar = _io.read_bytes(2)
        i += 2
        if wchar == b"\x00\x00":
            break
        raw += wchar

    if i < size:
        _io.read_bytes(size - i)

    return raw.decode("UTF-16le", "replace")
