def Utf16Cstring(_io):
    raw = b""
    wchar = _io.read_bytes(2)
    while wchar != b"\x00\x00":
        raw += wchar
        wchar = _io.read_bytes(2)
    return raw.decode("UTF-16le", "replace")
