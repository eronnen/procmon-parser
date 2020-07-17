def AsciiString(size, _io):
    raw = _io.read_bytes(size)
    return raw.decode("ascii", "replace")
