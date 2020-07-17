def SizedUtf16Multisz(size, _io):
    i = 0
    strings = []
    current = b""
    is_word_done = False
    while i < size:
        wchar = _io.read_bytes(2)
        i += 2
        if wchar == b"\x00\x00":
            if is_word_done:
                break
            is_word_done = True
            strings.append(current.decode("UTF-16le", "replace"))
            current = b""
        else:
            is_word_done = False
            current += wchar
    if current:
        strings.append(current.decode("UTF-16le", "replace"))

    if i < size:
        _io.read_bytes(size - i)

    return strings

