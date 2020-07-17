from .utf16_cstring import Utf16Cstring


def Utf16Multisz(_io):
    multisz = [Utf16Cstring(_io)]
    sz = Utf16Cstring(_io)
    while sz != '':
        multisz.append(sz)
        sz = Utf16Cstring(_io)
    return multisz
