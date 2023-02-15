#!/usr/bin/env python3
# -*- coding:utf-8 -*-
"""Module wrapper around DbgHelp.dll Windows library.

DbgHelp.dll is the main library for resolving symbols.
"""
import ctypes
import logging
import pathlib
import sys
import enum

from procmon_parser.symbol_resolver.win.win_types import (
    HANDLE, PCSTR, BOOL, DWORD, PCWSTR, PVOID, PWSTR, DWORD64, ULONG, ULONG64, WCHAR, PDWORD64, PDWORD)

if sys.version_info >= (3, 5, 0):
    import typing
    if typing.TYPE_CHECKING:
        import _ctypes  # only used for typing as ctypes doesn't export inner types.

logger = logging.getLogger(__name__)

#
# Callback Functions needed by some DbgHelp APIs.
#

# PFINDFILEINPATHCALLBACK; used with the SymFindFileInPath function.
# https://learn.microsoft.com/en-us/windows/win32/api/dbghelp/nc-dbghelp-pfindfileinpathcallback
PFINDFILEINPATHCALLBACK = ctypes.WINFUNCTYPE(BOOL, PCSTR, PVOID, use_last_error=False)


#
# Structures used by DbgHelp APIs.
#


class MODLOAD_DATA(ctypes.Structure):  # noqa
    """Contains module data. Used by SymLoadModuleExW.

    See: https://learn.microsoft.com/en-us/windows/win32/api/dbghelp/ns-dbghelp-modload_data
    """
    _fields_ = (
        ("ssize", DWORD),
        ("ssig", DWORD),
        ("data", PVOID),
        ("size", DWORD),
        ("flags", DWORD),
    )


PMODLOAD_DATA = ctypes.POINTER(MODLOAD_DATA)


class SYMBOL_INFOW(ctypes.Structure):  # noqa
    """Contains symbol information. Used by SymFromAddrW.

    See: https://learn.microsoft.com/en-us/windows/win32/api/dbghelp/ns-dbghelp-symbol_infow
    """
    BUFFER_NUM_ELEMENTS = 468

    _fields_ = (
        ("SizeOfStruct", ULONG),
        ("TypeIndex", ULONG),
        ("Reserved", ULONG64 * 2),
        ("Index", ULONG),
        ("Size", ULONG),
        ("ModBase", ULONG64),
        ("Flags", ULONG),
        ("Value", ULONG64),
        ("Address", ULONG64),
        ("Register", ULONG),
        ("Scope", ULONG),
        ("Tag", ULONG),
        ("NameLen", ULONG),
        ("MaxNameLen", ULONG),
        ("Name", WCHAR * BUFFER_NUM_ELEMENTS)
    )


PSYMBOL_INFOW = ctypes.POINTER(SYMBOL_INFOW)


class IMAGEHLP_LINEW64(ctypes.Structure):  # noqa
    """Represents a source file line. Used by SymGetLineFromAddrW64.

    See: https://learn.microsoft.com/en-us/windows/win32/api/dbghelp/ns-dbghelp-imagehlp_linew64
    """
    _fields_ = (
        ("SizeOfStruct", DWORD),
        ("Key", PVOID),
        ("LineNumber", DWORD),
        ("FileName", PWSTR),
        ("Address", DWORD64)
    )


PIMAGEHLP_LINEW64 = ctypes.POINTER(IMAGEHLP_LINEW64)


#
# Functions descriptors
#

class _FunctionDescriptor(object):
    __slots__ = ["name", "parameter_types", "return_type", "aliases"]

    def __init__(self, name, parameter_types=None, return_type=None, aliases=None):
        # type: (str, tuple[_ctypes._SimpleCData] | None, _ctypes._SimpleCData | None, list[str] | None) -> None
        """Class used to describe a Windows API function wrt its ctypes bindings."""
        self.name = name
        self.parameter_types = parameter_types
        self.return_type = return_type
        self.aliases = aliases


# list of function (descriptors) from DbgHelp.dll
# type: list[_FunctionDescriptor]
_functions_descriptors = [
    # SymInitializeW
    # https://learn.microsoft.com/en-us/windows/win32/api/dbghelp/nf-dbghelp-syminitializew
    _FunctionDescriptor("SymInitializeW",
                        (HANDLE, PCSTR, BOOL),
                        BOOL,
                        ["SymInitialize"]),
    # SymCleanup
    # https://learn.microsoft.com/en-us/windows/win32/api/dbghelp/nf-dbghelp-symcleanup
    _FunctionDescriptor("SymCleanup",
                        (HANDLE,),
                        BOOL),
    # SymSetOptions
    # https://learn.microsoft.com/en-us/windows/win32/api/dbghelp/nf-dbghelp-symsetoptions
    _FunctionDescriptor("SymSetOptions",
                        (DWORD,),
                        DWORD),
    # SymSetSearchPathW
    # https://learn.microsoft.com/en-us/windows/win32/api/dbghelp/nf-dbghelp-symsetsearchpathw
    _FunctionDescriptor("SymSetSearchPathW",
                        (HANDLE, PCWSTR),
                        BOOL,
                        ["SymSetSearchPath"]),
    # SymFindFileInPathW
    # https://learn.microsoft.com/en-us/windows/win32/api/dbghelp/nf-dbghelp-symfindfileinpathw
    _FunctionDescriptor("SymFindFileInPathW",
                        (HANDLE, PCWSTR, PCWSTR, PVOID, DWORD, DWORD, DWORD, PWSTR, PFINDFILEINPATHCALLBACK, PVOID),
                        BOOL,
                        ["SymFindFileInPath"]),
    # SymLoadModuleExW
    # https://learn.microsoft.com/en-us/windows/win32/api/dbghelp/nf-dbghelp-symloadmoduleexw
    _FunctionDescriptor("SymLoadModuleExW",
                        (HANDLE, HANDLE, PCWSTR, PCWSTR, DWORD64, DWORD, PMODLOAD_DATA, DWORD),
                        DWORD64,
                        ["SymLoadModuleEx"]),

    # SymFromAddrW
    # https://learn.microsoft.com/en-us/windows/win32/api/dbghelp/nf-dbghelp-symfromaddrw
    _FunctionDescriptor("SymFromAddrW",
                        (HANDLE, DWORD64, PDWORD64, PSYMBOL_INFOW),
                        BOOL,
                        ["SymFromAddr"]),

    # SymGetLineFromAddrW64
    # https://learn.microsoft.com/en-us/windows/win32/api/dbghelp/nf-dbghelp-symgetlinefromaddrw64
    _FunctionDescriptor("SymGetLineFromAddrW64",
                        (HANDLE, DWORD64, PDWORD, PIMAGEHLP_LINEW64),
                        BOOL),

    # SymGetLinePrevW64
    # https://learn.microsoft.com/en-us/windows/win32/api/dbghelp/nf-dbghelp-symgetlineprevw64
    _FunctionDescriptor("SymGetLinePrevW64",
                        (HANDLE, PIMAGEHLP_LINEW64),
                        BOOL),

    # SymGetSourceFileW
    # https://learn.microsoft.com/en-us/windows/win32/api/dbghelp/nf-dbghelp-symgetsourcefilew
    _FunctionDescriptor("SymGetSourceFileW",
                        (HANDLE, ULONG64, PCWSTR, PCWSTR, PWSTR, DWORD),
                        BOOL,
                        ["SymGetSourceFile"]
                        ),
]


#
# Constants
#

class SYMOPT(enum.IntFlag):
    """Options that are set/returned by SymSetOptions() & SymGetOptions(); these are used as a mask.

    Notes:
        This is a made up enum since constants are just `#define` in dbghelp.h. This prevents to have to import all
        constants though.
    """
    SYMOPT_CASE_INSENSITIVE = 0x00000001
    SYMOPT_UNDNAME = 0x00000002
    SYMOPT_DEFERRED_LOADS = 0x00000004
    SYMOPT_NO_CPP = 0x00000008
    SYMOPT_LOAD_LINES = 0x00000010
    SYMOPT_OMAP_FIND_NEAREST = 0x00000020
    SYMOPT_LOAD_ANYTHING = 0x00000040
    SYMOPT_IGNORE_CVREC = 0x00000080
    SYMOPT_NO_UNQUALIFIED_LOADS = 0x00000100
    SYMOPT_FAIL_CRITICAL_ERRORS = 0x00000200
    SYMOPT_EXACT_SYMBOLS = 0x00000400
    SYMOPT_ALLOW_ABSOLUTE_SYMBOLS = 0x00000800
    SYMOPT_IGNORE_NT_SYMPATH = 0x00001000
    SYMOPT_INCLUDE_32BIT_MODULES = 0x00002000
    SYMOPT_PUBLICS_ONLY = 0x00004000
    SYMOPT_NO_PUBLICS = 0x00008000
    SYMOPT_AUTO_PUBLICS = 0x00010000
    SYMOPT_NO_IMAGE_SEARCH = 0x00020000
    SYMOPT_SECURE = 0x00040000
    SYMOPT_NO_PROMPTS = 0x00080000
    SYMOPT_OVERWRITE = 0x00100000
    SYMOPT_IGNORE_IMAGEDIR = 0x00200000
    SYMOPT_FLAT_DIRECTORY = 0x00400000
    SYMOPT_FAVOR_COMPRESSED = 0x00800000
    SYMOPT_ALLOW_ZERO_ADDRESS = 0x01000000
    SYMOPT_DISABLE_SYMSRV_AUTODETECT = 0x02000000
    SYMOPT_READONLY_CACHE = 0x04000000
    SYMOPT_SYMPATH_LAST = 0x08000000
    SYMOPT_DISABLE_FAST_SYMBOLS = 0x10000000
    SYMOPT_DISABLE_SYMSRV_TIMEOUT = 0x20000000
    SYMOPT_DISABLE_SRVSTAR_ON_STARTUP = 0x40000000
    SYMOPT_DEBUG = 0x80000000


class SSRVOPT(enum.IntFlag):
    """Symbol Server Options; used by functions such as SymFindFileInPathW.

    Notes:
        This is a made up enum since constants are just `#define` in dbghelp.h. This prevents to have to import all
        constants though.
    """
    SSRVOPT_CALLBACK = 0x00000001
    SSRVOPT_DWORD = 0x00000002
    SSRVOPT_DWORDPTR = 0x00000004
    SSRVOPT_GUIDPTR = 0x00000008
    SSRVOPT_OLDGUIDPTR = 0x00000010
    SSRVOPT_UNATTENDED = 0x00000020
    SSRVOPT_NOCOPY = 0x00000040
    SSRVOPT_GETPATH = 0x00000040
    SSRVOPT_PARENTWIN = 0x00000080
    SSRVOPT_PARAMTYPE = 0x00000100
    SSRVOPT_SECURE = 0x00000200
    SSRVOPT_TRACE = 0x00000400
    SSRVOPT_SETCONTEXT = 0x00000800
    SSRVOPT_PROXY = 0x00001000
    SSRVOPT_DOWNSTREAM_STORE = 0x00002000
    SSRVOPT_OVERWRITE = 0x00004000
    SSRVOPT_RESETTOU = 0x00008000
    SSRVOPT_CALLBACKW = 0x00010000
    SSRVOPT_FLAT_DEFAULT_STORE = 0x00020000
    SSRVOPT_PROXYW = 0x00040000
    SSRVOPT_MESSAGE = 0x00080000
    SSRVOPT_SERVICE = 0x00100000  # deprecated
    SSRVOPT_FAVOR_COMPRESSED = 0x00200000
    SSRVOPT_STRING = 0x00400000
    SSRVOPT_WINHTTP = 0x00800000
    SSRVOPT_WININET = 0x01000000
    SSRVOPT_DONT_UNCOMPRESS = 0x02000000
    SSRVOPT_DISABLE_PING_HOST = 0x04000000
    SSRVOPT_DISABLE_TIMEOUT = 0x08000000
    SSRVOPT_ENABLE_COMM_MSG = 0x10000000


class DbgHelp:
    """Main wrapper around DbgHelp.dll library functions.

    Examples:
        ```
        # functions can be called as attributes from the class instance, as long as they have a function descriptor.
        ret_val = DbgHelp.SymInitialize(0xdeadbeef, None, False)
        if ret_val == 0:
            # log error
            pass
        ```
    """

    def __init__(self, dbghelp_path):
        # type: (pathlib.Path) -> None
        """Class init.

        Args:
            dbghelp_path: Path to the dbghelp.dll library.
        """
        if not dbghelp_path.is_file():
            raise ValueError(f"The given path '{dbghelp_path}' is not a file.")

        self._dll_path = dbghelp_path

        # Dictionary of functions; key is str (function name), value is ctypes function pointer.
        self._functions: dict[str: _ctypes.CFuncPtr] = dict()

        # DLL instance
        self._dbghelp = ctypes.WinDLL(str(dbghelp_path), use_last_error=True)

        # resolve all needed functions.
        self._resolve_functions(_functions_descriptors)

    def __getitem__(self, item: str):
        return self._functions[item]

    def __getattr__(self, item: str):
        return self[item]

    def _resolve_functions(self, function_descriptors):
        # type: (list[_FunctionDescriptor]) -> None
        """[internal] Resolve functions, for the given DLL, from the list of `_FunctionsDescriptor`.

        Raises:
            AttributeError: A given function was not found.
        """
        for function_descriptor in function_descriptors:
            self._register_function(function_descriptor)

    def _register_function(self, function_descriptor) -> None:
        # type: (_FunctionDescriptor) -> None
        """[internal] Build a function ctypes wrapping from its function descriptor.

        Args:
            function_descriptor: An instance of a _FunctionDescriptor that describes a function ctypes wrapping.

        Raises:
            AttributeError: A given function was not found.
        """
        try:
            function_pointer = getattr(self._dbghelp, function_descriptor.name)
        except AttributeError:
            # We land here if the function can't be found in the given DLL.
            # note: it raises from quite deep inside ctypes if the function can't be resolved, which might be confusing.
            # Log it now and re-raise.
            logger.error(f"The function {function_descriptor.name} was not found in the DLL: '{self._dll_path!r}'.")
            raise
        if function_descriptor.parameter_types:
            function_pointer.argtypes = function_descriptor.parameter_types
        if function_descriptor.return_type:
            function_pointer.restype = function_descriptor.return_type
        self._functions.update({function_descriptor.name: function_pointer})
        if function_descriptor.aliases:
            for alias in function_descriptor.aliases:
                self._functions.update({alias: function_pointer})
