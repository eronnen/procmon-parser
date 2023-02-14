#!/usr/bin/env python3
# -*- coding:utf-8 -*-
"""Module used to resolve symbolic information for a given a stack trace.
"""
import ctypes
import dataclasses
import enum
import logging
import os
import platform
import re
import sys
import winreg

import procmon_parser

if sys.platform != "win32":
    raise RuntimeError("Symbol Resolver can only be used on Windows Operating Systems.")

if sys.version_info < (3, 5, 0):
    raise RuntimeError("Symbol Resolver can only be called from python 3.5 +.")

import pathlib
import typing

from procmon_parser.symbol_resolver.win.dbghelp import (
    DbgHelp, PFINDFILEINPATHCALLBACK, SYMBOL_INFOW, IMAGEHLP_LINEW64, SYMOPT, SSRVOPT)
from procmon_parser.symbol_resolver.win.win_types import PVOID, HANDLE, DWORD64, DWORD


if typing.TYPE_CHECKING:
    from procmon_parser import ProcmonLogsReader
    from procmon_parser.logs import Event
    from procmon_parser.logs import Module

logger = logging.getLogger(__name__)


@enum.unique
class FrameType(enum.Enum):
    """Type of frame in a stack trace. Either User (the frame lies in user mode) or Kernel (the frame lies in kernel
    mode).
    """
    KERNEL = enum.auto()
    USER = enum.auto()

    @staticmethod
    def from_address(address: int, max_user_address: int) -> "FrameType":
        """Get the type of frame given an address and the maximum possible user address.

        Args:
            address: The address for which the FrameType should be obtained.
            max_user_address: The maximum possible user address.

        Returns:
            A `FrameType` which corresponds to the given address.
        """
        return FrameType.KERNEL if address > max_user_address else FrameType.USER


@dataclasses.dataclass
class StackTraceFrameInformation:
    """Contain various symbolic information about a frame in a stacktrace.
    """
    #: Type of the frame, either Kernel or User.
    frame_type: FrameType
    #: The frame number (its position in the stack trace).
    frame_number: int
    #: Address at which the frame happens.
    address: int
    #: The module inside which the frame happens.
    module: procmon_parser.Module | None = None
    #: Symbolic information about the frame.
    symbol_info: SYMBOL_INFOW | None = None
    #: The displacement in regard to the symbol.
    #: For example if the symbol name is 'foo' and the displacement is 0x10, then the frame happened at 'foo + 0x10'.
    displacement: int | None = None
    #: Line information  in regard to the symbol (available only if symbolic source information is present).
    line_info: IMAGEHLP_LINEW64 | None = None
    #: Displacement from the source code line (that is, the column in the source code line).
    line_displacement: int | None = None
    #: The source code full file path at which the frame happened.
    source_file_path: pathlib.Path | None = None

    @property
    def frame(self) -> str:
        """Return a string representation of a frame (its `FrameType` and frame number).
        """
        return f"{self.frame_type.name[0]} {self.frame_number}"

    @property
    def location(self) -> str:
        """Return a string representation of the symbolic location at which the frame happens.
        """
        if self.symbol_info is None:
            return f"{self.address:#x}"

        # symbolic information (symbol + asm offset)
        sym_str = f"{self.symbol_info.Name} + {self.displacement:#x}"
        if self.line_info is None:
            return sym_str

        # line information
        path = self.source_file_path if self.source_file_path else self.line_info.FileName
        line_str = f"{path} ({self.line_info.LineNumber}; col: {self.line_displacement})"

        return f"{sym_str}, {line_str}"

    @property
    def module_name(self) -> str:
        """Return a string representation of the frame main module name.
        """
        if not self.module.path:
            return "<unknown>"

        return pathlib.Path(self.module.path).name

    @property
    def path(self) -> str:
        """Return a string representation of the frame main module fully qualified path.
        """
        if not self.module.path:
            return "<unknown>"

        return self.module.path

    def __repr__(self) -> str:
        return f"{self.frame} {self.module_name} {self.location} {self.address:#x} {self.path}"


class StackTraceInformation:
    """Class used to prettify a whole stack trace so its output if similar to ProcMon's stack trace window tab for an
    event.
    """
    @staticmethod
    def prettify(resolved_stack_trace: list[StackTraceFrameInformation]) -> str:
        """Prettify a list of `StackTraceFrameInformation` so it's output is similar to the one given by ProcMon.

        Args:
            resolved_stack_trace: A list of stack trace frame information.

        Returns:
            A string that match closely the output of a stack trace from ProcMon.
        """
        if not resolved_stack_trace:
            return ""

        max_frame = max([len(ssi.frame) for ssi in resolved_stack_trace])
        max_module = max([len(ssi.module_name) for ssi in resolved_stack_trace])
        max_location = max([len(ssi.location) for ssi in resolved_stack_trace])
        max_address = max([len(f"{ssi.address:#x}") for ssi in resolved_stack_trace])

        output = list()
        for ssi in resolved_stack_trace:
            output.append(f"{ssi.frame:<{max_frame}} {ssi.module_name:<{max_module}} {ssi.location:<{max_location}} "
                          f"0x{ssi.address:<{max_address}x} {ssi.path}")

        return '\n'.join(output)


class SymbolResolver:
    """Main workhorse class for resolving symbolic information from a stack trace.
    """
    def __init__(self,
                 procmon_logs_reader: "ProcmonLogsReader",
                 dll_dir_path: str | pathlib.Path | None = None,
                 skip_symsrv: bool = False) -> None:
        """Class Initialisation.

        Args:
            procmon_logs_reader: An instance of the `ProcmonLogsReader` class.
            dll_dir_path: Path to a directory containing at least `dbghelp.dll`, and optionally `symsrv.dll`.
            skip_symsrv: Set to True if symbols are available locally on the machine and `_NT_SYMBOL_PATH` environment
                variable is correctly set. This skips the check for `symsrv.dll` presence altogether.

        Notes:
            If `dll_dir_path` is None, then the code does its best to find matching installations of the Debugging Tools
            for Windows (can be installed from the Windows SDK) and Windbg Preview (installed from the Windows Store).
            If neither can be found, the function raises.

        Raises:
            ValueError: The provided DLL path is not a valid directory, does not contain the required DLL(s) or the
            automatic finder could not find the required DLL.
        """
        # Check if we can find the needed DLLs if not path has been provided.
        # Both DLLs are needed to resolve symbolic information.
        # * 'dbghelp.dll' contains the functionalities to resolve symbols.
        # * 'symsrv.dll' downloads symbol from the symbol store.
        if dll_dir_path is None:
            dll_dir_path = next(
                (v for v in [DbgHelpUtils.find_debugging_tools(), DbgHelpUtils.find_windbg_preview()] if v is not None),
                None)
            if not dll_dir_path:
                raise ValueError("You need to provide a valid path to 'dbghelp.dll' and 'symsrv.dll'.")
        else:
            # just check that the given dir contains dbghelp and symsrv.
            if not dll_dir_path.is_dir():
                raise ValueError(f"The given path '{dll_dir_path}' is not a directory.")
            files_to_check = ["dbghelp.dll"]
            if not skip_symsrv:
                files_to_check.append("symsrv.dll")
            if not all((dll_dir_path / file_name).is_file() for file_name in files_to_check):
                raise ValueError(f"The given path must be a path to a directory containing: {files_to_check!r}.")
        self.dll_dir_path = dll_dir_path

        # _NT_SYMBOL_PATH is needed to store symbols locally. If it's not set, we need to set it.
        symbol_path = os.environ.get("_NT_SYMBOL_PATH", None)
        if symbol_path is None:
            # resolve TEMP folder and set it at the symbol path.
            os.environ["_NT_SYMBOL_PATH"] = f"srv*{os.environ['TEMP']}https://msdl.microsoft.com/download/symbols"
        logger.debug(f"NT_SYMBOL_PATH: {os.environ['_NT_SYMBOL_PATH']}")

        # DbgHelp wrapper instance initialisation and symbolic option setting.
        self._dbghelp = DbgHelp(self.dll_dir_path / "dbghelp.dll")
        self._dbghelp.SymSetOptions(
            SYMOPT.SYMOPT_CASE_INSENSITIVE | SYMOPT.SYMOPT_UNDNAME | SYMOPT.SYMOPT_DEFERRED_LOADS |
            SYMOPT.SYMOPT_LOAD_LINES | SYMOPT.SYMOPT_OMAP_FIND_NEAREST | SYMOPT.SYMOPT_FAIL_CRITICAL_ERRORS |
            SYMOPT.SYMOPT_INCLUDE_32BIT_MODULES | SYMOPT.SYMOPT_AUTO_PUBLICS)  # 0x12237.
        self._dbghelp_pid = 0  # TODO: get rid of it, just call SymCleanup when exiting from resolve_stack_trace()

        # maximum user-address, used to discern between user and kernel modules (which don't change between processes).
        self._max_user_address: int = procmon_logs_reader.maximum_application_address

        # Keep track of all system modules.
        for process in procmon_logs_reader.processes():
            # Can't remember if System pid has always been 4.
            # Just check its name (doesn't end with .exe) and company is MS. That should be foolproof enough.
            if process.process_name in ["System"] and process.company.lower().startswith("microsoft"):
                self.system_modules = process.modules
                break

    def __del__(self):
        # TODO: remove this if you remove self._dbghelp_pid
        if self._dbghelp_pid != 0:
            self._dbghelp.SymCleanup(self._dbghelp_pid)

    def find_module(self, event, address: int) -> procmon_parser.Module | None:
        """Try to find the corresponding module given an address from an event stack trace.

        Args:
            event: The event from which the address belongs to.
            address: The address to be resolved to its containing module.

        Returns:
            If the address lies inside a known module, the module is returned, otherwise the function returns None.
        """
        def is_kernel(addr: int) -> bool:
            """[Internal] Return whether an address is kernel (True) or not (user mode address: False)."""
            return addr > self._max_user_address

        def find_module_from_list(addr: int, modules: list['Module']) -> typing.Optional['Module']:
            """[Internal] Return an instance of a Module given an address (if the address lies inside the module).
            """
            for m in modules:
                base = m.base_address
                end = m.base_address + m.size
                if base <= addr < end:
                    return m
            return None

        # get the right modules depending on the address type.
        # kernel address: check modules in the system process.
        # user land address: check modules in the process itself.
        module_source = self.system_modules if is_kernel(address) else event.process.modules
        module = find_module_from_list(address, module_source)
        return module  # may be None.

    def resolve_stack_trace(self, event: "Event") -> typing.Iterator[StackTraceFrameInformation]:
        """Resolve the stack trace of an event to include symbolic information.

        Args:
            event: The event for which the stack trace should be resolved.

        Notes:
            The `ProcmonLogsReader` instance must be instantiated with `should_get_stacktrace` set to True (default).

        Raises:
            RuntimeError: the given event des not contain any stack trace information. Be sure to call
            `ProcmonLogsReader` with the `should_get_stacktrace` parameter set to True.

        Examples:
            ```python
            p = pathlib.Path(r"C:\temp\Logfile.PML")

            with p.open("rb") as f:
                log_reader = ProcmonLogsReader(f, should_get_stacktrace=True)
                sym_resolver = SymbolResolver(log_reader)
                for i, event in enumerate(log_reader):
                    print(f"{i:04x} {event!r}")
                    frames = list(sym_resolver.resolve_stack_trace(event))
                    print(StackTraceInformation.prettify(frames))
            ```

        Yields:
            An instance of `StackTraceFrameInformation` for each of the frame in the stack trace.
        """
        if not event.stacktrace or event.stacktrace is None:
            raise RuntimeError("Trying to resolve a stack trace while there is no stack trace.")

        # keep track of dbghelp initialization with the given process.
        pid = event.process.pid
        if self._dbghelp_pid != 0:
            # TODO: don't cleanup if it's the same pid, and the same process?
            self._dbghelp.SymCleanup(self._dbghelp_pid)
        self._dbghelp.SymInitialize(pid, None, False)
        self._dbghelp_pid = pid

        logger.debug(f"Stack Trace frames: {len(event.stacktrace)}")
        logger.debug(f"PID: {pid:#08x}")

        # Resolve each of the addresses in the stack trace, frame by frame.
        for frame_number, address in enumerate(event.stacktrace):
            frame_type = FrameType.from_address(address, self._max_user_address)
            logger.debug(f"{'-' * 79}\nStack Frame: {frame_number:04} type: {frame_type}")

            # find the module that contains the given address. It might not be found.
            logger.debug(f"Address: {address:#016x}")
            module = self.find_module(event, address)
            if not module:
                yield StackTraceFrameInformation(frame_type, frame_number, address)
                continue

            logger.debug(f"Address: {address:#016x}  --> Module: {module!r}")

            # We have the address and the module name. Get the corresponding file from the Symbol store!
            # Once we have the file, we'll be able to query the symbol for the address.
            found_file = ctypes.create_unicode_buffer(260 * 2)
            module_id = PVOID(module.timestamp)
            search_path = None  # use the default search path provided to SymInitialize.

            # We give it two tries:
            # 1. The module is an MS module, in which case it's going to be resolved pretty much automatically.
            #   1.a if it's not an MS module it's going to fail.
            # 2. If it's not an MS module, then we indicate to SymFindFileInPath where to find the binary in SearchPath.
            for j in range(2):
                ret_val = self._dbghelp.SymFindFileInPathW(
                    HANDLE(pid),  # hProcess
                    search_path,  # SearchPath
                    module.path,  # FileName (PCWSTR: it's fine to pass a python string)
                    ctypes.byref(module_id),  # id
                    module.size,  # two
                    0,  # three
                    SSRVOPT.SSRVOPT_GUIDPTR,  # flags: ProcMon uses 'SSRVOPT_GUIDPTR' but it's not a GUID??? still works
                    found_file,  # [out] FoundFile
                    PFINDFILEINPATHCALLBACK(0),  # callback (nullptr)
                    None  # context
                )
                if not ret_val:
                    last_err = ctypes.get_last_error()
                    logger.debug(f"SymFindFileInPathW failed at attempt {j} (error: {last_err:#08x}).")
                    if j == 0 and last_err == 2:  # ERROR_FILE_NOT_FOUND
                        # 1st try and file was not found: check if the directory exists. If it is, give it another try.
                        dir_path = pathlib.Path(module.path).parent
                        if dir_path.is_dir():
                            # directory exists; loop and try again.
                            search_path = str(dir_path)
                        else:
                            # the directory doesn't contain the required file on the local computer; just get out.
                            break
                    else:
                        # no more tries left or unknown error.
                        logger.error(f"SymFindFileInPathW: ({last_err:#08x}) {ctypes.FormatError(last_err)}")
                        break
                else:
                    # no error.
                    break

            if not found_file.value:
                yield StackTraceFrameInformation(frame_type, frame_number, address, module)
                continue

            logger.debug(f"Found file: {found_file.value}")

            # We have the file from the symbol store, we now 'load' the symbolic module (it does not load it inside
            # the process address space) to be able to query the symbol right after that.
            module_base = self._dbghelp.SymLoadModuleExW(
                pid,  # hProcess
                None,  # hFile
                found_file,  # ImageName
                None,  # ModuleName
                module.base_address,  # BaseOfDll
                module.size,  # DllSize
                None,  # Data (nullptr)
                0  # Flags
            )
            if module_base == 0:
                # the function return 0 (FALSE) and GetLastError will also return 0 if there was no error, but the
                # module was already loaded. This is not an error in this case.
                last_err = ctypes.get_last_error()
                if last_err != 0:  # if it's not 0, then it's really an error.
                    logger.error(f"SymLoadModuleExW: ({last_err:#08x}) {ctypes.FormatError(last_err)}")
                    yield StackTraceFrameInformation(frame_type, frame_number, address, module)
                    continue

            logger.debug(f"Module Base: {module_base:#x}")

            # Now that we have loaded the symbolic module, we query it with the address (lying inside it) to get the
            # name of the symbol and the displacement from the symbol (if any).
            displacement = DWORD64(0)
            symbol_info = SYMBOL_INFOW()
            symbol_info.MaxNameLen = SYMBOL_INFOW.BUFFER_NUM_ELEMENTS
            symbol_info.SizeOfStruct = 0x58
            ret_val = self._dbghelp.SymFromAddr(
                pid,  # hProcess
                address,  # Address of the symbol
                ctypes.byref(displacement),  # [out] displacement from the base of the symbol. e.g. 'foo + 0x10'
                ctypes.byref(symbol_info)  # [in, out] symbol information.
            )
            if ret_val == 0:
                last_err = ctypes.get_last_error()
                logger.error(f"SymFromAddr: ({last_err:#08x}) {ctypes.FormatError(last_err)}")
                yield StackTraceFrameInformation(frame_type, frame_number, address, module)
                continue

            logger.debug(f"Symbol Name: {symbol_info.Name}; Displacement: {displacement.value:#08x}")

            # In case we have source information, we need to continue to query the symbol to get source information such
            # as the source file name and the line number. This obviously fails if there are no symbolic source code
            # information.
            line_displacement = DWORD(0)
            line = IMAGEHLP_LINEW64()
            line.SizeOfStruct = ctypes.sizeof(IMAGEHLP_LINEW64)
            ret_val = self._dbghelp.SymGetLineFromAddrW64(
                pid,  # hProcess
                address,  # Address
                ctypes.byref(line_displacement),  # Displacement
                ctypes.byref(line)  # [out] Line
            )
            # The above call fails if there are no source code information. This is the default for Windows binaries.
            if ret_val == 0:
                last_err = ctypes.get_last_error()
                logger.debug(f"SymGetLineFromAddrW64 [no source line]: ({last_err:#08x}) "
                             f"{ctypes.FormatError(last_err)}")
                yield StackTraceFrameInformation(frame_type, frame_number, address, module, symbol_info,
                                                 displacement.value)
                continue

            # FIX: If you don't copy the line.FileName buffer, it gets overwritten in the next call to
            # SymGetLineFromAddrW64(). After much debugging, the solution is in fact currently written in the
            # SymGetLineFromAddrW64() documentation:
            #       This function returns a pointer to a buffer that may be reused by another function. Therefore, be
            #       sure to copy the data returned to another buffer immediately.
            # The following 2 lines just do that.
            file_name = ctypes.create_unicode_buffer(line.FileName)  # noqa
            line.FileName = ctypes.cast(file_name, ctypes.c_wchar_p)

            logger.debug(f"File Name: '{line.FileName}'; Line Number: {line.LineNumber}; "
                         f"Line Displacement (col): {line_displacement.value}")

            source_file_path_size = DWORD(260)
            source_file_path = ctypes.create_unicode_buffer(source_file_path_size.value)
            ret_val = self._dbghelp.SymGetSourceFileW(
                pid,  # hProcess
                module.base_address,  # Base
                None,  # Params (never used)
                line.FileName,  # FileSpec (name of source file) [PCWSTR]
                source_file_path,  # [out] FilePath: fully qualified path of source file
                source_file_path_size  # FilePath size (num chars)
            )
            if ret_val == 0:
                last_err = ctypes.get_last_error()
                logger.debug(f"SymGetSourceFileW: ({last_err:#08x}) {ctypes.FormatError(last_err)}")
                logger.debug(f"--> FileName: {line.FileName}")
                yield StackTraceFrameInformation(frame_type, frame_number, address, module, symbol_info,
                                                 displacement.value, line, line_displacement.value)
                continue

            logger.debug(f"source file path: {source_file_path.value}")

            yield StackTraceFrameInformation(frame_type, frame_number, address, module, symbol_info, displacement.value,
                                             line, line_displacement.value, source_file_path.value)


class DbgHelpUtils:
    """Utility functions to automatically find DbgHelp.dll and Symsrv.dll if Debugging Tools For Windows or Windbg
    preview are installed on the current system.
    """
    @staticmethod
    def find_debugging_tools() -> pathlib.Path | None:
        """Find the path of the directory containing DbgHelp.dll and Symsrv.dll from the Debugging Tools For Windows
        (installed from the Windows SDK).

        Returns:
            The path to the DLLs directory (that corresponds to the interpreter architecture) , or None if the Debugging
            Tools for Windows are not installed.
        """
        sdk_key = r"SOFTWARE\WOW6432Node\Microsoft\Windows Kits\Installed Roots"
        debugger_roots = list()
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, sdk_key) as top_key:
                _, num_values, _ = winreg.QueryInfoKey(top_key)
                for i in range(num_values):
                    value_name, _, _ = winreg.EnumValue(top_key, i)
                    if value_name.startswith("{"):  # skip GUIDs
                        continue
                    if "windowsdebuggersroot" in value_name.lower():
                        # 'WindowsDebuggerRoot' key is followed by the SDK major number, i.e. 'WindowsDebuggersRoot10'.
                        debugger_roots.append(value_name)
        except OSError:
            return None

        if not debugger_roots:
            return None

        # we have the debugger roots, we need to find the latest version. 11 > 10 > 81 > 80 > 7 ...
        versions = {}
        for debugger_root in debugger_roots:
            match = re.search(r"WindowsDebuggersRoot(\d+)", debugger_root)
            if not match:
                return None
            version = float(match.group(1))
            if version > 20.0:
                version = version / 10.0  # e.g. 81 -> 8.1
            versions.update({version: match.group(1)})

        if not versions:
            return None

        max_ver = max(versions.keys())
        max_ver_str = versions[max_ver]

        debugger_path: pathlib.Path | None = None
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, sdk_key) as top_key:
                value, value_type = winreg.QueryValueEx(top_key, f"WindowsDebuggersRoot{max_ver_str}")
                if value_type == winreg.REG_SZ:
                    debugger_path = pathlib.Path(value)
        except OSError:
            return None

        if not debugger_path or not debugger_path.is_dir():
            return None

        # we have found Windbg installation path; we need to get the correct architecture directory.
        lookup = {
            "amd64": "x64",
            "win32": "x86",
            "arm64": "arm64",
            "arm32": "arm"
        }

        return DbgHelpUtils._arch_dir(debugger_path, lookup)

    @staticmethod
    def find_windbg_preview() -> pathlib.Path | None:
        """Find the directory path of the DbgHelp.dll and Symsrv.dll from the Windbg preview installation (installed
        from the Windows Store).

        Returns:
            The path to the DLLs directory (that corresponds to the interpreter architecture), or None if Windbg Preview
            directory couldn't be found.
        """
        package_key = (r"SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel"
                       r"\Repository\Packages")

        windbg_location: pathlib.Path | None = None
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, package_key) as top_key:
                num_keys, _, _ = winreg.QueryInfoKey(top_key)
                for i in range(num_keys):
                    key_name = winreg.EnumKey(top_key, i)
                    if "microsoft.windbg" in key_name.lower():
                        # found Windbg Preview. Get its installation location.
                        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, f"{package_key}\\{key_name}") as windbg_key:
                            install_location, key_type = winreg.QueryValueEx(windbg_key, "PackageRootFolder")
                            if key_type == winreg.REG_SZ:
                                windbg_location = pathlib.Path(install_location)
                                break
        except OSError:
            return None

        if windbg_location is None or windbg_location.is_dir():
            return None

        # we have found the installation path; we need to get the correct architecture directory.
        # One of: 'x86', 'amd64' or 'arm64' (there's no 'arm32' support in Windbg Preview).
        lookup = {
            "amd64": "amd64",
            "win32": "x86",
            "arm64": "arm64",
            # note: Windbg preview doesn't support arm32.
        }

        return DbgHelpUtils._arch_dir(windbg_location, lookup)

    @staticmethod
    def _arch_dir(debugger_dir: pathlib.Path, arch_lookup: dict[str, str]) -> pathlib.Path | None:
        """[internal] Get the path to the right DLLs (depending on the architecture used by the python interpreter).

        Args:
            debugger_dir: The top level directory of the debugger (Windbg / Windbg Preview).
            arch_lookup: A dictionary which translate the system architecture to a folder name in the Windbg
                installation.

        Returns:
            The correct path to the DLLs (dbghelp & symsrv) directory. None if the directory couldn't be found.
        """
        machine = platform.machine().lower()
        bitness = arch_lookup.get(machine, None)
        if bitness is None:
            return None
        arch_dir = debugger_dir / bitness
        if not arch_dir.is_dir():
            return None

        # check that there are both 'dbghelp.dll' and 'symsrv.dll' in the given directory.
        if not all((arch_dir / file_name).is_file() for file_name in ("symsrv.dll", "dbghelp.dll")):
            return None

        return arch_dir
