#!/usr/bin/env python3
# -*- coding:utf-8 -*-
"""Module used to resolve symbolic information for a given a stack trace.
"""
import ctypes
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

if sys.version_info >= (3, 5, 0):
    import typing
    import pathlib  # TODO: to be converted to py 2.7 equivalent.

from procmon_parser.symbol_resolver.win.dbghelp import (
    DbgHelp, PFINDFILEINPATHCALLBACK, SYMBOL_INFOW, IMAGEHLP_LINEW64, SYMOPT, SSRVOPT, PSYMBOL_REGISTERED_CALLBACK64,
    CBA, PIMAGEHLP_CBA_EVENTW)
from procmon_parser.symbol_resolver.win.win_types import PVOID, HANDLE, DWORD64, DWORD, ULONG, ULONG64, BOOL

logger = logging.getLogger(__name__)

# Maximum (default) Windows path length.
MAX_PATH = 260
# Windows standard error code.
ERROR_FILE_NOT_FOUND = 2


@enum.unique
class FrameType(enum.Enum):
    """Type of frame in a stack trace. Either User (the frame lies in user mode) or Kernel (the frame lies in kernel
    mode).
    """
    KERNEL = enum.auto()
    USER = enum.auto()

    @staticmethod
    def from_address(address, max_user_address):
        # type: (int, int) -> "FrameType"
        """Get the type of frame given an address and the maximum possible user address.

        Args:
            address: The address for which the FrameType should be obtained.
            max_user_address: The maximum possible user address.

        Returns:
            A `FrameType` which corresponds to the given address.
        """
        return FrameType.KERNEL if address > max_user_address else FrameType.USER


class StackTraceFrameInformation(object):
    def __init__(self,
                 frame_type,  # type: FrameType
                 frame_number,  # type: int
                 address,  # type: int
                 module=None,  # type: procmon_parser.Module | None
                 symbol_info=None,  # type: SYMBOL_INFOW | None
                 displacement=None,  # type: int | None
                 line_info=None,  # type: IMAGEHLP_LINEW64 | None
                 line_displacement=None,  # type: int | None
                 source_file_path=None  # type: str | None
                 ):
        # type: (...) -> None
        """Contain various symbolic information about a frame in a stacktrace.
        """
        # Type of the frame, either Kernel or User.
        self.frame_type = frame_type
        # The frame number (its position in the stack trace).
        self.frame_number = frame_number
        # Address of the symbol, at which the frame happens.
        self.address = address
        # The module inside which the frame happens.
        self.module = module
        # Symbolic information about the frame.
        self.symbol_info = symbol_info
        # The displacement in regard to the symbol.
        # For example if the symbol name is 'foo' and the displacement is 0x10, then the frame happened at 'foo + 0x10'.
        self.displacement = displacement
        #  Line information in regard to the symbol (available only if symbolic source information is present).
        self.line_info = line_info
        # Displacement from the source code line (that is, the column in the source code line).
        self.line_displacement = line_displacement
        # The source code full file path at which the frame happened.
        self.source_file_path = source_file_path

    @property
    def frame(self):
        # type: () -> str
        """Return a string representation of a frame (its `FrameType` and frame number).
        """
        return "{frame_type.name[0]} {frame_number}".format(
            frame_type=self.frame_type, frame_number=self.frame_number)

    @property
    def location(self):
        # type: () -> str
        """Return a string representation of the symbolic location at which the frame happens.
        """
        if self.symbol_info is None:
            return "{address:#x}".format(address=self.address)

        # symbolic information (symbol + asm offset)
        sym_str = "{symbol_info.Name} + {displacement:#x}".format(
            symbol_info=self.symbol_info, displacement=self.displacement)
        if self.line_info is None:
            return sym_str

        # line information
        path = self.source_file_path if self.source_file_path else self.line_info.FileName
        line_str = "{path} ({line_info.LineNumber}; col: {line_displacement})".format(
            path=path, line_info=self.line_info, line_displacement=self.line_displacement
        )

        return "{sym_str}, {line_str}".format(sym_str=sym_str, line_str=line_str)

    @property
    def module_name(self):
        # type: () -> str
        """Return a string representation of the frame main module name.
        """
        if self.module is None or not self.module.path:
            return "<unknown>"

        return pathlib.Path(self.module.path).name

    @property
    def module_path(self):
        # type: () -> str
        """Return a string representation of the frame main module fully qualified path.
        """
        if self.module is None or not self.module.path:
            return "<unknown>"

        return self.module.path

    def __repr__(self):
        # type: () -> str
        return "{frame} {module_name} {location} {address:#x} {module_path}".format(
            frame=self.frame, module_name=self.module_name, location=self.location, address=self.address,
            module_path=self.module_path)


class StackTraceInformation(object):
    """Class used to prettify a whole stack trace so its output if similar to ProcMon's stack trace window tab for an
    event.
    """

    @staticmethod
    def prettify(resolved_stack_trace):
        # type: (list[StackTraceFrameInformation]) -> str
        """Prettify a list of `StackTraceFrameInformation` so its output is similar to the one given by ProcMon.

        Args:
            resolved_stack_trace: A list of stack trace frame information.

        Returns:
            A string that match closely the output of a stack trace from ProcMon.
        """
        if not resolved_stack_trace:
            return ""

        max_frame = max(len(stfi.frame) for stfi in resolved_stack_trace)
        max_module = max(len(stfi.module_name) for stfi in resolved_stack_trace)
        max_location = max(len(stfi.location) for stfi in resolved_stack_trace)
        max_address = max(len("{stfi.address:#x}".format(stfi=stfi)) for stfi in resolved_stack_trace)

        output = list()
        for stfi in resolved_stack_trace:
            output.append(f"{stfi.frame:<{max_frame}} {stfi.module_name:<{max_module}} {stfi.location:<{max_location}} "
                          f"0x{stfi.address:<{max_address}x} {stfi.module_path}")

        return '\n'.join(output)


class SymbolResolver(object):
    """Main workhorse class for resolving symbolic information from a stack trace.
    """

    def __init__(self,
                 procmon_logs_reader,  # type: procmon_parser.ProcmonLogsReader
                 dll_dir_path=None,  # type: str | pathlib.Path | None
                 skip_symsrv=False,  # type: bool
                 symbol_path=None,  # type: str
                 debug_callback=None  # type: typing.Callable[[int, CBA | int, str, int], int]
                 ):
        # type: (...) -> None
        """Class Initialisation.

        Args:
            procmon_logs_reader: An instance of the `ProcmonLogsReader` class.
            dll_dir_path: Path to a directory containing at least `dbghelp.dll`, and optionally `symsrv.dll`.
            skip_symsrv: Set to True if symbols are available locally on the machine and `_NT_SYMBOL_PATH` environment
                variable is correctly set. This skips the check for `symsrv.dll` presence altogether.
            symbol_path: Replace the `_NT_SYMBOL_PATH` environment variable if it exists, or prevent using %TEMP% as
                the download location of the symbol files. This must be a string compatible with the `_NT_SYMBOL_PATH`
                syntax.
            debug_callback: A callback which can be used to understand and debug problems with symbol downloading and
                resolution.

        Notes:
            If `dll_dir_path` is None, then the code does its best to find matching installations of the Debugging Tools
            for Windows (can be installed from the Windows SDK) and Windbg Preview (installed from the Windows Store).
            If neither can be found, the function raises.

        Raises:
            ValueError:
                The provided DLL path is not a valid directory, does not contain the required DLL(s) or the automatic
                finder could not find the required DLL.
            RuntimeError:
                The initialisation couldn't get the system modules.
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
                raise ValueError("You need to provide a valid path to 'dbghelp.dll' and 'symsrv.dll' or install either "
                                 "debugging tools or windbg preview.")
        else:
            # just check that the given dir contains dbghelp and symsrv.
            if not dll_dir_path.is_dir():
                raise ValueError("The given path '{dll_dir_path}' is not a directory.".format(
                    dll_dir_path=dll_dir_path))
            files_to_check = ["dbghelp.dll"]
            if not skip_symsrv:
                files_to_check.append("symsrv.dll")
            if not all((dll_dir_path / file_name).is_file() for file_name in files_to_check):
                raise ValueError("The given path must be a path to a directory containing: {files_to_check!r}.".format(
                    files_to_check=files_to_check))
        self.dll_dir_path = dll_dir_path

        # _NT_SYMBOL_PATH is needed to store symbols locally. If it's not set, we need to set it.
        nt_symbol_path = os.environ.get("_NT_SYMBOL_PATH", None)
        if nt_symbol_path is None:
            if symbol_path is None:
                # resolve TEMP folder and set it at the symbol path.
                symbol_path = "srv*{environ_tmp}*https://msdl.microsoft.com/download/symbols".format(
                    environ_tmp=os.environ['TEMP'])
            # set symbol path
            os.environ["_NT_SYMBOL_PATH"] = symbol_path
        logger.debug("NT_SYMBOL_PATH: {environ_nt_symbol_path}".format(
            environ_nt_symbol_path=os.environ['_NT_SYMBOL_PATH']))

        # DbgHelp wrapper instance initialisation and symbolic option setting.
        self._dbghelp = DbgHelp(self.dll_dir_path / "dbghelp.dll")

        self._debug_callback = debug_callback
        dbghelp_options = [
            SYMOPT.SYMOPT_CASE_INSENSITIVE | SYMOPT.SYMOPT_UNDNAME | SYMOPT.SYMOPT_DEFERRED_LOADS |
            SYMOPT.SYMOPT_LOAD_LINES | SYMOPT.SYMOPT_OMAP_FIND_NEAREST | SYMOPT.SYMOPT_FAIL_CRITICAL_ERRORS |
            SYMOPT.SYMOPT_INCLUDE_32BIT_MODULES | SYMOPT.SYMOPT_AUTO_PUBLICS]

        if self._debug_callback is not None:
            dbghelp_options.append(SYMOPT.SYMOPT_DEBUG)

        self._dbghelp.SymSetOptions(sum(dbghelp_options))  # 0x12237 (if not SYMOPT_DEBUG).

        # maximum user-address, used to discern between user and kernel modules (which don't change between processes).
        self._max_user_address: int = procmon_logs_reader.maximum_application_address

        # Keep track of all system modules.
        for process in procmon_logs_reader.processes():
            # Can't remember if System pid has always been 4.
            # Just check its name (doesn't end with .exe) and company is MS. That should be foolproof enough.
            if process.process_name in ["System"] and process.user.lower() == "nt authority\\system":
                self.system_modules = process.modules
                break
        else:
            # Couldn't find system modules. Log possible candidates.
            sys_pid = next((p for p in procmon_logs_reader.processes() if p.pid == 4), None)
            sys_name = next((p for p in procmon_logs_reader.processes() if p.process_name.lower() == "system"), None)
            if sys_pid is not None:
                logger.debug("Process w/ PID = 4: {sys_pid!r}".format(sys_pid=sys_pid))
            if sys_name is not None:
                logger.debug("Process w/ Name = 'System': {sys_name!r}".format(sys_name=sys_name))
            raise RuntimeError("Could not get system modules.")

    def find_module(self, event, address):
        # type: (procmon_parser.Event, int) -> procmon_parser.Module | None
        """Try to find the corresponding module given an address from an event stack trace.

        Args:
            event: The event from which the address belongs to.
            address: The address to be resolved to its containing module.

        Returns:
            If the address lies inside a known module, the module is returned, otherwise the function returns None.
        """

        def is_kernel(addr):
            # type: (int) -> bool
            """[Internal] Return whether an address is kernel (True) or not (user mode address: False)."""
            return addr > self._max_user_address

        def find_module_from_list(addr, modules):
            # type: (int, list[procmon_parser.Module]) -> procmon_parser.Module | None
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

    def resolve_stack_trace(self, event):
        # type: (procmon_parser.Event) -> typing.Iterator[StackTraceFrameInformation]
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

        # Initialize dbghelp symbolic information.
        pid = event.process.pid
        self._dbghelp.SymInitialize(pid, None, False)

        # set up callback if we are in debug mode
        if self._debug_callback:
            callback = PSYMBOL_REGISTERED_CALLBACK64(self._symbol_registered_callback)
            self._dbghelp.SymRegisterCallbackW64(pid, callback, PVOID(pid))

        logger.debug("# Stack Trace frames: {len_event_stack_trace}".format(
            len_event_stack_trace=len(event.stacktrace)))
        logger.debug("PID: {pid:#08x}".format(pid=pid))

        # Resolve each of the addresses in the stack trace, frame by frame.
        for frame_number, address in enumerate(event.stacktrace):
            frame_type = FrameType.from_address(address, self._max_user_address)
            logger.debug("{sep}\nStack Frame: {frame_number:04} type: {frame_type}".format(
                sep='-' * 79, frame_number=frame_number, frame_type=frame_type))

            # find the module that contains the given address. It might not be found.
            logger.debug("Address: {address:#016x}".format(address=address))
            module = self.find_module(event, address)
            if not module:
                yield StackTraceFrameInformation(frame_type, frame_number, address)
                continue

            logger.debug("Address: {address:#016x}  --> Module: {module!r}".format(address=address, module=module))

            # We have the address and the module name. Get the corresponding file from the Symbol store!
            # Once we have the file, we'll be able to query the symbol for the address.
            found_file = ctypes.create_unicode_buffer(MAX_PATH * ctypes.sizeof(ctypes.c_wchar))
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
                    logger.debug("SymFindFileInPathW failed at attempt {j} (error: {last_err:#08x}).".format(
                        j=j, last_err=last_err))
                    if j == 0 and last_err == ERROR_FILE_NOT_FOUND:
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
                        logger.error("SymFindFileInPathW: ({last_err:#08x}) {formatted_last_err}".format(
                            last_err=last_err, formatted_last_err=ctypes.FormatError(last_err)))
                        break
                else:
                    # no error.
                    break

            if not found_file.value:
                yield StackTraceFrameInformation(frame_type, frame_number, address, module)
                continue

            logger.debug("Found file: {found_file.value}".format(found_file=found_file))

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
                    logger.error("SymLoadModuleExW: ({last_err:#08x}) {formatted_last_err}".format(
                        last_err=last_err, formatted_last_err=ctypes.FormatError(last_err)))
                    yield StackTraceFrameInformation(frame_type, frame_number, address, module)
                    continue

            logger.debug("Module Base: {module_base:#x}".format(module_base=module_base))

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
                logger.error("SymFromAddr: ({last_err:#08x}) {formatted_last_err}".format(
                    last_err=last_err, formatted_last_err=ctypes.FormatError(last_err)))
                yield StackTraceFrameInformation(frame_type, frame_number, address, module)
                continue

            logger.debug("Symbol Name: {symbol_info.Name}; Displacement: {displacement.value:#08x}".format(
                symbol_info=symbol_info, displacement=displacement))

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
                logger.debug(
                    "SymGetLineFromAddrW64 [no source line]: ({last_err:#08x}) {formatted_last_err}".format(
                        last_err=last_err, formatted_last_err=ctypes.FormatError(last_err)))
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

            logger.debug("File Name: '{line.FileName}'; Line Number: {line.LineNumber}; "
                         "Line Displacement (col): {line_displacement.value}".format(
                         line=line, line_displacement=line_displacement))  # noqa

            # It's possible that the returned line.Filename is already a fully qualified path, in which case there's no
            #    need to call SymGetSourceFileW, as the latter would be only used to retrieve the fully qualified path.
            # We just check that we already have fully qualified path. If it is, then we bail out, otherwise we call
            #    SymGetSourceFileW.
            if pathlib.Path(line.FileName).is_absolute():  # noqa
                # we have a fully qualified source file path.
                logger.debug("source file path [from line.Filename]: {line.FileName}".format(line=line))
                fully_qualified_source_path = line.FileName
            else:
                # we don't have a fully qualified source file path.
                source_file_path_size = DWORD(MAX_PATH)
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
                    logger.debug("SymGetSourceFileW: ({last_err:#08x}) {formatted_last_err}".format(
                        last_err=last_err, formatted_last_err=ctypes.FormatError(last_err)))
                    logger.debug("SymGetSourceFileW failed: using '{line.FileName}' as fallback.".format(
                        line=line))
                    # use line.FileName as fallback
                    fully_qualified_source_path = line.FileName
                else:
                    logger.debug("source file path [from SymGetSourceFileW]: {source_file_path.value}".format(
                        source_file_path=source_file_path))
                    fully_qualified_source_path = source_file_path.value

            yield StackTraceFrameInformation(frame_type, frame_number, address, module, symbol_info, displacement.value,
                                             line, line_displacement.value, fully_qualified_source_path)

        # dbghelp symbol cleanup
        self._dbghelp.SymCleanup(pid)

    def _symbol_registered_callback(self, handle, action_code, callback_data, user_context):
        # type: (HANDLE, ULONG, ULONG64, ULONG64) -> BOOL
        param_callback_data = callback_data
        try:
            param_action_code = CBA(action_code)
            if param_action_code == CBA.CBA_DEBUG_INFO:
                param_callback_data = ctypes.cast(callback_data, ctypes.c_wchar_p).value
            elif param_action_code == CBA.CBA_EVENT:
                param_callback_data = ctypes.cast(callback_data, PIMAGEHLP_CBA_EVENTW).contents
        except ValueError:
            # can't convert from int to CBA. this happens for internal messages that surfaces.
            param_action_code = action_code

        ret = self._debug_callback(handle, param_action_code, param_callback_data, user_context)
        return ret


class DbgHelpUtils(object):
    """Utility functions to automatically find DbgHelp.dll and Symsrv.dll if Debugging Tools For Windows or Windbg
    preview are installed on the current system.
    """

    @staticmethod
    def find_debugging_tools():
        # type: () -> pathlib.Path | None
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
                value, value_type = winreg.QueryValueEx(top_key, "WindowsDebuggersRoot{max_ver_str}".format(
                    max_ver_str=max_ver_str))
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
    def find_windbg_preview():
        # type: () -> pathlib.Path | None
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
                        install_key = "{package_key}\\{key_name}".format(package_key=package_key, key_name=key_name)
                        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, install_key) as windbg_key:
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
    def _arch_dir(debugger_dir, arch_lookup):
        # type: (pathlib.Path, dict[str, str]) -> pathlib.Path | None
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
