#!/usr/bin/env python3
# -*- coding:utf-8 -*-
import ctypes
from .win_types import BOOL, LPWSTR

_kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

# SetEnvironmentVariableW
# https://learn.microsoft.com/en-us/windows/win32/api/processenv/nf-processenv-setenvironmentvariablew
SetEnvironmentVariableW = _kernel32.SetEnvironmentVariableW
SetEnvironmentVariableW.argtypes = (LPWSTR, LPWSTR)
SetEnvironmentVariableW.restype = BOOL
SetEnvironmentVariable = SetEnvironmentVariableW
