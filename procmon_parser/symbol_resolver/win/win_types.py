#!/usr/bin/env python3
# -*- coding:utf-8 -*-
"""Module that declares various Windows types for ctypes.
"""
import ctypes

HANDLE = ctypes.c_void_p
BOOL = ctypes.c_long
PCSTR = PCWSTR = PSTR = PWSTR = LPWSTR = ctypes.c_wchar_p
DWORD = ctypes.c_uint32
DWORD64 = ctypes.c_uint64
ULONG = ctypes.c_uint32
ULONG64 = ctypes.c_uint64
CHAR = ctypes.c_char
WCHAR = ctypes.c_wchar

# pointer types
PVOID = ctypes.c_void_p
PDWORD = ctypes.POINTER(DWORD)
PDWORD64 = ctypes.POINTER(DWORD64)
