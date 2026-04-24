#!/usr/bin/env python3
# -*- coding:utf-8 -*-
# credit: __https://github.com/realoriginal/titanldr-ng/blob/master/python3/hashstring.py__
# credit: __https://github.com/HavocFramework/Havoc/tree/main/payloads/Demon/scripts__

import random
import sys
import os

randintHash = random.randint(1000, 9999)

WINAPI_NAMES = {
    # ADVAPI32
    "GETTOKENINFORMATION":          "GetTokenInformation",
    "GETUSERNAMEA":                 "GetUserNameA",
    "LOOKUPPRIVILEGEDISPLAYNAMEA":  "LookupPrivilegeDisplayNameA",
    "LOOKUPPRIVILEGENAMEA":         "LookupPrivilegeNameA",
    "OPENPROCESSTOKEN":             "OpenProcessToken",
    # IPHLPAPI
    "GETADAPTERSINFO":              "GetAdaptersInfo",
    # KERNEL32
    "CLOSEHANDLE":                  "CloseHandle",
    "CREATEFILEA":                  "CreateFileA",
    "CREATEPIPE":                   "CreatePipe",
    "CREATEPROCESSA":               "CreateProcessA",
    "DELETECRITICALSECTION":        "DeleteCriticalSection",
    "ENTERCRITICALSECTION":         "EnterCriticalSection",
    "EXITPROCESS":                  "ExitProcess",
    "FILETIMETOLOCALFILETIME":      "FileTimeToLocalFileTime",
    "FILETIMETOSYSTEMTIME":         "FileTimeToSystemTime",
    "FINDCLOSE":                    "FindClose",
    "FINDFIRSTFILEA":               "FindFirstFileA",
    "FINDNEXTFILEA":                "FindNextFileA",
    "GETCOMPUTERNAMEXA":            "GetComputerNameExA",
    "GETCURRENTDIRECTORYA":         "GetCurrentDirectoryA",
    "GETCURRENTPROCESS":            "GetCurrentProcess",
    "GETCURRENTPROCESSID":          "GetCurrentProcessId",
    "GETFILESIZE":                  "GetFileSize",
    "GETFULLPATHNAMEA":             "GetFullPathNameA",
    "GETLASTERROR":                 "GetLastError",
    "GETMODULEFILENAMEA":           "GetModuleFileNameA",
    "GETMODULEHANDLEA":             "GetModuleHandleA",
    "GETPROCADDRESS":               "GetProcAddress",
    "GETSTARTUPINFOA":              "GetStartupInfoA",
    "GETTICKCOUNT":                 "GetTickCount",
    "INITIALIZECRITICALSECTION":    "InitializeCriticalSection",
    "ISDBCSLEADBYTEEX":             "IsDBCSLeadByteEx",
    "LEAVECRITICALSECTION":         "LeaveCriticalSection",
    "LOCALALLOC":                   "LocalAlloc",
    "LOCALFREE":                    "LocalFree",
    "LOCALREALLOC":                 "LocalReAlloc",
    "MULTIBYTETOWIDECHAR":          "MultiByteToWideChar",
    "PEEKNAMEDPIPE":                "PeekNamedPipe",
    "QUEUEUSERAPC":                 "QueueUserAPC",
    "READFILE":                     "ReadFile",
    "RESUMETHREAD":                 "ResumeThread",
    "SETCURRENTDIRECTORYA":         "SetCurrentDirectoryA",
    "SETHANDLEINFORMATION":         "SetHandleInformation",
    "SETUNHANDLEDEXCEPTIONFILTER":  "SetUnhandledExceptionFilter",
    "SLEEP":                        "Sleep",
    "TERMINATEPROCESS":             "TerminateProcess",
    "TLSGETVALUE":                  "TlsGetValue",
    "VIRTUALALLOCEX":               "VirtualAllocEx",
    "VIRTUALPROTECT":               "VirtualProtect",
    "VIRTUALPROTECTEX":             "VirtualProtectEx",
    "VIRTUALQUERY":                 "VirtualQuery",
    "WAITFORSINGLEOBJECT":          "WaitForSingleObject",
    "WIDECHARTOMULTIBYTE":          "WideCharToMultiByte",
    "WRITEFILE":                    "WriteFile",
    "WRITEPROCESSMEMORY":           "WriteProcessMemory",
    # WINHTTP
    "WINHTTPADDREQUESTHEADERS":     "WinHttpAddRequestHeaders",
    "WINHTTPCLOSEHANDLE":           "WinHttpCloseHandle",
    "WINHTTPCONNECT":               "WinHttpConnect",
    "WINHTTPOPEN":                  "WinHttpOpen",
    "WINHTTPOPENREQUEST":           "WinHttpOpenRequest",
    "WINHTTPREADDATA":              "WinHttpReadData",
    "WINHTTPRECEIVERESPONSE":       "WinHttpReceiveResponse",
    "WINHTTPSENDREQUEST":           "WinHttpSendRequest",
    "WINHTTPSETOPTION":             "WinHttpSetOption",
}

MODULE_NAMES = {
    "ADVAPI32":  "ADVAPI32.dll",
    "IPHLPAPI":  "IPHLPAPI.DLL",
    "KERNEL32":  "kernel32.dll",
    "NTDLL":     "ntdll.dll",
    "WINHTTP":   "WINHTTP.dll",
}

DEFINE_WIDTH = 56

def hash_string( string ):
    try:
        hash = randintHash
        for x in string.upper():
            hash = (( hash << 5 ) + hash ) + ord(x)
        return hash & 0xFFFFFFFF
    except:
        pass

def hash_string_wide( string ):
    """Hash a string as if it were a wide (UTF-16LE) string.
    Matches the C HashString() behavior with IsWide=TRUE.
    The C code only hashes the first character properly,
    then processes null bytes for each subsequent wide char pair."""
    try:
        hash = randintHash
        upper = string.upper()
        for x in range(0, len(upper), 1):
            if x == 0:
                hash = (( hash << 5 ) + hash ) + ord(upper[x])
            if True:  # wide: always hash the null byte
                hash = (( hash << 5 ) + hash )
        return hash & 0xFFFFFFFF
    except:
        pass

def hash_coffapi( string ):
    try:
        hash = randintHash
        for x in string:
            hash = (( hash << 5 ) + hash ) + ord(x)
        return hash & 0xFFFFFFFF
    except:
        pass

def format_define(prefix, name, hash_val):
    define_name = f"#define {prefix}_{name}"
    return f"{define_name:<{DEFINE_WIDTH}} 0x{hash_val:08x}"

if __name__ == '__main__':
    script_dir = os.path.dirname(os.path.abspath(__file__))
    output_path = os.path.join(script_dir, "..", "Include", "Defines.h")

    #output_path = "../Include/Defines.h"
    lines = []

    print(f'[*] Using hash seed: {randintHash}')

    # Add the hash seed define
    lines.append(f"#define APIhashval {randintHash}")
    lines.append("")

    # Hash all function defines (ANSI)
    for name, api in WINAPI_NAMES.items():
        h = hash_string(api)
        lines.append(format_define("H_FUNC", name, h))

    lines.append("")

    # Hash all module defines (WIDE — matches C HashString with IsWide=TRUE)
    for name, dll in MODULE_NAMES.items():
        h = hash_string_wide(dll)
        lines.append(format_define("H_MODULE", name, h))

    body = "\n".join(lines) + "\n"

    # Wrap in include guard
    output  = "#ifndef DEFINES_H\n"
    output += "#define DEFINES_H\n\n"
    output += body
    output += "\n#endif // DEFINES_H\n"

    # Write to file
    with open(output_path, 'w') as f:
        f.write(output)

    print(f'[+] Written to {output_path}')
    print()
    print(output)