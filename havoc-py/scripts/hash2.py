import sys
import random
import os
import secrets

randintHash = random.randint(1000, 9999)
hex_string = "0x" + secrets.token_hex(4).upper()
hex_number = int(hex_string, 16)

# This script is used for indirect syscalls to generate hash

NTAPIS_NAMES = {
    "NTALLOCATEVIRTUALMEMORYEX": "NtAllocateVirtualMemoryEx",
    "NTALLOCATEVIRTUALMEMORY": "NtAllocateVirtualMemory",
    "NTWRITEVIRTUALMEMORY": "NtWriteVirtualMemory",
    "NTPROTECTVIRTUALMEMORY": "NtProtectVirtualMemory",
    "NTCREATETHREAD": "NtCreateThread",
    "NTOPENPROCESS": "NtOpenProcess",
    "NTCREATESECTION": "NtCreateSection",
    "NTMAPVIEWOFSECTION": "NtMapViewOfSection",
    "NTQUEUEAPCTHREAD": "NtQueueApcThread",
    "NTRESUMETHREAD": "NtResumeThread",
    "NTCREATETHREADEX": "NtCreateThreadEx",
    "NTCREATEPROCESS":"NtCreateProcess",
    "NTCREATEPROCESSEX":"NtCreateProcessEx",
    "NTTERMINATEPROCESS": "NtTerminateProcess",
    "NTQUEUEAPCTHREAD": "NtQueueApcThread",
    "NTRESUMETHREAD": "NtResumeThread",
    "NTCREATEUSERPROCESS": "NtCreateUserProcess",
    "NTWAITFORSINGLEOBJECT":"NtWaitForSingleObject",
    "NTCLOSE": "NtClose",
    "NTSUSPENDTHREAD": "NtSuspendThread",
    "NTFREEVIRTUALMEMORY": "NtFreeVirtualMemory"
}

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
XOR_HASH_KEY = hex_number
#0x41424344
#0x18B05949
def djb2(string: str) -> int:
    hash_val = randintHash
    #print(f"hash value for djb2: {hash_val}\n")
    
    # Convert string to bytes to iterate over character byte values matching C's unsigned char*
    for c in string.encode('utf-8'):
        # Apply 32-bit mask to simulate 32-bit unsigned integer overflow
        hash_val = (((hash_val << 5) + hash_val) + c) & 0xFFFFFFFF
        
    return hash_val

def xor_hash(hash_val: int, key: int) -> int:
    return (hash_val ^ key) & 0xFFFFFFFF


def format_define(prefix, name, hash_val):
    define_name = f"#define {prefix}_{name}"
    return f"{define_name:<{DEFINE_WIDTH}} 0x{hash_val:08x}"

def main():
    # Check if an argument was passed (sys.argv[0] is the script name)
    #if len(sys.argv) < 2:
    #    return

    #name = sys.argv[1]
    #hash_val = djb2(name)
    #hash_crypted = xor_hash(hash_val, 0x41424344)


    # :x formats the integer as a lowercase hexadecimal string
    #print(f"0x{hash_val:x}")
    #print(f"0x{hash_crypted:x}")

    lines = []

    print(f'[*] Using hash seed: {randintHash}')
    print(f'[*] Using XOR key: {hex_number}\n\n')

    # Add the hash seed define
    
    #lines.append(f"#include \"windows.h\"")
    lines.append(f"#include \"typedef.h\"")
    lines.append("")
    lines.append(f"#define APIhashval2 {randintHash}")
    lines.append(f"#define XOR_HASH_KEY 0x{XOR_HASH_KEY:X}")
    lines.append("")
    lines.append("//recycledgate defines")
    lines.append(f"#define FAIL 0")
    lines.append(f"#define SUCCESS 1")
    lines.append(f"#define SYS_STUB_SIZE 32")
    lines.append(f"#define UP -32")
    lines.append(f"#define DOWN 32")
    lines.append(f"#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)")
    lines.append("")

    # NT apis
    lines.append("//NT APIs")
    for name,api in NTAPIS_NAMES.items():
        hash_val = djb2(api)
        hash_crypted = xor_hash(hash_val, XOR_HASH_KEY)
        # print(f"{api}")
        # print(f"Hash value: 0x{hash_val:x}")
        # print(f"Hash crypted value: 0x{hash_crypted:x}")
        # print("\n================================")
        
        lines.append(format_define("H_FUNC", name, hash_crypted))
    lines.append("")

    #DLL
    lines.append("//DLL HASH")
    for dll_name,api2 in MODULE_NAMES.items():
        hash_val = djb2(api2)
        hash_crypted = xor_hash(hash_val, XOR_HASH_KEY)
        # print(f"{api2}")
        # print(f"Hash value: 0x{hash_val:x}")
        # print(f"Hash crypted value: 0x{hash_crypted:x}")
        # print("\n================================")
        
        lines.append(format_define("H_MODULE", dll_name, hash_crypted))
    lines.append("")

    # for i in lines:
    #     print(i)

    script_dir = os.path.dirname(os.path.abspath(__file__))
    output_path = os.path.join(script_dir, "..", "Include", "Defines2.h")

    body = "\n".join(lines) + "\n"

    # Wrap in include guard
    output  = "#ifndef DEFINES2_H\n"
    output += "#define DEFINES2_H\n\n"
    output += body
    output += "\n#endif // DEFINES2_H\n"

    # Write to file
    with open(output_path, 'w') as f:
        f.write(output)

    print(f'[+] Written to {output_path}')
    print()
    print(output)

if __name__ == "__main__":
    main()
