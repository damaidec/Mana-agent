//RecycledGate.h

#ifndef MANA_RECYCLED_GATE_H
#define MANA_RECYCLED_GATE_H

#include <windows.h>
#include "typedef.h"
#include "Defines2.h"

#ifdef USE_INDIRECT_SYSCALL

// Functions from RecycledGate.c
DWORD getSyscall(DWORD dwCryptedHash, Syscall* pSyscall);
PVOID findNtDll(void);
unsigned long djb2_unicode(const wchar_t* str);
unsigned long djb2(unsigned char* str);
unsigned long xor_hash(unsigned long hash);
WCHAR* toLower(WCHAR* str);

// Assembly functions from GateTrampolin
extern void PrepareSyscall(DWORD dwSyscallNr, PVOID pGate);
extern NTSTATUS DoSyscall();

#endif // USE_INDIRECT_SYSCALL

#endif // MANA_RECYCLED_GATE_H
