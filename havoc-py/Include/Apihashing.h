#ifndef APIHASHING_H
#define APIHASHING_H

#include <windows.h>
#include <Defines.h>
#include <typedef.h>

#ifdef _WIN64
#define PPEB_PTR __readgsqword( 0x60 )
#else
#define PPEB_PTR __readfsdword( 0x30 )
#endif

// Function declarations
UINT_PTR HashString(LPVOID String, BOOLEAN IsWide);
VOID ACharStringToWCharString(PWCHAR Destination, PCHAR Source, SIZE_T MaximumAllowed);
SIZE_T StringLength(PBYTE String, BOOLEAN IsWide);
PVOID LoadModulePeb(UINT_PTR hModuleHash);
PVOID LoadFunction(UINT_PTR Module, UINT_PTR FunctionHash);
void initializeAPI();

#endif // APIHASHING_H