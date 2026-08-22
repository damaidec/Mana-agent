#ifndef DEFINES2_H
#define DEFINES2_H

#include "typedef.h"

#define APIhashval2 3988
#define XOR_HASH_KEY 0xB55CA030

//recycledgate defines
#define FAIL 0
#define SUCCESS 1
#define SYS_STUB_SIZE 32
#define UP -32
#define DOWN 32
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

//NT APIs
#define H_FUNC_NTALLOCATEVIRTUALMEMORYEX                 0xaa9db928
#define H_FUNC_NTALLOCATEVIRTUALMEMORY                   0x366f44cb
#define H_FUNC_NTWRITEVIRTUALMEMORY                      0x3b082f91
#define H_FUNC_NTPROTECTVIRTUALMEMORY                    0x29382aa7
#define H_FUNC_NTCREATETHREAD                            0x0a9d6fd2
#define H_FUNC_NTOPENPROCESS                             0x52d68b77
#define H_FUNC_NTCREATESECTION                           0xd7a7a34f
#define H_FUNC_NTMAPVIEWOFSECTION                        0x7be41189
#define H_FUNC_NTQUEUEAPCTHREAD                          0x7596faf7
#define H_FUNC_NTRESUMETHREAD                            0x0193a5cf
#define H_FUNC_NTCREATETHREADEX                          0x0229f98f
#define H_FUNC_NTCREATEPROCESS                           0x2e7380b9
#define H_FUNC_NTCREATEPROCESSEX                         0x9625d016
#define H_FUNC_NTTERMINATEPROCESS                        0x77c1e34e
#define H_FUNC_NTCREATEUSERPROCESS                       0xcb0647b8
#define H_FUNC_NTWAITFORSINGLEOBJECT                     0xe5b7101b
#define H_FUNC_NTCLOSE                                   0x4c0a16dc
#define H_FUNC_NTSUSPENDTHREAD                           0x56970020
#define H_FUNC_NTFREEVIRTUALMEMORY                       0xd0bbea28

//DLL HASH
#define H_MODULE_ADVAPI32                                0x35c5a6a8
#define H_MODULE_IPHLPAPI                                0x5b981765
#define H_MODULE_KERNEL32                                0x394297b4
#define H_MODULE_NTDLL                                   0x9008a16c
#define H_MODULE_WINHTTP                                 0xb1b171fc


#endif // DEFINES2_H
