MAKEFLAGS += -s
NAME      = Mana
CCX64     = x86_64-w64-mingw32-gcc
RC        = x86_64-w64-mingw32-windres
NASM      = nasm

# =============================================================================
# INDIRECT_SYSCALL: 1 = RecycledGate, 0 = WinAPI (default)
# =============================================================================
INDIRECT_SYSCALL ?= 0

CFLAGS    = -Os -fno-asynchronous-unwind-tables -masm=intel
CFLAGS    += -fno-ident -fpack-struct=8 -falign-functions=1
CFLAGS    += -s -ffunction-sections -falign-jumps=1 -w
CFLAGS    += -falign-labels=1 -fPIC
CFLAGS    += -Wl,-s,--no-seh,--enable-stdcall-fixup
CFLAGS    += -e WinMain

# Set API mode based on INDIRECT_SYSCALL flag
ifeq ($(INDIRECT_SYSCALL),1)
    CFLAGS += -DUSE_INDIRECT_SYSCALL
    ASM_OBJ = Bin/GateTrampolin.obj
    API_MODE_STR = RecycledGate (Indirect Syscalls)
else
    CFLAGS += -DUSE_WINAPI
    ASM_OBJ =
    API_MODE_STR = WinAPI (Standard)
endif

INCLUDE   = -I Include
LINKING   = -lwinhttp -lkernel32 -ladvapi32 -lntdll -liphlpapi
SOURCE    = $(wildcard Source/*.c)
RES       = Include/Resource.rc
RESOBJ    = Include/resource.res

all: x64

# Assemble GateTrampolin.asm (only when INDIRECT_SYSCALL=1)
Bin/GateTrampolin.obj: Source/GateTrampolin.asm
	@mkdir -p Bin
	@printf "\033[0;36m[*]\033[0m Assembling GateTrampolin.asm...\n"
	$(NASM) -f win64 $< -o $@

x64: $(ASM_OBJ)
	@printf "\033[0;36m[*]\033[0m Building Mana agent...\n"
	@printf "\033[0;36m[*]\033[0m API Mode: $(API_MODE_STR)\n"
	@printf "\033[0;36m[*]\033[0m Compiling resource file...\n"
	$(RC) $(RES) -O coff -o $(RESOBJ)
	@mkdir -p Bin
	$(CCX64) $(SOURCE) $(ASM_OBJ) $(RESOBJ) $(INCLUDE) $(CFLAGS) $(LINKING) -m64 -o Bin/Mana.exe
	@printf "\033[0;36m[*]\033[0m Finished!\n"

clean:
	@rm -rf Bin/*

.PHONY: all x64 clean
