MAKEFLAGS += -s
NAME      = Mana
CCX64     = x86_64-w64-mingw32-gcc
RC 		  = x86_64-w64-mingw32-windres
CFLAGS    = -Os -fno-asynchronous-unwind-tables -masm=intel
CFLAGS    += -fno-ident -fpack-struct=8 -falign-functions=1
CFLAGS    += -s -ffunction-sections -falign-jumps=1 -w
CFLAGS    += -falign-labels=1 -fPIC
CFLAGS    += -Wl,-s,--no-seh,--enable-stdcall-fixup
CFLAGS    += -e WinMain
INCLUDE   = -I Include
LINKING   = -lwinhttp -lkernel32 -ladvapi32 -lntdll -liphlpapi
SOURCE    = $(wildcard Source/*.c)
RES 	  = Include/Resource.rc
RESOBJ    = Include/resource.res

all:
	@printf "\033[0;36m[*]\033[0m Building Mana agent...\n"
	@printf "\033[0;36m[*]\033[0m Compiling resource file...\n"
	$(RC) $(RES) -O coff -o $(RESOBJ)
	@mkdir -p Bin
	$(CCX64) $(SOURCE) $(RESOBJ) $(INCLUDE) $(CFLAGS) $(LINKING) -m64 -o Bin/Mana.exe
	@printf "\033[0;36m[*]\033[0m Finished!\n"

clean:
	@rm -rf Bin/*

.PHONY: all clean