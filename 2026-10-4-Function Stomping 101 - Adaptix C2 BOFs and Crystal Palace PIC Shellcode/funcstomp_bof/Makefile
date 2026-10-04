BOF = funcstomp
CC64 = x86_64-w64-mingw32-gcc
CC86 = i686-w64-mingw32-gcc
STRIP64 = x86_64-w64-mingw32-strip --strip-unneeded
STRIP86 = i686-w64-mingw32-strip --strip-unneeded
CFLAGS = -I ./_include -w -Wno-int-conversion -Wno-incompatible-pointer-types -Os -s -DBOF -c

all: bof
bof: clean
	@mkdir -p _bin
	@($(CC64) $(CFLAGS) $(BOF).c -o _bin/$(BOF).x64.o && $(STRIP64) _bin/$(BOF).x64.o) && echo '[+] x64' || echo '[!] x64 failed'
	@($(CC86) $(CFLAGS) $(BOF).c -o _bin/$(BOF).x86.o && $(STRIP86) _bin/$(BOF).x86.o) && echo '[+] x86' || echo '[!] x86 failed'
clean:
	@rm -rf _bin
.PHONY: all bof clean
