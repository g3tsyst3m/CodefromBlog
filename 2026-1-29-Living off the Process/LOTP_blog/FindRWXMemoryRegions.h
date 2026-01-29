#ifndef FINDRWXMEMORYREGIONS_H
#define FINDRWXMEMORYREGIONS_H

int FindRWXMemoryRegions(unsigned char* shellcode_base, HANDLE hProcess, LPVOID& remoteShellcode, LPVOID& remoteGadgets, LPVOID& remoteStack);

#endif
