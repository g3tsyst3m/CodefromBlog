#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <iostream>
#include <vector>
#include <iomanip>

PVOID FindGadget(DWORD pid, const BYTE* gadget, SIZE_T gadgetSize, const char* description) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) return nullptr;

    HMODULE hMods[1024];
    DWORD cbNeeded;
    PVOID gadgetAddress = nullptr;

    std::wcout << L"[*] Searching for " << description << L"..." << std::endl;

    if (EnumProcessModulesEx(hProcess, hMods, sizeof(hMods), &cbNeeded, LIST_MODULES_ALL)) {
        for (int i = 0; i < (int)(cbNeeded / sizeof(HMODULE)) && !gadgetAddress; ++i) {
            MODULEINFO modInfo;
            WCHAR modName[MAX_PATH];
            if (!GetModuleInformation(hProcess, hMods[i], &modInfo, sizeof(modInfo)) ||
                !GetModuleBaseNameW(hProcess, hMods[i], modName, MAX_PATH)) continue;

            MEMORY_BASIC_INFORMATION mbi{};
            for (BYTE* addr = (BYTE*)modInfo.lpBaseOfDll; addr < (BYTE*)modInfo.lpBaseOfDll + modInfo.SizeOfImage; ) {
                if (!VirtualQueryEx(hProcess, addr, &mbi, sizeof(mbi))) break;
                if (mbi.State == MEM_COMMIT && (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))) {
                    BYTE* buffer = new BYTE[mbi.RegionSize];
                    SIZE_T bytesRead;
                    if (ReadProcessMemory(hProcess, mbi.BaseAddress, buffer, mbi.RegionSize, &bytesRead)) {
                        for (SIZE_T j = 0; j + gadgetSize <= bytesRead; ++j) {
                            if (memcmp(buffer + j, gadget, gadgetSize) == 0) {
                                gadgetAddress = (PVOID)((uintptr_t)mbi.BaseAddress + j);
                                std::wcout << L"[+] Found in " << modName << L" at 0x" << std::hex << gadgetAddress << " !!!" << std::dec << std::endl;
                                delete[] buffer;
                                CloseHandle(hProcess);
                                return gadgetAddress;
                            }
                        }
                    }
                    delete[] buffer;
                }
                addr += mbi.RegionSize;
            }
        }
    }
    CloseHandle(hProcess);
    return gadgetAddress;
}

