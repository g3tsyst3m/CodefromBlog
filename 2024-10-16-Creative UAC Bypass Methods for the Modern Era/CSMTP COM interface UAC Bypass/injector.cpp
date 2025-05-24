#include <windows.h>
#include <tlhelp32.h>
#include <iostream>

DWORD GetExplorerPID() {
    DWORD pid = 0;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);
    if (Process32First(snapshot, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, L"explorer.exe") == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32Next(snapshot, &pe));
    }

    CloseHandle(snapshot);
    return pid;
}

int main() {
    // STEP 1: Get explorer.exe PID
    DWORD pid = GetExplorerPID();
    if (!pid) {
        std::wcerr << L"explorer.exe not found!\n";
        return 1;
    }

    // STEP 2: Open process
    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    if (!hKernel32) return 1;

    // Dynamically resolve LoadLibraryW
    auto pLoadLibraryW = (LPTHREAD_START_ROUTINE)GetProcAddress(hKernel32, "LoadLibraryW");
    if (!pLoadLibraryW) return 1;

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        std::wcerr << L"Failed to open explorer.exe\n";
        return 1;
    }

    // STEP 3: Allocate memory in target process
    //const wchar_t* dllPath = L"C:\\Users\\robbi\\source\\repos\\injectit\\x64\\Debug\\injectit.dll";
    const wchar_t* dllPath = L"C:\\Users\\robbi\\source\\repos\\injected2\\x64\\Debug\\injected2.dll";
    size_t size = (wcslen(dllPath) + 1) * sizeof(wchar_t);

    LPVOID remoteMem = VirtualAllocEx(hProcess, nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteMem) {
        std::wcerr << L"VirtualAllocEx failed\n";
        CloseHandle(hProcess);
        return 1;
    }

    // STEP 4: Write DLL path to remote process
    if (!WriteProcessMemory(hProcess, remoteMem, dllPath, size, nullptr)) {
        std::wcerr << L"WriteProcessMemory failed\n";
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }

    // STEP 5: Create remote thread in explorer.exe
    HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0, pLoadLibraryW, remoteMem, 0, nullptr);
    if (!hThread) {
        std::wcerr << L"CreateRemoteThread failed\n";
    }
    else {
        std::wcout << L"Injection successful!\n";
        CloseHandle(hThread);
    }

    // Clean up
    VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
    CloseHandle(hProcess);
    return 0;
}
