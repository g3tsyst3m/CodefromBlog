#include "ManualNtdll.h"
#include <winnt.h>
#include <iostream>

ManualNtdll::ManualNtdll() {}

ManualNtdll::~ManualNtdll() {
    if (mappedBase) UnmapViewOfFile(mappedBase);
    if (hMapping) CloseHandle(hMapping);
    if (hFile) CloseHandle(hFile);
}

bool ManualNtdll::LoadFromDisk(const std::wstring& path) {
    hFile = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return false;

    hMapping = CreateFileMappingW(hFile, nullptr, PAGE_READONLY, 0, 0, nullptr);
    if (!hMapping) return false;

    mappedBase = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
    return mappedBase != nullptr;
}

void* ManualNtdll::GetMappedBase() const {
    return mappedBase;
}

void* ManualNtdll::GetProcAddress(const std::string& name) {
    if (!mappedBase) return nullptr;

    auto dos = (PIMAGE_DOS_HEADER)mappedBase;
    auto nt = (PIMAGE_NT_HEADERS)((BYTE*)mappedBase + dos->e_lfanew);
    auto exports = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)mappedBase +
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    auto names = (DWORD*)((BYTE*)mappedBase + exports->AddressOfNames);
    auto funcs = (DWORD*)((BYTE*)mappedBase + exports->AddressOfFunctions);
    auto ords = (WORD*)((BYTE*)mappedBase + exports->AddressOfNameOrdinals);

    for (DWORD i = 0; i < exports->NumberOfNames; ++i) {
        const char* funcName = (const char*)mappedBase + names[i];
        if (name == funcName) {
            WORD ordinal = ords[i];
            return (BYTE*)mappedBase + funcs[ordinal];
        }
    }
    return nullptr;
}

void* ManualNtdll::ResolveSyscallStub(void* funcAddr) {
    void* stub = VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!stub) return nullptr;
    memcpy(stub, funcAddr, 0x20);
    return stub;
}