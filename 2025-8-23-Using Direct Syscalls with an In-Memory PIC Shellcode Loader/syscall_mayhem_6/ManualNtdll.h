#pragma once
#include <windows.h>
#include <string>

class ManualNtdll {
public:
    ManualNtdll();
    ~ManualNtdll();
    bool LoadFromDisk(const std::wstring& path);
    void* GetProcAddress(const std::string& name);
    void* ResolveSyscallStub(void* funcAddr);
    void* GetMappedBase() const;

private:
    HANDLE hFile = nullptr;
    HANDLE hMapping = nullptr;
    void* mappedBase = nullptr;
}; 
