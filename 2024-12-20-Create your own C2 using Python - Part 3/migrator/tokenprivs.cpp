#pragma once
#include <Windows.h>
#include <iostream>
#include <conio.h>
#include "def.h"

bool IsProcessElevated() {
    BOOL isElevated = FALSE;
    HANDLE hToken = NULL;
    TOKEN_ELEVATION elevation;
    DWORD dwSize;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        std::cerr << "OpenProcessToken error: " << GetLastError() << std::endl;
        return false;
    }

    if (!GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &dwSize)) {
        std::cerr << "GetTokenInformation error: " << GetLastError() << std::endl;
        CloseHandle(hToken);
        return false;
    }

    isElevated = elevation.TokenIsElevated;
    CloseHandle(hToken);
    return isElevated;
}

void setThreadPrivs(LPCWSTR privname)
{

    TOKEN_PRIVILEGES tp;
    LUID luid;
    HANDLE pToken;

    if (!LookupPrivilegeValue(
        NULL,            // lookup privilege on local system
        privname,   // privilege to lookup 
        &luid))        // receives LUID of privilege
    {
        printf("[!] LookupPrivilegeValue error: %u\n", GetLastError());
        exit(0);
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (OpenThreadToken(GetCurrentThread(), TOKEN_ADJUST_PRIVILEGES, NULL, &pToken))
        printf("[+] opened process thread token!\n");
    else
        printf("error opening thread token: %d\n", GetLastError());

    if (!AdjustTokenPrivileges(pToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL))
    {

        printf("{!] AdjustTokenPrivileges error: %u\n", GetLastError());
        exit(0);
    }

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)

    {
        printf("[!] The thread token does not have this specified privilege available to the process. \n");
        exit(0);
    }
    printf("[+] Privilege: %ws added successfully to the thread!!!\n", privname);
    CloseHandle(pToken);

}


void setProcessPrivs(LPCWSTR privname)
{

    TOKEN_PRIVILEGES tp;
    LUID luid;
    HANDLE pToken;

    if (!LookupPrivilegeValue(
        NULL,            // lookup privilege on local system
        privname,   // privilege to lookup 
        &luid))        // receives LUID of privilege
    {
        printf("[!] LookupPrivilegeValue error: %u\n", GetLastError());
        exit(0);
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &pToken))
        printf("[+] opened process token!\n");

    if (!AdjustTokenPrivileges(pToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL))
    {
        printf("[!] AdjustTokenPrivileges error: %u\n", GetLastError());
        exit(0);
    }

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)

    {
        printf("[!] The token does not have this specified privilege available to the process. \n");
        exit(0);
    }
    printf("[+] Privilege: %ws added successfully!!!\n", privname);
    CloseHandle(pToken);

}