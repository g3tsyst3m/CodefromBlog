# stomp_poc — Remote Function Stomping

Standalone PoC for the AdaptixC2 function-stomping BOF module.
Validates the technique before porting to a COFF BOF.

## Technique

Cross-process function stomping: open a target process, read its PE export
table from memory, overwrite a chosen export with shellcode, optionally
trigger execution via `CreateRemoteThread`.

## Build

```bash
make          # requires x86_64-w64-mingw32-gcc
```

Produces `stomp.exe` (statically linked, no runtime DLLs needed).

## Usage

```
.\stomp.exe
```

Interactive flow:
1. List running processes → pick by PID or name fragment
2. List loaded modules in that process → pick by number or name fragment
3. List exported functions (parsed from PE export table in target memory)
   → pick by number or exact name
4. **File dialog** opens to select the shellcode `.bin` file
5. `VirtualProtectEx(RW)` → `WriteProcessMemory` → `VirtualProtectEx(RWX)`
6. Optional: `CreateRemoteThread` at the stomped address

## Requirements

- Windows x64 (target process should be x64 to match the tool)
- Admin privileges (or same integrity level as target) for `OpenProcess`
  with `PROCESS_VM_WRITE | PROCESS_VM_OPERATION`

## Next Steps

Port to AdaptixC2 COFF BOF:
- BOF params: `int` (PID), `cstr` (DLL name), `cstr` (function name), `bytes` (shellcode)
- No file dialog in BOF context — shellcode arrives as `bytes` param via `ax.bof_pack`
- No `CreateToolhelp32Snapshot` needed in BOF (beacon is already in-process or
  can use `Toolhelp32` via `KERNEL32$CreateToolhelp32Snapshot` DFR)

## Files

| File | Purpose |
|------|---------|
| `stomp.c` | Source — full interactive PoC |
| `Makefile` | MinGW cross-compile |
| `stomp.exe` | Built binary (264 KB, static) |
