bits 64

section .data
api1 db "GetProcAddress",0
api2 db "InternetOpenA",0
api3 db "RtlMoveMemory",0
api4 db "InternetOpenUrlA",0
api5 db "InternetReadFile",0
api6 db "InternetCloseHandle",0
api7 db "CloseHandle",0
api8 db "ExitProcess",0
api9 db "VirtualAlloc",0
api10 db "VirtualFree",0
api11 db "VirtualProtect",0
api12 db "CreateThread",0
api13 db "WaitForSingleObject",0
api14 db "LoadLibraryA",0

section .bss
;api1_hash resd 1        ; reserve 4 bytes for the hash (DWORD)

section .text
global main
main:
    xor ecx, ecx
    ; Hash the string
    api_1:
    lea rsi, [rel api1] ; rsi = pointer to string
    jmp initiator
    api_2:
    lea rsi, [rel api2]
    jmp initiator
    api_3:
    lea rsi, [rel api3]
    jmp initiator
    api_4:
    lea rsi, [rel api4]
    jmp initiator
    api_5:
    lea rsi, [rel api5]
    jmp initiator
    api_6:
    lea rsi, [rel api6]
    jmp initiator
    api_7:
    lea rsi, [rel api7]
    jmp initiator
    api_8:
    lea rsi, [rel api8]
    jmp initiator
    api_9:
    lea rsi, [rel api9]
    jmp initiator
    api_10:
    lea rsi, [rel api10]
    jmp initiator
    api_11:
    lea rsi, [rel api11]
    jmp initiator
    api_12:
    lea rsi, [rel api12]
    jmp initiator
    api_13:
    lea rsi, [rel api13]
    jmp initiator
    api_14:
    lea rsi, [rel api14]
    jmp initiator

initiator:
    xor eax, eax
    
next_char:
    mov bl, [rsi]       ; load next char
    test bl, bl
    jz store_hash
    rol eax, 5          ; rotate hash left 5 bits
    xor eax, ebx        ; hash ^= char
    inc rsi
    jmp next_char

store_hash:
    ;mov [rel api1_hash], eax  ; store final hash in .bss
    push rax
    inc ecx
    cmp ecx, 1
    je api_2
    cmp ecx, 2
    je api_3
    cmp ecx, 3
    je api_4
    cmp ecx, 4
    je api_5
    cmp ecx, 5
    je api_6
    cmp ecx, 6
    je api_7
    cmp ecx, 7
    je api_8
    cmp ecx, 8
    je api_9
    cmp ecx, 9
    je api_10
    cmp ecx, 10
    je api_11
    cmp ecx, 11
    je api_12
    cmp ecx, 12
    je api_13
    cmp ecx, 13
    je api_14
    cmp ecx, 14
    je goodbye

    goodbye:
    int3
    int3
    int3
    
