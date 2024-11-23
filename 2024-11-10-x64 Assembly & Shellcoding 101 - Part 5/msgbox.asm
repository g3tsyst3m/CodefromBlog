;nasm -fwin64 [x64findkernel32.asm]
;ld -m i386pep -o x64findkernel32.exe x64findkernel32.obj
BITS 64
SECTION .text
global main
main:
sub rsp, 0x28
and rsp, 0xFFFFFFFFFFFFFFF0
xor rcx, rcx                  ; RCX = 0
mov rax, [gs:rcx + 0x60]      ; RAX = PEB
mov rax, [rax + 0x18]         ; RAX = PEB->Ldr
mov rsi,[rax+0x10]            ; PEB.Ldr->InMemOrderModuleList
mov rsi, [rsi]
mov rsi,[rsi]
mov rbx, [rsi+0x30]           ; kernel32.dll base address
mov r8, rbx                   ; mov kernel32.dll base addr into r8
mov ebx, [rbx+0x3C]           ; Get Kernel32 PE Signature (offset 0x3C) into EBX
add rbx, r8                   ; Add signature offset to kernel32 base. Store in RBX.
xor rcx, rcx                  ; Avoid null bytes from mov edx,[rbx+0x88] by using rcx register to add
add cx, 0x88ff                ; cx is the lower 16 bit portion of ecx (32 bit), and rcx is 64 bit.
shr rcx, 0x8                  ; RCX = 0x88ff --> 0x88
mov edx, [rbx+rcx]            ; EDX = [&NewEXEHeader + Offset RVA ExportTable] = RVA ExportTable
add rdx, r8                   ; RDX = kernel32.dll + RVA ExportTable = ExportTable Address
mov r10d, [rdx+0x14]          ; Number of functions
xor r11, r11                  ; Zero R11 before use
mov r11d, [rdx+0x20]          ; AddressOfNames RVA
add r11, r8                   ; AddressOfNames VMA
mov rcx, r10                  ; store number of functions for future use
mov rax, 0x9090737365726464     ; 'ddress'
shl rax, 0x10                  ; 7373657264640000
shr rax, 0x10                  ; 0000737365726464 terminate our string w/ no nulls present in our shellcode!
push rax
mov rax, 0x41636F7250746547   ; 'GetProcA '
push rax
mov rax, rsp	
kernel32findfunction:             ; Loop over Export Address Table to find WinApi names
    jecxz FunctionNameNotFound    ; Loop around this function until we find WinExec
    xor ebx,ebx                   ; Zero EBX for use
    mov ebx, [r11+rcx*4]        ; EBX = RVA for first AddressOfName
    add rbx, r8                   ; RBX = Function name VMA / add kernel32 base address to RVA and get WinApi name
    dec rcx                       ; Decrement our loop by one, this goes from Z to A
    ; Load first 8 bytes of "LoadLibrary"
    mov r9, qword [rax]                ; R9 = "GetProcA"
    cmp [rbx], r9                      ; Compare first 8 bytes
    jnz kernel32findfunction            ; If not equal, continue loop
    ; Check next part for "aryA" (4 bytes)
    mov r9d, dword [rax + 8]           ; R9 = "ddress"
    cmp [rbx + 8], r9d                 ; Compare remaining part
    jz FunctionNameFound               ; If match, function found
	jnz kernel32findfunction
FunctionNameNotFound:
    int3
FunctionNameFound:
    push rcx
    pop r15         ;getprocaddress position
    inc r15   
    xor r11, r11
    mov r11d, [rdx+0x1c]            ; AddressOfFunctions RVA
    add r11, r8                     ; AddressOfFunctions VMA in R11. Kernel32+RVA for addressoffunctions
    mov eax, [r11+r15*4]            ; Get the function RVA.
    add rax, r8                     ; Found the GetProcAddress WinApi!!!
    push rax                        ; push GetProcAddress temporarily to be used by next segment
; Prepare arguments for getting handle to LoadLibraryA:
    pop r15                         ; temporary use
    mov r12, r15                    ; save copy of GetProcAddress for future use
    mov rdi, r8                     ; make a copy of kernel32 base address for future use
    mov rcx, r8                     ; RCX = handle to kernel32.dll (first argument)
; Load "LoadLibraryA" onto the stack
    mov rax, 0x41797261             ; aryA, 0 (include null byte)
    push rax
    mov rax, 0x7262694C64616F4C     ; LoadLibr 
    push rax
    mov rdx, rsp	                 ; RDX points to "LoadLibraryA" (second argument)
    sub rsp, 0x30                    ; decimal 48 ( 3 x 16 bytes)
    call r15                         ; Call GetProcAddress
    add rsp, 0x30
    mov r15, rax                     ;holds LoadLibraryA!
;getexitprocess
    mov r14, r12                         ;temporary assignment of GetProcess handle
    mov rcx, rdi                         ; RCX = handle to kernel32.dll (first argument)
; Load "ExitProcess" onto the stack
    mov rax, 0x90737365              ; 'ess'
    shl eax, 0x8                     ; 0000000073736500
    shr eax, 0x8                     ; 0000000000737365 terminate our string w/ no nulls present in our shellcode!
    push rax
    mov rax, 0x636F725074697845      ; ExitProc 
    push rax
    mov rdx, rsp	                 ; RDX points to "ExitProcess" (second argument)
    sub rsp, 0x30
    call r14                         ; Call GetProcAddress
    add rsp, 0x30
    mov r14, rax                     ; holds ExitProcess!
;locate user32.dll
    mov rax, 0x90906C6C              ; add "ll" string to RAX
    shl eax, 0x10                    ; 000000006C6C0000
    shr eax, 0x10                    ; 0000000000006C6C
    push rax                         ; push RAX to stack
    mov rax, 0x642E323372657375      ; Add "user32.d" string to RAX.
    push rax                         ; Push RAX to stack
    mov rcx, rsp                     ; Move a pointer to User32.dll into RCX.
    sub rsp, 0x30
    call r15                         ; Call LoadLibraryA("user32.dll")
    mov rdi, rax                     ; holds User32.dll address
; Prepare arguments for GetProcAddress for MessageBoxA:
    mov rcx, rdi                     ; RCX = handle to user32.dll (first argument)
    mov rax, 0x9041786F              ; Load "oxA" into RAX
    shl eax, 0x8                     ; 0000000041786F00
    shr eax, 0x8                     ; 000000000041786F
    push rax
    mov rax, 0x426567617373654D      ; Load "MessageB" into RAX                  
    push rax
    mov rdx, rsp                     ; RDX points to "MessageBoxA" (second argument)
    sub rsp, 0x30
    call r12                         ; Call GetProcAddress
    mov r15, rax                     ; store MessageBoxA
;messageboxfinally: 
    xor rcx, rcx                     ; hWnd = NULL (no owner window)
	mov rax, 0x9090906D              ; m, 0
	shl eax, 24                      ; 000000006D000000
    shr eax, 24                      ; 000000000000006D
    push rax
	mov rax, 0x3374737973743367      ;g3tsyst3
	push rax
	mov rdx, rsp                     ; lpText = pointer to message
    mov r8, rsp                      ; lpCaption = pointer to title
    xor r9d, r9d                     ; uType = MB_OK (OK button only)
    sub rsp, 0x30
    call r15                         ; Call MessageBoxA
	add rsp, 0x30
;exitcleanly:
    xor ecx, ecx
    call r14 ;ExitProcess