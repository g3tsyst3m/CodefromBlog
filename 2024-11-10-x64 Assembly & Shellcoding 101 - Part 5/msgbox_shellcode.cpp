#include <windows.h>
#include <iostream>

// Shellcode (as given, formatted for clarity)
unsigned char shellcode[] =
"\x48\x83\xec\x28\x48\x83\xe4\xf0\x48\x31\xc9\x65\x48\x8b\x41\x60\x48\x8b\x40\x18\x48\x8b"
"\x70\x10\x48\x8b\x36\x48\x8b\x36\x48\x8b\x5e\x30\x49\x89\xd8\x8b\x5b\x3c\x4c\x01\xc3\x48"
"\x31\xc9\x66\x81\xc1\xff\x88\x48\xc1\xe9\x08\x8b\x14\x0b\x4c\x01\xc2\x44\x8b\x52\x14\x4d"
"\x31\xdb\x44\x8b\x5a\x20\x4d\x01\xc3\x4c\x89\xd1\x48\xb8\x64\x64\x72\x65\x73\x73\x90\x90"
"\x48\xc1\xe0\x10\x48\xc1\xe8\x10\x50\x48\xb8\x47\x65\x74\x50\x72\x6f\x63\x41\x50\x48\x89"
"\xe0\x67\xe3\x20\x31\xdb\x41\x8b\x1c\x8b\x4c\x01\xc3\x48\xff\xc9\x4c\x8b\x08\x4c\x39\x0b"
"\x75\xe9\x44\x8b\x48\x08\x44\x39\x4b\x08\x74\x03\x75\xdd\xcc\x51\x41\x5f\x49\xff\xc7\x4d"
"\x31\xdb\x44\x8b\x5a\x1c\x4d\x01\xc3\x43\x8b\x04\xbb\x4c\x01\xc0\x50\x41\x5f\x4d\x89\xfc"
"\x4c\x89\xc7\x4c\x89\xc1\xb8\x61\x72\x79\x41\x50\x48\xb8\x4c\x6f\x61\x64\x4c\x69\x62\x72"
"\x50\x48\x89\xe2\x48\x83\xec\x30\x41\xff\xd7\x48\x83\xc4\x30\x49\x89\xc7\x4d\x89\xe6\x48"
"\x89\xf9\xb8\x65\x73\x73\x90\xc1\xe0\x08\xc1\xe8\x08\x50\x48\xb8\x45\x78\x69\x74\x50\x72"
"\x6f\x63\x50\x48\x89\xe2\x48\x83\xec\x30\x41\xff\xd6\x48\x83\xc4\x30\x49\x89\xc6\xb8\x6c"
"\x6c\x90\x90\xc1\xe0\x10\xc1\xe8\x10\x50\x48\xb8\x75\x73\x65\x72\x33\x32\x2e\x64\x50\x48"
"\x89\xe1\x48\x83\xec\x30\x41\xff\xd7\x48\x89\xc7\x48\x89\xf9\xb8\x6f\x78\x41\x90\xc1\xe0"
"\x08\xc1\xe8\x08\x50\x48\xb8\x4d\x65\x73\x73\x61\x67\x65\x42\x50\x48\x89\xe2\x48\x83\xec"
"\x30\x41\xff\xd4\x49\x89\xc7\x48\x31\xc9\xb8\x6d\x90\x90\x90\xc1\xe0\x18\xc1\xe8\x18\x50"
"\x48\xb8\x67\x33\x74\x73\x79\x73\x74\x33\x50\x48\x89\xe2\x49\x89\xe0\x45\x31\xc9\x48\x83"
"\xec\x30\x41\xff\xd7\x48\x83\xc4\x30\x31\xc9\x41\xff\xd6";


int main() {
    // Allocate executable memory
    void* exec_mem = VirtualAlloc(0, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    if (exec_mem == nullptr) {
        std::cerr << "Memory allocation failed\n";
        return -1;
    }

    // Copy shellcode to the allocated memory
    memcpy(exec_mem, shellcode, sizeof(shellcode));

    // Create a function pointer to the shellcode
    auto shellcode_func = reinterpret_cast<void(*)()>(exec_mem);

    // Execute the shellcode
    shellcode_func();

    // Free the allocated memory
    VirtualFree(exec_mem, 0, MEM_RELEASE);

    return 0;
}