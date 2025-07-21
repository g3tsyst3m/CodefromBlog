#include <windows.h>
#include <iostream>
#include <cstring>

//compilation instructions on mingw32
//x86_64-w64-mingw32-g++ -o overflow.exe overflow.cpp -fno-stack-protector -no-pie

// Disable security features to make the program vulnerable
#pragma comment(linker, "/SAFESEH:NO") // Disable SafeSEH
#pragma comment(linker, "/DYNAMICBASE:NO") // Disable ASLR
#pragma comment(linker, "/NXCOMPAT:NO") // Disable DEP


void win_function() {
    std::cout << "You have successfully exploited the program!\n";
    system("calc.exe"); // Launch calculator as a demonstration
}


void vulnerable_function() {
    char buffer[275]; // medium-size buffer for the overflow
    std::cout << "Enter some input: ";
    std::cin >> buffer; // Unsafe function vulnerable to overflow
}

int main() {
    LPVOID allocatedMemory = VirtualAlloc(
        NULL,  // Address, NULL means it is chosen by the system
        1024,  // Size in bytes
        MEM_COMMIT | MEM_RESERVE, // Allocation type
        PAGE_READWRITE // Memory protection
    );

    if (allocatedMemory != NULL) {
        printf("Memory allocated at %p\n", allocatedMemory);
    } else {
        printf("VirtualAlloc failed with error code %lu\n", GetLastError());
    }
    std::cout << "Welcome to the vulnerable program!\n";
    vulnerable_function();
    std::cout << "Goodbye!\n";
    return 0;
}
