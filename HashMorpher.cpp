#include <stdio.h>
#include <windows.h>
#include <stdbool.h>
#include <string.h>
#include <wincrypt.h>

#define ANSI_COLOR_RED     "\x1b[31m"
#define ANSI_COLOR_GREEN   "\x1b[32m"
#define ANSI_COLOR_YELLOW  "\x1b[33m"
#define ANSI_COLOR_MAGENTA "\x1b[35m"
#define ANSI_COLOR_BLUE    "\x1b[34m"
#define ANSI_COLOR_RESET   "\x1b[0m"

bool copyFile(const char* sourcePath, const char* destinationPath) {
    if (!CopyFileA(sourcePath, destinationPath, FALSE)) {
        printf(ANSI_COLOR_RED);
        printf("Failed to copy file. Error code: %d\n", GetLastError());
        printf(ANSI_COLOR_RESET);
        return false;
    }

    HANDLE destinationFile = CreateFileA(destinationPath, FILE_APPEND_DATA, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (destinationFile == INVALID_HANDLE_VALUE) {
        printf(ANSI_COLOR_RED);
        printf("Failed to open destination file. Error code: %d\n", GetLastError());
        printf(ANSI_COLOR_RESET);
        return false;
    }

    srand(GetTickCount());  // Initialize the random seed based on the system tick count
    unsigned char byte1 = rand() % 256;  // Generate a random value between 0 and 255
    unsigned char byte2 = rand() % 256;

    DWORD bytesWritten;
    if (!WriteFile(destinationFile, &byte1, sizeof(byte1), &bytesWritten, NULL) ||
        !WriteFile(destinationFile, &byte2, sizeof(byte2), &bytesWritten, NULL)) {
        printf(ANSI_COLOR_RED);
        printf("Failed to write bytes to file. Error code: %d\n", GetLastError());
        printf(ANSI_COLOR_RESET);
        CloseHandle(destinationFile);
        return false;
    }

    CloseHandle(destinationFile);

    return true;
}

void printFileHash(const char* filePath) {
    HANDLE fileHandle = CreateFileA(filePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (fileHandle == INVALID_HANDLE_VALUE) {
        printf(ANSI_COLOR_RED);
        printf("Failed to open file. Error code: %d\n", GetLastError());
        printf(ANSI_COLOR_RESET);
        return;
    }

    HCRYPTPROV hCryptProv;
    if (!CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        printf(ANSI_COLOR_RED);
        printf("Failed to acquire cryptographic context. Error code: %d\n", GetLastError());
        printf(ANSI_COLOR_RESET);
        CloseHandle(fileHandle);
        return;
    }

    HCRYPTHASH hHash;
    if (!CryptCreateHash(hCryptProv, CALG_MD5, 0, 0, &hHash)) {
        printf(ANSI_COLOR_RED);
        printf("Failed to create hash object. Error code: %d\n", GetLastError());
        printf(ANSI_COLOR_RESET);
        CryptReleaseContext(hCryptProv, 0);
        CloseHandle(fileHandle);
        return;
    }

    const int bufferSize = 8192;
    BYTE buffer[bufferSize];
    DWORD bytesRead;
    while (ReadFile(fileHandle, buffer, bufferSize, &bytesRead, NULL) && bytesRead > 0) {
        if (!CryptHashData(hHash, buffer, bytesRead, 0)) {
            printf(ANSI_COLOR_RED);
            printf("Failed to hash data. Error code: %d\n", GetLastError());
            printf(ANSI_COLOR_RESET);
            CryptDestroyHash(hHash);
            CryptReleaseContext(hCryptProv, 0);
            CloseHandle(fileHandle);
            return;
        }
    }

    BYTE hashValue[16];
    DWORD hashSize = sizeof(hashValue);
    if (CryptGetHashParam(hHash, HP_HASHVAL, hashValue, &hashSize, 0)) {
        printf("MD5: ");
        for (DWORD i = 0; i < hashSize; i++) {
            printf("%02x", hashValue[i]);
        }
        printf("\n");
    }
    else {
        printf(ANSI_COLOR_RED);
        printf("Failed to retrieve hash value. Error code: %d\n", GetLastError());
        printf(ANSI_COLOR_RESET);
    }

    CryptDestroyHash(hHash);
    CryptReleaseContext(hCryptProv, 0);
    CloseHandle(fileHandle);
}

int main() {
    int choice;
    const char* sourcePath;
    char destinationPath[MAX_PATH] = "";

    // ASCII art
    printf(ANSI_COLOR_RED);
    printf("\t\t\t|_| _  _|_ |\\/| _  _ _ |_  _  _\n");
    printf("\t\t\t| |(_|_\\| ||  |(_)| |_)| |(/_| \n");
    printf("\t\t\t                    |           \n");
    printf(ANSI_COLOR_RESET);
    printf(ANSI_COLOR_BLUE);
    printf("\t\t\t\t\tBy Abdulaziz Almetairy\n");
    printf("\t\t\t\t\t   github.com/oh-az\n\n\n");
    printf(ANSI_COLOR_RESET);

    printf(ANSI_COLOR_GREEN);
    printf("Select an option:\n\n");
    printf("1: CMD\n");
    printf("2: Powershell\n");
    printf("3: Powershell_ise\n");
    printf("4: Custom path\n\n");
    printf("#  ");
    printf(ANSI_COLOR_RESET);
    scanf_s("%d", &choice);

    switch (choice) {
    case 1:
        sourcePath = "C:\\Windows\\System32\\cmd.exe";
        break;
    case 2:
        sourcePath = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
        break;
    case 3:
        sourcePath = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\PowerShell_ise.exe";
        break;
    case 4:
        printf(ANSI_COLOR_GREEN);
        printf("Enter custom source path: ");
        printf(ANSI_COLOR_RESET);
        char customSourcePath[MAX_PATH];
        scanf_s("%s", customSourcePath, sizeof(customSourcePath));
        sourcePath = customSourcePath;
        break;
    default:
        printf(ANSI_COLOR_RED);
        printf("Invalid choice.\n");
        printf(ANSI_COLOR_RESET);
        return 1;
    }
    printf(ANSI_COLOR_GREEN);
    printf("Enter destination path (leave empty for current directory): ");
    printf(ANSI_COLOR_RESET);
    getchar();  // Consume the newline character after choice input

    char input[MAX_PATH];
    fgets(input, sizeof(input), stdin);
    input[strcspn(input, "\n")] = '\0';  // Remove trailing newline character

    if (strcmp(input, "") != 0) {
        strncpy_s(destinationPath, sizeof(destinationPath), input, _TRUNCATE);
    }
    else {
        // If the destination path is empty, use the current directory with the copied file name appended with "_new"
        const char* fileName = strrchr(sourcePath, '\\');
        if (fileName == NULL) {
            printf(ANSI_COLOR_RED);
            printf("Invalid source path.\n");
            printf(ANSI_COLOR_RESET);
            return 1;
        }
        fileName++;  // Move past the '\' character
        const char* dot = strrchr(fileName, '.');
        if (dot != NULL) {
            strncpy_s(destinationPath, sizeof(destinationPath), fileName, dot - fileName);
            strcat_s(destinationPath, sizeof(destinationPath), "_new");
            strcat_s(destinationPath, sizeof(destinationPath), dot);
        }
        else {
            strcpy_s(destinationPath, sizeof(destinationPath), fileName);
            strcat_s(destinationPath, sizeof(destinationPath), "_new");
        }
    }

    if (copyFile(sourcePath, destinationPath)) {
        char fullPath[MAX_PATH];
        if (GetFullPathNameA(destinationPath, sizeof(fullPath), fullPath, NULL) == 0) {
            printf(ANSI_COLOR_RED);
            printf("Failed to get full path of the destination file. Error code: %d\n", GetLastError());
            printf(ANSI_COLOR_RESET);
        }
        else {
            printf(ANSI_COLOR_GREEN);
            printf("\nFile copied successfully to: %s\n\n", fullPath);
            printf(ANSI_COLOR_MAGENTA);
            printf("Calculating hash values...\n\n");
            printf(ANSI_COLOR_YELLOW);
            printf("Old File Hash:\n");
            printFileHash(sourcePath);
            printf(ANSI_COLOR_BLUE);
            printf("\nNew File Hash:\n");
            printFileHash(destinationPath);
            printf(ANSI_COLOR_RESET);
        }
    }
    else {
        printf(ANSI_COLOR_RED);
        printf("File copy failed.\n");
        printf(ANSI_COLOR_RESET);
    }

    return 0;
}
