#pragma once
#include <Windows.h>
#include <winternl.h>
#include <string>
#include <vector>
#include <algorithm>
#include "DrvOps.h"

#ifndef STATUS_INFO_LENGTH_MISMATCH
#define STATUS_INFO_LENGTH_MISMATCH 0xC0000004L
#endif
#ifndef SystemHandleInformation
#define SystemHandleInformation 0x10
#endif

typedef struct _GFO_SYSTEM_HANDLE_TABLE_ENTRY_INFO {
    USHORT UniqueProcessId;
    USHORT CreatorBackTraceIndex;
    UCHAR  ObjectTypeIndex;
    UCHAR  HandleAttributes;
    USHORT HandleValue;
    PVOID  Object;
    ULONG  GrantedAccess;
} GFO_SYSTEM_HANDLE_TABLE_ENTRY_INFO;

typedef struct _GFO_SYSTEM_HANDLE_INFORMATION {
    ULONG HandleCount;
    GFO_SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
} GFO_SYSTEM_HANDLE_INFORMATION;

typedef NTSTATUS(NTAPI* pfnGFO_NtQuerySystemInformation)(
    ULONG, PVOID, ULONG, PULONG);

// FILE_OBJECT.FileName offsets (x64, Windows 10/11)
#define FILE_OBJECT_FILENAME_LENGTH_OFFSET  0x58
#define FILE_OBJECT_FILENAME_BUFFER_OFFSET  0x60

inline DWORD64 getFileObjectByName(HANDLE drv, const wchar_t* targetPath) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    auto NtQSI = (pfnGFO_NtQuerySystemInformation)GetProcAddress(ntdll, "NtQuerySystemInformation");
    if (!NtQSI) {
        printf("[-] Failed to resolve NtQuerySystemInformation\n");
        return 0;
    }

    HANDLE hRef = CreateFileW(L"C:\\Windows\\System32\\notepad.exe", FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, 0, NULL);
    if (hRef == INVALID_HANDLE_VALUE) {
        printf("[-] Failed to open reference file: %d\n", GetLastError());
        return 0;
    }

    ULONG bufSize = 1 << 23;
    std::vector<BYTE> buf(bufSize);
    NTSTATUS st;
    while ((st = NtQSI((SYSTEM_INFORMATION_CLASS)SystemHandleInformation, buf.data(), bufSize, nullptr)) == STATUS_INFO_LENGTH_MISMATCH) {
        bufSize *= 2;
        buf.resize(bufSize);
    }
    if (st != 0) {
        printf("[-] NtQuerySystemInformation failed: 0x%X\n", st);
        CloseHandle(hRef);
        return 0;
    }

    DWORD myPid = GetCurrentProcessId();
    UCHAR fileTypeIndex = 0;
    auto* info = reinterpret_cast<GFO_SYSTEM_HANDLE_INFORMATION*>(buf.data());

    for (ULONG i = 0; i < info->HandleCount; i++) {
        auto& e = info->Handles[i];
        if (e.UniqueProcessId != myPid) continue;
        if ((HANDLE)(ULONG_PTR)e.HandleValue != hRef) continue;
        fileTypeIndex = e.ObjectTypeIndex;
        break;
    }
    CloseHandle(hRef);

    if (fileTypeIndex == 0) {
        printf("[-] Could not determine File ObjectTypeIndex\n");
        return 0;
    }
    printf("[+] File ObjectTypeIndex: %d\n", fileTypeIndex);

    std::wstring targetSuffix;
    std::wstring targetWide(targetPath);
    if (targetWide.size() > 2 && targetWide[1] == L':') targetSuffix = targetWide.substr(2); 
    std::replace(targetSuffix.begin(), targetSuffix.end(), L'/', L'\\');

    DWORD64 result = 0;
    DWORD checked = 0;

    for (ULONG i = 0; i < info->HandleCount; i++) {
        auto& e = info->Handles[i];
        if (e.ObjectTypeIndex != fileTypeIndex) continue;

        DWORD64 fileObj = (DWORD64)e.Object;

        USHORT length = 0;
        if (!ReadPrimitive(drv, &length, (LPVOID)(uintptr_t)(fileObj + FILE_OBJECT_FILENAME_LENGTH_OFFSET),
            sizeof(USHORT)) || length == 0)
            continue;

        DWORD64 bufferPtr = 0;
        if (!ReadPrimitive(drv, &bufferPtr, (LPVOID)(uintptr_t)(fileObj + FILE_OBJECT_FILENAME_BUFFER_OFFSET), sizeof(DWORD64)) || bufferPtr == 0)
            continue;

        USHORT safeLen = min(length, (USHORT)1024);
        std::vector<WCHAR> nameBuf(safeLen / sizeof(WCHAR) + 1, 0);
        if (!ReadPrimitive(drv, nameBuf.data(), (LPVOID)(uintptr_t)bufferPtr, safeLen))
            continue;

        std::wstring fullName(nameBuf.data(), safeLen / sizeof(WCHAR));

        checked++;
        if (!targetSuffix.empty() && fullName.size() >= targetSuffix.size() && _wcsicmp(fullName.c_str() + fullName.size() - targetSuffix.size(), targetSuffix.c_str()) == 0) {
            wprintf(L"[+] Found! PID: %d | Object: %p | Name: %s\n", e.UniqueProcessId, e.Object, fullName.c_str());
            result = fileObj;
            break;
        }
    }

    if (result == 0)
        printf("[-] File object not found\n");

    return result;
}