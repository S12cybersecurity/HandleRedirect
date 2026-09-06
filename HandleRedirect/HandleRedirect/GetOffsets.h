#pragma once
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>
#include <winhttp.h>
#include <dbghelp.h>
#include <stdio.h>
#include <string>
#include <vector>
//#include <algorithm>

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "dbghelp.lib")

// Data Structures
struct PdbCodeViewInfo {
    GUID  Guid;
    DWORD Age;
    char  PdbFileName[MAX_PATH];
};

struct KernelOffsets {
    // EPROCESS struct field offsets (bytes from struct base)
    DWORD ObjectTable;
    DWORD64 ObHeaderCookie;
    DWORD UniqueProcessId;
    DWORD ActiveProcessLinks;
    DWORD64 PsInitialSystemProcess;
};

// PE Parsing 

#pragma pack(push, 1)
struct CV_INFO_PDB70 {
    DWORD CvSignature;   // 0x53445352 = 'RSDS'
    GUID  Signature;
    DWORD Age;
    char  PdbFileName[1];
};
#pragma pack(pop)

static DWORD RvaToFileOffset(PIMAGE_NT_HEADERS nt, DWORD rva) {
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++) {
        if (rva >= sec->VirtualAddress &&
            rva < sec->VirtualAddress + sec->Misc.VirtualSize)
            return rva - sec->VirtualAddress + sec->PointerToRawData;
    }
    return 0;
}

static bool GetPdbInfoFromPE(const char* exePath, PdbCodeViewInfo& out) {
    HANDLE hFile = CreateFileA(exePath, GENERIC_READ, FILE_SHARE_READ,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[-] Cannot open '%s' (err %lu)\n", exePath, GetLastError());
        return false;
    }

    LARGE_INTEGER sz{};
    GetFileSizeEx(hFile, &sz);
    std::vector<BYTE> buf(static_cast<size_t>(sz.QuadPart));
    DWORD rd = 0;
    bool ok = ReadFile(hFile, buf.data(), static_cast<DWORD>(buf.size()), &rd, nullptr)
        && rd == buf.size();
    CloseHandle(hFile);
    if (!ok) return false;

    auto* dos = reinterpret_cast<PIMAGE_DOS_HEADER>(buf.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    auto* nt = reinterpret_cast<PIMAGE_NT_HEADERS>(buf.data() + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;

    auto& dd = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
    if (!dd.VirtualAddress || !dd.Size) return false;

    DWORD ddOff = RvaToFileOffset(nt, dd.VirtualAddress);
    if (!ddOff || ddOff + dd.Size > buf.size()) return false;

    int entryCount = dd.Size / sizeof(IMAGE_DEBUG_DIRECTORY);
    auto* entries = reinterpret_cast<PIMAGE_DEBUG_DIRECTORY>(buf.data() + ddOff);

    for (int i = 0; i < entryCount; i++) {
        if (entries[i].Type != IMAGE_DEBUG_TYPE_CODEVIEW) continue;

        DWORD raw = entries[i].PointerToRawData;
        if (!raw) raw = RvaToFileOffset(nt, entries[i].AddressOfRawData);
        if (!raw || raw >= buf.size()) continue;

        auto* cv = reinterpret_cast<CV_INFO_PDB70*>(buf.data() + raw);
        if (cv->CvSignature != 0x53445352) continue;  // 'RSDS'

        out.Guid = cv->Signature;
        out.Age = cv->Age;
        strncpy_s(out.PdbFileName, cv->PdbFileName, _TRUNCATE);
        return true;
    }

    printf("[-] No CodeView RSDS entry found in PE\n");
    return false;
}

// PDB Cache Validation 

#pragma pack(push, 1)
struct MsfSuperBlock {
    char  FileMagic[0x20];
    DWORD BlockSize;
    DWORD FreeBlockMapBlock;
    DWORD NumBlocks;
    DWORD NumDirectoryBytes;
    DWORD Unknown;
    DWORD BlockMapAddr;
};
struct PdbInfoStreamHeader {
    DWORD Version;
    DWORD Signature;
    DWORD Age;
    GUID  UniqueId;
};
#pragma pack(pop)

static bool ExtractGuidFromPdb(const char* pdbPath, GUID& outGuid) {
    HANDLE hFile = CreateFileA(pdbPath, GENERIC_READ, FILE_SHARE_READ,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return false;

    LARGE_INTEGER sz{};
    GetFileSizeEx(hFile, &sz);
    std::vector<BYTE> buf(static_cast<size_t>(sz.QuadPart));
    DWORD rd = 0;
    ReadFile(hFile, buf.data(), static_cast<DWORD>(buf.size()), &rd, nullptr);
    CloseHandle(hFile);

    if (buf.size() < sizeof(MsfSuperBlock)) return false;

    // MSF 7.00 magic (null-terminated string is 32 bytes including padding)
    static const char kMsfMagic[] = "Microsoft C/C++ MSF 7.00\r\n\x1A""DS";
    auto* sb = reinterpret_cast<MsfSuperBlock*>(buf.data());
    if (memcmp(sb->FileMagic, kMsfMagic, sizeof(kMsfMagic) - 1) != 0) return false;

    DWORD bs = sb->BlockSize;
    DWORD nd = sb->NumDirectoryBytes;
    if (!bs || !nd) return false;

    DWORD nDirBlocks = (nd + bs - 1) / bs;
    DWORD bmOffset = sb->BlockMapAddr * bs;
    if (bmOffset >= buf.size()) return false;

    // Reconstruct stream directory into contiguous buffer
    auto* blockIdx = reinterpret_cast<DWORD*>(buf.data() + bmOffset);
    std::vector<BYTE> dir(nd, 0);
    DWORD written = 0;
    for (DWORD i = 0; i < nDirBlocks; i++) {
        DWORD blkOff = blockIdx[i] * bs;
        if (blkOff >= buf.size()) break;
        DWORD chunk = min(bs, nd - written);
        memcpy(dir.data() + written, buf.data() + blkOff, chunk);
        written += chunk;
    }

    // Directory layout: [NumStreams(4)] [StreamSizes(4*N)] [StreamBlockIndices...]
    DWORD numStreams = *reinterpret_cast<DWORD*>(dir.data());
    if (numStreams < 2) return false;

    auto* streamSizes = reinterpret_cast<DWORD*>(dir.data() + 4);
    auto* flatBlocks = reinterpret_cast<DWORD*>(dir.data() + 4 + numStreams * 4);

    DWORD s0Size = streamSizes[0];
    DWORD s0Blocks = (s0Size == 0xFFFFFFFF) ? 0 : (s0Size + bs - 1) / bs;

    // Stream 1 first block index sits right after all of stream 0's block indices
    DWORD s1BlockOff = flatBlocks[s0Blocks] * bs;
    if (s1BlockOff + sizeof(PdbInfoStreamHeader) > buf.size()) return false;

    outGuid = reinterpret_cast<PdbInfoStreamHeader*>(buf.data() + s1BlockOff)->UniqueId;
    return true;
}

// PDB Download via WinHTTP from Microsoft Symbol Server
static std::wstring BuildSymSrvUri(const GUID& g, DWORD age, const wchar_t* pdbName) {
    wchar_t guid[48];
    swprintf_s(guid,
        L"%08X%04X%04X%02X%02X%02X%02X%02X%02X%02X%02X%X",
        g.Data1, g.Data2, g.Data3,
        g.Data4[0], g.Data4[1], g.Data4[2], g.Data4[3],
        g.Data4[4], g.Data4[5], g.Data4[6], g.Data4[7],
        age);

    std::wstring uri = L"/download/symbols/";
    uri += pdbName; uri += L"/";
    uri += guid;    uri += L"/";
    uri += pdbName;
    return uri;
}

static bool DownloadPdb(const GUID& guid, DWORD age, const wchar_t* pdbNameW, const char* outPath) {
    std::wstring uri = BuildSymSrvUri(guid, age, pdbNameW);
    printf("[*] Downloading: https://msdl.microsoft.com%ls\n", uri.c_str());

    HINTERNET hSess = WinHttpOpen(L"PDBOffsets/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSess) { printf("[-] WinHttpOpen failed (%lu)\n", GetLastError()); return false; }

    HINTERNET hConn = WinHttpConnect(hSess, L"msdl.microsoft.com",
        INTERNET_DEFAULT_HTTPS_PORT, 0);
    HINTERNET hReq = hConn ? WinHttpOpenRequest(hConn, L"GET", uri.c_str(),
        nullptr, WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        WINHTTP_FLAG_SECURE) : nullptr;

    auto closeAll = [&] {
        if (hReq)  WinHttpCloseHandle(hReq);
        if (hConn) WinHttpCloseHandle(hConn);
        WinHttpCloseHandle(hSess);
        };

    if (!hReq) { closeAll(); return false; }

    if (!WinHttpSendRequest(hReq, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
        WINHTTP_NO_REQUEST_DATA, 0, 0, 0) ||
        !WinHttpReceiveResponse(hReq, nullptr)) {
        printf("[-] WinHTTP request failed (%lu)\n", GetLastError());
        closeAll();
        return false;
    }

    DWORD status = 0, statusLen = sizeof(status);
    WinHttpQueryHeaders(hReq,
        WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        WINHTTP_HEADER_NAME_BY_INDEX, &status, &statusLen, WINHTTP_NO_HEADER_INDEX);

    if (status != 200) {
        printf("[-] HTTP %lu from symbol server\n", status);
        closeAll();
        return false;
    }

    // Read body in chunks
    std::vector<BYTE> body;
    body.reserve(32 * 1024 * 1024);
    BYTE chunk[65536];
    DWORD rd = 0;
    while (WinHttpReadData(hReq, chunk, sizeof(chunk), &rd) && rd > 0)
        body.insert(body.end(), chunk, chunk + rd);

    closeAll();

    if (body.empty()) {
        printf("[-] Empty response from symbol server\n");
        return false;
    }

    HANDLE hFile = CreateFileA(outPath, GENERIC_WRITE, 0, nullptr,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[-] Cannot write PDB to '%s' (%lu)\n", outPath, GetLastError());
        return false;
    }
    DWORD wr = 0;
    WriteFile(hFile, body.data(), static_cast<DWORD>(body.size()), &wr, nullptr);
    CloseHandle(hFile);

    printf("[+] PDB saved: %s (%zu bytes)\n", outPath, body.size());
    return true;
}

// DbgHelp Symbol Resolution
struct SymFindCtx {
    const char* name;
    DWORD64     address;
    bool        found;
};

struct TypeFindCtx {
    const char* name;
    ULONG       typeIndex;
    bool        found;
};

static BOOL CALLBACK OnSymbol(PSYMBOL_INFO pInfo, ULONG, PVOID ctx) {
    auto* s = static_cast<SymFindCtx*>(ctx);
    if (_stricmp(pInfo->Name, s->name) == 0) {
        s->address = pInfo->Address;
        s->found = true;
        return FALSE;
    }
    return TRUE;
}

static BOOL CALLBACK OnType(PSYMBOL_INFO pInfo, ULONG, PVOID ctx) {
    auto* t = static_cast<TypeFindCtx*>(ctx);
    if (_stricmp(pInfo->Name, t->name) == 0) {
        t->typeIndex = pInfo->TypeIndex;
        t->found = true;
        return FALSE;
    }
    return TRUE;
}

// Returns RVA (offset from module base) of a named global symbol.
static DWORD64 ResolveSymbolRva(HANDLE hSym, DWORD64 modBase, const char* symName) {
    SymFindCtx ctx{ symName, 0, false };
    SymEnumSymbols(hSym, modBase, symName, OnSymbol, &ctx);
    if (!ctx.found || !ctx.address) {
        printf("[-] Symbol not found: %s\n", symName);
        return 0;
    }
    return ctx.address - modBase;
}

// Returns byte offset of a named field within a named struct.
static DWORD ResolveFieldOffset(HANDLE hSym, DWORD64 modBase,
    const char* structName, const char* fieldName) {
    TypeFindCtx tCtx{ structName, 0, false };
    SymEnumTypesByName(hSym, modBase, structName, OnType, &tCtx);
    if (!tCtx.found) {
        printf("[-] Struct not found: %s\n", structName);
        return 0;
    }

    DWORD childCount = 0;
    if (!SymGetTypeInfo(hSym, modBase, tCtx.typeIndex, TI_GET_CHILDRENCOUNT, &childCount) ||
        childCount == 0)
        return 0;

    // TI_FINDCHILDREN_PARAMS has a variable-length ChildId[] at the end
    size_t paramSz = sizeof(TI_FINDCHILDREN_PARAMS) + childCount * sizeof(ULONG);
    std::vector<BYTE> paramBuf(paramSz, 0);
    auto* params = reinterpret_cast<TI_FINDCHILDREN_PARAMS*>(paramBuf.data());
    params->Count = childCount;
    params->Start = 0;

    if (!SymGetTypeInfo(hSym, modBase, tCtx.typeIndex, TI_FINDCHILDREN, params))
        return 0;

    // Convert target field name to wide for comparison with TI_GET_SYMNAME output
    wchar_t wField[256];
    MultiByteToWideChar(CP_ACP, 0, fieldName, -1, wField, 256);

    for (DWORD i = 0; i < childCount; i++) {
        WCHAR* nameW = nullptr;
        if (!SymGetTypeInfo(hSym, modBase, params->ChildId[i], TI_GET_SYMNAME, &nameW) || !nameW)
            continue;

        bool match = (_wcsicmp(nameW, wField) == 0);
        LocalFree(nameW);  // DbgHelp allocates with LocalAlloc

        if (match) {
            DWORD offset = 0;
            SymGetTypeInfo(hSym, modBase, params->ChildId[i], TI_GET_OFFSET, &offset);
            return offset;
        }
    }

    printf("[-] Field not found: %s::%s\n", structName, fieldName);
    return 0;
}


static bool ResolveKernelOffsets(KernelOffsets& out) {
    // Locate ntoskrnl.exe
    char sysDir[MAX_PATH];
    if (!GetSystemDirectoryA(sysDir, MAX_PATH)) return false;

    char ntosPath[MAX_PATH];
    snprintf(ntosPath, MAX_PATH, "%s\\ntoskrnl.exe", sysDir);
    printf("[*] Kernel image: %s\n", ntosPath);

    // Extract CodeView PDB info from PE debug directory
    PdbCodeViewInfo pdbInfo{};
    if (!GetPdbInfoFromPE(ntosPath, pdbInfo)) {
        printf("[-] Failed to extract CodeView info from PE\n");
        return false;
    }

    // Strip any path prefix from PDB filename (keep leaf only)
    char* pdbName = pdbInfo.PdbFileName;
    for (int i = static_cast<int>(strlen(pdbInfo.PdbFileName)) - 1; i >= 0; i--) {
        if (pdbInfo.PdbFileName[i] == '\\' || pdbInfo.PdbFileName[i] == '/') {
            pdbName = &pdbInfo.PdbFileName[i + 1];
            break;
        }
    }
    printf("[*] PDB: %s  Age: %lu\n", pdbName, pdbInfo.Age);

    // Local cache path: %TEMP%\<pdbname>
    char tempDir[MAX_PATH];
    GetTempPathA(MAX_PATH, tempDir);
    char localPdb[MAX_PATH];
    snprintf(localPdb, MAX_PATH, "%s%s", tempDir, pdbName);

    // Validate cached PDB by checking its MSF stream-1 GUID
    bool needDownload = true;
    DWORD attr = GetFileAttributesA(localPdb);
    if (attr != INVALID_FILE_ATTRIBUTES && !(attr & FILE_ATTRIBUTE_DIRECTORY)) {
        GUID cachedGuid{};
        if (ExtractGuidFromPdb(localPdb, cachedGuid) && IsEqualGUID(cachedGuid, pdbInfo.Guid)) {
            printf("[+] Valid cached PDB: %s\n", localPdb);
            needDownload = false;
        }
        else {
            printf("[*] Cached PDB GUID mismatch, re-downloading\n");
        }
    }

    if (needDownload) {
        wchar_t pdbNameW[MAX_PATH];
        MultiByteToWideChar(CP_ACP, 0, pdbName, -1, pdbNameW, MAX_PATH);
        if (!DownloadPdb(pdbInfo.Guid, pdbInfo.Age, pdbNameW, localPdb)) {
            printf("[-] Failed to download PDB\n");
            return false;
        }
    }

    // Initialize DbgHelp and load the PDB
    SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS);

    // Use a unique fake handle so DbgHelp doesn't collide with any real process
    HANDLE hSym = reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(0xDEAD1234));
    if (!SymInitialize(hSym, nullptr, FALSE)) {
        printf("[-] SymInitialize failed (0x%lX)\n", GetLastError());
        return false;
    }

    wchar_t localPdbW[MAX_PATH];
    MultiByteToWideChar(CP_ACP, 0, localPdb, -1, localPdbW, MAX_PATH);

    const DWORD64 kFakeBase = 0x10000000ULL;
    DWORD64 modBase = SymLoadModuleExW(hSym, nullptr, localPdbW, nullptr,
        kFakeBase, 0, nullptr, 0);
    if (modBase == 0) {
        DWORD err = GetLastError();
        if (err != ERROR_SUCCESS) {
            printf("[-] SymLoadModuleExW failed (0x%lX)\n", err);
            SymCleanup(hSym);
            return false;
        }
        modBase = kFakeBase;  // already loaded
    }

    printf("[+] PDB loaded at base 0x%llX\n", modBase);

    // Resolve EPROCESS field offsets
    out.ObjectTable = ResolveFieldOffset(hSym, modBase, "_EPROCESS", "ObjectTable");
    out.UniqueProcessId = ResolveFieldOffset(hSym, modBase, "_EPROCESS", "UniqueProcessId");
    out.ActiveProcessLinks = ResolveFieldOffset(hSym, modBase, "_EPROCESS", "ActiveProcessLinks");
    //out.PsInitialSystemProcess = ResolveFieldOffset(hSym, modBase, "_EPROCESS", "PsInitialSystemProcess");
    out.PsInitialSystemProcess = ResolveSymbolRva(hSym, modBase, "PsInitialSystemProcess");
    out.ObHeaderCookie = ResolveSymbolRva(hSym, modBase, "ObHeaderCookie");

    SymUnloadModule64(hSym, modBase);
    SymCleanup(hSym);

    return 1;
}