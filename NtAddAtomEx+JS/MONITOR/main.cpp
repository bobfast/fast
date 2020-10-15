//////////////////////////////////////////////////////////////////////////////
//
//  Test DetourCreateProcessfast function (fast.cpp).
//
//  Microsoft Research Detours Package
//
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//
#include <stdio.h>
#include <windows.h>
#include "tchar.h"
#include <tlhelp32.h>
#include <detours.h>
#include <string>
#pragma warning(push)
#if _MSC_VER > 1400
#pragma warning(disable : 6102 6103) // /analyze warnings
#endif
#include <strsafe.h>
#pragma warning(pop)


typedef struct shared {
    char dllout[256];
    DWORD thispid;
}shared;

//////////////////////////////////////////////////////////////////////////////
//
void PrintUsage(void)
{
    printf("Usage:\n"
        "    fast.exe [options] [command line]\n"
        "    fast.exe /d:simple64.dll \n"
        "    fast.exe /f /d:simple64.dll \n"
        "Options:\n"
        "    /d:file.dll   : Start the process with file.dll.\n"
        "    /v            : Verbose, display memory at start.\n"
        "    /f            : FreeLibrary dlls.\n"
        "    /?            : This help screen.\n");
}

//////////////////////////////////////////////////////////////////////////////
//
//  This code verifies that the named DLL has been configured correctly
//  to be imported into the target process.  DLLs must export a function with
//  ordinal #1 so that the import table touch-up magic works.
//
struct ExportContext
{
    BOOL fHasOrdinal1;
    ULONG nExports;
};

static BOOL CALLBACK ExportCallback(_In_opt_ PVOID pContext,
    _In_ ULONG nOrdinal,
    _In_opt_ LPCSTR pszSymbol,
    _In_opt_ PVOID pbTarget)
{
    (void)pContext;
    (void)pbTarget;
    (void)pszSymbol;

    ExportContext* pec = (ExportContext*)pContext;

    if (nOrdinal == 1)
    {
        pec->fHasOrdinal1 = TRUE;
    }
    pec->nExports++;

    return TRUE;
}

//////////////////////////////////////////////////////////////////////////////
//

//////////////////////////////////////////////////////////////////////////////
//

void TypeToString(DWORD Type, char* pszBuffer, size_t cBuffer)
{
    if (Type == MEM_IMAGE)
    {
        StringCchPrintfA(pszBuffer, cBuffer, "img");
    }
    else if (Type == MEM_MAPPED)
    {
        StringCchPrintfA(pszBuffer, cBuffer, "map");
    }
    else if (Type == MEM_PRIVATE)
    {
        StringCchPrintfA(pszBuffer, cBuffer, "pri");
    }
    else
    {
        StringCchPrintfA(pszBuffer, cBuffer, "%x", Type);
    }
}

void StateToString(DWORD State, char* pszBuffer, size_t cBuffer)
{
    if (State == MEM_COMMIT)
    {
        StringCchPrintfA(pszBuffer, cBuffer, "com");
    }
    else if (State == MEM_FREE)
    {
        StringCchPrintfA(pszBuffer, cBuffer, "fre");
    }
    else if (State == MEM_RESERVE)
    {
        StringCchPrintfA(pszBuffer, cBuffer, "res");
    }
    else
    {
        StringCchPrintfA(pszBuffer, cBuffer, "%x", State);
    }
}

void ProtectToString(DWORD Protect, char* pszBuffer, size_t cBuffer)
{
    if (Protect == 0)
    {
        StringCchPrintfA(pszBuffer, cBuffer, "");
    }
    else if (Protect == PAGE_EXECUTE)
    {
        StringCchPrintfA(pszBuffer, cBuffer, "--x");
    }
    else if (Protect == PAGE_EXECUTE_READ)
    {
        StringCchPrintfA(pszBuffer, cBuffer, "r-x");
    }
    else if (Protect == PAGE_EXECUTE_READWRITE)
    {
        StringCchPrintfA(pszBuffer, cBuffer, "rwx");
    }
    else if (Protect == PAGE_EXECUTE_WRITECOPY)
    {
        StringCchPrintfA(pszBuffer, cBuffer, "rcx");
    }
    else if (Protect == PAGE_NOACCESS)
    {
        StringCchPrintfA(pszBuffer, cBuffer, "---");
    }
    else if (Protect == PAGE_READONLY)
    {
        StringCchPrintfA(pszBuffer, cBuffer, "r--");
    }
    else if (Protect == PAGE_READWRITE)
    {
        StringCchPrintfA(pszBuffer, cBuffer, "rw-");
    }
    else if (Protect == PAGE_WRITECOPY)
    {
        StringCchPrintfA(pszBuffer, cBuffer, "rc-");
    }
    else if (Protect == (PAGE_GUARD | PAGE_EXECUTE))
    {
        StringCchPrintfA(pszBuffer, cBuffer, "g--x");
    }
    else if (Protect == (PAGE_GUARD | PAGE_EXECUTE_READ))
    {
        StringCchPrintfA(pszBuffer, cBuffer, "gr-x");
    }
    else if (Protect == (PAGE_GUARD | PAGE_EXECUTE_READWRITE))
    {
        StringCchPrintfA(pszBuffer, cBuffer, "grwx");
    }
    else if (Protect == (PAGE_GUARD | PAGE_EXECUTE_WRITECOPY))
    {
        StringCchPrintfA(pszBuffer, cBuffer, "grcx");
    }
    else if (Protect == (PAGE_GUARD | PAGE_NOACCESS))
    {
        StringCchPrintfA(pszBuffer, cBuffer, "g---");
    }
    else if (Protect == (PAGE_GUARD | PAGE_READONLY))
    {
        StringCchPrintfA(pszBuffer, cBuffer, "gr--");
    }
    else if (Protect == (PAGE_GUARD | PAGE_READWRITE))
    {
        StringCchPrintfA(pszBuffer, cBuffer, "grw-");
    }
    else if (Protect == (PAGE_GUARD | PAGE_WRITECOPY))
    {
        StringCchPrintfA(pszBuffer, cBuffer, "grc-");
    }
    else
    {
        StringCchPrintfA(pszBuffer, cBuffer, "%x", Protect);
    }
}

static BYTE buffer[65536];

typedef union
{
    struct
    {
        DWORD Signature;
        IMAGE_FILE_HEADER FileHeader;
    } ih;

    IMAGE_NT_HEADERS32 ih32;
    IMAGE_NT_HEADERS64 ih64;
} IMAGE_NT_HEADER;

struct SECTIONS
{
    PBYTE pbBeg;
    PBYTE pbEnd;
    CHAR szName[16];
} Sections[256];
DWORD SectionCount = 0;
DWORD Bitness = 0;

PCHAR FindSectionName(PBYTE pbBase, PBYTE& pbEnd)
{
    for (DWORD n = 0; n < SectionCount; n++)
    {
        if (Sections[n].pbBeg == pbBase)
        {
            pbEnd = Sections[n].pbEnd;
            return Sections[n].szName;
        }
    }
    pbEnd = NULL;
    return NULL;
}

ULONG PadToPage(ULONG Size)
{
    return (Size & 0xfff)
        ? Size + 0x1000 - (Size & 0xfff)
        : Size;
}

BOOL GetSections(HANDLE hp, PBYTE pbBase)
{
    DWORD beg = 0;
    DWORD cnt = 0;
    SIZE_T done;
    IMAGE_DOS_HEADER idh;

    if (!ReadProcessMemory(hp, pbBase, &idh, sizeof(idh), &done) || done != sizeof(idh))
    {
        return FALSE;
    }

    if (idh.e_magic != IMAGE_DOS_SIGNATURE)
    {
        return FALSE;
    }

    IMAGE_NT_HEADER inh;
    if (!ReadProcessMemory(hp, pbBase + idh.e_lfanew, &inh, sizeof(inh), &done) || done != sizeof(inh))
    {
        printf("No Read\n");
        return FALSE;
    }

    if (inh.ih.Signature != IMAGE_NT_SIGNATURE)
    {
        printf("No NT\n");
        return FALSE;
    }

    beg = idh.e_lfanew + FIELD_OFFSET(IMAGE_NT_HEADERS, OptionalHeader) + inh.ih.FileHeader.SizeOfOptionalHeader;
    cnt = inh.ih.FileHeader.NumberOfSections;
    Bitness = (inh.ih32.OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) ? 32 : 64;
#if 0
    printf("%d %d count=%d\n", beg, Bitness, cnt);
#endif

    IMAGE_SECTION_HEADER ish;
    for (DWORD n = 0; n < cnt; n++)
    {
        if (!ReadProcessMemory(hp, pbBase + beg + n * sizeof(ish), &ish, sizeof(ish), &done) || done != sizeof(ish))
        {
            printf("No Read\n");
            return FALSE;
        }
        Sections[n].pbBeg = pbBase + ish.VirtualAddress;
        Sections[n].pbEnd = pbBase + ish.VirtualAddress + PadToPage(ish.Misc.VirtualSize);
        memcpy(Sections[n].szName, ish.Name, sizeof(ish.Name));
        Sections[n].szName[sizeof(ish.Name)] = '\0';
#if 0
        printf("--- %p %s\n", Sections[n].pbBeg, Sections[n].szName);
#endif
    }
    SectionCount = cnt;

    return TRUE;
}

BOOL DumpProcess(HANDLE hp)
{
    ULONG64 base;
    ULONG64 next;

    MEMORY_BASIC_INFORMATION mbi;

    printf("  %12s %8s %8s: %3s %3s %4s %3s : %8s\n", "Address", "Offset", "Size", "Typ", "Sta", "Prot", "Ini", "Contents");
    printf("  %12s %8s %8s: %3s %3s %4s %3s : %8s\n", "------------", "--------", "--------", "---", "---", "----", "---", "-----------------");

    for (next = 0;;)
    {
        base = next;
        ZeroMemory(&mbi, sizeof(mbi));
        if (VirtualQueryEx(hp, (PVOID)base, &mbi, sizeof(mbi)) == 0)
        {
            break;
        }
        if ((mbi.RegionSize & 0xfff) == 0xfff)
        {
            break;
        }

        next = (ULONG64)mbi.BaseAddress + mbi.RegionSize;

        if (mbi.State == MEM_FREE)
        {
            continue;
        }

        CHAR szType[16];
        TypeToString(mbi.Type, szType, ARRAYSIZE(szType));
        CHAR szState[16];
        StateToString(mbi.State, szState, ARRAYSIZE(szState));
        CHAR szProtect[16];
        ProtectToString(mbi.Protect, szProtect, ARRAYSIZE(szProtect));
        CHAR szAllocProtect[16];
        ProtectToString(mbi.AllocationProtect, szAllocProtect, ARRAYSIZE(szAllocProtect));

        CHAR szFile[MAX_PATH];
        szFile[0] = '\0';
        DWORD cb = 0;
        PCHAR pszFile = szFile;

        if (base == (ULONG64)mbi.AllocationBase)
        {
#if 0
            cb = pfGetMappedFileName(hp, (PVOID)mbi.AllocationBase, szFile, ARRAYSIZE(szFile));
#endif
            if (GetSections(hp, (PBYTE)mbi.AllocationBase))
            {
                next = base + 0x1000;
                StringCchPrintfA(szFile, ARRAYSIZE(szFile), "%d-bit PE", Bitness);
            }
        }
        if (cb > 0)
        {
            for (DWORD c = 0; c < cb; c++)
            {
                szFile[c] = (szFile[c] >= 'a' && szFile[c] <= 'z')
                    ? szFile[c] - 'a' + 'A'
                    : szFile[c];
            }
            szFile[cb] = '\0';
        }

        if ((pszFile = strrchr(szFile, '\\')) == NULL)
        {
            pszFile = szFile;
        }
        else
        {
            pszFile++;
        }

        PBYTE pbEnd;
        PCHAR pszSect = FindSectionName((PBYTE)base, pbEnd);
        if (pszSect != NULL)
        {
            pszFile = pszSect;
            if (next > (ULONG64)pbEnd)
            {
                next = (ULONG64)pbEnd;
            }
        }

        CHAR szDesc[128];
        ZeroMemory(&szDesc, ARRAYSIZE(szDesc));
        if (base == (ULONG64)mbi.AllocationBase)
        {
            StringCchPrintfA(szDesc, ARRAYSIZE(szDesc), "  %12I64x %8I64x %8I64x: %3s %3s %4s %3s : %s",
                (ULONG64)base,
                (ULONG64)base - (ULONG64)mbi.AllocationBase,
                (ULONG64)next - (ULONG64)base,
                szType,
                szState,
                szProtect,
                szAllocProtect,
                pszFile);
        }
        else
        {
            StringCchPrintfA(szDesc, ARRAYSIZE(szDesc), "  %12s %8I64x %8I64x: %3s %3s %4s %3s : %s",
                "-",
                (ULONG64)base - (ULONG64)mbi.AllocationBase,
                (ULONG64)next - (ULONG64)base,
                szType,
                szState,
                szProtect,
                szAllocProtect,
                pszFile);
        }
        printf("%s\n", szDesc);
    }
    return TRUE;
}

typedef enum _SECTION_INHERIT
{
    ViewShare = 1,
    ViewUnmap = 2
} SECTION_INHERIT;

static NTSTATUS(*PNtMapViewOfSection)(
    HANDLE SectionHandle,
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    SIZE_T CommitSize,
    PLARGE_INTEGER SectionOffset,
    PSIZE_T ViewSize,
    SECTION_INHERIT InheritDisposition,
    ULONG AllocationType,
    ULONG Win32Protect);

DWORD findPidByName(const char* pname)
{
    HANDLE h;
    PROCESSENTRY32 procSnapshot;
    h = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    procSnapshot.dwSize = sizeof(PROCESSENTRY32);

    do
    {
        if (!strcmp((const char*)procSnapshot.szExeFile, pname))
        {
            DWORD pid = procSnapshot.th32ProcessID;
            CloseHandle(h);
            return pid;
        }
    } while (Process32Next(h, &procSnapshot));

    CloseHandle(h);
    return 0;
}

HMODULE findRemoteHModule(DWORD dwProcessId, const char* szdllout)
{
    MODULEENTRY32 me = { sizeof(me) };
    BOOL bMore = FALSE;
    HANDLE hSnapshot;


    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwProcessId);
    if (hSnapshot == (HANDLE)-1) {
        printf("CreateToolhelp32Snapshot Failed.\n");
    }
    bMore = Module32First(hSnapshot, &me);
    for (; bMore; bMore = Module32Next(hSnapshot, &me))
    {
        //printf("%s\n", (LPCSTR)me.szModule);
        //wprintf(L"%s\n", (LPCWSTR)me.szExePath);
        //printf("%s\n", szdllout);
        if (
            //!_stricmp((LPCSTR)me.szModule, szdllout) ||
            !_tcsicmp((LPCTSTR)me.szExePath, szdllout))
        {
            printf("find!\n");
            //wprintf(L"%s\n", (LPCWSTR)me.szExePath);
            return (HMODULE)me.modBaseAddr;
        }
    }
    return NULL;
}



void CallVirtualAllocEx(LPVOID monMMF) {

   //pid // printf("%d\n", atoi((char*)monMMF));
   //size //printf("%s\n", (char*)monMMF+sizeof(DWORD)*3);
    printf("%s%s\n", (char*)monMMF,(char*)monMMF + sizeof(DWORD) * 6);
   // address//printf("%lp\n",  (char*)monMMF + sizeof(DWORD) * 30);
    std::string buf(std::to_string(GetCurrentProcessId()));
    buf.append(":CallVirtualAllocEx:Response Sended!");
    memcpy(monMMF, buf.c_str(), buf.size());
}

void CallLoadLibraryA(LPVOID monMMF) {

    printf("%s\n", (char*)monMMF);
    std::string buf(std::to_string(GetCurrentProcessId()));
    buf.append(":CallNtProtectVirtualMemory:Response Sended!");
    memcpy(monMMF, buf.c_str(), buf.size());
}

void CallWriteProcessMemory(LPVOID monMMF) {

    printf("%s\n", (char*)monMMF);
    std::string buf(std::to_string(GetCurrentProcessId()));
    buf.append(":CallNtWriteVirtualMemory:Response Sended!");
    memcpy(monMMF, buf.c_str(), buf.size());
}

void CallCreateRemoteThread(LPVOID monMMF) {

    printf("%s\n", (char*)monMMF);
    std::string buf(std::to_string(GetCurrentProcessId()));
    buf.append(":CallNtCreateThreadEx:Response Sended!");
    memcpy(monMMF, buf.c_str(), buf.size());
}

void CallNtMapViewOfSection(LPVOID monMMF) {

    printf("%s\n", (char*)monMMF);
    std::string buf(std::to_string(GetCurrentProcessId()));
    buf.append(":CallNtMapViewOfSection:Response Sended!");
    memcpy(monMMF, buf.c_str(), buf.size());
}

void CallCreateFileMappingA(LPVOID monMMF) {

    printf("%s\n", (char*)monMMF);
    std::string buf(std::to_string(GetCurrentProcessId()));
    buf.append(":CallCreateFileMappingA:Response Sended!");
    memcpy(monMMF, buf.c_str(), buf.size());
}

void CallGetThreadContext(LPVOID monMMF) {

    printf("%s\n", (char*)monMMF);
    std::string buf(std::to_string(GetCurrentProcessId()));
    buf.append(":CallNtGetThreadContext:Response Sended!");
    memcpy(monMMF, buf.c_str(), buf.size());
}

void CallSetThreadContext(LPVOID monMMF) {

    printf("%s\n", (char*)monMMF);
    std::string buf(std::to_string(GetCurrentProcessId()));
    buf.append(":CallNtSetThreadContext:Response Sended!");
    memcpy(monMMF, buf.c_str(), buf.size());
}

void CallNtQueueApcThread(LPVOID monMMF) {

    printf("%s\n", (char*)monMMF);
    std::string buf(std::to_string(GetCurrentProcessId()));
    buf.append(":CallNtQueueApcThread:Response Sended!");
    memcpy(monMMF, buf.c_str(), buf.size());
}

void CallSetWindowLongPtrA(LPVOID monMMF) {

    printf("%s\n", (char*)monMMF);
    std::string buf(std::to_string(GetCurrentProcessId()));
    buf.append(":CallSetWindowLongPtrA:Response Sended!");
    memcpy(monMMF, buf.c_str(), buf.size());
}


void CallSleepEx(LPVOID monMMF) {

    printf("%s\n", (char*)monMMF);
    std::string buf(std::to_string(GetCurrentProcessId()));
    buf.append(":CallSleepEx:Response Sended!");
    memcpy(monMMF, buf.c_str(), buf.size());
}




//////////////////////////////////////////////////////////////////////// main.
//
int CDECL main(int argc, char** argv)
{
    BOOLEAN fNeedHelp = FALSE;
    BOOLEAN fVerbose = FALSE;
    BOOLEAN isFree = FALSE;
    LPCSTR rpszDllsRaw[256];
    LPCSTR rpszDllsOut[256];
    DWORD nDlls = 0;

    for (DWORD n = 0; n < ARRAYSIZE(rpszDllsRaw); n++)
    {
        rpszDllsRaw[n] = NULL;
        rpszDllsOut[n] = NULL;
    }

    int arg = 1;
    for (; arg < argc && (argv[arg][0] == '-' || argv[arg][0] == '/'); arg++)
    {

        CHAR* argn = argv[arg] + 1;
        CHAR* argp = argn;
        while (*argp && *argp != ':' && *argp != '=')
            argp++;
        if (*argp == ':' || *argp == '=')
            *argp++ = '\0';

        switch (argn[0])
        {
        case 'd': // Set DLL Name
        case 'D':
            if (nDlls < ARRAYSIZE(rpszDllsRaw))
            {
                rpszDllsRaw[nDlls++] = argp;
            }
            else
            {
                printf("fast.exe: Too many DLLs.\n");
                fNeedHelp = TRUE;
                break;
            }
            break;

        case 'v': // Verbose
        case 'V':
            fVerbose = TRUE;
            break;

        case '?': // Help
            fNeedHelp = TRUE;
            break;

        case 'f': // free
            isFree = TRUE;
            break;

        default:
            fNeedHelp = TRUE;
            printf("fast.exe: Bad argument: %s\n", argv[arg]);
            break;
        }
    }

    if (--arg >= argc)
    {
        fNeedHelp = TRUE;
    }

    if (nDlls == 0)
    {
        fNeedHelp = TRUE;
    }

    if (fNeedHelp)
    {
        PrintUsage();
        return 9001;
    }

    ///////////////////////////////////////////////////////// Validate DLLs.

    for (DWORD n = 0; n < nDlls; n++)
    {
        CHAR szDllPath[1024];
        PCHAR pszFilePart = NULL;

        if (!GetFullPathNameA(rpszDllsRaw[n], ARRAYSIZE(szDllPath), szDllPath, &pszFilePart))
        {
            printf("fast.exe: Error: %s is not a valid path name..\n",
                rpszDllsRaw[n]);
            return 9002;
        }

        DWORD c = (DWORD)strlen(szDllPath) + 1;
        PCHAR psz = new CHAR[c];
        StringCchCopyA(psz, c, szDllPath);
        rpszDllsOut[n] = psz;

        HMODULE hDll = LoadLibraryExA(rpszDllsOut[n], NULL, DONT_RESOLVE_DLL_REFERENCES);
        if (hDll == NULL)
        {
            printf("fast.exe: Error: %s failed to load (error %ld).\n",
                rpszDllsOut[n],
                GetLastError());
            return 9003;
        }

        ExportContext ec;
        ec.fHasOrdinal1 = FALSE;
        ec.nExports = 0;
        DetourEnumerateExports(hDll, &ec, ExportCallback);
        FreeLibrary(hDll);

        if (!ec.fHasOrdinal1)
        {
            printf("fast.exe: Error: %s does not export ordinal #1.\n",
                rpszDllsOut[n]);
            printf("             See help entry DetourCreateProcessfastEx in Detours.chm.\n");
            return 9004;
        }
    }

    CHAR szCommand[2048];

    printf("fast.exe: Starting: `%s'\n", szCommand);
    for (DWORD n = 0; n < nDlls; n++)
    {
        printf("fast.exe:   with `%s'\n", rpszDllsOut[n]);
    }
    fflush(stdout);


    SetLastError(0);

    SendMessage(HWND_BROADCAST, WM_SETTINGCHANGE, 0, (LPARAM)TEXT("Environment"));
    char* pValue2 = NULL;
    size_t len = NULL;
    _dupenv_s(&pValue2, &len, "path");
    printf("_dupenv_s() : %s, %zd\n", pValue2, len);
    TOKEN_PRIVILEGES tp;
    BOOL bResult = FALSE;
    HANDLE hToken = NULL;
    DWORD dwSize;

    ZeroMemory(&tp, sizeof(tp));
    tp.PrivilegeCount = 1;

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken) &&
        LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid))
    {
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        bResult = AdjustTokenPrivileges(hToken, FALSE, &tp, 0, NULL, &dwSize);
    }
    CloseHandle(hToken);

    HANDLE hProcess = NULL, hThread = NULL;
    HMODULE hMod = NULL;


    LPTHREAD_START_ROUTINE pThreadProc = NULL;

    HANDLE fm = NULL;
    char* map_addr;
    LPVOID lpMap = 0;
    SIZE_T viewsize = 0;
    PNtMapViewOfSection = (NTSTATUS(*)(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID * BaseAddress, ULONG_PTR ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, SECTION_INHERIT InheritDisposition, ULONG AllocationType, ULONG Win32Protect)) GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtMapViewOfSection");

    hMod = GetModuleHandleA("kernel32.dll");
    if (!hMod)
    {
        return FALSE;
    }



    LPCSTR sz = NULL;
    DWORD dwBufSize = 0;
    DWORD thispid = GetCurrentProcessId();


    if (!isFree)
    {
        printf("Injection...\n");
        pThreadProc = (LPTHREAD_START_ROUTINE)GetProcAddress(hMod, "LoadLibraryA");


    }
    else
    {
        printf("Freeing...\n");
        pThreadProc = (LPTHREAD_START_ROUTINE)GetProcAddress(hMod, "FreeLibrary");

    }

    if (!pThreadProc)
    {
        return FALSE;
    }

    // if (fVerbose)
    // {
    //     DumpProcess(hProcess);
    // }

    // //WaitForSingleObject(hThread, INFINITE);
    // CloseHandle(hThread);
    // CloseHandle(hProcess);

    if (!isFree)
    {
        sz = rpszDllsOut[0];
        dwBufSize = (DWORD)(strlen(sz) + 1) * sizeof(char);

        fm = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE,
            0,
            (DWORD)((dwBufSize + sizeof(DWORD) + 11 * sizeof(DWORD64))), (LPCSTR)"shared");


        map_addr = (char*)MapViewOfFile(fm, FILE_MAP_ALL_ACCESS, 0, 0, 0);

        memcpy(map_addr, sz, dwBufSize);
        memcpy(map_addr + dwBufSize, &thispid, sizeof(DWORD));


        printf("c %p\n", CallVirtualAllocEx);
        printf("c %llu\n", CallVirtualAllocEx);
        LPVOID fp = CallVirtualAllocEx;
        memcpy(map_addr + dwBufSize + sizeof(DWORD), &fp, sizeof(DWORD64));
        printf("%d\t%d\t%llu\n", thispid, *(DWORD*)(map_addr + dwBufSize), *(DWORD64*)(map_addr + dwBufSize + sizeof(DWORD)));

        printf("c %p\n", CallLoadLibraryA);
        printf("c %llu\n", CallLoadLibraryA);
        fp = CallLoadLibraryA;
        memcpy(map_addr + dwBufSize + sizeof(DWORD) + sizeof(DWORD64), &fp, sizeof(DWORD64));
        printf("%d\t%d\t%llu\n", thispid, *(DWORD*)(map_addr + dwBufSize), *(DWORD64*)(map_addr + dwBufSize + sizeof(DWORD) + sizeof(DWORD64)));

        fp = CallWriteProcessMemory;
        memcpy(map_addr + dwBufSize + sizeof(DWORD) + 2 * sizeof(DWORD64), &fp, sizeof(DWORD64));

        fp = CallCreateRemoteThread;
        memcpy(map_addr + dwBufSize + sizeof(DWORD) + 3 * sizeof(DWORD64), &fp, sizeof(DWORD64));

        fp = CallNtMapViewOfSection;
        memcpy(map_addr + dwBufSize + sizeof(DWORD) + 4 * sizeof(DWORD64), &fp, sizeof(DWORD64));

        fp = CallCreateFileMappingA;
        memcpy(map_addr + dwBufSize + sizeof(DWORD) + 5 * sizeof(DWORD64), &fp, sizeof(DWORD64));

        fp = CallGetThreadContext;
        memcpy(map_addr + dwBufSize + sizeof(DWORD) + 6 * sizeof(DWORD64), &fp, sizeof(DWORD64));

        fp = CallSetThreadContext;
        memcpy(map_addr + dwBufSize + sizeof(DWORD) + 7 * sizeof(DWORD64), &fp, sizeof(DWORD64));

        fp = CallNtQueueApcThread;
        memcpy(map_addr + dwBufSize + sizeof(DWORD) + 8 * sizeof(DWORD64), &fp, sizeof(DWORD64));

        fp = CallSetWindowLongPtrA;
        memcpy(map_addr + dwBufSize + sizeof(DWORD) + 9 * sizeof(DWORD64), &fp, sizeof(DWORD64));

        fp = CallSleepEx;
        memcpy(map_addr + dwBufSize + sizeof(DWORD) + 10 * sizeof(DWORD64), &fp, sizeof(DWORD64));


    }

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 entry = { sizeof(PROCESSENTRY32) };
    Process32First(hSnap, &entry);
    do
    {
        //printf("%ld\n",entry.th32ProcessID);
        //hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, (DWORD)atol((const char*)argv[arg]));
        if (thispid == entry.th32ProcessID)
            continue;
        hProcess = OpenProcess(MAXIMUM_ALLOWED, FALSE, entry.th32ProcessID);
        if (!(hProcess))
        {
            //printf("OpenProcess(%ld) failed!!! [%ld]\n", atol((const char*)argv[arg]), GetLastError());
            //return FALSE;
            printf("OpenProcess(%ld) failed!!! [%ld]\n", entry.th32ProcessID, GetLastError());
            continue;
        }
        printf("OpenProcess(%ld) Succeed!!! \n", entry.th32ProcessID);
        (*PNtMapViewOfSection)(fm, hProcess, &lpMap, 0, dwBufSize ,
            nullptr, &viewsize, ViewUnmap, 0, PAGE_READONLY);


        if (fVerbose)
        {
            DumpProcess(hProcess);
        }

        if (!isFree)
        {
            hThread = CreateRemoteThread(hProcess, NULL, 0, pThreadProc, lpMap, 0, NULL);
            if (!hThread)
            {
                //return FALSE;
                printf("CreateRemoteThread(%ld) failed!!! [%ld]\n", entry.th32ProcessID, GetLastError());
                continue;
            }
        }
        else
        {
            HMODULE fdllpath = findRemoteHModule(entry.th32ProcessID, (const char*)rpszDllsOut[0]);
            if (fdllpath != NULL)
            {
                hThread = CreateRemoteThread(hProcess, NULL, 0, pThreadProc, fdllpath, 0, NULL);
                if (!hThread)
                {
                    //return FALSE;
                    printf("CreateRemoteThread(%ld) failed!!! [%ld]\n", entry.th32ProcessID, GetLastError());
                    continue;
                }
            }
        }

        if (fVerbose)
        {
            DumpProcess(hProcess);
        }

        //WaitForSingleObject(hThread, INFINITE);
        CloseHandle(hThread);
        CloseHandle(hProcess);

    } while (Process32Next(hSnap, &entry));

    CloseHandle(hSnap);


    printf("fast.exe: Finished.\n");

    if (!isFree)
        while (TRUE)
            Sleep(0);

    for (DWORD n = 0; n < nDlls; n++)
    {
        if (rpszDllsOut[n] != NULL)
        {
            delete[] rpszDllsOut[n];
            rpszDllsOut[n] = NULL;
        }
    }

    return 0; //dwResult;
}
//
///////////////////////////////////////////////////////////////// End of File.