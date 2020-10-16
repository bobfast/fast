//////////////////////////////////////////////////////////////////////////////
//
//  Detours Test Program (simple.cpp of simple.dll)
//
//  Microsoft Research Detours Package
//
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//
//  This DLL will detour the Windows SleepEx API so that TimedSleep function
//  gets called instead.  TimedSleepEx records the before and after times, and
//  calls the real SleepEx API through the TrueSleepEx function pointer.
//



#include <stdio.h>
#include <windows.h>
#include <processthreadsapi.h>
#include <string>
#include "detours.h"
#include "kmkmi.h"

#define DLLBASIC_API extern "C" __declspec(dllexport)
#define HOOKDLL_PATH "C:\\kmkmi.dll"
#define MSG_SIZE 256


//#####################################

static HANDLE hProcess = NULL;
static HANDLE hMonProcess = NULL;

static LPVOID monMMF = NULL;
static LPVOID dllMMF = NULL;
static VIRTUALALLOCEX pVirtualAllocEx = VirtualAllocEx;
static LPTHREAD_START_ROUTINE  CallVirtualAllocEx = NULL;
static LPTHREAD_START_ROUTINE  CallLoadLibraryA = NULL;
static LPTHREAD_START_ROUTINE  CallWriteProcessMemory = NULL;
static LPTHREAD_START_ROUTINE  CallCreateRemoteThread = NULL;
static LPTHREAD_START_ROUTINE  CallNtMapViewOfSection = NULL;
static LPTHREAD_START_ROUTINE  CallCreateFileMappingA = NULL;
static LPTHREAD_START_ROUTINE  CallGetThreadContext = NULL;
static LPTHREAD_START_ROUTINE  CallSetThreadContext = NULL;
static LPTHREAD_START_ROUTINE  CallNtQueueApcThread = NULL;
static LPTHREAD_START_ROUTINE  CallSetWindowLongPtrA = NULL;
static LPTHREAD_START_ROUTINE  CallSleepEx = NULL;

//#####################################



typedef
ULONG(__cdecl* fnDbgPrintEx) (
    _In_ ULONG ComponentId,
    _In_ ULONG Level,
    _In_z_ _Printf_format_string_ PCSTR Format,
    ...
    );
static fnDbgPrintEx _dbg_print = nullptr;

static TrueNtUserSetWindowLongPtr pNtUserSetWindowLongPtr;
static pNtQueueApcThread NtQueueApcThread = NULL;
static TrueNtWriteVirtualMemory pNtWriteVirtualMemory;
static NTMAPVIEWOFSECTION TrueNtMapViewOfSection;


void dbg_print(_In_ uint32_t log_level, _In_ const char* msg)
{
    //
    //	log level
    //
    uint32_t ll = DPFLTR_ERROR_LEVEL;
    switch (log_level)
    {
    case log_level_debug:
        ll = DPFLTR_INFO_LEVEL;
        break;
    case log_level_info:
        ll = DPFLTR_TRACE_LEVEL;
        break;
    case log_level_warn:
        ll = DPFLTR_WARNING_LEVEL;
        break;
    case log_level_error:
        ll = DPFLTR_ERROR_LEVEL;
        break;
    }

    if (_dbg_print)
    {
        _dbg_print(DPFLTR_IHVDRIVER_ID,
            ll,
            "%s",
            msg);
    }
    else
    {
        OutputDebugStringA(msg);
    }
}






static LONG dwSlept = 0;
static DWORD(WINAPI* TrueSleepEx)(DWORD dwMilliseconds, BOOL bAlertable) = SleepEx;

unsigned char* writtenBuffer = NULL;
unsigned int writtenBufferLen = 0;

DLLBASIC_API NTSTATUS NTAPI MyNtQueueApcThread(
    HANDLE ThreadHandle,
    PVOID ApcRoutine,
    PVOID ApcRoutineContext OPTIONAL,
    PVOID ApcStatusBlock OPTIONAL,
    PVOID ApcReserved OPTIONAL
) {
    HANDLE hThread = NULL;
    if (ApcRoutine == GlobalGetAtomNameA)
    {
    std::string buf(std::to_string(GetCurrentProcessId()));
    buf.append(":CallNtQueueApcThread:IPC Succeed!     ");
    memcpy(dllMMF, buf.c_str(), buf.size());
    hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)CallNtQueueApcThread, monMMF, 0, NULL);
    WaitForSingleObject(hThread, INFINITE);
    printf("%s\n", dllMMF);
    }
    return NtQueueApcThread(ThreadHandle,
        ApcRoutine,
        ApcRoutineContext OPTIONAL,
        ApcStatusBlock OPTIONAL,
        ApcReserved OPTIONAL);
}

DLLBASIC_API NTSTATUS NTAPI MyNtWriteVirtualMemory(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    ULONG NumberOfBytesToWrite,
    PULONG NumberOfBytesWritten)
{
    printf("kmkmi: PID=%d, NtWriteVirtualMemory is hooked!\n", GetCurrentProcessId());
    printf("              NumberOfBytesToWrite=%u\n", NumberOfBytesToWrite);
    printf("              Buffer(first 30) = ");

    if (writtenBuffer != NULL) {
        free(writtenBuffer);
        writtenBuffer = NULL;
        writtenBufferLen = 0;
    }

    writtenBuffer = (unsigned char*)malloc(NumberOfBytesToWrite);
    writtenBufferLen = NumberOfBytesToWrite;

    if (writtenBuffer != NULL) {
        memcpy(writtenBuffer, Buffer, NumberOfBytesToWrite);
        for (ULONG i = 0; i < 30 && i < NumberOfBytesToWrite; i++) {
            printf("%02x ", writtenBuffer[i]);
        }
    }
    else {
        printf("(memory allocation failed)");
    }

    printf("\n");

    return (*pNtWriteVirtualMemory)(
        ProcessHandle,
        BaseAddress,
        Buffer,
        NumberOfBytesToWrite,
        NumberOfBytesWritten
        );
}
DLLBASIC_API LPVOID WINAPI MyVirtualAllocEx(
    HANDLE thProcess, //thProcess  modified
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD  flAllocationType,
    DWORD  flProtect)
{
    LPVOID ret = pVirtualAllocEx(
        thProcess,
        lpAddress,
        dwSize,
        flAllocationType,
        flProtect
    );
    char buf4[MSG_SIZE] = "";
    HANDLE hMonThread = NULL;
    std::string buf(std::to_string(GetProcessId(thProcess)));

    std::string buf2(std::to_string(dwSize));
    std::string buf3(":CallVirtualAllocEx:IPC Successed!");
    sprintf_s(buf4,"%lp", ret);
  
    if (flAllocationType == (MEM_RESERVE | MEM_COMMIT) && flProtect == PAGE_EXECUTE_READWRITE) {

        memcpy(dllMMF, buf.c_str(), buf.size());
        memcpy((char*)dllMMF + 3*sizeof(DWORD), buf2.c_str(), buf2.size());
        memcpy((char*)dllMMF + 6 * sizeof(DWORD), buf3.c_str(), buf3.size());
        memcpy((char*)dllMMF + 30 * sizeof(DWORD), buf4,strlen(buf4) );
        hMonThread = CreateRemoteThread(hProcess, NULL, 0, CallVirtualAllocEx, monMMF, 0, NULL);
        WaitForSingleObject(hMonThread, INFINITE);
        printf("%s\n", dllMMF);
    }
    return ret;
}
DLLBASIC_API LONG_PTR NTAPI MyNtUserSetWindowLongPtr(
    HWND hWnd,
    DWORD Index,
    LONG_PTR NewValue,
    BOOL Ansi
) {
    //dbg_print(log_level_info, "NtUserSetWindowLongPtr hooked.\n");
    printf("NtUserSetWindowLongPtr hooked.\n");
    return (*pNtUserSetWindowLongPtr)(hWnd, Index, NewValue, Ansi);
}

static LONG_PTR(WINAPI* TrueSetWindowLongPtrA) (
    HWND     hWnd,
    int      nIndex,
    LONG_PTR dwNewLong
    ) = SetWindowLongPtrA;

static BOOL(WINAPI* TrueCreateProcessA)(
    LPCSTR                lpApplicationName,
    LPSTR                 lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL                  bInheritHandles,
    DWORD                 dwCreationFlags,
    LPVOID                lpEnvironment,
    LPCSTR                lpCurrentDirectory,
    LPSTARTUPINFOA        lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation
    ) = CreateProcessA;


static BOOL(WINAPI* TrueCreateProcessW)(
    LPCWSTR               lpApplicationName,
    LPWSTR                lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL                  bInheritHandles,
    DWORD                 dwCreationFlags,
    LPVOID                lpEnvironment,
    LPCWSTR               lpCurrentDirectory,
    LPSTARTUPINFOW        lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation
    ) = CreateProcessW;

DLLBASIC_API LONG_PTR WINAPI MySetWindowLongPtrA
(HWND     hWnd,
    int      nIndex,
    LONG_PTR dwNewLong) {

    HANDLE hThread = NULL;
    std::string buf(std::to_string(GetCurrentProcessId()));
    buf.append(":CallSetWindowLongPtrA:IPC Succeed!     ");
    memcpy(dllMMF, buf.c_str(), buf.size());
    hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)CallSetWindowLongPtrA, monMMF, 0, NULL);
    WaitForSingleObject(hThread, INFINITE);
    printf("%s\n", dllMMF);
    return TrueSetWindowLongPtrA(hWnd, nIndex, dwNewLong);
}

DLLBASIC_API BOOL WINAPI HookCreateProcessA(
    LPCSTR                lpApplicationName,
    LPSTR                 lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL                  bInheritHandles,
    DWORD                 dwCreationFlags,
    LPVOID                lpEnvironment,
    LPCSTR                lpCurrentDirectory,
    LPSTARTUPINFOA        lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation)
{
    char* pValue2 = NULL;
    size_t len = NULL;
    _dupenv_s(&pValue2, &len, "expHDll");
    return DetourCreateProcessWithDllA(lpApplicationName,
        lpCommandLine,
        lpProcessAttributes,
        lpThreadAttributes,
        bInheritHandles,
        dwCreationFlags,
        lpEnvironment,
        lpCurrentDirectory,
        lpStartupInfo,
        lpProcessInformation,
        HOOKDLL_PATH,
        TrueCreateProcessA);
}



DLLBASIC_API BOOL WINAPI HookCreateProcessW(
    LPCWSTR               lpApplicationName,
    LPWSTR                lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL                  bInheritHandles,
    DWORD                 dwCreationFlags,
    LPVOID                lpEnvironment,
    LPCWSTR               lpCurrentDirectory,
    LPSTARTUPINFOW        lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation
)
{
    char* pValue2 = NULL;
    size_t len = NULL;
    _dupenv_s(&pValue2, &len, "expHDll");

    return DetourCreateProcessWithDllW(lpApplicationName,
        lpCommandLine,
        lpProcessAttributes,
        lpThreadAttributes,
        bInheritHandles,
        dwCreationFlags,
        lpEnvironment,
        lpCurrentDirectory,
        lpStartupInfo,
        lpProcessInformation,
        HOOKDLL_PATH,
        TrueCreateProcessW);

}

HMODULE hMod = NULL;



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

DLLBASIC_API NTSTATUS NTAPI MyNtMapViewOfSection(
    HANDLE SectionHandle,
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    SIZE_T CommitSize,
    PLARGE_INTEGER SectionOffset,
    PSIZE_T ViewSize,
    SECTION_INHERIT InheritDisposition,
    ULONG AllocationType,
    ULONG Win32Protect
)
{

    if (Win32Protect == PAGE_EXECUTE_READWRITE) {
        HANDLE hThread = NULL;
        std::string buf(std::to_string(GetCurrentProcessId()));
        buf.append(":CallNtMapViewOfSection:PAGE_EXECUTE_READWRITE");
        memcpy(dllMMF, buf.c_str(), buf.size());
        hThread = CreateRemoteThread(hProcess, NULL, 0, CallNtMapViewOfSection, monMMF, 0, NULL);
        WaitForSingleObject(hThread, INFINITE);
        printf("%s\n", dllMMF);
    }
    return (*TrueNtMapViewOfSection)(
        SectionHandle,
        ProcessHandle,
        BaseAddress,
        ZeroBits,
        CommitSize,
        SectionOffset,
        ViewSize,
        InheritDisposition,
        AllocationType,
        Win32Protect);
}


DWORD WINAPI TimedSleepEx(DWORD dwMilliseconds, BOOL bAlertable)
{
    //printf("sleep5.exe: is Hooked.\n");
    DWORD dwBeg = GetTickCount();
    DWORD ret = TrueSleepEx(dwMilliseconds, bAlertable);
    DWORD dwEnd = GetTickCount();

    InterlockedExchangeAdd(&dwSlept, dwEnd - dwBeg);

    HANDLE hThread = NULL;
    std::string buf(std::to_string(GetCurrentProcessId()));
    buf.append(":CallSleepEx:IPC Succeed!     ");
    memcpy(dllMMF, buf.c_str(), buf.size());
    hThread = CreateRemoteThread(hProcess, NULL, 0, CallSleepEx, monMMF, 0, NULL);
    WaitForSingleObject(hThread, INFINITE);
    printf("%s\n", dllMMF);


    return ret;
}




BOOL WINAPI DllMain(HINSTANCE hinst, DWORD dwReason, LPVOID reserved)
{
    LONG error;
    (void)hinst;
    (void)reserved;

    HMODULE nt = GetModuleHandleW(L"ntdll.dll");
    if (nt == NULL) {
        printf("GetModuleHandleA ntdll.dll Failed.\n");
        return 1;
    }
    NtQueueApcThread = (pNtQueueApcThread)GetProcAddress(nt, "NtQueueApcThread");
    if (NtQueueApcThread == NULL) {
        printf("GetProcAddress NtQueueApcThread  Failed.\n");
        return 1;
    }
    _dbg_print = (fnDbgPrintEx)GetProcAddress(nt, "DbgPrintEx");
    TrueNtMapViewOfSection = (NTMAPVIEWOFSECTION)GetProcAddress(nt, "NtMapViewOfSection");

   
    pNtWriteVirtualMemory = (TrueNtWriteVirtualMemory)GetProcAddress(nt, "NtWriteVirtualMemory");
    if (pNtWriteVirtualMemory == NULL) {
        printf("GetProcAddress NtWriteVirtualMemory  Failed.\n");
        return 1;
    }

    HMODULE w32u = GetModuleHandleA("Win32u.dll");
    if (w32u == NULL) {
        printf("GetModuleHandleA Win32u.dll Failed.\n");
        return 1;
    }


    pNtUserSetWindowLongPtr = (TrueNtUserSetWindowLongPtr)GetProcAddress(w32u, "NtUserSetWindowLongPtr");
    if (pNtUserSetWindowLongPtr == NULL) {
        printf("GetProcAddress NtUserSetWindowLongPtr Failed.\n");
        return 1;
    }

    if (DetourIsHelperProcess()) {
        return TRUE;
    }

    if (dwReason == DLL_PROCESS_ATTACH) {

        //#############################



        HANDLE hMemoryMap = NULL;

        LPBYTE pMemoryMap = NULL;



        hMemoryMap = OpenFileMapping(FILE_MAP_READ, FALSE, (LPCSTR)"shared");

        pMemoryMap = (BYTE*)MapViewOfFile(
            hMemoryMap, FILE_MAP_READ,
            0, 0, 0
        );
        if (!pMemoryMap)
        {

            CloseHandle(hMemoryMap);
            printf("MapViewOfFile Failed.\n");
            return FALSE;

        }

        int sz = strlen((char*)pMemoryMap) + 1;


        printf("%s\n", (char*)pMemoryMap);
        printf("%d\n", *(DWORD*)((char*)pMemoryMap + sz));


        HANDLE fm;
        char* map_addr;

        LPVOID lpMap = 0;
        SIZE_T viewsize = 0;
        PNtMapViewOfSection = (NTSTATUS(*)(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID * BaseAddress, ULONG_PTR ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, SECTION_INHERIT InheritDisposition, ULONG AllocationType, ULONG Win32Protect))GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtMapViewOfSection");


        fm = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, MSG_SIZE, NULL);
        map_addr = (char*)MapViewOfFile(fm, FILE_MAP_ALL_ACCESS, 0, 0, 0);

        hProcess = OpenProcess(PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD, FALSE, *(DWORD*)((char*)pMemoryMap + sz));

        (*PNtMapViewOfSection)(fm, hProcess, &lpMap, 0, MSG_SIZE, nullptr, &viewsize, ViewUnmap, 0, PAGE_READWRITE); // "The default behavior for executable pages allocated is to be marked valid call targets for CFG." (https://docs.microsoft.com/en-us/windows/desktop/api/memoryapi/nf-memoryapi-mapviewoffile)

        monMMF = (LPVOID)lpMap;
        dllMMF = (LPVOID)map_addr;



        CallVirtualAllocEx = (LPTHREAD_START_ROUTINE)(*(DWORD64*)(pMemoryMap + sz + sizeof(DWORD)));
        CallLoadLibraryA = (LPTHREAD_START_ROUTINE)(*(DWORD64*)(pMemoryMap + sz + sizeof(DWORD) + sizeof(DWORD64)));
        CallWriteProcessMemory = (LPTHREAD_START_ROUTINE)(*(DWORD64*)(pMemoryMap + sz + sizeof(DWORD) + 2 * sizeof(DWORD64)));
        CallCreateRemoteThread = (LPTHREAD_START_ROUTINE)(*(DWORD64*)(pMemoryMap + sz + sizeof(DWORD) + 3 * sizeof(DWORD64)));
        CallNtMapViewOfSection = (LPTHREAD_START_ROUTINE)(*(DWORD64*)(pMemoryMap + sz + sizeof(DWORD) + 4 * sizeof(DWORD64)));
        CallCreateFileMappingA = (LPTHREAD_START_ROUTINE)(*(DWORD64*)(pMemoryMap + sz + sizeof(DWORD) + 5 * sizeof(DWORD64)));
        CallGetThreadContext = (LPTHREAD_START_ROUTINE)(*(DWORD64*)(pMemoryMap + sz + sizeof(DWORD) + 6 * sizeof(DWORD64)));
        CallSetThreadContext = (LPTHREAD_START_ROUTINE)(*(DWORD64*)(pMemoryMap + sz + sizeof(DWORD) + 7 * sizeof(DWORD64)));
        CallNtQueueApcThread = (LPTHREAD_START_ROUTINE)(*(DWORD64*)(pMemoryMap + sz + sizeof(DWORD) + 8 * sizeof(DWORD64)));
        CallSetWindowLongPtrA = (LPTHREAD_START_ROUTINE)(*(DWORD64*)(pMemoryMap + sz + sizeof(DWORD) + 9 * sizeof(DWORD64)));
        CallSleepEx = (LPTHREAD_START_ROUTINE)(*(DWORD64*)(pMemoryMap + sz + sizeof(DWORD) + 10 * sizeof(DWORD64)));

        printf("%llu\n", *(DWORD64*)(pMemoryMap + sz + sizeof(DWORD)));




        //#############################

        DetourRestoreAfterWith();

        printf("kmkmi" DETOURS_STRINGIFY(DETOURS_BITS) ".dll:"
            " Starting.\n");
        fflush(stdout);

        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        //DetourAttach(&(PVOID&)TrueSleepEx, TimedSleepEx);
        DetourAttach(&(PVOID&)TrueCreateProcessA, HookCreateProcessA);
        DetourAttach(&(PVOID&)TrueCreateProcessW, HookCreateProcessW);
        //DetourAttach(&(PVOID&)pNtUserSetWindowLongPtr, MyNtUserSetWindowLongPtr);
        DetourAttach(&(PVOID&)TrueSetWindowLongPtrA, MySetWindowLongPtrA);
        DetourAttach(&(PVOID&)pVirtualAllocEx, MyVirtualAllocEx);
      //  DetourAttach(&(PVOID&)NtQueueApcThread, MyNtQueueApcThread);
        //DetourAttach(&(PVOID&)TrueNtMapViewOfSection, MyNtMapViewOfSection);
     //   DetourAttach(&(PVOID&)pNtAllocateVirtualMemory, MyNtAllocateVirtualMemory);
        //DetourAttach(&(PVOID&)pNtWriteVirtualMemory, MyNtWriteVirtualMemory);
        error = DetourTransactionCommit();

        if (error == NO_ERROR) {
            printf("kmkmi" DETOURS_STRINGIFY(DETOURS_BITS) ".dll:"
                " Detoured SleepEx().\n");
        }
        else {
            printf("kmkmi" DETOURS_STRINGIFY(DETOURS_BITS) ".dll:"
                " Error detouring SleepEx(): %ld\n", error);
        }
    }
    else if (dwReason == DLL_PROCESS_DETACH) {
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        //DetourDetach(&(PVOID&)TrueSleepEx, TimedSleepEx);
        DetourDetach(&(PVOID&)TrueCreateProcessA, HookCreateProcessA);
        DetourDetach(&(PVOID&)TrueCreateProcessW, HookCreateProcessW);
        //DetourDetach(&(PVOID&)pNtUserSetWindowLongPtr, MyNtUserSetWindowLongPtr);
        DetourDetach(&(PVOID&)TrueSetWindowLongPtrA, MySetWindowLongPtrA);
        DetourDetach(&(PVOID&)pVirtualAllocEx, MyVirtualAllocEx);
      //  DetourDetach(&(PVOID&)NtQueueApcThread, MyNtQueueApcThread);
        //DetourDetach(&(PVOID&)TrueNtMapViewOfSection, MyNtMapViewOfSection);
     //   DetourDetach(&(PVOID&)pNtAllocateVirtualMemory, MyNtAllocateVirtualMemory);
        //DetourDetach(&(PVOID&)pNtWriteVirtualMemory, MyNtWriteVirtualMemory);
        error = DetourTransactionCommit();

        printf("kmkmi" DETOURS_STRINGIFY(DETOURS_BITS) ".dll:"
            " Removed SleepEx() (result=%ld), slept %ld ticks.\n", error, dwSlept);
        fflush(stdout);
    }
    return TRUE;
}

//
///////////////////////////////////////////////////////////////// End of File.
