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
#include "detours.h"
#include "kmkmi.h"

#define DLLBASIC_API extern "C" __declspec(dllexport)
#define HOOKDLL_PATH "C:\\kmkmi.dll"


typedef
ULONG(__cdecl* fnDbgPrintEx) (
    _In_ ULONG ComponentId,
    _In_ ULONG Level,
    _In_z_ _Printf_format_string_ PCSTR Format,
    ...
    );
static fnDbgPrintEx _dbg_print = nullptr;

static TrueNtUserSetWindowLongPtr pNtUserSetWindowLongPtr;
static TrueNtAllocateVirtualMemory pNtAllocateVirtualMemory;
static TrueNtWriteVirtualMemory pNtWriteVirtualMemory;

void dbg_print(_In_ uint32_t log_level, _In_ const char* msg)
{
    //
    //	log level º¯È¯
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
static DWORD (WINAPI * TrueSleepEx)(DWORD dwMilliseconds, BOOL bAlertable) = SleepEx;

unsigned char* writtenBuffer = NULL;
unsigned int writtenBufferLen = 0;

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

DLLBASIC_API NTSTATUS NTAPI MyNtAllocateVirtualMemory(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect)
{
    printf("kmkmi: PID=%d, NtAllocateVirtualMemory is hooked!\n", GetCurrentProcessId());
    printf("              AllocationType = %x, Protect = %x\n", AllocationType, Protect);
    //MEM_COMMIT: 0x00001000
    //MEM_RESERVE: 0x00002000
    //MEM_RESET: 0x00080000

    //PAGE_NOACCESS: 0x01
    //PAGE_READONLY: 0x02
    //PAGE_READWRITE: 0x04
    //PAGE_EXECUTE: 0x10
    //PAGE_EXECUTE_READ: 0x20
    //PAGE_EXECUTE_READWRITE: 0x40
    //PAGE_GUARD: 0x100
    //PAGE_NOCACHE: 0x200
    //PAGE_WRITECOMBINE: 0x400

    return (*pNtAllocateVirtualMemory)(
        ProcessHandle,
        BaseAddress,
        ZeroBits,
        RegionSize,
        AllocationType,
        Protect
        );
}

DLLBASIC_API LONG_PTR NTAPI MyNtUserSetWindowLongPtr(
    HWND hWnd,
    DWORD Index,
    LONG_PTR NewValue,
    BOOL Ansi
) {
    //dbg_print(log_level_info, "NtUserSetWindowLongPtr hooked.\n");
    //printf("NtUserSetWindowLongPtr hooked.\n");
    return (*pNtUserSetWindowLongPtr)(hWnd, Index, NewValue, Ansi);
}

static LONG_PTR(WINAPI* TrueSetWindowLongPtrA) (
	HWND     hWnd,
	int      nIndex,
	LONG_PTR dwNewLong
	) = SetWindowLongPtrA;

static BOOL(WINAPI * TrueCreateProcessA)(
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


static BOOL(WINAPI * TrueCreateProcessW)(
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

	dbg_print(log_level_info, "SetWindowLongPtrA hooked.\n");
	printf("SetWindowLongPtrA hooked.");
    printf("\t%ull\n", dwNewLong);
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
    char *pValue2 = NULL;
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
    char *pValue2 = NULL;
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




DWORD WINAPI TimedSleepEx(DWORD dwMilliseconds, BOOL bAlertable)
{
    //printf("sleep5.exe: is Hooked.\n");
    DWORD dwBeg = GetTickCount();
    DWORD ret = TrueSleepEx(dwMilliseconds, bAlertable);
    DWORD dwEnd = GetTickCount();

    InterlockedExchangeAdd(&dwSlept, dwEnd - dwBeg);

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
    _dbg_print = (fnDbgPrintEx)GetProcAddress(nt, "DbgPrintEx");

    pNtAllocateVirtualMemory = (TrueNtAllocateVirtualMemory)GetProcAddress(nt, "NtAllocateVirtualMemory");
    if (pNtAllocateVirtualMemory == NULL) {
        printf("GetProcAddress NtAllocateVirtualMemory Failed.\n");
        return 1;
    }

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
        DetourRestoreAfterWith();

        printf("kmkmi" DETOURS_STRINGIFY(DETOURS_BITS) ".dll:"
               " Starting.\n");
        fflush(stdout);

        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourAttach(&(PVOID&)TrueSleepEx, TimedSleepEx);
        DetourAttach(&(PVOID&)TrueCreateProcessA, HookCreateProcessA);
        DetourAttach(&(PVOID&)TrueCreateProcessW, HookCreateProcessW);
        //DetourAttach(&(PVOID&)pNtUserSetWindowLongPtr, MyNtUserSetWindowLongPtr);
        DetourAttach(&(PVOID&)TrueSetWindowLongPtrA, MySetWindowLongPtrA);
        //DetourAttach(&(PVOID&)pNtAllocateVirtualMemory, MyNtAllocateVirtualMemory);
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
        DetourDetach(&(PVOID&)TrueSleepEx, TimedSleepEx);
        DetourDetach(&(PVOID&)TrueCreateProcessA, HookCreateProcessA);
        DetourDetach(&(PVOID&)TrueCreateProcessW, HookCreateProcessW);
        //DetourDetach(&(PVOID&)pNtUserSetWindowLongPtr, MyNtUserSetWindowLongPtr);
        DetourDetach(&(PVOID&)TrueSetWindowLongPtrA, MySetWindowLongPtrA);
        //DetourDetach(&(PVOID&)pNtAllocateVirtualMemory, MyNtAllocateVirtualMemory);
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
