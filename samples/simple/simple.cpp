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

#define DLLBASIC_API extern "C" __declspec(dllexport)
#define HOOKDLL_PATH "C:\\simple64.dll"

static LONG dwSlept = 0;
static DWORD (WINAPI * TrueSleepEx)(DWORD dwMilliseconds, BOOL bAlertable) = SleepEx;

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

    if (DetourIsHelperProcess()) {
        return TRUE;
    }

    if (dwReason == DLL_PROCESS_ATTACH) {
        DetourRestoreAfterWith();

        printf("simple" DETOURS_STRINGIFY(DETOURS_BITS) ".dll:"
               " Starting.\n");
        fflush(stdout);

        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourAttach(&(PVOID&)TrueSleepEx, TimedSleepEx);
        DetourAttach(&(PVOID&)TrueCreateProcessA, HookCreateProcessA);
        DetourAttach(&(PVOID&)TrueCreateProcessW, HookCreateProcessW);
        error = DetourTransactionCommit();

        if (error == NO_ERROR) {
            printf("simple" DETOURS_STRINGIFY(DETOURS_BITS) ".dll:"
                   " Detoured SleepEx().\n");
        }
        else {
            printf("simple" DETOURS_STRINGIFY(DETOURS_BITS) ".dll:"
                   " Error detouring SleepEx(): %ld\n", error);
        }
    }
    else if (dwReason == DLL_PROCESS_DETACH) {
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourDetach(&(PVOID&)TrueSleepEx, TimedSleepEx);
        DetourDetach(&(PVOID&)TrueCreateProcessA, HookCreateProcessA);
        DetourDetach(&(PVOID&)TrueCreateProcessW, HookCreateProcessW);
        error = DetourTransactionCommit();

        printf("simple" DETOURS_STRINGIFY(DETOURS_BITS) ".dll:"
               " Removed SleepEx() (result=%ld), slept %ld ticks.\n", error, dwSlept);
        fflush(stdout);
    }
    return TRUE;
}

//
///////////////////////////////////////////////////////////////// End of File.
