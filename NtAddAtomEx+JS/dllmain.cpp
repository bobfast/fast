// dllmain.cpp : DLL 애플리케이션의 진입점을 정의합니다.
#include "pch.h"
#include <Windows.h>
#include <detours.h>
#include <winternl.h>
#include <stdio.h>
#include "atombomb.h"
#define DLLBASIC_API extern "C" __declspec(dllexport)

static LONG dwSlept = 0;
static pNtQueueApcThread NtQueueApcThread = NULL;
static DWORD(WINAPI* TrueSleepEx)(DWORD dwMilliseconds, BOOL bAlertable) = SleepEx;
static LPVOID(WINAPI* TrueVirtualAllocEx)(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize,DWORD flAllocationType,DWORD flProtect) = VirtualAllocEx;
DLLBASIC_API NTSTATUS NTAPI MyNtQueueApcThread(
    HANDLE ThreadHandle,
    PVOID ApcRoutine,
    PVOID ApcRoutineContext OPTIONAL,
    PVOID ApcStatusBlock OPTIONAL,
    PVOID ApcReserved OPTIONAL
) {
    printf("MyNtQueueApcThread is used\n");
    return NtQueueApcThread(ThreadHandle,
        ApcRoutine,
        ApcRoutineContext OPTIONAL,
        ApcStatusBlock OPTIONAL,
        ApcReserved OPTIONAL);
}

DLLBASIC_API LPVOID WINAPI DetectVirtualAllocEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect) {
    
    printf("VirtualAllocEx is used\n");
    return TrueVirtualAllocEx(hProcess, lpAddress, dwSize, flAllocationType, flProtect);

}
DLLBASIC_API DWORD WINAPI DetectSleepEx(DWORD dwMilliseconds, BOOL bAlertable) {
    DWORD dwBeg = GetTickCount();
    DWORD ret = TrueSleepEx(dwMilliseconds, bAlertable);
    DWORD dwEnd = GetTickCount();
    InterlockedExchangeAdd(&dwSlept, dwEnd - dwBeg);
    
    return ret;
}


BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    LONG error;

    if (DetourIsHelperProcess())
        return TRUE;

    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        hModule = GetModuleHandleA("ntdll.dll");
        NtQueueApcThread = (pNtQueueApcThread)GetProcAddress(hModule, "NtQueueApcThread");

        DetourRestoreAfterWith();
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourAttach(&(PVOID&)TrueSleepEx, DetectSleepEx);
        DetourAttach(&(PVOID&)TrueVirtualAllocEx, DetectVirtualAllocEx);
        if (NtQueueApcThread != NULL)
            DetourAttach(&(PVOID&)NtQueueApcThread, MyNtQueueApcThread);
        error = DetourTransactionCommit();
        if (error == NO_ERROR) {
            printf(DETOURS_STRINGIFY(DETOURS_BITS) ".dll:"
                " Detoured start().\n");
        }
        else {
            printf("simple" DETOURS_STRINGIFY(DETOURS_BITS) ".dll:"
                " Error detouring SleepEx(): %ld\n", error);
        }
        break;
    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourDetach(&(PVOID&)TrueSleepEx, DetectSleepEx);
        DetourDetach(&(PVOID&)TrueVirtualAllocEx, DetectVirtualAllocEx);
        if (NtQueueApcThread != NULL)
            DetourDetach(&(PVOID&)NtQueueApcThread, MyNtQueueApcThread);
        error = DetourTransactionCommit();
        printf("Removed SleepEx() (result=%ld),slept %ld ticks\n", error, dwSlept);
        break;
    }
    return TRUE;
}

