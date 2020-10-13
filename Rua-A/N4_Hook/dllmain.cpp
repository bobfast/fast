#include <stdio.h>
#include <winternl.h>
#include <iostream>
#include <Windows.h>
#include <string>
#include <winnt.h>
#include <map>
#include "pch.h"
#include "detours.h"

static DBGPRINT pDbgPrint; // for debug printing 
static NTSUSPENDTHREAD pNtSuspendThread;
static NTGETCONTEXTTHREAD pNtGetThreadContext;
static NTSETCONTEXTTHREAD pNtSetThreadContext;
static RESUMETHREAD pNtResumeThread;

CONTEXT old_ctx, new_ctx;
RUNTIME_MEM_ENTRY* result;
HMODULE hMod = NULL;
DWORD64 old_result,new_result;

//TargetThreadHandle


//NtSuspendThread
DLLBASIC_API NTSTATUS NTAPI NtSuspendThread(
	HANDLE ThreadHandle,
	PULONG PreviousSuspendCount
) {
	return pNtSuspendThread(
		ThreadHandle,
		PreviousSuspendCount
	);
}

//NtGetContextThread
DLLBASIC_API NTSTATUS NTAPI NtGetThreadContext(
	HANDLE ThreadHandle,
	PCONTEXT pContext
) {
	pDbgPrint("1N4_HOOK: PID=%d, NtGetThreadContext is hooked!\n", GetCurrentProcessId());
	old_ctx.ContextFlags = CONTEXT_INTEGER;
	pContext = &old_ctx;
	pDbgPrint("1N4_HOOK: DETECTED GetThreadContext\n");
	pDbgPrint("1CONTEXT.Rip : %016I64X\n", old_ctx.Rip);
	printf("1OLD_CONTEXT.Rip : % 016I64X\n", old_ctx.Rip);
	return (*pNtGetThreadContext)(
		ThreadHandle,
		pContext
		);
};

//NtSetContextThread
DLLBASIC_API NTSTATUS NTAPI NtSetThreadContext(
	HANDLE ThreadHandle,
	PCONTEXT lpContext
) {
	pDbgPrint("1N4_HOOK: PID=%d, NtSetThreadContext is hooked!\n", GetCurrentProcessId());
	new_ctx.ContextFlags = CONTEXT_INTEGER;
	lpContext = &new_ctx;
	pDbgPrint("1N4_HOOK: DETECTED SetThreadContext\n");
	pDbgPrint("1CONTEXT.Rip : %016I64X\n", new_ctx.Rip);
	printf("1NEW_CONTEXT.Rip : % 016I64X\n", new_ctx.Rip);
	return (*pNtSetThreadContext)(
		ThreadHandle,
		lpContext
	);
}

//NtResumeThread
DLLBASIC_API NTSTATUS NTAPI NtResumeThread(
	HANDLE ThreadHandle
) {
	return pNtResumeThread(
		ThreadHandle
	);
}

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD dwReason, LPVOID reserved)
{
	(void)hinst;
	(void)reserved;
	HMODULE hMod = NULL;
	switch (dwReason)
	{
	case DLL_PROCESS_ATTACH:
		// get ntdll module
		hMod = GetModuleHandleA("ntdll.dll");
		if (hMod == NULL) {
			printf("N4Hook: Error - cannot find ntdll.dll module.\n");
			return 1;
		}
		// get functions in ntdll
		pNtSuspendThread = (NTSUSPENDTHREAD)GetProcAddress(hMod, "NtSuspendThread");
		if (pNtSuspendThread == NULL) {
			printf("N4Hook: Error - cannot find NtSuspendThread's address.\n");
			return 1;
		}
		pNtGetThreadContext = (NTGETCONTEXTTHREAD)GetProcAddress(hMod, "NtGetContextThread");
		if (pNtGetThreadContext == NULL) {
			printf("N4Hook: Error - cannot find NtGetContextThread's address.\n");
			return 1;
		}
		pNtSetThreadContext = (NTSETCONTEXTTHREAD)GetProcAddress(hMod, "NtSetContextThread");
		if (pNtSetThreadContext == NULL) {
			printf("N4Hook: Error - cannot find NtSetContextThread's address.\n");
			return 1;
		}
		pNtResumeThread = (RESUMETHREAD)GetProcAddress(hMod, "NtResumeThread");
		if (pNtResumeThread == NULL) {
			printf("N4Hook: Error - cannot find NtResumeThread's address.\n");
			return 1;
		}
		pDbgPrint = (DBGPRINT)GetProcAddress(hMod, "DbgPrint");
		if (pDbgPrint == NULL) {
			printf("N4Hook: Error - cannot get DbgPrint's address.\n");
			return 1;
		}

		DetourRestoreAfterWith();
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());

		DetourAttach(&(PVOID&)pNtSuspendThread, NtSuspendThread);
		DetourAttach(&(PVOID&)pNtGetThreadContext, NtGetThreadContext);
		DetourAttach(&(PVOID&)pNtSetThreadContext, NtSetThreadContext);	
		DetourAttach(&(PVOID&)pNtResumeThread, NtResumeThread);
		DetourTransactionCommit();
		printf("DLL_PROCESS_ATTACH\n");
		break;
	case DLL_THREAD_ATTACH:
		printf("DLL_THREAD_ATTACH\n");
		break;
	case DLL_THREAD_DETACH:
		printf("DLL_THREAD_DETACH\n");
		break;
	case DLL_PROCESS_DETACH:
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());

		DetourDetach(&(PVOID&)pNtSuspendThread, NtSuspendThread);
		DetourDetach(&(PVOID&)pNtGetThreadContext, NtGetThreadContext);
		DetourDetach(&(PVOID&)pNtSetThreadContext, NtSetThreadContext);
		DetourDetach(&(PVOID&)pNtResumeThread, NtResumeThread);
		DetourTransactionCommit();
		printf("DLL_PROCESS_DETACH\n");
		break;
	}

	if (old_ctx.Rip =!new_ctx.Rip)
	{
		pDbgPrint("Hacked\n");
		pDbgPrint("2old.CONTEXT.Rip : %016I64X\n", old_ctx.Rip);
		pDbgPrint("2new.CONTEXT.Rip : %016I64X\n", new_ctx.Rip);
	}
	return TRUE;
}