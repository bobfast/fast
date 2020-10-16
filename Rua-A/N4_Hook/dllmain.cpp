#include <stdio.h>
#include <winternl.h>
#include <iostream>
#include <Windows.h>
#include <string>
#include <winnt.h>
#include <map>
#include "pch.h"
#include "detours.h"

#define MSG_SIZE 256
HMODULE hMod = NULL;
//#####################################monitor
static HANDLE hProcess = NULL;
static LPVOID monMMF = NULL;
static LPVOID dllMMF = NULL;
unsigned char* writtenBuffer = NULL;
unsigned int writtenBufferLen = 0;

static DBGPRINT pDbgPrint; // for debug printing 
static NTSETCONTEXTTHREAD pNtSetThreadContext;

//CONTEXT old_ctx, new_ctx; last use
RUNTIME_MEM_ENTRY* result;
HMODULE hMod = NULL;
DWORD64 old_result,new_result;
CONTEXT old_ctx, new_ctx;

//NtSetContextThread
DLLBASIC_API NTSTATUS NTAPI NtSetThreadContext(
	HANDLE ThreadHandle,
	CONTEXT lpContext
) {
	lpContext.ContextFlags = CONTEXT_ALL;
	old_ctx.ContextFlags = CONTEXT_ALL;
	new_ctx = lpContext;
	GetThreadContext(ThreadHandle, &old_ctx);

	pDbgPrint("N4_HOOK: PID=%d, NtSetThreadContext is hooked!\n", GetCurrentProcessId());
	pDbgPrint("N4_HOOK: DETECTED SetThreadContext\n");
	pDbgPrint("OLD_CONTEXT.Rip : %016I64X\n", old_ctx.Rip);
	pDbgPrint("OLD_CONTEXT.Rip : %016I64X\n", new_ctx.Rip);

	return (*pNtSetThreadContext)(
		ThreadHandle,
		lpContext
	);
}

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD dwReason, LPVOID reserved)
{
	hinst;
	dwReason;
	reserved;

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
		
		pNtSetThreadContext = (NTSETCONTEXTTHREAD)GetProcAddress(hMod, "NtSetContextThread");
		if (pNtSetThreadContext == NULL) {
			printf("N4Hook: Error - cannot find NtSetContextThread's address.\n");
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
		DetourAttach(&(PVOID&)pNtSetThreadContext, NtSetThreadContext);
		DetourTransactionCommit();
		printf("N4Hook: DLL_PROCESS_ATTACH\n");
		break;
	case DLL_THREAD_ATTACH:
		printf("N4Hook: DLL_THREAD_ATTACH\n");
		break;
	case DLL_THREAD_DETACH:
		printf("N4Hook: DLL_THREAD_DETACH\n");
		break;
	case DLL_PROCESS_DETACH:
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		DetourDetach(&(PVOID&)pNtSetThreadContext, NtSetThreadContext);
		DetourTransactionCommit();
		printf("N4Hook: DLL_PROCESS_DETACH\n");
		break;
	}

	return TRUE;
}