#include "pch.h"
#include "detours.h"
#include <stdio.h>
#include <processthreadsapi.h>
#include <winternl.h>
#include <iostream>


static NTSUSPENDTHREAD pNtSuspendThread;
static NTGETCONTEXTTHREAD pNtGetContextThread;
static NTSETCONTEXTTHREAD pNtSetContextThread;
static RESUMETHREAD pNtResumeThread;
HMODULE hMod = NULL;


//NtSuspendThread
DLLBASIC_API NTSTATUS NTAPI NtSuspendThread(
	HANDLE ThreadHandle,
	PULONG PreviousSuspendCount
) {
	printf("NtSuspendThread is Used\n");
	return pNtSuspendThread(
		ThreadHandle,
		PreviousSuspendCount
	);
}

//NtGetContextThread
DLLBASIC_API NTSTATUS NTAPI NtGetContextThread(
	HANDLE ThreadHandle,
	PCONTEXT pContext
) {
	printf("NtGetContextThread is Used\n");
	wprintf(L"%s\n", pContext);
	return pNtGetContextThread(
		ThreadHandle,
		pContext
	);
}

//NtSetContextThread
DLLBASIC_API NTSTATUS NTAPI NtSetContextThread(
	HANDLE ThreadHandle,
	PCONTEXT lpContext
) {
	printf("NtSetContextThread is Used\n");
	wprintf(L"%s\n", lpContext);
	return pNtSetContextThread(
		ThreadHandle,
		lpContext
	);
}

//NtResumeThread
DLLBASIC_API NTSTATUS NTAPI NtResumeThread(
	HANDLE ThreadHandle
) {
	printf("NtResumeThread is Used\n");
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
		pNtGetContextThread = (NTGETCONTEXTTHREAD)GetProcAddress(hMod, "NtGetContextThread");
		if (pNtGetContextThread == NULL) {
			printf("N4Hook: Error - cannot find NtGetContextThread's address.\n");
			return 1;
		}
		pNtSetContextThread = (NTSETCONTEXTTHREAD)GetProcAddress(hMod, "NtSetContextThread");
		if (pNtSetContextThread == NULL) {
			printf("N4Hook: Error - cannot find NtSetContextThread's address.\n");
			return 1;
		}
		pNtResumeThread = (RESUMETHREAD)GetProcAddress(hMod, "NtResumeThread");
		if (pNtResumeThread == NULL) {
			printf("CreationHook: Error - cannot find NtResumeThread's address.\n");
			return 1;
		}

		DetourRestoreAfterWith();
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());

		if (pNtSuspendThread != NULL)
			DetourAttach(&(PVOID&)pNtSuspendThread, NtSuspendThread);
		if (pNtGetContextThread != NULL)
			DetourAttach(&(PVOID&)pNtGetContextThread, NtGetContextThread);
		if (pNtSetContextThread != NULL)
			DetourAttach(&(PVOID&)pNtSetContextThread, NtSetContextThread);
		if (pNtResumeThread != NULL)
			DetourAttach(&(PVOID&)pNtResumeThread, NtResumeThread);

		printf("DLL_PROCESS_ATTACH\n");

		DetourTransactionCommit();
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
		if (pNtSuspendThread != NULL)
			DetourDetach(&(PVOID&)pNtSuspendThread, NtSuspendThread);
		if (pNtGetContextThread != NULL)
			DetourDetach(&(PVOID&)pNtGetContextThread, NtGetContextThread);
		if (pNtSetContextThread != NULL)
			DetourDetach(&(PVOID&)pNtSetContextThread, NtSetContextThread);
		if (pNtResumeThread != NULL)
			DetourDetach(&(PVOID&)pNtResumeThread, NtResumeThread);
		DetourTransactionCommit();
		printf("DLL_PROCESS_DETACH\n");
		break;
	}
	return TRUE;
}