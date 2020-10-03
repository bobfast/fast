#include <Windows.h>
#include <stdio.h>
#include "detours.h"
#include "Silver0Hook.h"
#include <memoryapi.h>

#define DLLBASIC_API extern "C" __declspec(dllexport)
static NTOPENPROCESS NtOpenProcess;
HMODULE hMod = NULL;

// NtOpenProcess Hooking
DLLBASIC_API NTSTATUS NTAPI MyNtOpenProcess(
	PHANDLE            ProcessHandle,
	ACCESS_MASK        DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PCLIENT_ID         ClientId
)
{
	printf("NtOpenProcess is HOOKED!########################################\n");

	return NtOpenProcess(
		ProcessHandle,
		DesiredAccess,
		ObjectAttributes,
		ClientId
	);
}

// CreateFileMappingNumaW
DLLBASIC_API HANDLE WINAPI MyCreateFileMappingNumaW(
	HANDLE                hFile,
	LPSECURITY_ATTRIBUTES lpFileMappingAttributes,
	DWORD                 flProtect,
	DWORD                 dwMaximumSizeHigh,
	DWORD                 dwMaximumSizeLow,
	LPCWSTR               lpName,
	DWORD                 nndPreferred
)
{
	printf("CreateFileMappingNumaW is HOOKED!########################################\n");

	return CreateFileMappingNumaW(
		hFile,
		lpFileMappingAttributes,
		flProtect,
		dwMaximumSizeHigh,
		dwMaximumSizeLow,
		lpName,
		nndPreferred
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
		printf("Process attached\n");

		hMod = GetModuleHandleA("ntdll.dll");
		if (hMod == NULL) {
			printf("Faild to get ntdll\n");
			return 1;
		}

		NtOpenProcess = (NTOPENPROCESS)GetProcAddress(hMod, "NtOpenProcess");
		if (NtOpenProcess == NULL) {
			printf("Failed to get NtOpenProcess()\n");
			return 1;
		}

		DetourRestoreAfterWith();
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		DetourAttach(&(PVOID&)NtOpenProcess, MyNtOpenProcess);
		DetourAttach(&(PVOID&)TrueCreateFileMappingNumaW, MyCreateFileMappingNumaW);
		DetourTransactionCommit();
		break;

	case DLL_THREAD_ATTACH:
		printf("Thread attached\n");
		break;

	case DLL_THREAD_DETACH:
		printf("Thread detached\n");
		break;

	case DLL_PROCESS_DETACH:
		printf("Process detached\n");
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		DetourDetach(&(PVOID&)NtOpenProcess, MyNtOpenProcess);
		DetourDetach(&(PVOID&)TrueCreateFileMappingNumaW, MyCreateFileMappingNumaW);
		DetourTransactionCommit();
		break;
	}

	return TRUE;
}