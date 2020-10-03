#include <Windows.h>
#include <stdio.h>
#include "detours.h"
#include "Silver0Hook.h"

#define DLLBASIC_API extern "C" __declspec(dllexport)

//#pragma comment(lib, "detours.lib")
//#pragma comment(lib, "ntdll.lib")

static NTOPENPROCESS NtOpenProcess;

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

HMODULE hMod = NULL;

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
		if (DetourTransactionCommit() == NO_ERROR) {
			printf("Detour Attach GOOOOOOOOOOOOOOOOOOD!!\n");
		}
		else {
			printf("Detour Attach FAILED\n");
		}
		//DetourTransactionCommit();
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
		DetourTransactionCommit();
		break;
	}

	return TRUE;
}