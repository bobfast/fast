#include <Windows.h>
#include <stdio.h>
// #include "../../src/detours.h"
#include "detours.h"

#define DLLBASIC_API extern "C" __declspec(dllexport)

// Enumeration type for NtMapViewOfSection
typedef enum _SECTION_INHERIT {
	ViewShare = 1,
	ViewUnmap = 2
} SECTION_INHERIT, * PSECTION_INHERIT;

// NtMapViewOfSection Function Pointer
typedef NTSTATUS (NTAPI* NTMAPVIEWOFSECTION)(
	HANDLE SectionHandle,
	HANDLE ProcessHandle,
	PVOID *BaseAddress,
	ULONG ZeroBits,
	ULONG CommitSize,
	PLARGE_INTEGER SectionOffset,
	PULONG ViewSize,
	SECTION_INHERIT InheritDisposition,
	ULONG AllocationType,
	ULONG Protect
	);

static NTMAPVIEWOFSECTION NtMapViewOfSection;

// My NtMapViewOfSection Hooking Function
DLLBASIC_API NTSTATUS NTAPI MyNtMapViewOfSection(
	HANDLE SectionHandle,
	HANDLE ProcessHandle,
	PVOID* BaseAddress,
	ULONG ZeroBits,
	ULONG CommitSize,
	PLARGE_INTEGER SectionOffset,
	PULONG ViewSize,
	SECTION_INHERIT InheritDisposition,
	ULONG AllocationType,
	ULONG Protect)
{
	printf("CreationHook: NtMapViewOfSection is hooked!\n");

	return NtMapViewOfSection(
		SectionHandle,
		ProcessHandle,
		BaseAddress,
		ZeroBits,
		CommitSize,
		SectionOffset,
		ViewSize,
		InheritDisposition,
		AllocationType,
		Protect);
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
		printf("CreationHook: Process attached.\n");

		hMod = GetModuleHandleA("ntdll.dll");
		NtMapViewOfSection = (NTMAPVIEWOFSECTION)GetProcAddress(hMod, "NtMapViewOfSection");
		if (NtMapViewOfSection == NULL) {
			printf("CreationHook: Error - cannot get NtMapViewOfSection's address.\n");
			return 1;
		}

		DetourRestoreAfterWith();
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());

		// TODO: attaching
		DetourAttach(&(PVOID&)NtMapViewOfSection, MyNtMapViewOfSection);

		DetourTransactionCommit();
		break;

	case DLL_THREAD_ATTACH:
		printf("CreationHook: Thread attached.\n");
		break;

	case DLL_THREAD_DETACH:
		printf("CreationHook: Thread detached.\n");
		break;

	case DLL_PROCESS_DETACH:
		printf("CreationHook: Process detached.\n");
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());

		// TODO: detaching
		DetourDetach(&(PVOID&)NtMapViewOfSection, MyNtMapViewOfSection);

		DetourTransactionCommit();
		break;
	}

	return TRUE;
}