#include <Windows.h>
#include <stdio.h>
// #include "../../src/detours.h"
#include "detours.h"
#include "CreationHook.h"

static NTMAPVIEWOFSECTION pNtMapViewOfSection;
static NTCREATETHREADEX pNtCreateThreadEx;
static NTALLOCATEVIRTUALMEMORY pNtAllocateVirtualMemory;
static NTWRITEVIRTUALMEMORY pNtWriteVirtualMemory;
static NTPROTECTVIRTUALMEMORY pNtProtectVirtualMemory;
static DBGPRINT pDbgPrint;  // for debug printing 
HMODULE hMod = NULL;

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
	pDbgPrint("CreationHook: NtMapViewOfSection is hooked!\n");

	return (*pNtMapViewOfSection)(
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

// My NtCreateThreadEx Hooking Function
DLLBASIC_API NTSTATUS NTAPI MyNtCreateThreadEx (
	PHANDLE ThreadHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	HANDLE ProcessHandle,
	LPTHREAD_START_ROUTINE StartAddress,
	LPVOID Parameter,
	BOOL CreateSuspended,
	DWORD StackZeroBits,
	DWORD SizeOfStackCommit,
	DWORD SizeOfStackReserve,
	CREATE_THREAD_INFO* ThreadInfo)
{
	pDbgPrint("CreationHook: NtCreateThreadEx is hooked!\n");

	return (*pNtCreateThreadEx)(
		ThreadHandle,
		DesiredAccess,
		ObjectAttributes,
		ProcessHandle,
		StartAddress,
		Parameter,
		CreateSuspended,
		StackZeroBits,
		SizeOfStackCommit,
		SizeOfStackReserve,
		ThreadInfo
	);
}

// My NtAllocateVirtualMemory Hooking Function
DLLBASIC_API NTSTATUS NTAPI MyNtAllocateVirtualMemory(
	HANDLE ProcessHandle,
	PVOID* BaseAddress,
	ULONG_PTR ZeroBits,
	PSIZE_T RegionSize,
	ULONG AllocationType,
	ULONG Protect)
{
	pDbgPrint("CreationHook: NtAllocateVirtualMemory is hooked!\n");

	return (*pNtAllocateVirtualMemory)(
		ProcessHandle,
		BaseAddress,
		ZeroBits,
		RegionSize,
		AllocationType,
		Protect
	);
}

// My NtWriteVirtualMemory Hooking Function
DLLBASIC_API NTSTATUS NTAPI MyNtWriteVirtualMemory(
	HANDLE ProcessHandle,
	PVOID BaseAddress,
	PVOID Buffer,
	ULONG NumberOfBytesToWrite,
	PULONG NumberOfBytesWritten)
{
	pDbgPrint("CreationHook: NtWriteVirtualMemory is hooked!\n");

	return (*pNtWriteVirtualMemory)(
		ProcessHandle,
		BaseAddress,
		Buffer,
		NumberOfBytesToWrite,
		NumberOfBytesWritten
	);
}

// My NtProtectVirtualMemory Hooking Function
DLLBASIC_API NTSTATUS NTAPI MyNtProtectVirtualMemory(
	HANDLE ProcessHandle,
	PVOID* BaseAddress,
	PULONG NumberOfBytesToProtect,
	ULONG NewAccessProtection,
	PULONG OldAccessProtection)
{
	pDbgPrint("CreationHook: NtProtectVirtualMemory is hooked!\n");

	return (*pNtProtectVirtualMemory)(
		ProcessHandle,
		BaseAddress,
		NumberOfBytesToProtect,
		NewAccessProtection,
		OldAccessProtection
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
			printf("CreationHook: Error - cannot get ntdll.dll module.\n");
			return 1;
		}

		// get functions in ntdll
		pNtMapViewOfSection = (NTMAPVIEWOFSECTION)GetProcAddress(hMod, "NtMapViewOfSection");
		if (pNtMapViewOfSection == NULL) {
			printf("CreationHook: Error - cannot get NtMapViewOfSection's address.\n");
			return 1;
		}
		pNtCreateThreadEx = (NTCREATETHREADEX)GetProcAddress(hMod, "NtCreateThreadEx");
		if (pNtCreateThreadEx == NULL) {
			printf("CreationHook: Error - cannot get NtCreateThreadEx's address.\n");
			return 1;
		}
		pNtAllocateVirtualMemory = (NTALLOCATEVIRTUALMEMORY)GetProcAddress(hMod, "NtAllocateVirtualMemory");
		if (pNtAllocateVirtualMemory == NULL) {
			printf("CreationHook: Error - cannot get NtAllocateVirtualMemory's address.\n");
			return 1;
		}
		pNtWriteVirtualMemory = (NTWRITEVIRTUALMEMORY)GetProcAddress(hMod, "NtWriteVirtualMemory");
		if (pNtWriteVirtualMemory == NULL) {
			printf("CreationHook: Error - cannot get NtWriteVirtualMemory's address.\n");
			return 1;
		}
		pNtProtectVirtualMemory = (NTPROTECTVIRTUALMEMORY)GetProcAddress(hMod, "NtProtectVirtualMemory");
		if (pNtProtectVirtualMemory == NULL) {
			printf("CreationHook: Error - cannot get NtProtectVirtualMemory's address.\n");
			return 1;
		}
		pDbgPrint = (DBGPRINT)GetProcAddress(hMod, "DbgPrint");
		if (pDbgPrint == NULL) {
			printf("CreationHook: Error - cannot get DbgPrint's address.\n");
			return 1;
		}

		DetourRestoreAfterWith();
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());

		// TODO: attaching
		DetourAttach(&(PVOID&)pNtMapViewOfSection, MyNtMapViewOfSection);
		DetourAttach(&(PVOID&)pNtCreateThreadEx, MyNtCreateThreadEx);
		DetourAttach(&(PVOID&)pNtAllocateVirtualMemory, MyNtAllocateVirtualMemory);
		DetourAttach(&(PVOID&)pNtWriteVirtualMemory, MyNtWriteVirtualMemory);
		DetourAttach(&(PVOID&)pNtProtectVirtualMemory, MyNtProtectVirtualMemory);

		DetourTransactionCommit();

		printf("CreationHook: Process attached.\n");
		break;

	case DLL_THREAD_ATTACH:
		printf("CreationHook: Thread attached.\n");
		break;

	case DLL_THREAD_DETACH:
		printf("CreationHook: Thread detached.\n");
		break;

	case DLL_PROCESS_DETACH:
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());

		// TODO: detaching
		DetourDetach(&(PVOID&)pNtMapViewOfSection, MyNtMapViewOfSection);
		DetourDetach(&(PVOID&)pNtCreateThreadEx, MyNtCreateThreadEx);
		DetourDetach(&(PVOID&)pNtAllocateVirtualMemory, MyNtAllocateVirtualMemory);
		DetourDetach(&(PVOID&)pNtWriteVirtualMemory, MyNtWriteVirtualMemory);
		DetourDetach(&(PVOID&)pNtProtectVirtualMemory, MyNtProtectVirtualMemory);

		DetourTransactionCommit();
		printf("CreationHook: Process detached.\n");
		break;
	}

	return TRUE;
}