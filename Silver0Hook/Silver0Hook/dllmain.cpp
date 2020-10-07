// dllmain.cpp : DLL 애플리케이션의 진입점을 정의합니다.
#include "pch.h"
#include "framework.h"
#include <Windows.h>
#include <stdio.h>
#include <detours.h>
#include <memoryapi.h>
#include <winnt.h>

#pragma comment(lib, "detours.lib")
#pragma comment(lib, "ntdll.lib")
#define DLLBASIC_API extern "C" __declspec(dllexport)
static NTOPENPROCESS pNtOpenProcess;
static NTMAPVIEWOFSECTION pNtMapViewOfSection;
HMODULE hMod = NULL;

int a = 0;
int b = 0;
int c = 0;

// NtOpenProcess Hooking
DLLBASIC_API NTSTATUS NTAPI MyNtOpenProcess(
	PHANDLE				 ProcessHandle,
	ACCESS_MASK          AccessMask,
	POBJECT_ATTRIBUTES   ObjectAttributes,
	PCLIENT_ID           ClientId
)
{
	printf("NtOpenProcess is HOOKED!\n");
	a++;

	return (*pNtOpenProcess)(
		ProcessHandle,
		AccessMask,
		ObjectAttributes,
		ClientId
	);
}

// NtMapViewOfSection
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
	printf("NtMapViewOfSection is HOOKED!\n");
	b++;

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

// CreateFileMappingNumaW
DLLBASIC_API HANDLE MyCreateFileMappingNumaW(
	HANDLE                hFile,
	LPSECURITY_ATTRIBUTES lpFileMappingAttributes,
	DWORD                 flProtect,
	DWORD                 dwMaximumSizeHigh,
	DWORD                 dwMaximumSizeLow,
	LPCWSTR               lpName,
	DWORD                 nndPreferred
)
{
	printf("CreateFileMappingNumaW is HOOKED!\n");
	c++;

	return (*TrueCreateFileMappingNumaW)(
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
		printf("Attach: %d, %d, %d\n", a, b, c);

		hMod = GetModuleHandleA("ntdll.dll");
		if (hMod == NULL) {
			printf("Faild to get ntdll\n");
			return 1;
		}

		pNtOpenProcess = (NTOPENPROCESS)GetProcAddress(hMod, "NtOpenProcess");
		if (pNtOpenProcess == NULL) {
			printf("Failed to get NtOpenProcess()\n");
			return 1;
		}

		pNtMapViewOfSection = (NTMAPVIEWOFSECTION)GetProcAddress(hMod, "NtMapViewOfSection");
		if (pNtMapViewOfSection == NULL) {
			printf("Failed to get NtMapViewOfSection()\n");
			return 1;
		}

		DetourRestoreAfterWith();
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		DetourAttach(&(PVOID&)pNtOpenProcess, MyNtOpenProcess);
		DetourAttach(&(PVOID&)pNtMapViewOfSection, MyNtMapViewOfSection);
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
		DetourDetach(&(PVOID&)pNtOpenProcess, MyNtOpenProcess);
		DetourDetach(&(PVOID&)pNtMapViewOfSection, MyNtMapViewOfSection);
		DetourDetach(&(PVOID&)TrueCreateFileMappingNumaW, MyCreateFileMappingNumaW);
		DetourTransactionCommit();
		printf("Detach: %d, %d, %d\n", a, b, c);
		break;
	}

	return TRUE;
}