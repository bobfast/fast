// dllmain.cpp : DLL 애플리케이션의 진입점을 정의합니다.
#include "pch.h"
#include "framework.h"
#include <stdio.h>
#include <detours.h>

#pragma comment(lib, "detours.lib")
#define DLLBASIC_API extern "C" __declspec(dllexport)

HMODULE hMod = NULL;

static NTOPENPROCESS TrueNtOpenProcess = NULL;
//static NTMAPVIEWOFSECTION TrueNtMapViewOfSection;
static HANDLE(WINAPI* TrueCreateFileMappingA)(HANDLE hFile, LPSECURITY_ATTRIBUTES lpFileMappingAttributes, DWORD flProtect, DWORD dwMaximumSizeHigh, DWORD dwMaximumSizeLow, LPCSTR lpName) = CreateFileMappingA;
static LPVOID(WINAPI* TrueMapViewOfFile)(HANDLE hFileMappingObject, DWORD dwDesiredAccess, DWORD dwFileOffsetHigh, DWORD dwFileOffsetLow, SIZE_T dwNumberOfBytesToMap) = MapViewOfFile;

// NtOpenProcess
NTSTATUS MyNtOpenProcess(
	PHANDLE ProcessHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PCLIENT_ID ClientId OPTIONAL
)
{
	printf("NtOpenProcess is HOOKED@@@\n");
	return TrueNtOpenProcess(ProcessHandle, DesiredAccess, ObjectAttributes, &ClientId);
}
// CreateFileMappingA
DLLBASIC_API HANDLE	WINAPI MyCreateFileMappingA(
	HANDLE                hFile,
	LPSECURITY_ATTRIBUTES lpFileMappingAttributes,
	DWORD                 flProtect,
	DWORD                 dwMaximumSizeHigh,
	DWORD                 dwMaximumSizeLow,
	LPCSTR                lpName
)
{
	printf("CreateFileMappingA is HOOKED!!\n");
	return TrueCreateFileMappingA(hFile, lpFileMappingAttributes, flProtect, dwMaximumSizeHigh, dwMaximumSizeLow, lpName);
}
// MapViewOfFile
DLLBASIC_API LPVOID	WINAPI MyMapViewOfFile(
	HANDLE hFileMappingObject,
	DWORD  dwDesiredAccess,
	DWORD  dwFileOffsetHigh,
	DWORD  dwFileOffsetLow,
	SIZE_T dwNumberOfBytesToMap
)
{
	printf("MapViewOfFile is HOOKED!!\n");
	return TrueMapViewOfFile(hFileMappingObject, dwDesiredAccess, dwFileOffsetHigh, dwFileOffsetLow, dwNumberOfBytesToMap);
}


/*
// NtMapViewOfSection
DLLBASIC_API NTSTATUS NTAPI MyNtMapViewOfSection(
	HANDLE SectionHandle,
	HANDLE ProcessHandle,
	PVOID BaseAddress,
	ULONG ZeroBits,
	ULONG CommitSize,
	PLARGE_INTEGER SectionOffset,
	PULONG ViewSize,
	SECTION_INHERIT InheritDisposition,
	ULONG AllocationType,
	ULONG Protect
)
{
	printf("NtMapViewOfSection is HOOKED!\n");

	return TrueNtMapViewOfSection(
		SectionHandle,
		ProcessHandle,
		&BaseAddress,
		ZeroBits,
		CommitSize,
		SectionOffset,
		ViewSize,
		InheritDisposition,
		AllocationType,
		Protect);
}
*/


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

		
		TrueNtOpenProcess = (NTOPENPROCESS)GetProcAddress(hMod, "NtOpenProcess");
		if (TrueNtOpenProcess == NULL) {
			printf("Failed to get NtOpenProcess()\n");
			return 1;
		}
		
		/*
		TrueNtMapViewOfSection = (NTMAPVIEWOFSECTION)GetProcAddress(hMod, "NtMapViewOfSection");
		if (TrueNtMapViewOfSection == NULL) {
			printf("Failed to get NtMapViewOfSection()\n");
			return 1;
		}
		*/

		DetourRestoreAfterWith();
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		DetourAttach(&(PVOID&)TrueCreateFileMappingA, MyCreateFileMappingA);
		DetourAttach(&(PVOID&)TrueMapViewOfFile, MyMapViewOfFile);
		DetourAttach(&(PVOID&)TrueNtOpenProcess, MyNtOpenProcess);
		//DetourAttach(&(PVOID&)TrueNtMapViewOfSection, MyNtMapViewOfSection);
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
		DetourDetach(&(PVOID&)TrueCreateFileMappingA, MyCreateFileMappingA);
		DetourDetach(&(PVOID&)TrueMapViewOfFile, MyMapViewOfFile);
		DetourDetach(&(PVOID&)TrueNtOpenProcess, MyNtOpenProcess);
		//DetourDetach(&(PVOID&)TrueNtMapViewOfSection, MyNtMapViewOfSection);
		DetourTransactionCommit();
		break;
	}

	return TRUE;
}