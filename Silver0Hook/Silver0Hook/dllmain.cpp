// dllmain.cpp : DLL 애플리케이션의 진입점을 정의합니다.
#include "pch.h"
#include "framework.h"
#include <stdio.h>
#include <detours.h>

#pragma comment(lib, "detours.lib")
#define DLLBASIC_API extern "C" __declspec(dllexport)

HMODULE hMod = NULL;
HANDLE CheckPoint_W = NULL;
HANDLE CheckPoint_M = NULL;

int MagicNum_W = 0;
int MagicNum_M = 0;

static NTMAPVIEWOFSECTION TrueNtMapViewOfSection;
static HANDLE(WINAPI* TrueCreateFileMappingA)(HANDLE hFile, LPSECURITY_ATTRIBUTES lpFileMappingAttributes, DWORD flProtect, DWORD dwMaximumSizeHigh, DWORD dwMaximumSizeLow, LPCSTR lpName) = CreateFileMappingA;
static LPVOID(WINAPI* TrueMapViewOfFile)(HANDLE hFileMappingObject, DWORD dwDesiredAccess, DWORD dwFileOffsetHigh, DWORD dwFileOffsetLow, SIZE_T dwNumberOfBytesToMap) = MapViewOfFile;
static HANDLE(WINAPI* TrueOpenProcess)(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId) = OpenProcess;

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
	// hFile = INVALID_HANDLE_VALUE CHECKING!!!
	// flProtect = PAGE_EXECUTE_READWRITE CHECKING!!!
	CheckPoint_W = TrueCreateFileMappingA(hFile, lpFileMappingAttributes, flProtect, dwMaximumSizeHigh, dwMaximumSizeLow, lpName);
	return CheckPoint_W;
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
	if (hFileMappingObject == CheckPoint_W) {
		MagicNum_W = 1;
	}
	// dwDesiredAccess = FILE_MAP_ALL_ACCESS CHECKING!!!
	return TrueMapViewOfFile(hFileMappingObject, dwDesiredAccess, dwFileOffsetHigh, dwFileOffsetLow, dwNumberOfBytesToMap);
}
// OpenProcess
DLLBASIC_API HANDLE	WINAPI MyOpenProcess(
	DWORD dwDesiredAccess,
	BOOL  bInheritHandle,
	DWORD dwProcessId
)
{
	printf("OpenProcess is HOOKED!!~~~~~~\n");
	// dwDesiredAccess = (PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD) CHECKING!!!
	CheckPoint_M = TrueOpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId);
	return CheckPoint_M;
}

// My NtMapViewOfSection Hooking Function
DLLBASIC_API NTSTATUS NTAPI MyNtMapViewOfSection(
	HANDLE SectionHandle,
	HANDLE ProcessHandle,
	PVOID* BaseAddress,
	ULONG_PTR ZeroBits,
	SIZE_T CommitSize,
	PLARGE_INTEGER SectionOffset,
	PSIZE_T ViewSize,
	SECTION_INHERIT InheritDisposition,
	ULONG AllocationType,
	ULONG Win32Protect
)
{
	printf("NtMapViewOfSection is HOOKED!\n");
	if ((CheckPoint_W == SectionHandle) && (CheckPoint_M == ProcessHandle)) {
		MagicNum_M = 1;
	}
	// Protect = PAGE_EXECUTE_READWRITE CHECKING!!!
	return (*TrueNtMapViewOfSection)(
		SectionHandle,
		ProcessHandle,
		BaseAddress,
		ZeroBits,
		CommitSize,
		SectionOffset,
		ViewSize,
		InheritDisposition,
		AllocationType,
		Win32Protect);
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

		TrueNtMapViewOfSection = (NTMAPVIEWOFSECTION)GetProcAddress(hMod, "NtMapViewOfSection");
		if (TrueNtMapViewOfSection == NULL) {
			printf("Failed to get NtMapViewOfSection\n");
			return 1;
		}

		DetourRestoreAfterWith();
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		DetourAttach(&(PVOID&)TrueCreateFileMappingA, MyCreateFileMappingA);
		DetourAttach(&(PVOID&)TrueMapViewOfFile, MyMapViewOfFile);
		DetourAttach(&(PVOID&)TrueOpenProcess, MyOpenProcess);
		DetourAttach(&(PVOID&)TrueNtMapViewOfSection, MyNtMapViewOfSection);
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
		DetourDetach(&(PVOID&)TrueOpenProcess, MyOpenProcess);
		DetourDetach(&(PVOID&)TrueNtMapViewOfSection, MyNtMapViewOfSection);
		DetourTransactionCommit();
		break;
	}

	if ((MagicNum_W == 1) && (MagicNum_M == 1)) {
		// ALERT
		// PUTS BUFFERRRRRR
		// (buffer : map_addr, this->m_buf, this->m_nbyte)
		printf("DETECTED PINJECTRA#3 ATTACK!!!!!!!\n");
	}

	return TRUE;
}




/// NtOpenProcess
/*
static NTOPENPROCESS TrueNtOpenProcess = NULL;

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
*/