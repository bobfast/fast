// dllmain.cpp : DLL 애플리케이션의 진입점을 정의합니다.
#include "pch.h"
#include "framework.h"
#include <stdio.h>
#include <string>
#include <detours.h>
#include <conio.h>

#pragma comment(lib, "detours.lib")
#define DLLBASIC_API extern "C" __declspec(dllexport)
#define MSG_SIZE 256

HMODULE hMod = NULL;
HANDLE check_map = NULL;
//BOOL check_remote = FALSE;

/// <summary>
///
/// </summary>
static HANDLE hProcess = NULL;
static LPVOID monMMF = NULL;
static LPVOID dllMMF = NULL;
static LPTHREAD_START_ROUTINE  CallVirtualAllocEx = NULL;
static LPTHREAD_START_ROUTINE  CallLoadLibraryA = NULL;
static LPTHREAD_START_ROUTINE  CallWriteProcessMemory = NULL;
static LPTHREAD_START_ROUTINE  CallCreateRemoteThread = NULL;
static LPTHREAD_START_ROUTINE  CallNtMapViewOfSection = NULL;
static LPTHREAD_START_ROUTINE  CallCreateFileMappingA = NULL;
static LPTHREAD_START_ROUTINE  CallGetThreadContext = NULL;
static LPTHREAD_START_ROUTINE  CallSetThreadContext = NULL;
static LPTHREAD_START_ROUTINE  CallNtQueueApcThread = NULL;
static LPTHREAD_START_ROUTINE  CallSetWindowLongPtrA = NULL;
static LPTHREAD_START_ROUTINE  CallSleepEx = NULL;
/// <summary>
/// 
/// </summary>
/// 


static NTMAPVIEWOFSECTION TrueNtMapViewOfSection;
static HANDLE(WINAPI* TrueCreateFileMappingA)(
	HANDLE					hFile, 
	LPSECURITY_ATTRIBUTES	lpFileMappingAttributes, 
	DWORD					flProtect, 
	DWORD					dwMaximumSizeHigh, 
	DWORD					dwMaximumSizeLow, 
	LPCSTR					lpName
	) = CreateFileMappingA;
static HANDLE(WINAPI* TrueCreateRemoteThread)(
	HANDLE                 hProcess,
	LPSECURITY_ATTRIBUTES  lpThreadAttributes,
	SIZE_T                 dwStackSize,
	LPTHREAD_START_ROUTINE lpStartAddress,
	LPVOID                 lpParameter,
	DWORD                  dwCreationFlags,
	LPDWORD                lpThreadId
	) = CreateRemoteThread;


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
	//printf("CreateFileMappingA is HOOKED!!\n");
	if ((hFile == INVALID_HANDLE_VALUE) && (flProtect == PAGE_EXECUTE_READWRITE)) {
		HANDLE hThread = NULL;
		std::string buf(std::to_string(GetCurrentProcessId()));
		buf.append(":CallCreateFileMappingA:IPC Successed!     ");
		memcpy(dllMMF, buf.c_str(), buf.size());
		hThread = TrueCreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)CallCreateFileMappingA, monMMF, 0, NULL);
		WaitForSingleObject(hThread, INFINITE);
		printf("%s\n", (char*)dllMMF);  //#####
	}

	check_map = TrueCreateFileMappingA(hFile, lpFileMappingAttributes, flProtect, dwMaximumSizeHigh, dwMaximumSizeLow, lpName);
	return check_map;
}

// NtMapViewOfSection Hooking Function
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
	//printf("NtMapViewOfSection is HOOKED!\n");
	if ((SectionHandle == check_map) && (Win32Protect == PAGE_EXECUTE_READWRITE)) {
		HANDLE hThread = NULL;
		std::string buf(std::to_string(GetCurrentProcessId()));
		buf.append(":CallNtMapViewOfSection:IPC Successed!     ");
		memcpy(dllMMF, buf.c_str(), buf.size());
		hThread = TrueCreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)CallNtMapViewOfSection, monMMF, 0, NULL);
		WaitForSingleObject(hThread, INFINITE);
		printf("%s\n", (char*)dllMMF); //####
		//check_remote = TRUE;

		if (strncmp((char*)dllMMF, "DROP", 4) == 0) {
			printf("So Dangerous\n");
			return FALSE;
		}
	}
	
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


/*
// CreateRemoteThread
DLLBASIC_API HANDLE	WINAPI MyCreateRemoteThread(
	HANDLE                 hProcess,
	LPSECURITY_ATTRIBUTES  lpThreadAttributes,
	SIZE_T                 dwStackSize,
	LPTHREAD_START_ROUTINE lpStartAddress,
	LPVOID                 lpParameter,
	DWORD                  dwCreationFlags,
	LPDWORD                lpThreadId
)
{
	//printf("CreteRemoteThread is HOOKED\n");
	if (check_remote) {
		HANDLE hThread = NULL;
		std::string buf(std::to_string(GetCurrentProcessId()));
		buf.append(":CallCreteRemoteThread:IPC Successed!     ");
		memcpy(dllMMF, buf.c_str(), buf.size());
		hThread = TrueCreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)CallCreateRemoteThread, monMMF, 0, NULL);
		WaitForSingleObject(hThread, INFINITE);
		check_remote == FALSE;
		printf("%s\n", (char*)dllMMF);  //#####

		if (strncmp((char*)dllMMF, "DROP", 4)==0) {
			printf("So Dangerous\n");
			return FALSE;
		}
	}
	return TrueCreateRemoteThread(hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId);
}*/

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD dwReason, LPVOID reserved)
{
	hinst;
	dwReason;
	reserved;
	if (dwReason == DLL_PROCESS_ATTACH)
	{
		//printf("Process attached\n");

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

		static NTMAPVIEWOFSECTION PNtMapViewOfSection;
		PNtMapViewOfSection = (NTMAPVIEWOFSECTION)GetProcAddress(hMod, "NtMapViewOfSection");

		HANDLE hMemoryMap = NULL;
		LPBYTE pMemoryMap = NULL;

		hMemoryMap = OpenFileMapping(FILE_MAP_READ, FALSE, L"shared");

		pMemoryMap = (BYTE*)MapViewOfFile(
			hMemoryMap, FILE_MAP_READ,
			0, 0, 0
		);
		if (!pMemoryMap)
		{
			CloseHandle(hMemoryMap);
			printf("MapViewOfFile Failed.\n");
			return FALSE;
		}

		int sz = strlen((char*)pMemoryMap) + 1;

		printf("%s\n", (char*)pMemoryMap);
		printf("%d\n", *(DWORD*)((char*)pMemoryMap + sz));

		HANDLE fm;
		char* map_addr;

		LPVOID lpMap = 0;
		SIZE_T viewsize = 0;

		fm = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, MSG_SIZE, NULL);
		map_addr = (char*)MapViewOfFile(fm, FILE_MAP_ALL_ACCESS, 0, 0, 0);
		hProcess = OpenProcess(PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD, FALSE, *(DWORD*)((char*)pMemoryMap + sz));

		(*PNtMapViewOfSection)(fm, hProcess, &lpMap, 0, MSG_SIZE, nullptr, &viewsize, ViewUnmap, 0, PAGE_READWRITE); // "The default behavior for executable pages allocated is to be marked valid call targets for CFG." (https://docs.microsoft.com/en-us/windows/desktop/api/memoryapi/nf-memoryapi-mapviewoffile)

		monMMF = (LPVOID)lpMap;
		dllMMF = (LPVOID)map_addr;

		CallVirtualAllocEx = (LPTHREAD_START_ROUTINE)(*(DWORD64*)(pMemoryMap + sz + sizeof(DWORD)));
		CallLoadLibraryA = (LPTHREAD_START_ROUTINE)(*(DWORD64*)(pMemoryMap + sz + sizeof(DWORD) + sizeof(DWORD64)));
		CallWriteProcessMemory = (LPTHREAD_START_ROUTINE)(*(DWORD64*)(pMemoryMap + sz + sizeof(DWORD) + 2 * sizeof(DWORD64)));
		CallCreateRemoteThread = (LPTHREAD_START_ROUTINE)(*(DWORD64*)(pMemoryMap + sz + sizeof(DWORD) + 3 * sizeof(DWORD64)));
		CallNtMapViewOfSection = (LPTHREAD_START_ROUTINE)(*(DWORD64*)(pMemoryMap + sz + sizeof(DWORD) + 4 * sizeof(DWORD64)));
		CallCreateFileMappingA = (LPTHREAD_START_ROUTINE)(*(DWORD64*)(pMemoryMap + sz + sizeof(DWORD) + 5 * sizeof(DWORD64)));
		CallGetThreadContext = (LPTHREAD_START_ROUTINE)(*(DWORD64*)(pMemoryMap + sz + sizeof(DWORD) + 6 * sizeof(DWORD64)));
		CallSetThreadContext = (LPTHREAD_START_ROUTINE)(*(DWORD64*)(pMemoryMap + sz + sizeof(DWORD) + 7 * sizeof(DWORD64)));
		CallNtQueueApcThread = (LPTHREAD_START_ROUTINE)(*(DWORD64*)(pMemoryMap + sz + sizeof(DWORD) + 8 * sizeof(DWORD64)));
		CallSetWindowLongPtrA = (LPTHREAD_START_ROUTINE)(*(DWORD64*)(pMemoryMap + sz + sizeof(DWORD) + 9 * sizeof(DWORD64)));
		CallSleepEx = (LPTHREAD_START_ROUTINE)(*(DWORD64*)(pMemoryMap + sz + sizeof(DWORD) + 10 * sizeof(DWORD64)));

		printf("%llu\n", *(DWORD64*)(pMemoryMap + sz + sizeof(DWORD)));

		DetourRestoreAfterWith();
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		DetourAttach(&(PVOID&)TrueCreateFileMappingA, MyCreateFileMappingA);
		DetourAttach(&(PVOID&)TrueNtMapViewOfSection, MyNtMapViewOfSection);
		//DetourAttach(&(PVOID&)TrueCreateRemoteThread, MyCreateRemoteThread);
		DetourTransactionCommit();
	}
	else if(dwReason == DLL_PROCESS_DETACH)
	{
		//printf("Process detached\n");
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		DetourDetach(&(PVOID&)TrueCreateFileMappingA, MyCreateFileMappingA);
		DetourDetach(&(PVOID&)TrueNtMapViewOfSection, MyNtMapViewOfSection);
		//DetourDetach(&(PVOID&)TrueCreateRemoteThread, MyCreateRemoteThread);
		DetourTransactionCommit();
		fflush(stdout);
	}

	return TRUE;
}
