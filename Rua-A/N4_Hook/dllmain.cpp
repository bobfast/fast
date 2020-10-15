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

static NTMAPVIEWOFSECTION pNtMapViewOfSection;
static NTCREATETHREADEX pNtCreateThreadEx;
static NTALLOCATEVIRTUALMEMORY pNtAllocateVirtualMemory;
static NTWRITEVIRTUALMEMORY pNtWriteVirtualMemory;
static NTPROTECTVIRTUALMEMORY pNtProtectVirtualMemory;
static NTQUERYSYSTEMINFORMATION pNtQuerySystemInformation;  // for getting system info

//#####################################monitor
static HANDLE hProcess = NULL;
static LPVOID monMMF = NULL;
static LPVOID dllMMF = NULL;

static LPTHREAD_START_ROUTINE  CallNtAllocateVirtualMemory = NULL;
static LPTHREAD_START_ROUTINE  CallNtProtectVirtualMemory = NULL;
static LPTHREAD_START_ROUTINE  CallNtWriteVirtualMemory = NULL;
static LPTHREAD_START_ROUTINE  CallNtCreateThreadEx = NULL;
static LPTHREAD_START_ROUTINE  CallNtMapViewOfSection = NULL;
static LPTHREAD_START_ROUTINE  CallCreateFileMappingA = NULL;
static LPTHREAD_START_ROUTINE  CallNtGetThreadContext = NULL;
static LPTHREAD_START_ROUTINE  CallNtSetThreadContext = NULL;
static LPTHREAD_START_ROUTINE  CallNtQueueApcThread = NULL;
static LPTHREAD_START_ROUTINE  CallSetWindowLongPtrA = NULL;
static LPTHREAD_START_ROUTINE  CallSleepEx = NULL;

static NTSTATUS(*PNtMapViewOfSection)(
	HANDLE SectionHandle,
	HANDLE ProcessHandle,
	PVOID* BaseAddress,
	ULONG_PTR ZeroBits,
	SIZE_T CommitSize,
	PLARGE_INTEGER SectionOffset,
	PSIZE_T ViewSize,
	SECTION_INHERIT InheritDisposition,
	ULONG AllocationType,
	ULONG Win32Protect);
//#####################################

static DBGPRINT pDbgPrint; // for debug printing 
static NTSUSPENDTHREAD pNtSuspendThread;
static NTGETCONTEXTTHREAD pNtGetThreadContext;
static NTSETCONTEXTTHREAD pNtSetThreadContext;
static RESUMETHREAD pNtResumeThread;

static NTSUSPENDTHREAD RuaNtSuspendThread;
static NTGETCONTEXTTHREAD RuaNtGetThreadContext;
static NTSETCONTEXTTHREAD RuaNtSetThreadContext;
static RESUMETHREAD RuaNtResumeThread;


//CONTEXT old_ctx, new_ctx; last use
RUNTIME_MEM_ENTRY* result;
HMODULE hMod = NULL;
DWORD64 old_result,new_result;
CONTEXT old_ctx, new_ctx;

//NtSuspendThread
DLLBASIC_API NTSTATUS NTAPI NtSuspendThread(
	HANDLE ThreadHandle,
	PULONG PreviousSuspendCount
) {
	return pNtSuspendThread(
		ThreadHandle,
		PreviousSuspendCount
	);
}

//NtGetContextThread
DLLBASIC_API NTSTATUS NTAPI NtGetThreadContext(
	HANDLE ThreadHandle,
	CONTEXT pContext
) {
	char buf[MSG_SIZE] = "";
	HANDLE hThread = NULL;
	pDbgPrint("1N4_HOOK: PID=%d, NtGetThreadContext is hooked!\n", GetCurrentProcessId());
	pDbgPrint("1N4_HOOK: DETECTED GetThreadContext\n");
	pDbgPrint("1CONTEXT.Rip : %016I64X\n", pContext.Rip);
	//************************************
	/*sprintf_s(buf, "%d:CallNtAllocateVirtualMemory:IPC Successed!", GetCurrentProcessId());
	memcpy(dllMMF, buf, strlen(buf));

	hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)CallNtAllocateVirtualMemory, monMMF, 0, NULL);
	WaitForSingleObject(hThread, INFINITE);
	pDbgPrint("%s\n", dllMMF);
	printf("%s\n", dllMMF);*/
	//************************************
	return (*pNtGetThreadContext)(
		ThreadHandle,
		pContext
		);
};

//NtSetContextThread
DLLBASIC_API NTSTATUS NTAPI NtSetThreadContext(
	HANDLE ThreadHandle,
	CONTEXT lpContext
) {
	pDbgPrint("1N4_HOOK: PID=%d, NtSetThreadContext is hooked!\n", GetCurrentProcessId());
	pDbgPrint("1N4_HOOK: DETECTED SetThreadContext\n");
	pDbgPrint("1CONTEXT.Rip : %016I64X\n", lpContext.Rip);
	return (*pNtSetThreadContext)(
		ThreadHandle,
		lpContext
	);
}

//NtResumeThread
DLLBASIC_API NTSTATUS NTAPI NtResumeThread(
	HANDLE ThreadHandle
) {
	return pNtResumeThread(
		ThreadHandle
	);
}

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD dwReason, LPVOID reserved)
{
	hinst;
	dwReason;
	reserved;

	HANDLE hMemoryMap = NULL;
	LPBYTE pMemoryMap = NULL;

	HANDLE fm;
	char* map_addr;

	LPVOID lpMap = 0;
	SIZE_T viewsize = 0;

	int sz;

	HMODULE hMod = NULL;
	switch (dwReason)
	{
	case DLL_PROCESS_ATTACH:
		/*
		//#############################monitor
		hMemoryMap = OpenFileMappingA(FILE_MAP_READ, FALSE, (LPCSTR)"shared");

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

		sz = strlen((char*)pMemoryMap) + 1;

		printf("%s\n", (char*)pMemoryMap);
		printf("%d\n", *(DWORD*)((char*)pMemoryMap + sz));
		*/
		// get ntdll module
		hMod = GetModuleHandleA("ntdll.dll");
		if (hMod == NULL) {
			printf("N4Hook: Error - cannot find ntdll.dll module.\n");
			return 1;
		}
		// get functions in ntdll
		pNtMapViewOfSection = (NTMAPVIEWOFSECTION)GetProcAddress(hMod, "NtMapViewOfSection");
		if (pNtMapViewOfSection == NULL) {
			printf("N4Hook: Error - cannot get NtMapViewOfSection's address.\n");
			return 1;
		}
		pNtCreateThreadEx = (NTCREATETHREADEX)GetProcAddress(hMod, "NtCreateThreadEx");
		if (pNtCreateThreadEx == NULL) {
			printf("N4Hook: Error - cannot get NtCreateThreadEx's address.\n");
			return 1;
		}
		pNtAllocateVirtualMemory = (NTALLOCATEVIRTUALMEMORY)GetProcAddress(hMod, "NtAllocateVirtualMemory");
		if (pNtAllocateVirtualMemory == NULL) {
			printf("N4Hook: Error - cannot get NtAllocateVirtualMemory's address.\n");
			return 1;
		}
		pNtWriteVirtualMemory = (NTWRITEVIRTUALMEMORY)GetProcAddress(hMod, "NtWriteVirtualMemory");
		if (pNtWriteVirtualMemory == NULL) {
			printf("N4Hook: Error - cannot get NtWriteVirtualMemory's address.\n");
			return 1;
		}
		pNtQuerySystemInformation = (NTQUERYSYSTEMINFORMATION)GetProcAddress(hMod, "NtQuerySystemInformation");
		if (pNtQuerySystemInformation == NULL) {
			printf("N4Hook: Error - cannot get NtQuerySystemInformation's address.\n");
			return 1;
		}
		pNtProtectVirtualMemory = (NTPROTECTVIRTUALMEMORY)GetProcAddress(hMod, "NtProtectVirtualMemory");
		if (pNtProtectVirtualMemory == NULL) {
			printf("N4Hook: Error - cannot get NtProtectVirtualMemory's address.\n");
			return 1;
		}
		pNtSuspendThread = (NTSUSPENDTHREAD)GetProcAddress(hMod, "NtSuspendThread");
		if (pNtSuspendThread == NULL) {
			printf("N4Hook: Error - cannot find NtSuspendThread's address.\n");
			return 1;
		}
		pNtGetThreadContext = (NTGETCONTEXTTHREAD)GetProcAddress(hMod, "NtGetContextThread");
		if (pNtGetThreadContext == NULL) {
			printf("N4Hook: Error - cannot find NtGetContextThread's address.\n");
			return 1;
		}
		RuaNtGetThreadContext = (NTGETCONTEXTTHREAD)GetProcAddress(hMod, "NtGetContextThread");
		if (pNtGetThreadContext == NULL) {
			printf("N4Hook: Error - cannot find NtGetContextThread's address.\n");
			return 1;
		}
		pNtSetThreadContext = (NTSETCONTEXTTHREAD)GetProcAddress(hMod, "NtSetContextThread");
		if (pNtSetThreadContext == NULL) {
			printf("N4Hook: Error - cannot find NtSetContextThread's address.\n");
			return 1;
		}
		pNtResumeThread = (RESUMETHREAD)GetProcAddress(hMod, "NtResumeThread");
		if (pNtResumeThread == NULL) {
			printf("N4Hook: Error - cannot find NtResumeThread's address.\n");
			return 1;
		}
		pDbgPrint = (DBGPRINT)GetProcAddress(hMod, "DbgPrint");
		if (pDbgPrint == NULL) {
			printf("N4Hook: Error - cannot get DbgPrint's address.\n");
			return 1;
		}/*
		fm = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, MSG_SIZE, NULL);
		map_addr = (char*)MapViewOfFile(fm, FILE_MAP_ALL_ACCESS, 0, 0, 0);

		hProcess = OpenProcess(PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD, FALSE, *(DWORD*)((char*)pMemoryMap + sz));

		(*pNtMapViewOfSection)(fm, hProcess, &lpMap, 0, MSG_SIZE, nullptr, (PULONG)(&viewsize), ViewUnmap, 0, PAGE_READWRITE); // "The default behavior for executable pages allocated is to be marked valid call targets for CFG." (https://docs.microsoft.com/en-us/windows/desktop/api/memoryapi/nf-memoryapi-mapviewoffile)

		monMMF = (LPVOID)lpMap;
		dllMMF = (LPVOID)map_addr;
		
		CallNtAllocateVirtualMemory = (LPTHREAD_START_ROUTINE)(*(DWORD64*)(pMemoryMap + sz + sizeof(DWORD)));
		CallNtProtectVirtualMemory = (LPTHREAD_START_ROUTINE)(*(DWORD64*)(pMemoryMap + sz + sizeof(DWORD) + sizeof(DWORD64)));
		CallNtWriteVirtualMemory = (LPTHREAD_START_ROUTINE)(*(DWORD64*)(pMemoryMap + sz + sizeof(DWORD) + 2 * sizeof(DWORD64)));
		CallNtCreateThreadEx = (LPTHREAD_START_ROUTINE)(*(DWORD64*)(pMemoryMap + sz + sizeof(DWORD) + 3 * sizeof(DWORD64)));
		CallNtMapViewOfSection = (LPTHREAD_START_ROUTINE)(*(DWORD64*)(pMemoryMap + sz + sizeof(DWORD) + 4 * sizeof(DWORD64)));
		CallCreateFileMappingA = (LPTHREAD_START_ROUTINE)(*(DWORD64*)(pMemoryMap + sz + sizeof(DWORD) + 5 * sizeof(DWORD64)));
		CallNtGetThreadContext = (LPTHREAD_START_ROUTINE)(*(DWORD64*)(pMemoryMap + sz + sizeof(DWORD) + 6 * sizeof(DWORD64)));
		CallNtSetThreadContext = (LPTHREAD_START_ROUTINE)(*(DWORD64*)(pMemoryMap + sz + sizeof(DWORD) + 7 * sizeof(DWORD64)));
		CallNtQueueApcThread = (LPTHREAD_START_ROUTINE)(*(DWORD64*)(pMemoryMap + sz + sizeof(DWORD) + 8 * sizeof(DWORD64)));
		CallSetWindowLongPtrA = (LPTHREAD_START_ROUTINE)(*(DWORD64*)(pMemoryMap + sz + sizeof(DWORD) + 9 * sizeof(DWORD64)));
		CallSleepEx = (LPTHREAD_START_ROUTINE)(*(DWORD64*)(pMemoryMap + sz + sizeof(DWORD) + 10 * sizeof(DWORD64)));

		printf("%llu\n", *(DWORD64*)(pMemoryMap + sz + sizeof(DWORD)));
		//#############################
		*/
		DetourRestoreAfterWith();
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());

		DetourAttach(&(PVOID&)pNtSuspendThread, NtSuspendThread);
		DetourAttach(&(PVOID&)pNtGetThreadContext, NtGetThreadContext);
		DetourAttach(&(PVOID&)pNtSetThreadContext, NtSetThreadContext);
		DetourAttach(&(PVOID&)pNtResumeThread, NtResumeThread);
		DetourTransactionCommit();
		printf("DLL_PROCESS_ATTACH\n");
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

		DetourDetach(&(PVOID&)pNtSuspendThread, NtSuspendThread);
		DetourDetach(&(PVOID&)pNtGetThreadContext, NtGetThreadContext);
		DetourDetach(&(PVOID&)pNtSetThreadContext, NtSetThreadContext);
		DetourDetach(&(PVOID&)pNtResumeThread, NtResumeThread);
		DetourTransactionCommit();
		printf("DLL_PROCESS_DETACH\n");
		break;
	}

	return TRUE;
}