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
static CREATEREMOTETHREAD pCreateRemoteThread = CreateRemoteThread;
static VIRTUALALLOCEX pVirtualAllocEx = VirtualAllocEx;
static WRITEPROCESSMEMORY pWriteProcessMemory = WriteProcessMemory;
static NTPROTECTVIRTUALMEMORY pNtProtectVirtualMemory;
static NTQUERYSYSTEMINFORMATION pNtQuerySystemInformation;  // for getting system info
HMODULE hMod = NULL;
//#####################################monitor
static HANDLE hProcess = NULL;
static LPVOID monMMF = NULL;
static LPVOID dllMMF = NULL;
unsigned char* writtenBuffer = NULL;
unsigned int writtenBufferLen = 0;
static HANDLE hMonProcess = NULL;

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
static NTSUSPENDTHREAD pMyNtSuspendThread;
static GETTHREADCONTEXT pMyNtGetThreadContext;
static SETTHREADCONTEXT pMyNtSetThreadContext;
static RESUMETHREAD pMyNtResumeThread;

// My CreateRemoteThread Hooking Function
DLLBASIC_API HANDLE WINAPI MyCreateRemoteThread(
	HANDLE                 hProcess,
	LPSECURITY_ATTRIBUTES  lpThreadAttributes,
	SIZE_T                 dwStackSize,
	LPTHREAD_START_ROUTINE lpStartAddress,
	LPVOID                 lpParameter,
	DWORD                  dwCreationFlags,
	LPDWORD                lpThreadId)
{
	char buf[MSG_SIZE] = "";
	HANDLE hMonThread = NULL;

	memcpy(dllMMF, buf, strlen(buf));
	hMonThread = pCreateRemoteThread(hMonProcess, NULL, 0, CallCreateRemoteThread, monMMF, 0, NULL);
	WaitForSingleObject(hMonThread, INFINITE);
	printf("%s\n", dllMMF);

	if (writtenBuffer != NULL) {
		free(writtenBuffer);
		writtenBuffer = NULL;
		writtenBufferLen = 0;
	}

	return pCreateRemoteThread(
		hProcess,
		lpThreadAttributes,
		dwStackSize,
		lpStartAddress,
		lpParameter,
		dwCreationFlags,
		lpThreadId
	);
}

//CONTEXT old_ctx, new_ctx; last use
RUNTIME_MEM_ENTRY* result;
DWORD64 old_result,new_result;
CONTEXT old_ctx, new_ctx;

//NtSuspendThread
DLLBASIC_API NTSTATUS NTAPI MyNtSuspendThread(
	HANDLE ThreadHandle,
	PULONG PreviousSuspendCount
) {
	return pMyNtSuspendThread(
		ThreadHandle,
		PreviousSuspendCount
	);
}

//NtGetContextThread

DLLBASIC_API BOOL WINAPI MyNtGetThreadContext(
	HANDLE ThreadHandle,
	CONTEXT pContext
) {
	printf("--------------------------------------------------------------\n");
	pContext.ContextFlags = CONTEXT_ALL;
	/*
	pDbgPrint("N4_HOOK: PID=%d, NtGetThreadContext is hooked!\n", GetCurrentProcessId());
	pDbgPrint("N4_HOOK: DETECTED GetThreadContext\n");
	pDbgPrint("CONTEXT.Rip : %016I64X\n", pContext.Rip);
	*/
	printf("N4_HOOK: PID=%d, NtGetThreadContext is hooked!\n", GetCurrentProcessId());
	printf("N4_HOOK: DETECTED GetThreadContext\n");
	printf("CONTEXT.Rip : %016I64X\n", pContext.Rip);
	//************************************
	char buf[MSG_SIZE] = "";
	HANDLE hThread = NULL;

	sprintf_s(buf, "%d:CallNtGetThreadContext:IPC Successed!\n", GetCurrentProcessId());
	memcpy(dllMMF, buf, strlen(buf));

	hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)CallGetThreadContext, monMMF, 0, NULL);
	WaitForSingleObject(hThread, INFINITE);
	printf("%s\n", dllMMF);
	//************************************
	return pContext.Rip;/*(*pMyNtGetThreadContext)(
		ThreadHandle,
		pContext
		);*/
};

//NtSetContextThread
DLLBASIC_API BOOL WINAPI MyNtSetThreadContext(
	HANDLE ThreadHandle,
	CONTEXT lpContext
) {
	lpContext.ContextFlags = CONTEXT_ALL;
	/*
	pDbgPrint("N4_HOOK: PID=%d, NtSetThreadContext is hooked!\n", GetCurrentProcessId());
	pDbgPrint("N4_HOOK: DETECTED SetThreadContext\n");
	pDbgPrint("CONTEXT.Rip : %016I64X\n", lpContext.Rip);
	*/
	printf("N4_HOOK: PID=%d, NtSetThreadContext is hooked!\n", GetCurrentProcessId());
	printf("N4_HOOK: DETECTED SetThreadContext\n");
	printf("CONTEXT.Rip : %016I64X\n", lpContext.Rip);
	return lpContext.Rip;/*(*pMyNtSetThreadContext)(
		ThreadHandle,
		lpContext
	);*/
}

//NtResumeThread
DLLBASIC_API NTSTATUS NTAPI MyNtResumeThread(
	HANDLE ThreadHandle
) {
	return pMyNtResumeThread(
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

	switch (dwReason)
	{
	case DLL_PROCESS_ATTACH:
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
		pMyNtSuspendThread = (NTSUSPENDTHREAD)GetProcAddress(hMod, "NtSuspendThread");
		if (pMyNtSuspendThread == NULL) {
			printf("N4Hook: Error - cannot find MyNtSuspendThread's address.\n");
			return 1;
		}
		
		pMyNtGetThreadContext = (GETTHREADCONTEXT)GetProcAddress(hMod, "NtGetContextThread");
		if (pMyNtGetThreadContext == NULL) {
			printf("N4Hook: Error - cannot find MyNtGetContextThread's address.\n");
			return 1;
		}
		pMyNtSetThreadContext = (SETTHREADCONTEXT)GetProcAddress(hMod, "NtSetContextThread");
		if (pMyNtSetThreadContext == NULL) {
			printf("N4Hook: Error - cannot find MyNtSetContextThread's address.\n");
			return 1;
		}
		
		pMyNtResumeThread = (RESUMETHREAD)GetProcAddress(hMod, "NtResumeThread");
		if (pMyNtResumeThread == NULL) {
			printf("N4Hook: Error - cannot find MyNtResumeThread's address.\n");
			return 1;
		}
		pDbgPrint = (DBGPRINT)GetProcAddress(hMod, "DbgPrint");
		if (pDbgPrint == NULL) {
			printf("N4Hook: Error - cannot get DbgPrint's address.\n");
			return 1;
		}
		fm = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, MSG_SIZE, NULL);
		map_addr = (char*)MapViewOfFile(fm, FILE_MAP_ALL_ACCESS, 0, 0, 0);

		hMonProcess = OpenProcess(PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD, FALSE, *(DWORD*)((char*)pMemoryMap + sz));

		(*pNtMapViewOfSection)(fm, hMonProcess, &lpMap, 0, MSG_SIZE, nullptr, (PULONG)(&viewsize), ViewUnmap, 0, PAGE_READWRITE); // "The default behavior for executable pages allocated is to be marked valid call targets for CFG." (https://docs.microsoft.com/en-us/windows/desktop/api/memoryapi/nf-memoryapi-mapviewoffile)

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
		//#############################
		
		DetourRestoreAfterWith();
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		DetourAttach(&(PVOID&)pCreateRemoteThread, MyCreateRemoteThread);
		DetourAttach(&(PVOID&)pMyNtSuspendThread, MyNtSuspendThread);
		DetourAttach(&(PVOID&)pMyNtGetThreadContext, MyNtGetThreadContext);
		DetourAttach(&(PVOID&)pMyNtSetThreadContext, MyNtSetThreadContext);
		DetourAttach(&(PVOID&)pMyNtResumeThread, MyNtResumeThread);
		DetourTransactionCommit();
		printf("N4Hook: DLL_PROCESS_ATTACH\n");
		break;
	case DLL_THREAD_ATTACH:
		printf("N4Hook: DLL_THREAD_ATTACH\n");
		break;
	case DLL_THREAD_DETACH:
		printf("N4Hook: DLL_THREAD_DETACH\n");
		break;
	case DLL_PROCESS_DETACH:
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		DetourDetach(&(PVOID&)pCreateRemoteThread, MyCreateRemoteThread);
		DetourDetach(&(PVOID&)pMyNtSuspendThread, MyNtSuspendThread);
		DetourDetach(&(PVOID&)pMyNtGetThreadContext, MyNtGetThreadContext);
		DetourDetach(&(PVOID&)pMyNtSetThreadContext, MyNtSetThreadContext);
		DetourDetach(&(PVOID&)pMyNtResumeThread, MyNtResumeThread);
		DetourTransactionCommit();
		printf("N4Hook: DLL_PROCESS_DETACH\n");
		break;
	}

	return TRUE;
}