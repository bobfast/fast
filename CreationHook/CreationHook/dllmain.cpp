// dllmain.cpp : DLL 애플리케이션의 진입점을 정의합니다.
#include "pch.h"
#include "detours.h"

static NTMAPVIEWOFSECTION pNtMapViewOfSection;
static CREATEREMOTETHREAD pCreateRemoteThread = CreateRemoteThread;
static VIRTUALALLOCEX pVirtualAllocEx = VirtualAllocEx;
static WRITEPROCESSMEMORY pWriteProcessMemory = WriteProcessMemory;
static DBGPRINT pDbgPrint;  // for debug printing 
HMODULE hMod = NULL;
unsigned char* writtenBuffer = NULL;
unsigned int writtenBufferLen = 0;
HANDLE eventLog = RegisterEventSourceA(NULL, "CreationHookLog");
bool isDetectedRWXPageWhenInitializing = false;

//#####################################

static HANDLE hMonProcess = NULL;

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

//#####################################

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
	pDbgPrint("CreationHook: PID=%d, NtMapViewOfSection is hooked!\n", GetCurrentProcessId());
	pDbgPrint("              AllocationType = %x, Protect = %x\n", AllocationType, Protect);

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
	/*
	char buf[MSG_SIZE] = "";
	HANDLE hThread = NULL;
	*/

	pDbgPrint("CreationHook: PID=%d, CreateRemoteThread is hooked!\n", GetCurrentProcessId());
	pDbgPrint("              lpStartAddress=%p\n", lpStartAddress);
	
	/*
	sprintf_s(buf, "%d:CallCreateRemoteThread:IPC Successful!     ", GetCurrentProcessId());
	memcpy(dllMMF, buf, strlen(buf));

	hThread = pCreateRemoteThread(hMonProcess, NULL, 0, (LPTHREAD_START_ROUTINE)CallCreateRemoteThread, monMMF, 0, NULL);
	WaitForSingleObject(hThread, INFINITE);
	*/

	if (lpStartAddress == (LPTHREAD_START_ROUTINE)LoadLibraryA) {
		pDbgPrint("************* LoadLibraryA DETECTED! *************\n");

		if (writtenBuffer != NULL) {
			LPCSTR msgs[] = {
				"LoadLibraryA Detected.",
				(LPCSTR)writtenBuffer
			};

			if (eventLog != NULL)
				ReportEventA(eventLog, EVENTLOG_SUCCESS, 0, 5678, NULL, 2, 0, msgs, NULL);
		}
	}

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

// My VirtualAllocEx Hooking Function
DLLBASIC_API LPVOID WINAPI MyVirtualAllocEx(
	HANDLE hProcess,
	LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD  flAllocationType,
	DWORD  flProtect)
{
	char buf[MSG_SIZE] = "";
	HANDLE hThread = NULL;

	pDbgPrint("CreationHook: PID=%d, VirtualAllocEx is hooked!\n", GetCurrentProcessId());
	pDbgPrint("              flAllocationType = %x, flProtect = %x\n", flAllocationType, flProtect);

	sprintf_s(buf, "%d:CallVirtualAllocEx:IPC Successful!   ", GetCurrentProcessId());

	if (flAllocationType == (MEM_RESERVE | MEM_COMMIT) && flProtect == PAGE_EXECUTE_READWRITE) {
		if (isDetectedRWXPageWhenInitializing) {
			char pid_msg[20];
			LPCSTR msgs[] = {
					"Non-initial RWX Page Detected.",
					(LPCSTR)pid_msg
			};
			sprintf_s(pid_msg, "PID=%d", GetCurrentProcessId());

			pDbgPrint("************* NON-INITIAL PAGE_EXECUTE_READWRITE DETECTED! *************\n");
			
			ReportEventA(eventLog, EVENTLOG_SUCCESS, 0, 5678, NULL, 2, 0, msgs, NULL);
			strcat_s(buf, "\nCreationHook:IPC:Non-initial RWX Page Detected.   ");
		}
		else {
			isDetectedRWXPageWhenInitializing = true;
		}
	}

	memcpy(dllMMF, buf, strlen(buf));
	hThread = CreateRemoteThread(hMonProcess, NULL, 0, (LPTHREAD_START_ROUTINE)CallVirtualAllocEx, monMMF, 0, NULL);
	WaitForSingleObject(hThread, INFINITE);
	printf("%s\n", dllMMF);

	//MEM_COMMIT: 0x00001000
	//MEM_RESERVE: 0x00002000
	//MEM_RESET: 0x00080000

	//PAGE_NOACCESS: 0x01
	//PAGE_READONLY: 0x02
	//PAGE_READWRITE: 0x04
	//PAGE_EXECUTE: 0x10
	//PAGE_EXECUTE_READ: 0x20
	//PAGE_EXECUTE_READWRITE: 0x40
	//PAGE_GUARD: 0x100
	//PAGE_NOCACHE: 0x200
	//PAGE_WRITECOMBINE: 0x400

	return pVirtualAllocEx(
		hProcess,
		lpAddress,
		dwSize,
		flAllocationType,
		flProtect
		);
}

// My WriteProcessMemory Hooking Function
DLLBASIC_API BOOL WINAPI MyWriteProcessMemory(
	HANDLE  hProcess,
	LPVOID  lpBaseAddress,
	LPCVOID lpBuffer,
	SIZE_T  nSize,
	SIZE_T* lpNumberOfBytesWritten)
{
	pDbgPrint("CreationHook: PID=%d, WriteProcessMemory is hooked!\n", GetCurrentProcessId());
	pDbgPrint("              nSize=%u\n", nSize);
	pDbgPrint("              Buffer(first 30) = ");

	if (writtenBuffer != NULL) {
		free(writtenBuffer);
		writtenBuffer = NULL;
		writtenBufferLen = 0;
	}
	
	writtenBufferLen = nSize < 64 ? nSize : 64;
	writtenBuffer = (unsigned char*) malloc((size_t)writtenBufferLen + 1);

	if (writtenBuffer != NULL) {
		memcpy(writtenBuffer, lpBuffer, writtenBufferLen);
		writtenBuffer[writtenBufferLen] = '\0';
		for (ULONG i = 0; i < 30 && i < nSize; i++) {
			pDbgPrint("%02x ", writtenBuffer[i]);
		}
	}
	else {
		pDbgPrint("(memory allocation failed)");
	}

	pDbgPrint("\n");

	return pWriteProcessMemory(
		hProcess,
		lpBaseAddress,
		lpBuffer,
		nSize,
		lpNumberOfBytesWritten
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

		//#############################

		hMemoryMap = OpenFileMapping(FILE_MAP_READ, FALSE, (LPCSTR)"shared");

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
			printf("CreationHook: Error - cannot get ntdll.dll module.\n");
			return 1;
		}

		// get functions in ntdll
		pNtMapViewOfSection = (NTMAPVIEWOFSECTION)GetProcAddress(hMod, "NtMapViewOfSection");
		if (pNtMapViewOfSection == NULL) {
			printf("CreationHook: Error - cannot get NtMapViewOfSection's address.\n");
			return 1;
		}
		pDbgPrint = (DBGPRINT)GetProcAddress(hMod, "DbgPrint");
		if (pDbgPrint == NULL) {
			printf("CreationHook: Error - cannot get DbgPrint's address.\n");
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

		// TODO: attaching
		DetourAttach(&(PVOID&)pNtMapViewOfSection, MyNtMapViewOfSection);
		DetourAttach(&(PVOID&)pCreateRemoteThread, MyCreateRemoteThread);
		DetourAttach(&(PVOID&)pVirtualAllocEx, MyVirtualAllocEx);
		DetourAttach(&(PVOID&)pWriteProcessMemory, MyWriteProcessMemory);

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
		DetourDetach(&(PVOID&)pCreateRemoteThread, MyCreateRemoteThread);
		DetourDetach(&(PVOID&)pVirtualAllocEx, MyVirtualAllocEx);
		DetourDetach(&(PVOID&)pWriteProcessMemory, MyWriteProcessMemory);

		DetourTransactionCommit();
		printf("CreationHook: Process detached.\n");
		break;
	}

	return TRUE;
}