// dllmain.cpp : DLL 애플리케이션의 진입점을 정의합니다.
#include "pch.h"
#include "detours.h"

static NTMAPVIEWOFSECTION pNtMapViewOfSection;
static NTCREATETHREADEX pNtCreateThreadEx;
static NTALLOCATEVIRTUALMEMORY pNtAllocateVirtualMemory;
static NTWRITEVIRTUALMEMORY pNtWriteVirtualMemory;
static NTPROTECTVIRTUALMEMORY pNtProtectVirtualMemory;
static DBGPRINT pDbgPrint;  // for debug printing 
static NTQUERYSYSTEMINFORMATION pNtQuerySystemInformation;  // for getting system info
HMODULE hMod = NULL;
unsigned char* writtenBuffer = NULL;
unsigned int writtenBufferLen = 0;
HANDLE eventLog = RegisterEventSourceA(NULL, "CreationHookLog");
bool isDetectedRWXPageWhenInitializing = false;

//#####################################

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

// My NtCreateThreadEx Hooking Function
DLLBASIC_API NTSTATUS NTAPI MyNtCreateThreadEx(
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
	/* ProcessID가 0으로 되는 등 제대로 출력이 안돼서 주석으로 남겨두었습니다. */
	/*
	NTSTATUS status;
	ULONG cbBuffer = 131072;
	PVOID pBuffer;
	PSYSTEM_PROCESS_INFORMATION info;

	while (1) {
		pBuffer = malloc(cbBuffer);
		if (pBuffer == NULL) {
			pDbgPrint("CreationHook: NtCreateThreadEx is hooked!\n");
			break;
		}

		status = pNtQuerySystemInformation(SystemProcessInformation, pBuffer, cbBuffer, &cbBuffer);
		pDbgPrint("CreationHook: status=%d\n", status);

		if (status == STATUS_INFO_LENGTH_MISMATCH) {
			free(pBuffer);
			cbBuffer *= 2;
			continue;
		}
		else if (status < 0) {
			pDbgPrint("CreationHook: NtCreateThreadEx is hooked!\n");
			free(pBuffer);
			break;
		}
		else {
			info = (PSYSTEM_PROCESS_INFORMATION)pBuffer;
			pDbgPrint("CreationHook: NtCreateThreadEx is hooked!\n");
			while (info->NextEntryDelta != 0) {
				pDbgPrint("              ProcessID=%u\n", info->ProcessId);
				pDbgPrint("              ProcessName=%wZ\n", (info->ProcessName).Buffer);
				pDbgPrint("              ThreadCount=%u\n", info->ThreadCount);

				info = (PSYSTEM_PROCESS_INFORMATION)(info->NextEntryDelta + (PBYTE)info);
			}
			free(pBuffer);
			break;
		}
	}
	*/

	/*
	char buf[MSG_SIZE] = "";
	HANDLE hThread = NULL;
	*/

	pDbgPrint("CreationHook: PID=%d, NtCreateThreadEx is hooked!\n", GetCurrentProcessId());
	pDbgPrint("              StartAddress=%p\n", StartAddress);
	
	/*
	sprintf_s(buf, "%d:CallNtCreateThread:IPC Successful!     ", GetCurrentProcessId());
	memcpy(dllMMF, buf, strlen(buf));

	hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)CallNtCreateThreadEx, monMMF, 0, NULL);
	WaitForSingleObject(hThread, INFINITE);
	*/

	if (StartAddress == (LPTHREAD_START_ROUTINE)LoadLibraryA) {
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
	char buf[MSG_SIZE] = "";
	HANDLE hThread = NULL;

	pDbgPrint("CreationHook: PID=%d, NtAllocateVirtualMemory is hooked!\n", GetCurrentProcessId());
	pDbgPrint("              AllocationType = %x, Protect = %x\n", AllocationType, Protect);

	sprintf_s(buf, "%d:CallNtAllocateVirtualMemory:IPC Successed!     ", GetCurrentProcessId());
	memcpy(dllMMF, buf, strlen(buf));

	hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)CallNtAllocateVirtualMemory, monMMF, 0, NULL);
	WaitForSingleObject(hThread, INFINITE);
	pDbgPrint("%s\n", dllMMF);

	if (AllocationType == (MEM_RESERVE | MEM_COMMIT) && Protect == PAGE_EXECUTE_READWRITE) {
		if (isDetectedRWXPageWhenInitializing) {
			char pid_msg[20];
			LPCSTR msgs[] = {
					"Non-initial RWX Page Detected.",
					(LPCSTR)pid_msg
			};
			sprintf_s(pid_msg, "PID=%d", GetCurrentProcessId());

			pDbgPrint("************* NON-INITIAL PAGE_EXECUTE_READWRITE DETECTED! *************\n");
			ReportEventA(eventLog, EVENTLOG_SUCCESS, 0, 5678, NULL, 2, 0, msgs, NULL);
		}
		else {
			isDetectedRWXPageWhenInitializing = true;
		}
	}
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
	pDbgPrint("CreationHook: PID=%d, NtWriteVirtualMemory is hooked!\n", GetCurrentProcessId());
	pDbgPrint("              NumberOfBytesToWrite=%u\n", NumberOfBytesToWrite);
	pDbgPrint("              Buffer(first 30) = ");

	if (writtenBuffer != NULL) {
		free(writtenBuffer);
		writtenBuffer = NULL;
		writtenBufferLen = 0;
	}
	
	writtenBufferLen = NumberOfBytesToWrite < 64 ? NumberOfBytesToWrite : 64;
	writtenBuffer = (unsigned char*) malloc(writtenBufferLen + 1);

	if (writtenBuffer != NULL) {
		memcpy(writtenBuffer, Buffer, writtenBufferLen);
		writtenBuffer[writtenBufferLen] = '\0';
		for (ULONG i = 0; i < 30 && i < NumberOfBytesToWrite; i++) {
			pDbgPrint("%02x ", writtenBuffer[i]);
		}
	}
	else {
		pDbgPrint("(memory allocation failed)");
	}

	pDbgPrint("\n");

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
	pDbgPrint("CreationHook: PID=%d, NtProtectVirtualMemory is hooked!\n", GetCurrentProcessId());
	pDbgPrint("              NumberOfBytesToProtect=%u\n", *NumberOfBytesToProtect);
	pDbgPrint("              Previous AccessProtection=%x\n", *OldAccessProtection);
	pDbgPrint("              Updating AccessProtection=%x\n", NewAccessProtection);

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
		pNtQuerySystemInformation = (NTQUERYSYSTEMINFORMATION)GetProcAddress(hMod, "NtQuerySystemInformation");
		if (pNtQuerySystemInformation == NULL) {
			printf("CreationHook: Error - cannot get NtQuerySystemInformation's address.\n");
			return 1;
		}

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