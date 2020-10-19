// dllmain.cpp : DLL 애플리케이션의 진입점을 정의합니다.
#include "pch.h"
#include "detours.h"

static NTMAPVIEWOFSECTION pNtMapViewOfSection;
static NTMAPVIEWOFSECTION TrueNtMapViewOfSection;
static CREATEREMOTETHREAD pCreateRemoteThread = CreateRemoteThread;
static VIRTUALALLOCEX pVirtualAllocEx = VirtualAllocEx;
static WRITEPROCESSMEMORY pWriteProcessMemory = WriteProcessMemory;
static DBGPRINT pDbgPrint;  // for debug printing 
HMODULE hMod = NULL;

HANDLE eventLog = RegisterEventSourceA(NULL, "FAST-DLLLog");
bool isDetectedRWXPageWhenInitializing = false;

//#####################################

static HANDLE hMonProcess = NULL;

static LPCSTR dll_path = NULL;

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



static BOOL(WINAPI* TrueCreateProcessA)(
	LPCSTR                lpApplicationName,
	LPSTR                 lpCommandLine,
	LPSECURITY_ATTRIBUTES lpProcessAttributes,
	LPSECURITY_ATTRIBUTES lpThreadAttributes,
	BOOL                  bInheritHandles,
	DWORD                 dwCreationFlags,
	LPVOID                lpEnvironment,
	LPCSTR                lpCurrentDirectory,
	LPSTARTUPINFOA        lpStartupInfo,
	LPPROCESS_INFORMATION lpProcessInformation
	) = CreateProcessA;

DLLBASIC_API BOOL WINAPI HookCreateProcessA(
	LPCSTR                lpApplicationName,
	LPSTR                 lpCommandLine,
	LPSECURITY_ATTRIBUTES lpProcessAttributes,
	LPSECURITY_ATTRIBUTES lpThreadAttributes,
	BOOL                  bInheritHandles,
	DWORD                 dwCreationFlags,
	LPVOID                lpEnvironment,
	LPCSTR                lpCurrentDirectory,
	LPSTARTUPINFOA        lpStartupInfo,
	LPPROCESS_INFORMATION lpProcessInformation)
{
	char* pValue2 = NULL;
	size_t len = NULL;
	_dupenv_s(&pValue2, &len, "expHDll");
	return DetourCreateProcessWithDllA(lpApplicationName,
		lpCommandLine,
		lpProcessAttributes,
		lpThreadAttributes,
		bInheritHandles,
		dwCreationFlags,
		lpEnvironment,
		lpCurrentDirectory,
		lpStartupInfo,
		lpProcessInformation,
		dll_path,
		TrueCreateProcessA);
}


//#####################################

static BOOL(WINAPI* TrueCreateProcessW)(
	LPCWSTR               lpApplicationName,
	LPWSTR                lpCommandLine,
	LPSECURITY_ATTRIBUTES lpProcessAttributes,
	LPSECURITY_ATTRIBUTES lpThreadAttributes,
	BOOL                  bInheritHandles,
	DWORD                 dwCreationFlags,
	LPVOID                lpEnvironment,
	LPCWSTR               lpCurrentDirectory,
	LPSTARTUPINFOW        lpStartupInfo,
	LPPROCESS_INFORMATION lpProcessInformation
	) = CreateProcessW;


DLLBASIC_API BOOL WINAPI HookCreateProcessW(
	LPCWSTR               lpApplicationName,
	LPWSTR                lpCommandLine,
	LPSECURITY_ATTRIBUTES lpProcessAttributes,
	LPSECURITY_ATTRIBUTES lpThreadAttributes,
	BOOL                  bInheritHandles,
	DWORD                 dwCreationFlags,
	LPVOID                lpEnvironment,
	LPCWSTR               lpCurrentDirectory,
	LPSTARTUPINFOW        lpStartupInfo,
	LPPROCESS_INFORMATION lpProcessInformation
)
{
	char* pValue2 = NULL;
	size_t len = NULL;
	_dupenv_s(&pValue2, &len, "expHDll");

	return DetourCreateProcessWithDllW(lpApplicationName,
		lpCommandLine,
		lpProcessAttributes,
		lpThreadAttributes,
		bInheritHandles,
		dwCreationFlags,
		lpEnvironment,
		lpCurrentDirectory,
		lpStartupInfo,
		lpProcessInformation,
		dll_path,
		TrueCreateProcessW);

}


//#####################################
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
	//printf("protect : %p\n", Win32Protect);
	if ((Win32Protect == PAGE_EXECUTE_READWRITE)) {
		memset(dllMMF, 0, MSG_SIZE);

		NTSTATUS res = (*TrueNtMapViewOfSection)(
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

		HANDLE hThread = NULL;
		char buf[MSG_SIZE] = "";
		sprintf_s(buf, "%d:%016x:%08x:CallNtMapViewOfSection:IPC Successful!     ", GetCurrentProcessId(), (LPVOID)(*BaseAddress), CommitSize);
		memcpy(dllMMF, buf, strlen(buf));
		hThread = pCreateRemoteThread(hMonProcess, NULL, 0, (LPTHREAD_START_ROUTINE)CallNtMapViewOfSection, monMMF, 0, NULL);
		WaitForSingleObject(hThread, INFINITE);
		printf("%s\n", (char*)dllMMF); //####
		//check_remote = TRUE;

		//if (strncmp((char*)dllMMF, "DROP", 4) == 0) {
		//	printf("So Dangerous\n");
		//	return FALSE;
		//}

		return res;
	}
	else
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



//#####################################
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
	memset(dllMMF, 0, MSG_SIZE);

	char buf[MSG_SIZE] = "";
	HANDLE hMonThread = NULL;

	//pDbgPrint("FAST-DLL: PID=%d, CreateRemoteThread is hooked!\n", GetCurrentProcessId());
	//pDbgPrint("              lpStartAddress=%p\n", lpStartAddress);



	if (lpStartAddress == (LPTHREAD_START_ROUTINE)LoadLibraryA) {
		unsigned char* writtenBuffer = NULL;
		unsigned int writtenBufferLen = 0;
		writtenBufferLen = 256;
		writtenBuffer = (unsigned char*)malloc((size_t)writtenBufferLen);

		if (writtenBuffer != NULL) {
			memcpy(writtenBuffer, lpParameter, writtenBufferLen);
		}

		//printf("%s\n", writtenBuffer);



		sprintf_s(buf, "%d:LoadLibraryA::CallCreateRemoteThread:IPC Successful!     ", GetCurrentProcessId());
	}
	else {



		sprintf_s(buf, "%d:%016x:%016x:CallCreateRemoteThread:IPC Successful!     ", GetCurrentProcessId(), lpStartAddress, lpParameter);
	}

	memcpy(dllMMF, buf, strlen(buf));
	hMonThread = pCreateRemoteThread(hMonProcess, NULL, 0, CallCreateRemoteThread, monMMF, 0, NULL);
	WaitForSingleObject(hMonThread, INFINITE);
	printf("%s\n", dllMMF);



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


//#####################################
// My VirtualAllocEx Hooking Function
DLLBASIC_API LPVOID WINAPI MyVirtualAllocEx(
	HANDLE hProcess,
	LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD  flAllocationType,
	DWORD  flProtect)
{
	memset(dllMMF, 0, MSG_SIZE);
	char buf[MSG_SIZE] = "";
	HANDLE hMonThread = NULL;

	//pDbgPrint("FAST-DLL: PID=%d, VirtualAllocEx is hooked!\n", GetCurrentProcessId());
	//pDbgPrint("              flAllocationType = %x, flProtect = %x\n", flAllocationType, flProtect);


	if (flProtect == PAGE_EXECUTE_READWRITE) {
		/*if (flAllocationType == (MEM_RESERVE | MEM_COMMIT) && flProtect == PAGE_EXECUTE_READWRITE) {
			if (isDetectedRWXPageWhenInitializing) {
				char pid_msg[20];
				LPCSTR msgs[] = {
						"Non-initial RWX Page Detected.",
						(LPCSTR)pid_msg
				};
				sprintf_s(pid_msg, "PID=%d", GetCurrentProcessId());

				pDbgPrint("************* NON-INITIAL PAGE_EXECUTE_READWRITE DETECTED! *************\n");

				ReportEventA(eventLog, EVENTLOG_SUCCESS, 0, 5678, NULL, 2, 0, msgs, NULL);
				strcat_s(buf, "\n     FAST-DLL:IPC:Non-initial RWX Page Detected.     ");
			}
			else {
				isDetectedRWXPageWhenInitializing = true;
			}*/

		LPVOID ret = pVirtualAllocEx(
			hProcess,
			lpAddress,
			dwSize,
			flAllocationType,
			flProtect
		);
		sprintf_s(buf, "%lu:%016x:%08x:CallVirtualAllocEx:IPC Successful!                           ", GetCurrentProcessId(), (DWORD64)ret, (DWORD)dwSize);
		memcpy(dllMMF, buf, strlen(buf));
		hMonThread = pCreateRemoteThread(hMonProcess, NULL, 0, CallVirtualAllocEx, monMMF, 0, NULL);
		WaitForSingleObject(hMonThread, INFINITE);
		printf("%s\n", dllMMF);
		return ret;
	}
	else
		return pVirtualAllocEx(
			hProcess,
			lpAddress,
			dwSize,
			flAllocationType,
			flProtect
		);
}

//#####################################
// My WriteProcessMemory Hooking Function
DLLBASIC_API BOOL WINAPI MyWriteProcessMemory(
	HANDLE  hProcess,
	LPVOID  lpBaseAddress,
	LPCVOID lpBuffer,
	SIZE_T  nSize,
	SIZE_T* lpNumberOfBytesWritten)
{
	memset(dllMMF, 0, MSG_SIZE);

	char buf[MSG_SIZE] = "";
	HANDLE hMonThread = NULL;


	pDbgPrint("FAST-DLL: PID=%d, WriteProcessMemory is hooked!\n", GetCurrentProcessId());
	pDbgPrint("              nSize=%u\n", nSize);
	pDbgPrint("              Buffer(first 30) = ");

	sprintf_s(buf, "%d:CallWriteProcessMemory:IPC Successful!     ", GetCurrentProcessId());

	//if (writtenBuffer != NULL) {
	//	free(writtenBuffer);
	//	writtenBuffer = NULL;
	//	writtenBufferLen = 0;
	//}
	//
	//writtenBufferLen = nSize < 64 ? nSize : 64;
	//writtenBuffer = (unsigned char*) malloc((size_t)writtenBufferLen + 1);

	//if (writtenBuffer != NULL) {
	//	memcpy(writtenBuffer, lpBuffer, writtenBufferLen);
	//	writtenBuffer[writtenBufferLen] = '\0';
	//	for (ULONG i = 0; i < 30 && i < nSize; i++) {
	//		pDbgPrint("%02x ", writtenBuffer[i]);
	//	}
	//}
	//else {
	//	pDbgPrint("(memory allocation failed)");
	//}

	//pDbgPrint("\n");


	memcpy(dllMMF, buf, strlen(buf));
	hMonThread = pCreateRemoteThread(hMonProcess, NULL, 0, CallWriteProcessMemory, monMMF, 0, NULL);
	WaitForSingleObject(hMonThread, INFINITE);
	printf("%s\n", dllMMF);


	return pWriteProcessMemory(
		hProcess,
		lpBaseAddress,
		lpBuffer,
		nSize,
		lpNumberOfBytesWritten
	);
}



//#####################################

static HANDLE(WINAPI* TrueCreateFileMappingA)(
	HANDLE					hFile,
	LPSECURITY_ATTRIBUTES	lpFileMappingAttributes,
	DWORD					flProtect,
	DWORD					dwMaximumSizeHigh,
	DWORD					dwMaximumSizeLow,
	LPCSTR					lpName
	) = CreateFileMappingA;

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
	if ((hFile == INVALID_HANDLE_VALUE)
		) {//&& (flProtect == PAGE_EXECUTE_READWRITE)) {
		memset(dllMMF, 0, MSG_SIZE);

		HANDLE hThread = NULL;
		char buf[MSG_SIZE] = "";
		sprintf_s(buf, "%d:CallCreateFileMappingA:IPC Successful!     ", GetCurrentProcessId());
		memcpy(dllMMF, buf, strlen(buf));
		hThread = pCreateRemoteThread(hMonProcess, NULL, 0, (LPTHREAD_START_ROUTINE)CallCreateFileMappingA, monMMF, 0, NULL);
		WaitForSingleObject(hThread, INFINITE);
		printf("%s\n", (char*)dllMMF);  //#####
	}
	HANDLE check_map = NULL;
	check_map = TrueCreateFileMappingA(hFile, lpFileMappingAttributes, flProtect, dwMaximumSizeHigh, dwMaximumSizeLow, lpName);
	return check_map;
}


//#####################################

typedef NTSTATUS(NTAPI* pNtQueueApcThread)(
	_In_ HANDLE ThreadHandle,
	_In_ PVOID ApcRoutine,
	_In_ PVOID ApcRoutineContext OPTIONAL,
	_In_ PVOID ApcStatusBlock OPTIONAL,
	_In_ PVOID ApcReserved OPTIONAL
	);

static pNtQueueApcThread NtQueueApcThread = NULL;



DLLBASIC_API NTSTATUS NTAPI MyNtQueueApcThread(
	HANDLE ThreadHandle,
	PVOID ApcRoutine,
	PVOID ApcRoutineContext OPTIONAL,
	PVOID ApcStatusBlock OPTIONAL,
	PVOID ApcReserved OPTIONAL
) {
	memset(dllMMF, 0, MSG_SIZE);

	HANDLE hThread = NULL;
	char buf[MSG_SIZE] = "";
	sprintf_s(buf, "%d:CallNtQueueApcThread:IPC Successful!     ", GetCurrentProcessId());
	memcpy(dllMMF, buf, strlen(buf));
	hThread = pCreateRemoteThread(hMonProcess, NULL, 0, (LPTHREAD_START_ROUTINE)CallNtQueueApcThread, monMMF, 0, NULL);
	WaitForSingleObject(hThread, INFINITE);
	printf("%s\n", dllMMF);
	return NtQueueApcThread(ThreadHandle,
		ApcRoutine,
		ApcRoutineContext OPTIONAL,
		ApcStatusBlock OPTIONAL,
		ApcReserved OPTIONAL);
}







//#####################################

static LONG_PTR(WINAPI* TrueSetWindowLongPtrA) (
	HWND     hWnd,
	int      nIndex,
	LONG_PTR dwNewLong
	) = SetWindowLongPtrA;

DLLBASIC_API LONG_PTR WINAPI MySetWindowLongPtrA
(HWND     hWnd,
	int      nIndex,
	LONG_PTR dwNewLong) {

	memset(dllMMF, 0, MSG_SIZE);


	char buf[MSG_SIZE] = "";
	HANDLE hThread = NULL;
	//printf("size: %d", sizeof(LONG_PTR));

	//DWORD64 target = *(DWORD64*)(*(DWORD64*)dwNewLong);
	printf("%016x\n", dwNewLong);
	//printf("%016x\n", (DWORD64*)(*(DWORD64*)dwNewLong));
	sprintf_s(buf, "%lu:%016x:CallSetWindowLongPtrA:IPC Successful!     ", GetCurrentProcessId(), dwNewLong);
	memcpy(dllMMF, buf, strlen(buf));
	hThread = pCreateRemoteThread(hMonProcess, NULL, 0, (LPTHREAD_START_ROUTINE)CallSetWindowLongPtrA, monMMF, 0, NULL);
	WaitForSingleObject(hThread, INFINITE);
	printf("%s\n", dllMMF);
	return TrueSetWindowLongPtrA(hWnd, nIndex, dwNewLong);
}


//#####################################




static LONG dwSlept = 0;
static DWORD(WINAPI* TrueSleepEx)(DWORD dwMilliseconds, BOOL bAlertable) = SleepEx;

DWORD WINAPI TimedSleepEx(DWORD dwMilliseconds, BOOL bAlertable)
{
	//printf("sleep5.exe: is Hooked.\n");
	DWORD dwBeg = GetTickCount();
	DWORD ret = TrueSleepEx(dwMilliseconds, bAlertable);
	DWORD dwEnd = GetTickCount();

	InterlockedExchangeAdd(&dwSlept, dwEnd - dwBeg);

	memset(dllMMF, 0, MSG_SIZE);

	HANDLE hThread = NULL;
	char buf[MSG_SIZE] = "";
	sprintf_s(buf, "%d:CallSleepEx:IPC Successful!     ", GetCurrentProcessId());
	memcpy(dllMMF, buf, strlen(buf));
	hThread = pCreateRemoteThread(hMonProcess, NULL, 0, CallSleepEx, monMMF, 0, NULL);
	WaitForSingleObject(hThread, INFINITE);
	printf("%s\n", dllMMF);


	return ret;
}


//#####################################

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

		dll_path = (LPCSTR)pMemoryMap;

		//printf("%s\n", (char*)pMemoryMap);
		//printf("%d\n", *(DWORD*)((char*)pMemoryMap + sz));

		// get ntdll module
		hMod = GetModuleHandleA("ntdll.dll");
		if (hMod == NULL) {
			printf("FAST-DLL: Error - cannot get ntdll.dll module.\n");
			return 1;
		}

		// get functions in ntdll
		TrueNtMapViewOfSection = (NTMAPVIEWOFSECTION)GetProcAddress(hMod, "NtMapViewOfSection");
		if (TrueNtMapViewOfSection == NULL) {
			printf("Failed to get NtMapViewOfSection\n");
			return 1;
		}
		pNtMapViewOfSection = (NTMAPVIEWOFSECTION)GetProcAddress(hMod, "NtMapViewOfSection");
		if (pNtMapViewOfSection == NULL) {
			printf("FAST-DLL: Error - cannot get NtMapViewOfSection's address.\n");
			return 1;
		}

		NtQueueApcThread = (pNtQueueApcThread)GetProcAddress(hMod, "NtQueueApcThread");
		if (NtQueueApcThread == NULL) {
			printf("GetProcAddress NtQueueApcThread  Failed.\n");
			return 1;
		}

		pDbgPrint = (DBGPRINT)GetProcAddress(hMod, "DbgPrint");
		if (pDbgPrint == NULL) {
			printf("FAST-DLL: Error - cannot get DbgPrint's address.\n");
			return 1;
		}

		fm = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, MSG_SIZE, NULL);
		map_addr = (char*)MapViewOfFile(fm, FILE_MAP_ALL_ACCESS, 0, 0, 0);

		hMonProcess = OpenProcess(PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD, FALSE, *(DWORD*)((char*)pMemoryMap + sz));

		(*pNtMapViewOfSection)(fm, hMonProcess, &lpMap, 0, MSG_SIZE, nullptr, &viewsize, ViewUnmap, 0, PAGE_READWRITE); // "The default behavior for executable pages allocated is to be marked valid call targets for CFG." (https://docs.microsoft.com/en-us/windows/desktop/api/memoryapi/nf-memoryapi-mapviewoffile)

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

		//printf("%llu\n", *(DWORD64*)(pMemoryMap + sz + sizeof(DWORD)));




		//#############################

		DetourRestoreAfterWith();
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());

		// TODO: attaching
		DetourAttach(&(PVOID&)TrueCreateProcessA, HookCreateProcessA);
		DetourAttach(&(PVOID&)TrueCreateProcessW, HookCreateProcessW);
		DetourAttach(&(PVOID&)pCreateRemoteThread, MyCreateRemoteThread);
		DetourAttach(&(PVOID&)pVirtualAllocEx, MyVirtualAllocEx);
		//DetourAttach(&(PVOID&)pWriteProcessMemory, MyWriteProcessMemory);
		DetourAttach(&(PVOID&)TrueNtMapViewOfSection, MyNtMapViewOfSection);
		DetourAttach(&(PVOID&)TrueCreateFileMappingA, MyCreateFileMappingA);
		DetourAttach(&(PVOID&)NtQueueApcThread, MyNtQueueApcThread);
		DetourAttach(&(PVOID&)TrueSetWindowLongPtrA, MySetWindowLongPtrA);
		//DetourAttach(&(PVOID&)TrueSleepEx, TimedSleepEx);

		DetourTransactionCommit();

		printf("FAST-DLL: Process attached.\n");
		break;

	case DLL_THREAD_ATTACH:
		printf("FAST-DLL: Thread attached.\n");
		break;

	case DLL_THREAD_DETACH:
		printf("FAST-DLL: Thread detached.\n");
		break;

	case DLL_PROCESS_DETACH:
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());

		// TODO: detaching
		DetourDetach(&(PVOID&)TrueCreateProcessA, HookCreateProcessA);
		DetourDetach(&(PVOID&)TrueCreateProcessW, HookCreateProcessW);
		DetourDetach(&(PVOID&)pCreateRemoteThread, MyCreateRemoteThread);
		DetourDetach(&(PVOID&)pVirtualAllocEx, MyVirtualAllocEx);
		//DetourDetach(&(PVOID&)pWriteProcessMemory, MyWriteProcessMemory);
		DetourDetach(&(PVOID&)TrueNtMapViewOfSection, MyNtMapViewOfSection);
		DetourDetach(&(PVOID&)TrueCreateFileMappingA, MyCreateFileMappingA);
		DetourDetach(&(PVOID&)NtQueueApcThread, MyNtQueueApcThread);
		DetourDetach(&(PVOID&)TrueSetWindowLongPtrA, MySetWindowLongPtrA);
		//DetourDetach(&(PVOID&)TrueSleepEx, TimedSleepEx);
		DetourTransactionCommit();
		printf("FAST-DLL: Process detached.\n");
		break;
	}

	return TRUE;
}