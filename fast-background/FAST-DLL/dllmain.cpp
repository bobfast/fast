// dllmain.cpp : DLL 애플리케이션의 진입점을 정의합니다.

#include "framework.h"
#include "detours.h"
#include <string>

static NTMAPVIEWOFSECTION pNtMapViewOfSection;
static NTMAPVIEWOFSECTION TrueNtMapViewOfSection;
static CREATEREMOTETHREAD pCreateRemoteThread = CreateRemoteThread;
static VIRTUALALLOCEX pVirtualAllocEx = VirtualAllocEx;
static WRITEPROCESSMEMORY pWriteProcessMemory = WriteProcessMemory;
static DBGPRINT pDbgPrint;  // for debug printing 
HMODULE hMod = NULL;

HANDLE eventLog = RegisterEventSourceA(NULL, "FAST-DLLLog");
bool isDetectedRWXPageWhenInitializing = false;

// For detection in WriteProcessMemory

//#####################################

static HANDLE hMonProcess = NULL;

static LPCSTR dll_path = NULL;

static LPVOID monMMF = NULL;
static LPVOID dllMMF = NULL;

static LPTHREAD_START_ROUTINE  CallVirtualAllocEx = NULL;
static LPTHREAD_START_ROUTINE  CallQueueUserAPC = NULL;
static LPTHREAD_START_ROUTINE  CallWriteProcessMemory = NULL;
static LPTHREAD_START_ROUTINE  CallCreateRemoteThread = NULL;
static LPTHREAD_START_ROUTINE  CallNtMapViewOfSection = NULL;
static LPTHREAD_START_ROUTINE  CallCreateFileMappingA = NULL;
static LPTHREAD_START_ROUTINE  CallGetThreadContext = NULL;
static LPTHREAD_START_ROUTINE  CallSetThreadContext = NULL;
static LPTHREAD_START_ROUTINE  CallNtQueueApcThread = NULL;
static LPTHREAD_START_ROUTINE  CallSetWindowLongPtrA = NULL;
static LPTHREAD_START_ROUTINE  CallSetPropA = NULL;
static LPTHREAD_START_ROUTINE CallVirtualProtectEx = NULL;
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
static DWORD(WINAPI* TrueQueueUserAPC)(
	PAPCFUNC  pfnAPC,
	HANDLE    hThread,
	ULONG_PTR dwData
	) = QueueUserAPC;

DLLBASIC_API BOOL WINAPI MyQueueUserAPC(
	PAPCFUNC  pfnAPC,
	HANDLE    hThread,
	ULONG_PTR dwData
) {
	memset(dllMMF, 0, MSG_SIZE);



	HANDLE hMonThread = NULL;
	char buf[MSG_SIZE] = "";
	//sprintf_s(buf, "%d:CallNtQueueApcThread:IPC Successful!", GetProcessIdOfThread(ThreadHandle));

	LPVOID fp = pfnAPC;
	sprintf_s(buf, "%d:%p:CallQueueUserAPC:IPC Successful!", GetCurrentProcessId(), fp);


	memcpy(dllMMF, buf, strlen(buf));
	hMonThread = pCreateRemoteThread(hMonProcess, NULL, 0, (LPTHREAD_START_ROUTINE)CallQueueUserAPC, monMMF, 0, NULL);
	WaitForSingleObject(hMonThread, INFINITE);
	CloseHandle(hMonThread);
	//printf("%s\n", (char*)dllMMF);
	return TrueQueueUserAPC(
		pfnAPC,
		hThread,
		dwData
	);
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
	
		memset(dllMMF, 0, MSG_SIZE);
		char buf[MSG_SIZE] = "";
		HANDLE hMonThread = NULL;


		if (Win32Protect == (PAGE_EXECUTE_READWRITE )) {

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

			//GetProcessId(ProcessHandle) failed.
			sprintf_s(buf, "%lu:%lu:%016llx:%08lx:%08lx:CallNtMapViewOfSection:IPC Successful!", GetCurrentProcessId(), GetProcessId(ProcessHandle), (DWORD64)BaseAddress, (DWORD)CommitSize, Win32Protect);
			memcpy(dllMMF, buf, strlen(buf));
			hMonThread = pCreateRemoteThread(hMonProcess, NULL, 0, CallNtMapViewOfSection, monMMF, 0, NULL);
			WaitForSingleObject(hMonThread, INFINITE);
			CloseHandle(hMonThread);
			//printf("%s\n", (char*)dllMMF);
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
// My CreateReCreateRemoteThread Hooking Function
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

	DWORD target_pid = GetProcessId(hProcess);

	// Getting PID using DuplicateHandle
	HANDLE hProcessDuplicated = NULL;
	DWORD duplicateHandleResult = 0;

	if (target_pid == 0) {
		duplicateHandleResult = DuplicateHandle(GetCurrentProcess(), hProcess, GetCurrentProcess(),
			&hProcessDuplicated, PROCESS_QUERY_INFORMATION, FALSE, 0);

		if (duplicateHandleResult != 0) {
			target_pid = GetProcessId(hProcessDuplicated);

			CloseHandle(hProcessDuplicated);
		}
	}

	if (lpStartAddress == (LPTHREAD_START_ROUTINE)LoadLibraryA) {

		if (!ReadProcessMemory(hProcess, lpParameter, buf, MSG_SIZE, NULL))
		{

			//printf("ReadProcessMemory(%ld) failed!!! [%ld]\n", GetCurrentProcessId(), GetLastError());

		}

		sprintf_s(buf, "%lu:%lu:LoadLibraryA:%p:CallCreateRemoteThread:IPC Successful!     ", GetCurrentProcessId(), target_pid, lpParameter);
		//sprintf_s(buf, "%lu:LoadLibraryA::CallCreateRemoteThread:IPC Successful!     ", GetProcessId(hProcess));
	}
	else {
		//sprintf_s(buf, "%lu:%016x:%016x:CallCreateRemoteThread:IPC Successful!     ", GetProcessId(hProcess), lpStartAddress, lpParameter);
		sprintf_s(buf, "%lu:%lu:%p:%p:CallCreateRemoteThread:IPC Successful!     ", GetCurrentProcessId(), target_pid, lpStartAddress, lpParameter);
	}

	memcpy(dllMMF, buf, strlen(buf));
	hMonThread = pCreateRemoteThread(hMonProcess, NULL, 0, CallCreateRemoteThread, monMMF, 0, NULL);
	WaitForSingleObject(hMonThread, INFINITE);
	CloseHandle(hMonThread);
	//printf("%s\n", (char*)dllMMF);

	/*
	char* cp = (char*)dllMMF;
	char* context = NULL;
	std::string pid(strtok_s(cp, ":", &context));
	std::string res(strtok_s(NULL, ":", &context));
	if (strncmp(res.c_str(), "Detected", 8) == 0) {
		printf("CreateRemoteThread : Process Injection Attack Detected and Prevented!\n");

		//return NULL;
	}
	*/


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

	DWORD target_pid = GetProcessId(hProcess);

	// Getting PID using DuplicateHandle
	HANDLE hProcessDuplicated = NULL;
	DWORD duplicateHandleResult = 0;

	if (target_pid == 0) {
		duplicateHandleResult = DuplicateHandle(GetCurrentProcess(), hProcess, GetCurrentProcess(),
			&hProcessDuplicated, PROCESS_QUERY_INFORMATION, FALSE, 0);

		if (duplicateHandleResult != 0) {
			target_pid = GetProcessId(hProcessDuplicated);

			CloseHandle(hProcessDuplicated);
		}
	}

	if (flProtect == (PAGE_EXECUTE_READWRITE)) {

		LPVOID ret = pVirtualAllocEx(
			hProcess,
			lpAddress,
			dwSize,
			flAllocationType,
			flProtect
		);

		sprintf_s(buf, "%lu:%lu:%016llx:%08lx:%08lx:CallVirtualAllocEx:IPC Successful!", GetCurrentProcessId(), target_pid, (DWORD64)ret, (DWORD)dwSize, flProtect);
		memcpy(dllMMF, buf, strlen(buf));
		hMonThread = pCreateRemoteThread(hMonProcess, NULL, 0, CallVirtualAllocEx, monMMF, 0, NULL);
		WaitForSingleObject(hMonThread, INFINITE);
		CloseHandle(hMonThread);
		//printf("%s\n", (char*)dllMMF);
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


	//pDbgPrint("FAST-DLL: PID=%d, WriteProcessMemory is hooked!\n", GetCurrentProcessId());
	//pDbgPrint("              nSize=%u\n", nSize);
	//pDbgPrint("              Buffer(first 30) = ");

	//sprintf_s(buf, "%d:CallWriteProcessMemory:IPC Successful!     ", GetCurrentProcessId());

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
	//sprintf_s(buf, "%lu:MyWriteProcessMemory:IPC Successful!", GetProcessId(hProcess));

	sprintf_s(buf, "%lu:MyWriteProcessMemory:IPC Successful!", GetCurrentProcessId());
	memcpy(dllMMF, buf, strlen(buf));
	hMonThread = pCreateRemoteThread(hMonProcess, NULL, 0, CallWriteProcessMemory, monMMF, 0, NULL);
	WaitForSingleObject(hMonThread, INFINITE);
	CloseHandle(hMonThread);
	//printf("%s\n", (char*)dllMMF);


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
		sprintf_s(buf, "%lu:CallCreateFileMappingA:IPC Successful!     ", GetCurrentProcessId());
		memcpy(dllMMF, buf, strlen(buf));
		hThread = pCreateRemoteThread(hMonProcess, NULL, 0, (LPTHREAD_START_ROUTINE)CallCreateFileMappingA, monMMF, 0, NULL);
		WaitForSingleObject(hThread, INFINITE);
		CloseHandle(hThread);
		//printf("%s\n", (char*)dllMMF);  //#####
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


	DWORD target_pid = GetProcessIdOfThread(ThreadHandle);
	HANDLE hThread = NULL;
	char buf[MSG_SIZE] = "";
	//sprintf_s(buf, "%d:CallNtQueueApcThread:IPC Successful!", pid);

	if (ApcRoutine == GlobalGetAtomNameA)
		sprintf_s(buf, "%lu:%lu:GlobalGetAtomNameA:CallNtQueueApcThread:IPC Successful!", GetCurrentProcessId(), target_pid);
	else
		sprintf_s(buf, "%lu:%lu:%p:CallNtQueueApcThread:IPC Successful!", GetCurrentProcessId(), target_pid, ApcRoutine);


	memcpy(dllMMF, buf, strlen(buf));
	hThread = pCreateRemoteThread(hMonProcess, NULL, 0, (LPTHREAD_START_ROUTINE)CallNtQueueApcThread, monMMF, 0, NULL);
	WaitForSingleObject(hThread, INFINITE);
	CloseHandle(hThread);
	//printf("%s\n", (char*)dllMMF);

	char* cp = (char*)dllMMF;
	char* context = NULL;
	std::string pid(strtok_s(cp, ":", &context));
	std::string res(strtok_s(NULL, ":", &context));
	if (strncmp(res.c_str(), "Detected", 8) == 0) {
		printf("NtQueueApcThread : Process Injection Attack Detected and Prevented!\n");

		//return NULL;
	}

	return NtQueueApcThread(ThreadHandle,
		ApcRoutine,
		ApcRoutineContext OPTIONAL,
		ApcStatusBlock OPTIONAL,
		ApcReserved OPTIONAL);
}


//#####################################

static BOOL(WINAPI* TrueSetThreadContext)(
	HANDLE        hThread,
	const CONTEXT* lpContext
	) = SetThreadContext;

DLLBASIC_API BOOL WINAPI MySetThreadContext(
	HANDLE        hThread,
	const CONTEXT* lpContext
) {
	memset(dllMMF, 0, MSG_SIZE);

	DWORD target_pid = GetProcessIdOfThread(hThread);
	char buf[MSG_SIZE] = "";
	HANDLE hMonThread= NULL;

	//GetProcessIdOfThread(hThread) failed.
	sprintf_s(buf, "%lu:%lu:%016llx:CallSetThreadContext:IPC Successful!", GetCurrentProcessId(), target_pid, lpContext->Rip);

	memcpy(dllMMF, buf, strlen(buf));
	hMonThread = pCreateRemoteThread(hMonProcess, NULL, 0, (LPTHREAD_START_ROUTINE)CallSetThreadContext, monMMF, 0, NULL);
	WaitForSingleObject(hMonThread, INFINITE);
	CloseHandle(hMonThread);
	//printf("%s\n", (char*)dllMMF);

	char* cp = (char*)dllMMF;
	char* context = NULL;
	std::string pid(strtok_s(cp, ":", &context));
	std::string res(strtok_s(NULL, ":", &context));
	if (strncmp(res.c_str(), "Detected", 8) == 0) {
		printf("CallSetThreadContext : Thread Hijacking Attack Detected and Prevented!\n");
		//return NULL;
	}
	return (*TrueSetThreadContext)(
		hThread,
		lpContext
		);
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
	DWORD dwpid = NULL;
	GetWindowThreadProcessId(hWnd, &dwpid);
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwpid);
	if (!hProcess)
	{
		printf("OpenProcess(%ld) failed!!! [%ld]\n", GetCurrentProcessId(), GetLastError());
		return NULL;
	}

	DWORD64 p1 = NULL, p2 = NULL;

	if (!ReadProcessMemory(hProcess, (LPCVOID)dwNewLong, (LPVOID)&p1, sizeof(LPVOID), NULL))
	{
		printf("ReadProcessMemory(%ld) failed!!! [%ld]\n", GetCurrentProcessId(), GetLastError());
		return NULL;
	}
	if (!ReadProcessMemory(hProcess, (LPCVOID)p1, (LPVOID)&p2, sizeof(LPVOID), NULL))
	{
		printf("ReadProcessMemory(%ld) failed!!! [%ld]\n", GetCurrentProcessId(), GetLastError());
		return NULL;
	}

	CloseHandle(hProcess);

	printf("%016llx\n", dwNewLong);
	sprintf_s(buf, "%lu:%lu:%016llx:CallSetWindowLongPtrA:IPC Successful!", GetCurrentProcessId(), dwpid, p2);
	memcpy(dllMMF, buf, strlen(buf));
	hThread = pCreateRemoteThread(hMonProcess, NULL, 0, (LPTHREAD_START_ROUTINE)CallSetWindowLongPtrA, monMMF, 0, NULL);
	WaitForSingleObject(hThread, INFINITE);
	CloseHandle(hThread);
	//printf("%s\n", (char*)dllMMF);

	char* cp = (char*)dllMMF;
	char* context = NULL;
	std::string pid(strtok_s(cp, ":", &context));
	std::string res(strtok_s(NULL, ":", &context));
	if (strncmp(res.c_str(), "Detected", 8) == 0) {
		printf("SetWindowLongPtrA : Windows Attribute Injection Attack Detected and Prevented!\n");
		//return NULL;
	}
	return TrueSetWindowLongPtrA(hWnd, nIndex, dwNewLong);
}


//#####################################



static BOOL (WINAPI* TrueSetPropA)(
	HWND   hWnd,
	LPCSTR lpString,
	HANDLE hData
) = SetPropA;

DLLBASIC_API BOOL WINAPI  MySetPropA(
	HWND   hWnd,
	LPCSTR lpString,
	HANDLE hData
) {
	memset(dllMMF, 0, MSG_SIZE);


	char buf[MSG_SIZE] = "";
	HANDLE hThread = NULL;
	DWORD dwpid = NULL;
	GetWindowThreadProcessId(hWnd, &dwpid);
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwpid);
	if (!hProcess)
	{
		printf("OpenProcess(%ld) failed!!! [%ld]\n", GetCurrentProcessId(), GetLastError());
		return NULL;
	}
	
	DWORD64 ptr = NULL;

	if (!ReadProcessMemory(hProcess, (LPCVOID)((DWORD64)hData+0x18), (LPVOID)&ptr, sizeof(LPVOID), NULL))
	{
		printf("ReadProcessMemory(%ld) failed!!! [%ld]\n", GetCurrentProcessId(), GetLastError());
		return NULL;
	}


	sprintf_s(buf, "%lu:%lu:%016llx:CallSetPropA:IPC Successful!", GetCurrentProcessId(),dwpid, ptr);
	memcpy(dllMMF, buf, strlen(buf));
	hThread = pCreateRemoteThread(hMonProcess, NULL, 0, (LPTHREAD_START_ROUTINE)CallSetPropA, monMMF, 0, NULL);
	WaitForSingleObject(hThread, INFINITE);
	CloseHandle(hThread);
	//printf("%s\n", (char*)dllMMF);

	char* cp = (char*)dllMMF;
	char* context = NULL;
	std::string pid(strtok_s(cp, ":", &context));
	std::string res(strtok_s(NULL, ":", &context));
	if (strncmp(res.c_str(), "Detected", 8) == 0) {
		printf("SetPropA : Windows Property Injection Attack Detected and Prevented!\n");
		//return NULL;
	}
	return TrueSetPropA(
		hWnd,
		lpString,
		hData
		);

}

//#####################################

static BOOL(WINAPI* TrueVirtualProtectEx)(
	HANDLE hProcess,
	LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD  flNewProtect,
	PDWORD lpflOldProtect
	) = VirtualProtectEx;

DLLBASIC_API BOOL WINAPI  MyVirtualProtectEx(
HANDLE hProcess,
LPVOID lpAddress,
SIZE_T dwSize,
DWORD  flNewProtect,
PDWORD lpflOldProtect)
{
	memset(dllMMF, 0, MSG_SIZE);
	char buf[MSG_SIZE] = "";
	HANDLE hMonThread = NULL;


	if ( flNewProtect == (PAGE_EXECUTE_READWRITE ) ) {

		sprintf_s(buf, "%lu:%lu:%016llx:%08lx:%08lx:MyVirtualProtectEx:IPC Successful!", GetCurrentProcessId(), GetProcessId(hProcess), (DWORD64)lpAddress, (DWORD)dwSize, flNewProtect);
		memcpy(dllMMF, buf, strlen(buf));
		hMonThread = pCreateRemoteThread(hMonProcess, NULL, 0, CallVirtualProtectEx, monMMF, 0, NULL);
		WaitForSingleObject(hMonThread, INFINITE);
		CloseHandle(hMonThread);
		//printf("%s\n", (char*)dllMMF);
	}

	return TrueVirtualProtectEx(
		hProcess,
		lpAddress,
		dwSize,
		flNewProtect,
		lpflOldProtect);
}
//#####################################

static LONG dwSlept = 0;
static DWORD(WINAPI* TrueSleepEx)(DWORD dwMilliseconds, BOOL bAlertable) = SleepEx;

DWORD WINAPI TimedSleepEx(DWORD dwMilliseconds, BOOL bAlertable)
{
	//printf("sleep5.exe: is Hooked.\n");
	ULONGLONG dwBeg = GetTickCount64();
	DWORD ret = TrueSleepEx(dwMilliseconds, bAlertable);
	ULONGLONG dwEnd = GetTickCount64();

	InterlockedExchangeAdd(&dwSlept, LONG(dwEnd - dwBeg));

	memset(dllMMF, 0, MSG_SIZE);

	HANDLE hThread = NULL;
	char buf[MSG_SIZE] = "";
	sprintf_s(buf, "%lu:CallSleepEx:IPC Successful!     ", GetCurrentProcessId());
	memcpy(dllMMF, buf, strlen(buf));
	hThread = pCreateRemoteThread(hMonProcess, NULL, 0, CallSleepEx, monMMF, 0, NULL);
	WaitForSingleObject(hThread, INFINITE);
	CloseHandle(hThread);
	//printf("%s\n", (char*)dllMMF);


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

	HANDLE fm = NULL;
	char* map_addr = nullptr;

	LPVOID lpMap = 0;
	SIZE_T viewsize = 0;

	size_t sz;

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
		//printf("%lu\n", *(DWORD*)((char*)pMemoryMap + sz));

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
		if (fm == NULL) {
			printf("FAST-DLL: Error - cannot create file mapping.\n");
			return 1;
		}
		map_addr = (char*)MapViewOfFile(fm, FILE_MAP_ALL_ACCESS, 0, 0, 0);

		hMonProcess = OpenProcess(PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD, FALSE, *(DWORD*)((char*)pMemoryMap + sz));

		(*pNtMapViewOfSection)(fm, hMonProcess, &lpMap, 0, MSG_SIZE, nullptr, &viewsize, SECTION_INHERIT::ViewUnmap, 0, PAGE_READWRITE); // "The default behavior for executable pages allocated is to be marked valid call targets for CFG." (https://docs.microsoft.com/en-us/windows/desktop/api/memoryapi/nf-memoryapi-mapviewoffile)

		monMMF = (LPVOID)lpMap;
		dllMMF = (LPVOID)map_addr;



		CallVirtualAllocEx = (LPTHREAD_START_ROUTINE)(*(DWORD64*)(pMemoryMap + sz + sizeof(DWORD)));
		CallQueueUserAPC = (LPTHREAD_START_ROUTINE)(*(DWORD64*)(pMemoryMap + sz + sizeof(DWORD) + sizeof(DWORD64)));
		CallWriteProcessMemory = (LPTHREAD_START_ROUTINE)(*(DWORD64*)(pMemoryMap + sz + sizeof(DWORD) + 2 * sizeof(DWORD64)));
		CallCreateRemoteThread = (LPTHREAD_START_ROUTINE)(*(DWORD64*)(pMemoryMap + sz + sizeof(DWORD) + 3 * sizeof(DWORD64)));
		CallNtMapViewOfSection = (LPTHREAD_START_ROUTINE)(*(DWORD64*)(pMemoryMap + sz + sizeof(DWORD) + 4 * sizeof(DWORD64)));
		CallCreateFileMappingA = (LPTHREAD_START_ROUTINE)(*(DWORD64*)(pMemoryMap + sz + sizeof(DWORD) + 5 * sizeof(DWORD64)));
		CallGetThreadContext = (LPTHREAD_START_ROUTINE)(*(DWORD64*)(pMemoryMap + sz + sizeof(DWORD) + 6 * sizeof(DWORD64)));
		CallSetThreadContext = (LPTHREAD_START_ROUTINE)(*(DWORD64*)(pMemoryMap + sz + sizeof(DWORD) + 7 * sizeof(DWORD64)));
		CallNtQueueApcThread = (LPTHREAD_START_ROUTINE)(*(DWORD64*)(pMemoryMap + sz + sizeof(DWORD) + 8 * sizeof(DWORD64)));
		CallSetWindowLongPtrA = (LPTHREAD_START_ROUTINE)(*(DWORD64*)(pMemoryMap + sz + sizeof(DWORD) + 9 * sizeof(DWORD64)));
		CallSetPropA = (LPTHREAD_START_ROUTINE)(*(DWORD64*)(pMemoryMap + sz + sizeof(DWORD) + 10 * sizeof(DWORD64)));
		CallVirtualProtectEx = (LPTHREAD_START_ROUTINE)(*(DWORD64*)(pMemoryMap + sz + sizeof(DWORD) + 11 * sizeof(DWORD64)));
		CallSleepEx = (LPTHREAD_START_ROUTINE)(*(DWORD64*)(pMemoryMap + sz + sizeof(DWORD) + 12 * sizeof(DWORD64)));

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
		//DetourAttach(&(PVOID&)TrueQueueUserAPC, MyQueueUserAPC);
		//DetourAttach(&(PVOID&)pWriteProcessMemory, MyWriteProcessMemory);
		DetourAttach(&(PVOID&)TrueNtMapViewOfSection, MyNtMapViewOfSection);
		DetourAttach(&(PVOID&)TrueCreateFileMappingA, MyCreateFileMappingA);
		DetourAttach(&(PVOID&)NtQueueApcThread, MyNtQueueApcThread);
		DetourAttach(&(PVOID&)TrueSetThreadContext, MySetThreadContext);
		DetourAttach(&(PVOID&)TrueSetWindowLongPtrA, MySetWindowLongPtrA);
		DetourAttach(&(PVOID&)TrueSetPropA, MySetPropA);
		DetourAttach(&(PVOID&)TrueVirtualProtectEx, MyVirtualProtectEx);
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
		//DetourDetach(&(PVOID&)TrueQueueUserAPC, MyQueueUserAPC);
		//DetourDetach(&(PVOID&)pWriteProcessMemory, MyWriteProcessMemory);
		DetourDetach(&(PVOID&)TrueNtMapViewOfSection, MyNtMapViewOfSection);
		DetourDetach(&(PVOID&)TrueCreateFileMappingA, MyCreateFileMappingA);
		DetourDetach(&(PVOID&)NtQueueApcThread, MyNtQueueApcThread);
		DetourDetach(&(PVOID&)TrueSetThreadContext, MySetThreadContext);
		DetourDetach(&(PVOID&)TrueSetWindowLongPtrA, MySetWindowLongPtrA);
		DetourDetach(&(PVOID&)TrueSetPropA, MySetPropA);
		DetourDetach(&(PVOID&)TrueVirtualProtectEx, MyVirtualProtectEx);
		//DetourDetach(&(PVOID&)TrueSleepEx, TimedSleepEx);
		DetourTransactionCommit();

		CloseHandle(hMonProcess);
		UnmapViewOfFile(pMemoryMap);
		UnmapViewOfFile(map_addr);
		CloseHandle(fm);

		printf("FAST-DLL: Process detached.\n");
		break;
	}

	return TRUE;
}