#include "call_api.h"

FILE* pFile;
static UINT32 hook_cnt = 0;
static 	HANDLE fm = NULL;
static char* map_addr;
static DWORD dwBufSize = 0;
static DWORD thispid = GetCurrentProcessId();
static LPCSTR rpszDllsOut = NULL;

#define NT_SUCCESS(x) ((x) >= 0)

void init() {
	//Initialize the log file.

	time_t t = time(NULL);
	struct tm pLocal;
	localtime_s(&pLocal, &t);

	char buf[256];
	sprintf_s(buf, "log-%04d-%02d-%02d-%02d-%02d-%02d.txt",
		pLocal.tm_year + 1900, pLocal.tm_mon + 1, pLocal.tm_mday,
		pLocal.tm_hour, pLocal.tm_min, pLocal.tm_sec);

	fopen_s(&pFile, buf, "w");
	if (pFile == NULL)
	{
		exit(1);
	}

	fprintf(pFile, buf);
	fprintf(pFile, "\n#####Monitor Turned on.\n");


	// Turn on the SeDebugPrivilege.

	TOKEN_PRIVILEGES tp;
	BOOL bResult = FALSE;
	HANDLE hToken = NULL;
	DWORD dwSize;

	ZeroMemory(&tp, sizeof(tp));
	tp.PrivilegeCount = 1;

	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken) &&
		LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid))
	{
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
		bResult = AdjustTokenPrivileges(hToken, FALSE, &tp, 0, NULL, &dwSize);
	}
	CloseHandle(hToken);


	/////////////////////////////////////////////////////////
	// Getting the DLL's full path.

	LPCSTR rpszDllsRaw = (LPCSTR)"FAST-DLL.dll";

	CHAR szDllPath[1024];
	PCHAR pszFilePart = NULL;

	if (!GetFullPathNameA(rpszDllsRaw, ARRAYSIZE(szDllPath), szDllPath, &pszFilePart))
	{
		return;
	}

	DWORD c = (DWORD)strlen(szDllPath) + 1;
	PCHAR psz = new CHAR[c];
	StringCchCopyA(psz, c, szDllPath);
	rpszDllsOut = psz;



	/////////////////////////////////////////////////////////
	// Making shared memory.

	dwBufSize = (DWORD)(strlen(rpszDllsOut) + 1) * sizeof(char);

	fm = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE,
		0,
		(DWORD)((dwBufSize + sizeof(DWORD) + 13 * sizeof(DWORD64))), (LPCSTR)"shared");


	map_addr = (char*)MapViewOfFile(fm, FILE_MAP_ALL_ACCESS, 0, 0, 0);

	memcpy(map_addr, rpszDllsOut, dwBufSize);
	memcpy(map_addr + dwBufSize, &thispid, sizeof(DWORD));

	LPVOID fp = CallVirtualAllocEx;
	memcpy(map_addr + dwBufSize + sizeof(DWORD), &fp, sizeof(DWORD64));

	fp = CallQueueUserAPC;
	memcpy(map_addr + dwBufSize + sizeof(DWORD) + sizeof(DWORD64), &fp, sizeof(DWORD64));

	fp = CallWriteProcessMemory;
	memcpy(map_addr + dwBufSize + sizeof(DWORD) + 2 * sizeof(DWORD64), &fp, sizeof(DWORD64));

	fp = CallCreateRemoteThread;
	memcpy(map_addr + dwBufSize + sizeof(DWORD) + 3 * sizeof(DWORD64), &fp, sizeof(DWORD64));

	fp = CallNtMapViewOfSection;
	memcpy(map_addr + dwBufSize + sizeof(DWORD) + 4 * sizeof(DWORD64), &fp, sizeof(DWORD64));

	fp = CallCreateFileMappingA;
	memcpy(map_addr + dwBufSize + sizeof(DWORD) + 5 * sizeof(DWORD64), &fp, sizeof(DWORD64));

	fp = CallGetThreadContext;
	memcpy(map_addr + dwBufSize + sizeof(DWORD) + 6 * sizeof(DWORD64), &fp, sizeof(DWORD64));

	fp = CallSetThreadContext;
	memcpy(map_addr + dwBufSize + sizeof(DWORD) + 7 * sizeof(DWORD64), &fp, sizeof(DWORD64));

	fp = CallNtQueueApcThread;
	memcpy(map_addr + dwBufSize + sizeof(DWORD) + 8 * sizeof(DWORD64), &fp, sizeof(DWORD64));

	fp = CallSetWindowLongPtrA;
	memcpy(map_addr + dwBufSize + sizeof(DWORD) + 9 * sizeof(DWORD64), &fp, sizeof(DWORD64));

	fp = CallSetPropA;
	memcpy(map_addr + dwBufSize + sizeof(DWORD) + 10 * sizeof(DWORD64), &fp, sizeof(DWORD64));

	fp = CallVirtualProtectEx;
	memcpy(map_addr + dwBufSize + sizeof(DWORD) + 11 * sizeof(DWORD64), &fp, sizeof(DWORD64));

	fp = CallSleepEx;
	memcpy(map_addr + dwBufSize + sizeof(DWORD) + 12 * sizeof(DWORD64), &fp, sizeof(DWORD64));



	//Initial Hooking.
	//mon(0);

}

void exiting(unsigned int t_pid) {

	//UnHooking All.
	for (int i = 0; i < hook_cnt; i++)
		mon(1, t_pid);


	//Close Everything.
	UnmapViewOfFile(map_addr);
	CloseHandle(fm);
	fclose(pFile);
}

DWORD findPidByName(const char* pname)
{
	HANDLE h;
	PROCESSENTRY32 procSnapshot;
	h = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	procSnapshot.dwSize = sizeof(PROCESSENTRY32);

	do
	{
		if (!strcmp((const char*)procSnapshot.szExeFile, pname))
		{
			DWORD pid = procSnapshot.th32ProcessID;
			CloseHandle(h);
			return pid;
		}
	} while (Process32Next(h, &procSnapshot));

	CloseHandle(h);
	return 0;
}



void exe(char op , unsigned int t_pid) {

	char cmd[MSG_SIZE] = "";


	sprintf_s(cmd, "/C InjDll64.exe %ud  -%c FAST-DLL.dll", t_pid, op);
	printf("%s\n", cmd);
	HANDLE vh = ShellExecute(NULL, "open", "cmd.exe", cmd, ".", SW_NORMAL);

	//DWORD dwProcessId = findPidByName("explorer.exe");
	//sprintf_s(cmd, "/C InjDll64.exe %ud  -%c FAST-DLL.dll", dwProcessId, op);
	//printf("%s\n", cmd);
	// vh = ShellExecute(NULL, "open", "cmd.exe", cmd, ".", SW_NORMAL);


	//sprintf_s(cmd, "/C InjDll64.exe *  -%c FAST-DLL.dll", op);
	//printf("%s\n", cmd);
	//vh = ShellExecute(NULL, "open", "cmd.exe", cmd, ".", SW_NORMAL);

	Sleep(500);

	//BOOL bShellExecute = FALSE;
	//SHELLEXECUTEINFO stShellInfo = { sizeof(SHELLEXECUTEINFO) };
	//stShellInfo.lpVerb = TEXT("runas");
	//stShellInfo.lpFile = TEXT("cmd.exe");
	//stShellInfo.lpParameters = TEXT(cmd);
	//stShellInfo.nShow = SW_SHOWNORMAL;
	//bShellExecute = ShellExecuteEx(&stShellInfo);

	//WaitForSingleObject(stShellInfo.hProcess, INFINITE);
}



// Find injected 'FAST-DLL.dll' handle from monitored process.
HMODULE findRemoteHModule(DWORD dwProcessId, const char* szdllout)
{
	MODULEENTRY32 me = { sizeof(me) };
	BOOL bMore = FALSE;
	HANDLE hSnapshot;


	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwProcessId);
	if (hSnapshot == (HANDLE)-1) {
		;
	}
	bMore = Module32First(hSnapshot, &me);
	for (; bMore; bMore = Module32Next(hSnapshot, &me))
	{
		if (!_tcsicmp((LPCTSTR)me.szExePath, szdllout))
		{
			return (HMODULE)me.modBaseAddr;
		}
	}
	return NULL;
}

typedef NTSTATUS(NTAPI* pfnNtCreateThreadEx)
(
	OUT PHANDLE hThread,
	IN ACCESS_MASK DesiredAccess,
	IN PVOID ObjectAttributes,
	IN HANDLE ProcessHandle,
	IN PVOID lpStartAddress,
	IN PVOID lpParameter,
	IN ULONG Flags,
	IN SIZE_T StackZeroBits,
	IN SIZE_T SizeOfStackCommit,
	IN SIZE_T SizeOfStackReserve,
	OUT PVOID lpBytesBuffer);

typedef struct _CLIENT_ID {
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
} CLIENT_ID, * PCLIENT_ID;

typedef NTSTATUS(NTAPI* pfnRtlCreateUserThread)(
	IN HANDLE ProcessHandle,
	IN PSECURITY_DESCRIPTOR SecurityDescriptor OPTIONAL,
	IN BOOLEAN CreateSuspended,
	IN ULONG StackZeroBits OPTIONAL,
	IN SIZE_T StackReserve OPTIONAL,
	IN SIZE_T StackCommit OPTIONAL,
	IN PTHREAD_START_ROUTINE StartAddress,
	IN PVOID Parameter OPTIONAL,
	OUT PHANDLE ThreadHandle OPTIONAL,
	OUT PCLIENT_ID ClientId OPTIONAL);


// main.
//
int CDECL mon(int isFree_, unsigned int t_pid)
{
	// Hook/Unhook flag 
	BOOLEAN isFree = (BOOLEAN)isFree_;



	///////////////////////////////////////////////////////// Validate DLLs. (get the full path name.)

	HMODULE hDll = LoadLibraryExA(rpszDllsOut, NULL, DONT_RESOLVE_DLL_REFERENCES);
	if (hDll == NULL)
	{
		return 1;
	}

	ExportContext ec;
	ec.fHasOrdinal1 = FALSE;
	ec.nExports = 0;
	DetourEnumerateExports(hDll, &ec, ExportCallback);
	FreeLibrary(hDll);

	if (!ec.fHasOrdinal1)
	{
		return 1;
	}


	/////////////////////////////////////////////////////////




	//HANDLE hProcess = NULL, hThread = NULL;
	//HMODULE hMod = NULL;


	//LPTHREAD_START_ROUTINE pThreadProc = NULL;


	//LPVOID lpMap = 0;
	//SIZE_T viewsize = 0;

	//PNtMapViewOfSection = (NTSTATUS(*)(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID * BaseAddress, ULONG_PTR ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, SECTION_INHERIT InheritDisposition, ULONG AllocationType, ULONG Win32Protect)) GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtMapViewOfSection");
	//if (!PNtMapViewOfSection)
	//{
	//	printf("GetProcAddress(%ld) PNtMapViewOfSection  failed!!! \n", GetLastError());
	//	return 1;
	//}


	//hMod = GetModuleHandleA("kernel32.dll");
	//if (!hMod)
	//{
	//	printf("GetModuleHandleA(%ld) failed!!! \n", GetLastError());
	//	return 1;
	//}




	//if (!isFree)
	//{
	//	hook_cnt++;
	//	fprintf(pFile, "Hook DLLs!\n");
	//	pThreadProc = (LPTHREAD_START_ROUTINE)GetProcAddress(hMod, "LoadLibraryA");
	//	if (!pThreadProc)
	//	{
	//		printf("GetProcAddress(%ld) LoadLibraryA  failed!!! \n", GetLastError());
	//		return 1;
	//	}

	//}
	//else
	//{
	//	if (hook_cnt > 0)
	//		hook_cnt--;
	//	fprintf(pFile, "UnHook DLLs!\n");
	//	pThreadProc = (LPTHREAD_START_ROUTINE)GetProcAddress(hMod, "FreeLibrary");
	//	if (!pThreadProc)
	//	{
	//		printf("GetProcAddress(%ld) FreeLibrary  failed!!! \n", GetLastError());
	//		return 1;
	//	}

	//}






	/////////////////////////////////////////////////////////
	// Traversing the process list, inject the dll to processes. 
	//HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	//PROCESSENTRY32 entry = { sizeof(PROCESSENTRY32) };
	//Process32First(hSnap, &entry);
	//do
	//{

	//	if (thispid == entry.th32ProcessID)
	//		continue;
	//	hProcess = OpenProcess(MAXIMUM_ALLOWED, FALSE, entry.th32ProcessID);
	//	if (!(hProcess))
	//	{
	//		printf("OpenProcess(%ld) failed!!! [%ld]\n", entry.th32ProcessID, GetLastError());
	//		continue;
	//	}
	//	printf("OpenProcess(%ld) Success!!! \n", entry.th32ProcessID);


	//	PNtMapViewOfSection(fm, hProcess, &lpMap, 0, dwBufSize,
	//		nullptr, &viewsize, ViewUnmap, 0, PAGE_READONLY);

	//	pfnNtCreateThreadEx NtCreateThreadEx = (pfnNtCreateThreadEx)GetProcAddress(GetModuleHandle("ntdll.dll"), "NtCreateThreadEx");
	//	//pfnRtlCreateUserThread RtlCreateUserThread = (pfnRtlCreateUserThread)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlCreateUserThread");


	//	if (!isFree)
	//	{
	//		NTSTATUS Status = NtCreateThreadEx(&hThread, 0x1FFFFF, NULL, hProcess, (LPTHREAD_START_ROUTINE)pThreadProc, lpMap, FALSE, NULL, NULL, NULL, NULL);

	//		//NTSTATUS Status = RtlCreateUserThread(hProcess, NULL, FALSE, 0, 0, 0, pThreadProc, lpMap, &hThread, NULL);
	//		if (!NT_SUCCESS(Status) || hThread == NULL)
	//		{
	//			printf("CreateRemoteThread(%ld) failed!!! [%ld]\n", entry.th32ProcessID, GetLastError());
	//			CloseHandle(hProcess);
	//			continue;
	//		}
	//	}
	//	else
	//	{
	//		HMODULE fdllpath = findRemoteHModule(entry.th32ProcessID, (const char*)rpszDllsOut);
	//		if (fdllpath != NULL)
	//		{
	//			NTSTATUS Status = NtCreateThreadEx(&hThread, 0x1FFFFF, NULL, hProcess, (LPTHREAD_START_ROUTINE)pThreadProc, fdllpath, FALSE, NULL, NULL, NULL, NULL);
	//			//NTSTATUS Status = RtlCreateUserThread(hProcess, NULL, FALSE, 0, 0, 0, pThreadProc, fdllpath, &hThread, NULL);
	//			if (!NT_SUCCESS(Status) || hThread == NULL)
	//			{
	//				printf("CreateRemoteThread(%ld) failed!!! [%ld]\n", entry.th32ProcessID, GetLastError());
	//				CloseHandle(hProcess);
	//				continue;
	//			}
	//		}
	//	}
	//	printf("CreateRemoteThread(%ld) Success!!! \n", entry.th32ProcessID);

	//	CloseHandle(hThread);
	//	hThread = NULL;
	//	CloseHandle(hProcess);
	//	hProcess = NULL;
	//} while (Process32Next(hSnap, &entry));

	//CloseHandle(hSnap);




	if (!isFree) {
		exe('i', t_pid);
	}
	else {
		exe('e', t_pid);
	}

	return 0;
}
