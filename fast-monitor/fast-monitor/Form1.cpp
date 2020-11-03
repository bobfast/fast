#include "call_api.h"


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

}

void exiting() {
	//Close the log file descriptor.
	mon(1);
	fclose(pFile);
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




// main.
//
int CDECL mon(int isFree_)
{
	BOOLEAN isFree = (BOOLEAN)isFree_;
	// Hook/Unhook flag 

	LPCSTR rpszDllsOut = NULL;
	LPCSTR rpszDllsRaw = (LPCSTR)"FAST-DLL.dll";;





	///////////////////////////////////////////////////////// Validate DLLs. (get the full path name.)

	CHAR szDllPath[1024];
	PCHAR pszFilePart = NULL;

	if (!GetFullPathNameA(rpszDllsRaw, ARRAYSIZE(szDllPath), szDllPath, &pszFilePart))
	{
		return 9002;
	}

	DWORD c = (DWORD)strlen(szDllPath) + 1;
	PCHAR psz = new CHAR[c];
	StringCchCopyA(psz, c, szDllPath);
	rpszDllsOut = psz;

	HMODULE hDll = LoadLibraryExA(rpszDllsOut, NULL, DONT_RESOLVE_DLL_REFERENCES);
	if (hDll == NULL)
	{
		return 9003;
	}

	ExportContext ec;
	ec.fHasOrdinal1 = FALSE;
	ec.nExports = 0;
	DetourEnumerateExports(hDll, &ec, ExportCallback);
	FreeLibrary(hDll);

	if (!ec.fHasOrdinal1)
	{
		return 9004;
	}


	/////////////////////////////////////////////////////////




	HANDLE hProcess = NULL, hThread = NULL;
	HMODULE hMod = NULL;


	LPTHREAD_START_ROUTINE pThreadProc = NULL;

	HANDLE fm = NULL;
	char* map_addr;
	LPVOID lpMap = 0;
	SIZE_T viewsize = 0;

	PNtMapViewOfSection = (NTSTATUS(*)(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID * BaseAddress, ULONG_PTR ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, SECTION_INHERIT InheritDisposition, ULONG AllocationType, ULONG Win32Protect)) GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtMapViewOfSection");


	hMod = GetModuleHandleA("kernel32.dll");
	if (!hMod)
	{
		return FALSE;
	}

	LPCSTR sz = NULL;
	DWORD dwBufSize = 0;
	DWORD thispid = GetCurrentProcessId();


	if (!isFree)
	{
		fprintf(pFile, "Hook DLLs!\n");
		pThreadProc = (LPTHREAD_START_ROUTINE)GetProcAddress(hMod, "LoadLibraryA");


	}
	else
	{
		fprintf(pFile, "UnHook DLLs!\n");
		pThreadProc = (LPTHREAD_START_ROUTINE)GetProcAddress(hMod, "FreeLibrary");

	}

	if (!pThreadProc)
	{
		return FALSE;
	}


	/////////////////////////////////////////////////////////
	// If it is injection process, it makes shared memory.
	if (!isFree)
	{
		sz = rpszDllsOut;
		dwBufSize = (DWORD)(strlen(sz) + 1) * sizeof(char);

		fm = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE,
			0,
			(DWORD)((dwBufSize + sizeof(DWORD) + 12 * sizeof(DWORD64))), (LPCSTR)"shared");


		map_addr = (char*)MapViewOfFile(fm, FILE_MAP_ALL_ACCESS, 0, 0, 0);

		memcpy(map_addr, sz, dwBufSize);
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

		fp = CallSleepEx;
		memcpy(map_addr + dwBufSize + sizeof(DWORD) + 11 * sizeof(DWORD64), &fp, sizeof(DWORD64));


	}


	/////////////////////////////////////////////////////////
	// Traversing the process list, inject the dll to processes. 
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32 entry = { sizeof(PROCESSENTRY32) };
	Process32First(hSnap, &entry);
	do
	{

		if (thispid == entry.th32ProcessID)
			continue;
		hProcess = OpenProcess(MAXIMUM_ALLOWED, FALSE, entry.th32ProcessID);
		if (!(hProcess))
		{
			continue;
		}

		(*PNtMapViewOfSection)(fm, hProcess, &lpMap, 0, dwBufSize,
			nullptr, &viewsize, ViewUnmap, 0, PAGE_READONLY);




		if (!isFree)
		{
			hThread = CreateRemoteThread(hProcess, NULL, 0, pThreadProc, lpMap, 0, NULL);
			if (!hThread)
			{
				continue;
			}
		}
		else
		{
			HMODULE fdllpath = findRemoteHModule(entry.th32ProcessID, (const char*)rpszDllsOut);
			if (fdllpath != NULL)
			{
				hThread = CreateRemoteThread(hProcess, NULL, 0, pThreadProc, fdllpath, 0, NULL);
				if (!hThread)
				{
					continue;
				}
			}
		}

		CloseHandle(hThread);
		hThread = NULL;
		CloseHandle(hProcess);
		hProcess = NULL;

	} while (Process32Next(hSnap, &entry));

	CloseHandle(hSnap);


	return 0;
}
