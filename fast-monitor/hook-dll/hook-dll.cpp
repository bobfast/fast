#include "hook-dll.h"

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


void init() {
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
		printf("Error: GetFullPathNameA failed.\n");
		return;
	}

	DWORD c = (DWORD)strlen(szDllPath) + 1;
	PCHAR psz = new CHAR[c];
	StringCchCopyA(psz, c, szDllPath);
	rpszDllsOut = psz;

	dwBufSize = (DWORD)(strlen(rpszDllsOut) + 1) * sizeof(char);
	fm = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_EXECUTE_READWRITE, 0, dwBufSize, NULL);

	if (!fm) {
		printf("Error: CreateFileMappingA failed.\n");
		return;
	}

	map_addr = (char*)MapViewOfFile(fm, FILE_MAP_ALL_ACCESS, 0, 0, 0);

	if (!map_addr) {
		printf("Error: MapViewOfFile failed.\n");
		return;
	}

	memcpy(map_addr, rpszDllsOut, dwBufSize);
}

void existing()
{
	//Close Everything.
	UnmapViewOfFile(map_addr);
	CloseHandle(fm);
}

// main.
//
int mon(int isFree_)
{
	// Hook/Unhook flag 
	BOOLEAN isFree = (BOOLEAN)isFree_;

	///////////////////////////////////////////////////////// Validate DLLs. (get the full path name.)

	HMODULE hDll = LoadLibraryExA(rpszDllsOut, NULL, DONT_RESOLVE_DLL_REFERENCES);
	if (hDll == NULL)
	{
		printf("Error: DLL load error.\n");
		return 1;
	}

	ExportContext ec;
	ec.fHasOrdinal1 = FALSE;
	ec.nExports = 0;
	DetourEnumerateExports(hDll, &ec, ExportCallback);
	FreeLibrary(hDll);

	if (!ec.fHasOrdinal1)
	{
		printf("Error: cannot export ordinal #1.\n");
		return 1;
	}

	/////////////////////////////////////////////////////////
	HANDLE hProcess = NULL, hThread = NULL;
	HMODULE hMod = NULL;


	LPTHREAD_START_ROUTINE pThreadProc = NULL;


	LPVOID lpMap = 0;
	SIZE_T viewsize = 0;

	PNtMapViewOfSection = (NTSTATUS(*)(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID * BaseAddress, ULONG_PTR ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, SECTION_INHERIT InheritDisposition, ULONG AllocationType, ULONG Win32Protect)) GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtMapViewOfSection");

	hMod = GetModuleHandleA("kernel32.dll");
	if (!hMod)
	{
		printf("Error: kernel32.dll load error.\n");
		return 1;
	}

	if (!isFree)
	{
		hook_cnt++;
		pThreadProc = (LPTHREAD_START_ROUTINE)GetProcAddress(hMod, "LoadLibraryA");
	}
	else
	{
		if (hook_cnt > 0)
			hook_cnt--;
		pThreadProc = (LPTHREAD_START_ROUTINE)GetProcAddress(hMod, "FreeLibrary");
	}

	if (!pThreadProc)
	{
		printf("Error: WinAPI load error.\n");
		return 1;
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

		if (!hProcess)
		{
			continue;
		}

		PNtMapViewOfSection(fm, hProcess, &lpMap, 0, dwBufSize,
			nullptr, &viewsize, ViewUnmap, 0, PAGE_READONLY);

		if (!isFree)
		{
			hThread = CreateRemoteThread(hProcess, NULL, 0, pThreadProc, lpMap, 0, NULL);
			if (!hThread)
			{
				CloseHandle(hProcess);
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
					CloseHandle(hProcess);
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


int main(int argc, char *argv[])
{
	if (argc < 2) {
		printf("Usage: %s <on/off>\n", argv[0]);
		return 0;
	}

	init();

	if (strcmp(argv[1], "on") == 0) {
		mon(0);
	}
	else if (strcmp(argv[1], "off") == 0) {
		mon(1);
	}
	else {
		printf("Usage: %s <on/off>\n", argv[0]);
	}

	existing();
	return 0;
}
