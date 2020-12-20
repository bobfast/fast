#include "hook-dll.h"


// Find injected 'FAST-DLL.dll' handle from monitored process.
HMODULE findRemoteHModule(DWORD dwProcessId, const char* szdllout, BOOL isWoW64)
{
	MODULEENTRY32 me = { sizeof(me) };
	BOOL bMore = FALSE;
	HANDLE hSnapshot;

	if (isWoW64)
		hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, dwProcessId);
	else
		hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwProcessId);

	if (hSnapshot == (HANDLE)-1) {
		;
	}
	bMore = Module32First(hSnapshot, &me);
	for (; bMore; bMore = Module32Next(hSnapshot, &me))
	{
		if (!_tcsicmp((LPCTSTR)me.szExePath, szdllout))
		{
			if (isWoW64) printf("%s\n", me.szExePath);
			return (HMODULE)me.modBaseAddr;
		}
	}
	return NULL;
}

DWORD getRVA(LPCSTR DllName, LPCSTR FuncName)
{
	HANDLE hSrcFile = CreateFileA(DllName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	if (!hSrcFile) {
		printf("getRVA: CreateFileA error.\n");
		return NULL;
	}
	
	HANDLE hMapSrcFile = CreateFileMappingA(hSrcFile, NULL, PAGE_READONLY, 0, 0, NULL);
	if (!hMapSrcFile) {
		printf("getRVA: CreateFileMappingA error.\n");
		return NULL;
	}
	
	PBYTE pSrcFile = (PBYTE)MapViewOfFile(hMapSrcFile, FILE_MAP_READ, 0, 0, 0);
	if (!pSrcFile) {
		printf("getRVA: MapViewOfFile error.\n");
		return NULL;
	}

	IMAGE_DOS_HEADER* pDosHeader = (IMAGE_DOS_HEADER*)pSrcFile;
	printf("e_lfanew = %d\n", pDosHeader->e_lfanew);
	IMAGE_NT_HEADERS32* pNtHdr = (IMAGE_NT_HEADERS32*)
		((PBYTE)pDosHeader + pDosHeader->e_lfanew);
	printf("IMAGE_NT_HEADERS = %p\n", pNtHdr);
	IMAGE_SECTION_HEADER* pFirstSectionHeader = (IMAGE_SECTION_HEADER*)
		((PBYTE)&pNtHdr->OptionalHeader +
			pNtHdr->FileHeader.SizeOfOptionalHeader);
	printf("First Section Header = %p\n", pFirstSectionHeader);

	IMAGE_EXPORT_DIRECTORY* pExportDirectory = NULL;
	int fileOffset;

	for (DWORD i = 0; i < (pNtHdr->FileHeader.NumberOfSections); i++) {
		IMAGE_SECTION_HEADER* pSectionHeader = &pFirstSectionHeader[i];
		fileOffset = pSectionHeader->PointerToRawData - pSectionHeader->VirtualAddress;

		printf("section header name: %s\n", pSectionHeader->Name);
		if (strcmp(".rdata", (const char *)(pSectionHeader->Name)) == 0) {
			pExportDirectory = (IMAGE_EXPORT_DIRECTORY*)((PBYTE)pSrcFile + fileOffset +
					pNtHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

			break;
		}
	}

	printf("Export Directory = %p\n", pExportDirectory);

	if (pExportDirectory) {
		PDWORD address = (PDWORD)((PBYTE)pSrcFile + fileOffset + pExportDirectory->AddressOfFunctions);
		PDWORD name = (PDWORD)((PBYTE)pSrcFile + fileOffset + pExportDirectory->AddressOfNames);
		PWORD ordinal = (PWORD)((PBYTE)pSrcFile + fileOffset + pExportDirectory->AddressOfNameOrdinals);
		printf("number of functions = %d\n", pExportDirectory->NumberOfFunctions);
		printf("address = %p\n", address);
		printf("name = %p\n", name);
		printf("ordinal = %p\n", ordinal);

		for (DWORD i = 0; i < (pExportDirectory->NumberOfFunctions); i++) {
			printf("function name = %s\n", (char*)pSrcFile + fileOffset + name[i]);
			printf("result = %d\n", address[ordinal[i]]);
			if (strcmp(FuncName, (char*)pSrcFile + fileOffset + name[i]) == 0) {
				return address[ordinal[i]];
			}
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

	// Load NTDLL
	HMODULE hModNtDll = GetModuleHandleA("ntdll.dll");
	if (!hModNtDll)
	{
		printf("Error: ntdll.dll load error.\n");
		return;
	}

	PNtMapViewOfSection = (NTSTATUS(*)(
		HANDLE SectionHandle, HANDLE ProcessHandle, PVOID * BaseAddress, ULONG_PTR ZeroBits, SIZE_T CommitSize,
		PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, SECTION_INHERIT InheritDisposition, ULONG AllocationType, ULONG Win32Protect))
		GetProcAddress(hModNtDll, "NtMapViewOfSection");

	/*
	PRtlImageNtHeader = (PIMAGE_NT_HEADERS(*)(PVOID ModuleAddress)) GetProcAddress(hModNtDll, "RtlImageNtHeader");

	PRtlImageDirectoryEntryToData = (PVOID(*)(
		PVOID BaseAddress,
		BOOLEAN MappedAsImage,
		USHORT Directory,
		PULONG Size))
		GetProcAddress(hModNtDll, "RtlImageDirectoryEntryToData");

	PNtOpenSection = (NTSTATUS(*)(
		PHANDLE SectionHandle,
		ACCESS_MASK DesiredAccess,
		POBJECT_ATTRIBUTES ObjectAttributes))
		GetProcAddress(hModNtDll, "NtOpenSection");

	PNtQuerySection = (NTSTATUS(*)(
		HANDLE               SectionHandle,
		SECTION_INFORMATION_CLASS InformationClass,
		PVOID                InformationBuffer,
		ULONG                InformationBufferSize,
		PULONG               ResultLength))
		GetProcAddress(hModNtDll, "NtQuerySection");

	PNtUnmapViewOfSection = (NTSTATUS(*)(
		HANDLE               ProcessHandle,
		PVOID                BaseAddress))
		GetProcAddress(hModNtDll, "NtUnmapViewOfSection");

	PNtClose = (NTSTATUS(*)(
		HANDLE               ObjectHandle))
		GetProcAddress(hModNtDll, "NtClose");

	*/
	/////////////////////////////////////////////////////////
	// Getting the DLL's full path.

	LPCSTR rpszDllsRaw32, rpszDllsRaw64;

	rpszDllsRaw32 = (LPCSTR)"FAST-DLL-32.dll";
	rpszDllsRaw64 = (LPCSTR)"FAST-DLL-64.dll";

	CHAR szDllPath32[1024], szDllPath64[1024];
	PCHAR pszFilePart32 = NULL, pszFilePart64 = NULL;

	if (!GetFullPathNameA(rpszDllsRaw32, ARRAYSIZE(szDllPath32), szDllPath32, &pszFilePart32))
	{
		printf("Error: GetFullPathNameA failed.\n");
		return;
	}

	DWORD c32 = (DWORD)strlen(szDllPath32) + 1;
	PCHAR psz32 = new CHAR[c32];
	StringCchCopyA(psz32, c32, szDllPath32);
	rpszDllsOut32 = psz32;

	dwBufSize32 = (DWORD)(strlen(rpszDllsOut32) + 1) * sizeof(char);

	fm32 = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_EXECUTE_READWRITE, 0, dwBufSize32, NULL);

	if (!fm32) {
		printf("Error: CreateFileMappingA failed.\n");
		return;
	}

	map_addr32 = (char*)MapViewOfFile(fm32, FILE_MAP_ALL_ACCESS, 0, 0, 0);

	if (!map_addr32) {
		printf("Error: MapViewOfFile failed.\n");
		return;
	}

	memcpy(map_addr32, rpszDllsOut32, dwBufSize32);

	/////////////////////////

	if (!GetFullPathNameA(rpszDllsRaw64, ARRAYSIZE(szDllPath64), szDllPath64, &pszFilePart64))
	{
		printf("Error: GetFullPathNameA failed.\n");
		return;
	}

	DWORD c64 = (DWORD)strlen(szDllPath64) + 1;
	PCHAR psz64 = new CHAR[c64];
	StringCchCopyA(psz64, c64, szDllPath64);
	rpszDllsOut64 = psz64;

	dwBufSize64 = (DWORD)(strlen(rpszDllsOut64) + 1) * sizeof(char);

	fm64 = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_EXECUTE_READWRITE, 0, dwBufSize64, NULL);

	if (!fm64) {
		printf("Error: CreateFileMappingA failed.\n");
		return;
	}

	map_addr64 = (char*)MapViewOfFile(fm64, FILE_MAP_ALL_ACCESS, 0, 0, 0);

	if (!map_addr64) {
		printf("Error: MapViewOfFile failed.\n");
		return;
	}

	memcpy(map_addr64, rpszDllsOut64, dwBufSize64);
}

void existing()
{
	//Close Everything.
	UnmapViewOfFile(map_addr32);
	CloseHandle(fm32);
	UnmapViewOfFile(map_addr64);
	CloseHandle(fm64);
}

// main.
//
int mon(int isFree_)
{
	// Hook/Unhook flag 
	BOOLEAN isFree = (BOOLEAN)isFree_;

	///////////////////////////////////////////////////////// Validate DLLs. (get the full path name.)

	HMODULE hDll = LoadLibraryExA(rpszDllsOut64, NULL, DONT_RESOLVE_DLL_REFERENCES);
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
	HMODULE hModKernel32 = NULL;

	LPTHREAD_START_ROUTINE pThreadProc;
	DWORD pProcRVA;

	LPVOID lpMap32 = 0, lpMap64 = 0;
	SIZE_T viewsize32 = 0, viewsize64 = 0;

	hModKernel32 = GetModuleHandleA("kernel32.dll");
	if (!hModKernel32)
	{
		printf("Error: kernel32.dll load error.\n");
		return 1;
	}

	if (!isFree)
	{
		hook_cnt++;
		pThreadProc = (LPTHREAD_START_ROUTINE)GetProcAddress(hModKernel32, "LoadLibraryA");
		pProcRVA = getRVA("C:\\WINDOWS\\SysWOW64\\KERNEL32.DLL", "LoadLibraryA");
	}
	else
	{
		if (hook_cnt > 0)
			hook_cnt--;
		pThreadProc = (LPTHREAD_START_ROUTINE)GetProcAddress(hModKernel32, "FreeLibrary");
		pProcRVA = getRVA("C:\\WINDOWS\\SysWOW64\\KERNEL32.DLL", "FreeLibrary");
	}

	if (!pThreadProc)
	{
		printf("Error: WinAPI (64bit) load error.\n");
		return 1;
	}

	if (!pProcRVA)
	{
		printf("Error: WoW64 kernel32.dll (32bit) load error.\n");
		return 1;
	}

	/////////////////////////////////////////////////////////
	// Traversing the process list, inject the dll to processes. 
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32 entry = { sizeof(PROCESSENTRY32) };
	BOOL wow64;

	Process32First(hSnap, &entry);
	
	do
	{
		if (thispid == entry.th32ProcessID)
			continue;
		hProcess = OpenProcess(MAXIMUM_ALLOWED, FALSE, entry.th32ProcessID);

		if (!hProcess)
		{
			printf("Open PID=%d failed.\n", entry.th32ProcessID);
			continue;
		}

		printf("Open PID=%d succeeded.\n", entry.th32ProcessID);

		IsWow64Process(hProcess, &wow64);

		if (wow64) {
			//PNtMapViewOfSection(fm32, hProcess, &lpMap32, 8, dwBufSize32,
			//	nullptr, &viewsize32, ViewUnmap, 0, PAGE_READONLY);
		}
		else
			PNtMapViewOfSection(fm64, hProcess, &lpMap64, 0, dwBufSize64,
				nullptr, &viewsize64, ViewUnmap, 0, PAGE_READONLY);

		if (!isFree)
		{
			if (wow64) {
				
				//LPTHREAD_START_ROUTINE pThreadProc32 = 
				//	(LPTHREAD_START_ROUTINE) findRemoteHModule(entry.th32ProcessID, "C:\\WINDOWS\\SysWOW64\\KERNEL32.DLL", wow64);
				//if (!pThreadProc32)
				//{
				//	printf("Error: kernel32.dll (32bit) load error.\n");
				//	continue;
				//}
				//
				//pThreadProc32 = (LPTHREAD_START_ROUTINE)((DWORD64)pThreadProc32 + (DWORD64)pProcRVA); // + WoW64 LoadLibraryA RVA
				//printf("WoW64.LoadLibraryA = %p\n", pThreadProc32);
				//printf("32bit MapViewOfSection = %p\n", lpMap32);
				///*
				//if (!DetourProcessViaHelperA(entry.th32ProcessID, rpszDllsOut32, CreateProcessA)) {
				//	printf("Error: DetourProcesViaHelperA failed.\n");
				//	continue;
				//}
				//*/

				//hThread = CreateRemoteThread(hProcess, NULL, 0, pThreadProc32, lpMap32, 0, NULL);
				//if (!hThread)
				//{
				//	printf("CreateRemoteThread failed.\n");
				//	CloseHandle(hProcess);
				//	continue;
				//}
			}
			else {
				//printf("%p\n", pThreadProc);
				hThread = CreateRemoteThread(hProcess, NULL, 0, pThreadProc, lpMap64, 0, NULL);
				if (!hThread)
				{
					printf("CreateRemoteThread failed.\n");
					CloseHandle(hProcess);
					continue;
				}
			}
		}
		else
		{
			HMODULE fdllpath;

			if (wow64) {
				//fdllpath = findRemoteHModule(entry.th32ProcessID, (const char*)rpszDllsOut32, wow64);
				//if (fdllpath != NULL)
				//{
				//	LPTHREAD_START_ROUTINE pThreadProc32 = 
				//		(LPTHREAD_START_ROUTINE) findRemoteHModule(entry.th32ProcessID, "C:\\WINDOWS\\SysWOW64\\KERNEL32.DLL", wow64);
				//	if (!pThreadProc32)
				//	{
				//		printf("Error: kernel32.dll (32bit) load error.\n");
				//		continue;
				//	}

				//	pThreadProc32 = (LPTHREAD_START_ROUTINE)((DWORD64)pThreadProc32 + (DWORD64)pProcRVA); // + WoW64 FreeLibrary RVA
				//	printf("WoW64.FreeLibrary = %p\n", pThreadProc32);

				//	hThread = CreateRemoteThread(hProcess, NULL, 0, pThreadProc32, fdllpath, 0, NULL);
				//	if (!hThread)
				//	{
				//		printf("CreateRemoteThread failed.\n");
				//		CloseHandle(hProcess);
				//		continue;
				//	}
				//}
			}
			else {
				fdllpath = findRemoteHModule(entry.th32ProcessID, (const char*)rpszDllsOut64, wow64);
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
