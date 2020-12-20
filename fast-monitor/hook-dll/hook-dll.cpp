#include "hook-dll.h"


// Find injected 'FAST-DLL.dll' handle from monitored process.
HMODULE findRemoteHModule(DWORD dwProcessId, const char* szdllout)
{
	MODULEENTRY32 me = { sizeof(me) };
	BOOL bMore = FALSE;
	HANDLE hSnapshot;

#ifdef _X86_
	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE32, dwProcessId);
#endif
#ifdef _AMD64_
	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwProcessId);
#endif

	if (hSnapshot == (HANDLE)-1) {
		;
	}
	bMore = Module32First(hSnapshot, &me);
	for (; bMore; bMore = Module32Next(hSnapshot, &me))
	{
		if (!_tcsicmp((LPCTSTR)me.szExePath, szdllout))
		{
			//if (isWoW64) printf("%s\n", me.szExePath);
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

	LPCSTR rpszDllsRaw;

#ifdef _X86_
	rpszDllsRaw = (LPCSTR)"FAST-DLL-32.dll";
#endif
#ifdef _AMD64_
	rpszDllsRaw = (LPCSTR)"FAST-DLL-64.dll";
#endif

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
	HMODULE hModKernel32 = NULL;

	LPTHREAD_START_ROUTINE pThreadProc;
	//DWORD pProcRVA;

	LPVOID lpMap = 0;
	SIZE_T viewsize = 0;

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
		//pProcRVA = getRVA("C:\\WINDOWS\\SysWOW64\\KERNEL32.DLL", "LoadLibraryA");
	}
	else
	{
		if (hook_cnt > 0)
			hook_cnt--;
		pThreadProc = (LPTHREAD_START_ROUTINE)GetProcAddress(hModKernel32, "FreeLibrary");
		//pProcRVA = getRVA("C:\\WINDOWS\\SysWOW64\\KERNEL32.DLL", "FreeLibrary");
	}

	if (!pThreadProc)
	{
		printf("Error: WinAPI load error.\n");
		return 1;
	}

	/*
	if (!pProcRVA)
	{
		printf("Error: WoW64 kernel32.dll (32bit) load error.\n");
		return 1;
	}
	*/

	/////////////////////////////////////////////////////////
	// Traversing the process list, inject the dll to processes. 
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32 entry = { sizeof(PROCESSENTRY32) };
	//BOOL wow64;

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

		//IsWow64Process(hProcess, &wow64);

		PNtMapViewOfSection(fm, hProcess, &lpMap, 0, dwBufSize,
			nullptr, &viewsize, ViewUnmap, 0, PAGE_READONLY);

		if (!isFree)
		{
			//printf("%p\n", pThreadProc);
			hThread = CreateRemoteThread(hProcess, NULL, 0, pThreadProc, lpMap, 0, NULL);
			if (!hThread)
			{
				printf("CreateRemoteThread failed.\n");
				CloseHandle(hProcess);
				continue;
			}
		}
		else
		{
			HMODULE fdllpath;

			fdllpath = findRemoteHModule(entry.th32ProcessID, (const char*)rpszDllsOut);
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
