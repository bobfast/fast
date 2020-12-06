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


PVOID getRVA(PVOID Base, ULONG_PTR BaseAddress, PCSTR Name)
{
	if (PIMAGE_NT_HEADERS32 pinth = (PIMAGE_NT_HEADERS32)PRtlImageNtHeader(Base))
	{
		BaseAddress -= pinth->OptionalHeader.AddressOfEntryPoint;

		DWORD Size, exportRVA;
		if (PIMAGE_EXPORT_DIRECTORY pied = (PIMAGE_EXPORT_DIRECTORY)
			PRtlImageDirectoryEntryToData(Base, TRUE, IMAGE_DIRECTORY_ENTRY_EXPORT, &Size))
		{
			exportRVA = RtlPointerToOffset(Base, pied);

			DWORD NumberOfFunctions = pied->NumberOfFunctions;
			DWORD NumberOfNames = pied->NumberOfNames;

			if (0 < NumberOfNames && NumberOfNames <= NumberOfFunctions)
			{
				PDWORD AddressOfFunctions = (PDWORD)RtlOffsetToPointer(Base, pied->AddressOfFunctions);
				PDWORD AddressOfNames = (PDWORD)RtlOffsetToPointer(Base, pied->AddressOfNames);
				PWORD AddressOfNameOrdinals = (PWORD)RtlOffsetToPointer(Base, pied->AddressOfNameOrdinals);

				DWORD a = 0, b = NumberOfNames, o;

				do
				{
					o = (a + b) >> 1;

					int i = strcmp(RtlOffsetToPointer(Base, AddressOfNames[o]), Name);

					if (!i)
					{
						DWORD Rva = AddressOfFunctions[AddressOfNameOrdinals[o]];
						return (ULONG_PTR)Rva - (ULONG_PTR)exportRVA < Size ? 0 : RtlOffsetToPointer(BaseAddress, Rva);
					}

					0 > i ? a = o + 1 : b = o;

				} while (a < b);
			}
		}
	}

	return 0;
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
	}
	else
	{
		if (hook_cnt > 0)
			hook_cnt--;
		pThreadProc = (LPTHREAD_START_ROUTINE)GetProcAddress(hModKernel32, "FreeLibrary");
	}

	if (!pThreadProc)
	{
		printf("Error: WinAPI (64bit) load error.\n");
		return 1;
	}

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

		/*
		IsWow64Process(hProcess, &wow64);

		if (wow64) {
			continue;
		}
		else {
			
		}
		*/

		PNtMapViewOfSection(fm, hProcess, &lpMap, 0, dwBufSize,
			nullptr, &viewsize, ViewUnmap, 0, PAGE_READONLY);

		if (!isFree)
		{
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
