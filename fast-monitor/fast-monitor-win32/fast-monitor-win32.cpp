#include "call_api.h"

FILE* pFile;
std::string ghidraDirectory = "";
static HANDLE fm32 = NULL;
static char* map_addr32;
static DWORD dwBufSize32 = 0;
static DWORD thispid = GetCurrentProcessId();
static LPCSTR rpszDllsOut32 = NULL;

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

	LPCSTR rpszDllsRaw32 = (LPCSTR)"FAST-DLL-32.dll";

	CHAR szDllPath32[1024];
	PCHAR pszFilePart32 = NULL;

	if (!GetFullPathNameA(rpszDllsRaw32, ARRAYSIZE(szDllPath32), szDllPath32, &pszFilePart32))
	{
		return;
	}

	DWORD c32 = (DWORD)strlen(szDllPath32) + 1;
	PCHAR psz32 = new CHAR[c32];
	StringCchCopyA(psz32, c32, szDllPath32);
	rpszDllsOut32 = psz32;


	/////////////////////////////////////////////////////////
	// Making shared memory.

	dwBufSize32 = (DWORD)(strlen(rpszDllsOut32) + 1) * sizeof(char);

	fm32 = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE,
		0,
		(DWORD)((dwBufSize32 + sizeof(DWORD) + 13 * sizeof(DWORD64))), (LPCSTR)"fast-shared32");


	map_addr32 = (char*)MapViewOfFile(fm32, FILE_MAP_ALL_ACCESS, 0, 0, 0);

	memcpy(map_addr32, rpszDllsOut32, dwBufSize32);
	memcpy(map_addr32 + dwBufSize32, &thispid, sizeof(DWORD));


	LPVOID fp = CallVirtualAllocEx;
	memcpy(map_addr32 + dwBufSize32 + sizeof(DWORD), &fp, sizeof(DWORD64));

	fp = CallQueueUserAPC;
	memcpy(map_addr32 + dwBufSize32 + sizeof(DWORD) + sizeof(DWORD64), &fp, sizeof(DWORD64));

	fp = CallWriteProcessMemory;
	memcpy(map_addr32 + dwBufSize32 + sizeof(DWORD) + 2 * sizeof(DWORD64), &fp, sizeof(DWORD64));

	fp = CallCreateRemoteThread;
	memcpy(map_addr32 + dwBufSize32 + sizeof(DWORD) + 3 * sizeof(DWORD64), &fp, sizeof(DWORD64));

	fp = CallNtMapViewOfSection;
	memcpy(map_addr32 + dwBufSize32 + sizeof(DWORD) + 4 * sizeof(DWORD64), &fp, sizeof(DWORD64));

	fp = CallCreateFileMappingA;
	memcpy(map_addr32 + dwBufSize32 + sizeof(DWORD) + 5 * sizeof(DWORD64), &fp, sizeof(DWORD64));

	fp = CallGetThreadContext;
	memcpy(map_addr32 + dwBufSize32 + sizeof(DWORD) + 6 * sizeof(DWORD64), &fp, sizeof(DWORD64));

	fp = CallSetThreadContext;
	memcpy(map_addr32 + dwBufSize32 + sizeof(DWORD) + 7 * sizeof(DWORD64), &fp, sizeof(DWORD64));

	fp = CallNtQueueApcThread;
	memcpy(map_addr32 + dwBufSize32 + sizeof(DWORD) + 8 * sizeof(DWORD64), &fp, sizeof(DWORD64));

	fp = CallSetWindowLongPtrA;
	memcpy(map_addr32 + dwBufSize32 + sizeof(DWORD) + 9 * sizeof(DWORD64), &fp, sizeof(DWORD64));

	fp = CallSetPropA;
	memcpy(map_addr32 + dwBufSize32 + sizeof(DWORD) + 10 * sizeof(DWORD64), &fp, sizeof(DWORD64));

	fp = CallVirtualProtectEx;
	memcpy(map_addr32 + dwBufSize32 + sizeof(DWORD) + 11 * sizeof(DWORD64), &fp, sizeof(DWORD64));

	fp = CallSleepEx;
	memcpy(map_addr32 + dwBufSize32 + sizeof(DWORD) + 12 * sizeof(DWORD64), &fp, sizeof(DWORD64));
}

void exiting() {
	//Close Everything.
	UnmapViewOfFile(map_addr32);
	CloseHandle(fm32);
	fclose(pFile);
}


int main() {
	init();

	while (1) {
		Sleep(0);
	}

	exiting();

	return 0;
}