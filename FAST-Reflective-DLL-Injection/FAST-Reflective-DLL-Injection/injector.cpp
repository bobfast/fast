#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>
#include "LoadLibraryR.h"

int main(int argc, char *argv[])
{
	HANDLE hFile = NULL;
	HANDLE hModule = NULL;
	HANDLE hProcess = NULL;
	HANDLE hToken = NULL;
	DWORD dwProcessId = 0;
	DWORD dwLength = 0;
	LPVOID lpBuffer = NULL;
	TOKEN_PRIVILEGES priv = { 0 };

	FILE* fp = NULL;

	if (argc != 5) {
		printf("usage: %s <injection_method> <dll> <exported_function_name> <pid>\n", argv[0]);
		printf("<exported_function_name>: Exported function name in DLL (function using __declspec(dllexport))\n");
		printf("\ninjection_method list (kind of LoadRemoteLibraryR):\n");
		printf("1. it uses CreateRemoteThread, VirtualAllocEx and WriteProcessMemory.\n");
		printf("2. it uses CreateRemoteThread, CreateFileMappingA, MapViewOfFile and PNtMapViewOfSection.\n");
		return 0;
	}

	int method = atoi(argv[1]);
	const char* cpDllFile = argv[2], * exportedFuncName = argv[3];
	dwProcessId = atoi(argv[4]);

	fopen_s(&fp, cpDllFile, "rb");
	if (fp == NULL) {
		printf("Error: file not found.\n");
		return 1;
	}

	fseek(fp, 0L, SEEK_END);
	dwLength = ftell(fp);
	fseek(fp, 0L, SEEK_SET);

	lpBuffer = malloc(dwLength);
	if (lpBuffer == NULL) {
		printf("Error: cannot allocate heap.\n");
		return 1;
	}

	fread(lpBuffer, 1, dwLength, fp);
	fclose(fp);

	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
	{
		priv.PrivilegeCount = 1;
		priv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

		if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &priv.Privileges[0].Luid))
		{
			AdjustTokenPrivileges(hToken, FALSE, &priv, 0, NULL, NULL);
		}

		CloseHandle(hToken);
	}

	hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, dwProcessId);
	if (hProcess == NULL) {
		printf("Error: cannot open the target process.\n");
		return 1;
	}

	// using various method for alternative LoadLibrary API
	switch (method) {
	case 1:
		hModule = LoadRemoteLibraryR(hProcess, lpBuffer, dwLength, NULL, exportedFuncName);
		break;
	case 2:
		hModule = LoadRemoteLibraryR2(hProcess, lpBuffer, dwLength, NULL, exportedFuncName);
		break;
	}

	if (hModule == NULL) {
		printf("Error: cannot inject %s DLL file.\n", cpDllFile);
		return 1;
	}

	printf("Injected the %s DLL into process %d.\n", cpDllFile, dwProcessId);
	WaitForSingleObject(hModule, -1);

	if (lpBuffer)
		free(lpBuffer);
	
	if (hProcess)
		CloseHandle(hProcess);

	return 0;
}