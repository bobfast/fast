#include "call_api.h"



void exDumpIt() {

	BOOL bShellExecute = FALSE;
	SHELLEXECUTEINFO stShellInfo = { sizeof(SHELLEXECUTEINFO) };
	stShellInfo.lpVerb = TEXT("runas");
	stShellInfo.lpFile = TEXT("DumpIt.exe");
	stShellInfo.nShow = SW_SHOWNORMAL;
	bShellExecute = ShellExecuteEx(&stShellInfo);
	if (!bShellExecute)
		MessageBoxA(NULL, "Executing DumpIt.exe Failed!", "DumpIt.exe Failed.!", MB_OK | MB_ICONQUESTION);

	WaitForSingleObject(stShellInfo.hProcess, INFINITE);
}

void insertList(std::string callee_pid, DWORD64 ret, DWORD dwSize, std::string caller_pid, UCHAR flags ) {
	std::vector<std::tuple<DWORD64, DWORD, std::string, UCHAR >> v = { std::make_tuple(ret, dwSize, caller_pid, flags) };
	auto rwxItem = rwxList.find(callee_pid);
	if (rwxItem != rwxList.end()) {
		rwxItem->second.push_back(v);
	}
	else {
		std::vector<std::vector<std::tuple<DWORD64, DWORD, std::string, UCHAR >>> ls = {v };
		rwxList.insert(std::make_pair(callee_pid, ls));
	}
}

BOOL checkList(std::string callee_pid, DWORD64 target, DWORD dwSize, std::string caller_pid, UCHAR flags) {
	auto item = rwxList.find(callee_pid);
	if (item != rwxList.end()) {

		for (auto i : item->second) {
			if (std::get<0>(i[0]) <= target && (std::get<0>(i[0]) + (DWORD64)(std::get<1>(i[0])) > target)) {
				std::tuple<DWORD64, DWORD, std::string, UCHAR > tp = { std::make_tuple(target, dwSize, caller_pid, flags) };
				i.push_back(tp);
				std::get<3>(i[0]) |= flags;
				Form1^ form = (Form1^)Application::OpenForms[0];
				form->show_detection(callee_pid, i);
				return TRUE;
			}

		}
	}

	return FALSE;
}

// Reference: https://stackoverflow.com/questions/3828835/how-can-we-check-if-a-file-exists-or-not-using-win32-program
int fileExists(TCHAR* file)
{
	WIN32_FIND_DATA FindFileData;
	HANDLE handle = FindFirstFile(file, &FindFileData);
	int found = handle != INVALID_HANDLE_VALUE;
	if (found)
	{
		//FindClose(&handle); this will crash
		FindClose(handle);
	}
	return found;
}

void memory_region_dump(DWORD pid, const char* filename, std::unordered_map<std::string, std::vector<std::vector<std::tuple<DWORD64, DWORD, std::string, UCHAR >>>>& list)
{
	if (list.find(std::to_string(pid)) == list.end()) {
		MessageBoxA(NULL, "Cannot dump memory region...", "Error", MB_OK | MB_ICONERROR);
		return;
	}

	auto recentAlloc = list[std::to_string(pid)].back();
	DWORD recentWrittenBufferSize = std::get<1>(recentAlloc[0]);
	LPVOID recentWrittenBaseAddress = (LPVOID)(std::get<0>(recentAlloc[0]));
	FILE* f = NULL;
	char* buf = NULL, filenameWithBaseAddr[261] = "";
	SIZE_T buflen = 0;
	HANDLE hProcess = NULL;

	do {
		buf = new char[recentWrittenBufferSize];

		if (buf == NULL) {
			printf("Error: cannot allocate buffer for memory region dump.\n");
			break;
		}

		int i = 0;

		while (1) {
			if (i == 0) sprintf_s(filenameWithBaseAddr, "%s_%p.bin", filename, recentWrittenBaseAddress);
			else sprintf_s(filenameWithBaseAddr, "%s_%p_%d.bin", filename, recentWrittenBaseAddress, i);

			if (!fileExists(filenameWithBaseAddr)) {
				break;
			}

			i++;
		}

		fopen_s(&f, filenameWithBaseAddr, "wb");

		if (f == NULL) {
			printf("Error: cannot create file.\n");
			break;
		}

		hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
		if (!hProcess) {
			printf("Error: failed to open target process.\n");
			break;
		}

		if (!ReadProcessMemory(hProcess, recentWrittenBaseAddress, buf, recentWrittenBufferSize, &buflen)) {
			printf("Error: cannot read target process memory for dump.\n");
			break;
		}

		fwrite(buf, 1, buflen, f);

		break;
	} while (1);

	if (buf != NULL) delete[] buf;
	if (hProcess != NULL) CloseHandle(hProcess);
	if (f != NULL) fclose(f);
}




//////////////////////////////////////////////////////////////////////////////
//Hooking Handlers

extern FILE* pFile;

void CallVirtualAllocEx(LPVOID monMMF) {

	Form1^ form = (Form1^)Application::OpenForms[0];

	char* cp = (char*)monMMF;
	char* cp_context = NULL;

	if (pFile != NULL) fprintf(pFile, "%s\n", cp);

	std::string caller_pid(strtok_s(cp, ":", &cp_context));
	std::string callee_pid(strtok_s(NULL, ":", &cp_context));
	form->logging(caller_pid+" : "+ callee_pid+ " : VirtualAllocEx ->Protection : PAGE_EXECUTE_READWRITE\r\n");

	DWORD64 ret = (DWORD64)strtoll(strtok_s(NULL, ":", &cp_context), NULL, 16);
	DWORD dwSize = (DWORD)strtol(strtok_s(NULL, ":", &cp_context), NULL, 16);
	DWORD protect = (DWORD)strtol(strtok_s(NULL, ":", &cp_context), NULL, 16);

	insertList(callee_pid, ret, dwSize, caller_pid, FLAG_VirtualAllocEx );

	memset(monMMF, 0, MSG_SIZE);
	char buf[MSG_SIZE] = "";
	sprintf_s(buf, "%s:%016llx:%08lx:CallVirtualAllocEx:Response Sended!", callee_pid.c_str(), ret, dwSize);
	memcpy(monMMF, buf, strlen(buf));
}

void CallQueueUserAPC(LPVOID monMMF) {

	Form1^ form = (Form1^)Application::OpenForms[0];

	char* cp = (char*)monMMF;
	char* cp_context = NULL;


	if (pFile != NULL) fprintf(pFile, "%s\n", cp);


	std::string pid(strtok_s(cp, ":", &cp_context));

	std::string buf(pid);
	buf.append(":CallQueueUserAPC:Response Sended!");
	memcpy(monMMF, buf.c_str(), buf.size());
}

void CallWriteProcessMemory(LPVOID monMMF) {

	Form1^ form = (Form1^)Application::OpenForms[0];

	char* cp = (char*)monMMF;
	char* cp_context = NULL;


	if (pFile != NULL) fprintf(pFile, "%s\n", cp);


	std::string pid(strtok_s(cp, ":", &cp_context));


	std::string buf(pid);
	buf.append(":CallWriteProcessMemory:Response Sended!");
	memcpy(monMMF, buf.c_str(), buf.size());
}

void CallCreateRemoteThread(LPVOID monMMF) {

	Form1^ form = (Form1^)Application::OpenForms[0];

	char* cp = (char*)monMMF;
	char* cp_context = NULL;

	if (pFile != NULL) fprintf(pFile, "%s\n", cp);


	std::string caller_pid(strtok_s(cp, ":", &cp_context));
	std::string callee_pid(strtok_s(NULL, ":", &cp_context));


	std::string addr(strtok_s(NULL, ":", &cp_context));
	DWORD64 lpStartAddress = (DWORD64)strtoll(addr.c_str(), NULL, 16);
	DWORD64 lpParameter = (DWORD64)strtoll(strtok_s(NULL, ":", &cp_context), NULL, 16);

	char buf[MSG_SIZE] = "";
	memset(monMMF, 0, MSG_SIZE);


	if (strncmp(addr.c_str(), "LoadLibraryA", 12) == 0) {
		sprintf_s(buf, "%s:Detected:LoadLibraryA:%016llx:CallCreateRemoteThread", caller_pid.c_str(), lpParameter);
		do {
			char buf[256] = "", messagePrint[356] = "";
			SIZE_T buflen = 0;

			HANDLE hTargetProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, std::stoi(callee_pid));
			if (!hTargetProcess) {
				printf("Error: failed to open target process.\n");
				break;
			}

			if (!ReadProcessMemory(hTargetProcess, (LPCVOID)lpParameter, buf, 256, &buflen)) {
				printf("Error: cannot read target process memory for dump.\n");
				break;
			}
			
			form->logging(caller_pid + " : " + callee_pid + " : CreateRemoteThread -> LoadLibraryA DLL Injection Detected!\r\n");
			form->logging("DLL File: " + std::string(buf) + "\r\n\r\n");
			sprintf_s(messagePrint, "CreateRemoteThread DLL Injection with LoadLibrary Detected!\nDLL File: %s", buf);
			MessageBoxA(NULL, messagePrint, "Detection Alert!", MB_OK | MB_ICONQUESTION);

			break;
		} while (1);

		memcpy(monMMF, buf, strlen(buf));
		return;
	}
	else if (checkList(callee_pid, lpStartAddress, NULL, caller_pid, FLAG_CreateRemoteThread)) {

		sprintf_s(buf, "%s:Detected:%016llx:%016llx:CallCreateRemoteThread", caller_pid.c_str(), lpStartAddress, lpParameter);

		form->logging(caller_pid + " : " + callee_pid + " : CreateRemoteThread -> Code Injection Detected! Addr:"+ addr+"\r\n\r\n");

		if (MessageBoxA(NULL, "CreateRemoteThread Code Injection Detected! Are you want to Dumpit?", "Detection Alert!", MB_YESNO | MB_ICONQUESTION) == IDYES) {
			exDumpIt();
		}
		memory_region_dump(std::stoi(callee_pid), "MemoryRegionDump_CodeInjection", rwxList);
		memcpy(monMMF, buf, strlen(buf));
		return;
	}

	sprintf_s(buf, "%s:%016llx:%016llx:CallCreateRemoteThread:Clean", callee_pid.c_str(), lpStartAddress, lpParameter);
	memcpy(monMMF, buf, strlen(buf));

}

void CallNtMapViewOfSection(LPVOID monMMF) {


	Form1^ form = (Form1^)Application::OpenForms[0];

	char* cp = (char*)monMMF;
	char* cp_context = NULL;

	if (pFile != NULL) fprintf(pFile, "%s\n", cp);

	std::string caller_pid(strtok_s(cp, ":", &cp_context));
	std::string callee_pid(strtok_s(NULL, ":", &cp_context));


	form->logging(caller_pid + " : " + callee_pid + " : NtMapViewOfSection ->Protection : PAGE_EXECUTE_READWRITE\r\n");

	DWORD64 ret = (DWORD64)strtoll(strtok_s(NULL, ":", &cp_context), NULL, 16);
	DWORD dwSize = (DWORD)strtol(strtok_s(NULL, ":", &cp_context), NULL, 16);
	DWORD protect = (DWORD)strtol(strtok_s(NULL, ":", &cp_context), NULL, 16);

	insertList(callee_pid, ret, dwSize, caller_pid, FLAG_NtMapViewOfSection);

	memset(monMMF, 0, MSG_SIZE);
	char buf[MSG_SIZE] = "";
	sprintf_s(buf, "%s:%016llx:%08lx:CallNtMapViewOfSection:Response Sended!", callee_pid.c_str(), ret, dwSize);
	memcpy(monMMF, buf, strlen(buf));
}

void CallCreateFileMappingA(LPVOID monMMF) {
	Form1^ form = (Form1^)Application::OpenForms[0];

	char* cp = (char*)monMMF;
	char* cp_context = NULL;

	if (pFile != NULL) fprintf(pFile, "%s\n", cp);


	std::string pid(strtok_s(cp, ":", &cp_context));


	std::string buf(pid);
	buf.append(":CallCreateFileMappingA:Response Sended!");
	memcpy(monMMF, buf.c_str(), buf.size());
}

void CallGetThreadContext(LPVOID monMMF) {
	Form1^ form = (Form1^)Application::OpenForms[0];

	char* cp = (char*)monMMF;
	char* cp_context = NULL;

	if (pFile != NULL) fprintf(pFile, "%s\n", cp);


	std::string pid(strtok_s(cp, ":", &cp_context));


	std::string buf(pid);
	buf.append(":CallGetThreadContext:Response Sended!");
	memcpy(monMMF, buf.c_str(), buf.size());
}

void CallSetThreadContext(LPVOID monMMF) {

	Form1^ form = (Form1^)Application::OpenForms[0];
	
	char* cp = (char*)monMMF;
	char* cp_context = NULL;

	if (pFile != NULL) fprintf(pFile, "%s\n", cp);


	std::string caller_pid(strtok_s(cp, ":", &cp_context));
	std::string callee_pid(strtok_s(NULL, ":", &cp_context));
	std::string addr(strtok_s(NULL, ":", &cp_context));
	DWORD64 lpStartAddress = (DWORD64)strtoll(addr.c_str(), NULL, 16);

	char buf[MSG_SIZE] = "";
	memset(monMMF, 0, MSG_SIZE);

	if (checkList(callee_pid, lpStartAddress, NULL, caller_pid, FLAG_SetThreadContext)) {
		sprintf_s(buf, "%s:Detected:%016llx:CallSetThreadContext", callee_pid.c_str(), lpStartAddress);
		form->logging(callee_pid+" : "+ caller_pid +" : SetThreadContext -> Thread Hijacking Detected! Addr: "+ addr+"\r\n\r\n");
		MessageBoxA(NULL, "SetThreadContext Thread Hijacking Detected!", "Detection Alert!", MB_OK | MB_ICONQUESTION);
		memcpy(monMMF, buf, strlen(buf));
		return;
	}

	sprintf_s(buf, "%s:%016llx:CallSetThreadContext:Clean", callee_pid.c_str(), lpStartAddress);
	memcpy(monMMF, buf, strlen(buf));
}

void CallNtQueueApcThread(LPVOID monMMF) {

	Form1^ form = (Form1^)Application::OpenForms[0];

	char* cp = (char*)monMMF;
	char* cp_context = NULL;

	if (pFile != NULL) fprintf(pFile, "%s\n", cp);

	std::string caller_pid(strtok_s(cp, ":", &cp_context));
	std::string callee_pid(strtok_s(NULL, ":", &cp_context));
	std::string apc_routine(strtok_s(NULL, ":", &cp_context));

	char buf[MSG_SIZE] = "";
	memset(monMMF, 0, MSG_SIZE);

	if (apc_routine.compare("GlobalGetAtomNameA") == 0) {
		sprintf_s(buf, "%s:Detected:GlobalGetAtomNameA:CallNtQueueApcThread", callee_pid.c_str());

		form->logging(" : NtQueueApcThread -> GlobalGetAtomNameA Detected!\r\n");

		//MessageBoxA(NULL, "NtQueueApcThread - GlobalGetAtomNameA Detected!", "Detection Alert!", MB_OK | MB_ICONQUESTION);
		//memory_region_dump(std::stoi(callee_pid), "MemoryRegionDump_NtQueueApcThread_GlobalGetAtomNameA", rwxList);
		memcpy(monMMF, buf, strlen(buf));
		return;
	}
	else {
		DWORD64 target = (DWORD64)strtoll(apc_routine.c_str(), NULL, 16);
		if (checkList(callee_pid, target, NULL, caller_pid, FLAG_NtQueueApcThread )) {
					sprintf_s(buf, "%s:Detected:%016llx:CallNtQueueApcThread", callee_pid.c_str(), target);

					form->logging(" : NtQueueApcThread -> Code Injection Detected!\r\n\r\n");

					MessageBoxA(NULL, "NtQueueApcThread Code Injection Detected!", "Detection Alert!", MB_OK | MB_ICONQUESTION);
					memory_region_dump(std::stoi(callee_pid), "MemoryRegionDump_NtQueueApcThread", rwxList);
					memcpy(monMMF, buf, strlen(buf));
					return;
			
		}
	}

	sprintf_s(buf, "%s:%s:CallNtQueueApcThread:Clean", callee_pid.c_str(), apc_routine.c_str());
	memcpy(monMMF, buf, strlen(buf));
}

void CallSetWindowLongPtrA(LPVOID monMMF) {

	Form1^ form = (Form1^)Application::OpenForms[0];

	char* cp = (char*)monMMF;
	char* cp_context = NULL;

	if (pFile != NULL) fprintf(pFile, "%s\n", cp);


	std::string caller_pid(strtok_s(cp, ":", &cp_context));
	std::string callee_pid(strtok_s(NULL, ":", &cp_context));

	std::string addr(strtok_s(NULL, ":", &cp_context));
	DWORD64 lpStartAddress = (DWORD64)strtoll(addr.c_str(), NULL, 16);

	char buf[MSG_SIZE] = "";
	memset(monMMF, 0, MSG_SIZE);


	if (checkList(callee_pid, lpStartAddress, NULL, caller_pid, FLAG_SetWindowLongPtrA)) {
				sprintf_s(buf, "%s:Detected:%016llx:CallSetWindowLongPtrA", callee_pid.c_str(), lpStartAddress);
				form->logging(caller_pid+" : "+ callee_pid +" : SetWindowLongPtrA -> Code Injection Detected! Addr: "+ addr +"\r\n\r\n");
				MessageBoxA(NULL, "SetWindowLongPtrA Code Injection Detected!", "Detection Alert!", MB_OK | MB_ICONQUESTION);
				memory_region_dump(std::stoi(callee_pid), "MemoryRegionDump_SetWindowLongPtrA", rwxList);
				memcpy(monMMF, buf, strlen(buf));
				return;
			
	}

	sprintf_s(buf, "%s:%016llx:CallSetWindowLongPtrA:Clean", callee_pid.c_str(), lpStartAddress);
	memcpy(monMMF, buf, strlen(buf));

}


void CallSetPropA(LPVOID monMMF) {

	Form1^ form = (Form1^)Application::OpenForms[0];

	char* cp = (char*)monMMF;
	char* cp_context = NULL;

	if (pFile != NULL) fprintf(pFile, "%s\n", cp);


	std::string caller_pid(strtok_s(cp, ":", &cp_context));
	std::string callee_pid(strtok_s(NULL, ":", &cp_context));

	std::string addr(strtok_s(NULL, ":", &cp_context));
	DWORD64 lpStartAddress = (DWORD64)strtoll(addr.c_str(), NULL, 16);

	char buf[MSG_SIZE] = "";
	memset(monMMF, 0, MSG_SIZE);



	if (checkList(callee_pid, lpStartAddress, NULL, caller_pid, FLAG_SetPropA)) {
				sprintf_s(buf, "%s:Detected:%016llx:CallSetPropA", callee_pid.c_str(), lpStartAddress);
				form->logging(caller_pid +" : "+ callee_pid+" : SetPropA -> Code Injection Detected! Addr: "+ addr+"\r\n\r\n");
				MessageBoxA(NULL, "CallSetPropA Code Injection Detected!", "Detection Alert!", MB_OK | MB_ICONQUESTION);
				memcpy(monMMF, buf, strlen(buf));
				return;
	}

	sprintf_s(buf, "%s:%016llx:CallSetPropA:Clean", callee_pid.c_str(), lpStartAddress);
	memcpy(monMMF, buf, strlen(buf));
}

void CallVirtualProtectEx(LPVOID monMMF) {

	Form1^ form = (Form1^)Application::OpenForms[0];

	char* cp = (char*)monMMF;
	char* cp_context = NULL;

	if (pFile != NULL) fprintf(pFile, "%s\n", cp);

	std::string caller_pid(strtok_s(cp, ":", &cp_context));
	std::string callee_pid(strtok_s(NULL, ":", &cp_context));

	form->logging(caller_pid + " : " + callee_pid + " : VirtualProtectEx ->Protection : PAGE_EXECUTE_READWRITE\r\n");

	DWORD64 ret = (DWORD64)strtoll(strtok_s(NULL, ":", &cp_context), NULL, 16);
	DWORD dwSize = (DWORD)strtol(strtok_s(NULL, ":", &cp_context), NULL, 16);
	DWORD protect = (DWORD)strtol(strtok_s(NULL, ":", &cp_context), NULL, 16);


	insertList(callee_pid, ret, dwSize, caller_pid, (UCHAR)0b00000100);


	memset(monMMF, 0, MSG_SIZE);
	char buf[MSG_SIZE] = "";
	sprintf_s(buf, "%s:%016llx:%08lx:CallVirtualProtectEx:Response Sended!", callee_pid.c_str(), ret, dwSize);
	memcpy(monMMF, buf, strlen(buf));
}


void CallSleepEx(LPVOID monMMF) {

	Form1^ form = (Form1^)Application::OpenForms[0];

	char* cp = (char*)monMMF;
	char* cp_context = NULL;

	if (pFile != NULL) fprintf(pFile, "%s\n", cp);


	std::string pid(strtok_s(cp, ":", &cp_context));

	if (pFile != NULL) fprintf(pFile, "%s\n", (char*)monMMF);
	std::string buf(pid);
	buf.append(":CallSleepEx:Response Sended!");
	memcpy(monMMF, buf.c_str(), buf.size());
}

