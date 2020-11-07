#include "call_api.h"

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

void memory_region_dump(DWORD pid, const char* filename, std::unordered_map<std::string, std::vector<std::pair<DWORD64, DWORD>>>& list)
{
	if (list.find(std::to_string(pid)) == list.end()) {
		MessageBoxA(NULL, "Cannot dump memory region...", "Error", MB_OK | MB_ICONERROR);
		return;
	}

	auto recentAlloc = list[std::to_string(pid)].back();
	DWORD recentWrittenBufferSize = recentAlloc.second;
	LPVOID recentWrittenBaseAddress = (LPVOID)(recentAlloc.first);
	FILE *f;
	char *buf, filenameWithBaseAddr[261];
	SIZE_T buflen;
	HANDLE hProcess;

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
	form->logging(gcnew System::String(caller_pid.c_str()));
	form->logging(gcnew System::String(" : "));
	form->logging(gcnew System::String(callee_pid.c_str()));
	form->logging(gcnew System::String(" : VirtualAlloc"));

	DWORD64 ret = (DWORD64)strtoll(strtok_s(NULL, ":", &cp_context), NULL, 16);
	DWORD dwSize = (DWORD)strtol(strtok_s(NULL, ":", &cp_context), NULL, 16);
	DWORD protect = (DWORD)strtol(strtok_s(NULL, ":", &cp_context), NULL, 16);

	switch (protect) {

	case PAGE_EXECUTE_READWRITE:
		form->logging(gcnew System::String(" -> Protection : PAGE_EXECUTE_READWRITE"));
	case PAGE_EXECUTE_WRITECOPY:
		form->logging(gcnew System::String(" + WRITECOPY"));

		{ // code block - RWX list
			auto rwxItem = rwxList.find(callee_pid);
			if (rwxItem != rwxList.end()) {
				rwxItem->second.push_back(std::make_pair(ret, dwSize));
			}
			else {
				std::vector<std::pair<DWORD64, DWORD >> ls = { std::make_pair(ret, dwSize) };
				rwxList.insert(std::make_pair(callee_pid, ls));
			}
		}
		
		form->logging(gcnew System::String("\r\n"));
		break;

	case PAGE_READWRITE:
		form->logging(gcnew System::String(" -> Protection : PAGE_READWRITE"));

		{ // code block - RW list
			auto rwItem = rwList.find(callee_pid);
			if (rwItem != rwList.end()) {
				rwItem->second.push_back(std::make_pair(ret, dwSize));
			}
			else {
				std::vector<std::pair<DWORD64, DWORD >> ls = { std::make_pair(ret, dwSize) };
				rwList.insert(std::make_pair(callee_pid, ls));
			}
		}

		form->logging(gcnew System::String("\r\n"));
		break;
	}

	memset(monMMF, 0, MSG_SIZE);
	char buf[MSG_SIZE] = "";
	sprintf_s(buf, "%s:%016llx:%08lx:CallVirtualAllocEx:Response Sended!", caller_pid.c_str(), ret, dwSize);
	memcpy(monMMF, buf, strlen(buf));
}

void CallQueueUserAPC(LPVOID monMMF) {

	Form1^ form = (Form1^)Application::OpenForms[0];

	char* cp = (char*)monMMF;
	char* cp_context = NULL;

	//form->logging(gcnew System::String(cp));
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

	//form->logging(gcnew System::String(cp));
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
	form->logging(gcnew System::String(caller_pid.c_str()));
	form->logging(gcnew System::String(" : "));
	form->logging(gcnew System::String(callee_pid.c_str()));

	std::string addr(strtok_s(NULL, ":", &cp_context));
	DWORD64 lpStartAddress = (DWORD64)strtoll(addr.c_str(), NULL, 16);
	DWORD64 lpParameter = (DWORD64)strtoll(strtok_s(NULL, ":", &cp_context), NULL, 16);



	char buf[MSG_SIZE] = "";
	memset(monMMF, 0, MSG_SIZE);
	
	auto rwxItem = rwxList.find(callee_pid);

	if (strncmp(addr.c_str(), "LoadLibraryA", 12) == 0) {
		sprintf_s(buf, "%s:Detected:LoadLibraryA:%016llx:CallCreateRemoteThread", caller_pid.c_str(), lpParameter);
		form->logging(gcnew System::String(" : CreateRemoteThread -> LoadLibraryA DLL Injection Detected!"));
		form->logging(gcnew System::String("\r\n"));
		form->logging(gcnew System::String("\r\n"));
		MessageBoxA(NULL, "CreateRemoteThread DLL Injection with LoadLibrary Detected!", "Detection Alert!", MB_OK | MB_ICONQUESTION);
		memory_region_dump(std::stoi(callee_pid), "MemoryRegionDump_LoadLibrary", rwList);
		memcpy(monMMF, buf, strlen(buf));
		return;
	}

	else if (rwxItem != rwxList.end()) {

		for (auto i : rwxItem->second) {
			if (i.first <= lpStartAddress && (i.first + (DWORD64)i.second > lpStartAddress)) {
				sprintf_s(buf, "%s:Detected:%016llx:%016llx:CallCreateRemoteThread", caller_pid.c_str(), lpStartAddress, lpParameter);
				form->logging(gcnew System::String(" : CreateRemoteThread -> Code Injection Detected! Addr: "));
				form->logging(gcnew System::String(addr.c_str()));
				form->logging(gcnew System::String("\r\n"));
				form->logging(gcnew System::String("\r\n"));
				MessageBoxA(NULL, "CreateRemoteThread Code Injection Detected!", "Detection Alert!", MB_OK | MB_ICONQUESTION);
				memory_region_dump(std::stoi(callee_pid), "MemoryRegionDump_CodeInjection", rwxList);
				memcpy(monMMF, buf, strlen(buf));
				return;
			}
		}
	}

	sprintf_s(buf, "%s:%016llx:%016llx:CallCreateRemoteThread:Clean", caller_pid.c_str(), lpStartAddress, lpParameter);
	memcpy(monMMF, buf, strlen(buf));

}

void CallNtMapViewOfSection(LPVOID monMMF) {

	Form1^ form = (Form1^)Application::OpenForms[0];

	char* cp = (char*)monMMF;
	char* cp_context = NULL;
	//form->logging(gcnew System::String(cp));
	if (pFile != NULL) fprintf(pFile, "%s\n", cp);


	std::string pid(strtok_s(cp, ":", &cp_context));

	form->logging(gcnew System::String(pid.c_str()));
	form->logging(gcnew System::String(" : NtMapViewOfSection -> Protection : PAGE_EXECUTE_READWRITE\r\n"));


	DWORD64 BaseAddress = (DWORD64)strtoll(strtok_s(NULL, ":", &cp_context), NULL, 16);
	DWORD CommitSize = (DWORD)strtol(strtok_s(NULL, ":", &cp_context), NULL, 16);
	if (pFile != NULL) fprintf(pFile, "%llu\n", BaseAddress);

	auto item = rwxList.find(pid);
	if (item != rwxList.end()) {
		item->second.push_back(std::make_pair(BaseAddress, CommitSize));
	}
	else {
		std::vector<std::pair<DWORD64, DWORD >> ls = { std::make_pair(BaseAddress, CommitSize) };
		rwxList.insert(std::make_pair(pid, ls));
	}

	memset(monMMF, 0, MSG_SIZE);
	char buf[MSG_SIZE] = "";
	sprintf_s(buf, "%s:%016llx:%08lx:CallNtMapViewOfSection:Response Sended!", pid.c_str(), BaseAddress, CommitSize);
	memcpy(monMMF, buf, strlen(buf));
}

void CallCreateFileMappingA(LPVOID monMMF) {
	Form1^ form = (Form1^)Application::OpenForms[0];

	char* cp = (char*)monMMF;
	char* cp_context = NULL;
	//form->logging(gcnew System::String(cp));
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
	//form->logging(gcnew System::String(cp));
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
	//form->logging(gcnew System::String(cp));
	if (pFile != NULL) fprintf(pFile, "%s\n", cp);


	std::string pid(strtok_s(cp, ":", &cp_context));



	std::string addr(strtok_s(NULL, ":", &cp_context));
	DWORD64 target = (DWORD64)strtoll(addr.c_str(), NULL, 16);
	char buf[MSG_SIZE] = "";
	memset(monMMF, 0, MSG_SIZE);
	auto item = rwxList.find(pid);
	if (item != rwxList.end()) {

		for (auto i : item->second) {
			if (i.first <= target && (i.first + (DWORD64)i.second > target)) {
				sprintf_s(buf, "%s:Detected:%016llx:CallSetThreadContext", pid.c_str(), target);
				form->logging(gcnew System::String(pid.c_str()));
				form->logging(gcnew System::String(" : SetThreadContext -> Thread Hijacking Detected! Addr: "));
				form->logging(gcnew System::String(addr.c_str()));
				form->logging(gcnew System::String("\r\n"));
				form->logging(gcnew System::String("\r\n"));
				MessageBoxA(NULL, "SetThreadContext Thread Hijacking Detected!", "Detection Alert!", MB_OK | MB_ICONQUESTION);
				memcpy(monMMF, buf, strlen(buf));
				return;
			}

		}
	}

	sprintf_s(buf, "%s:%016llx:CallSetThreadContext:Clean", pid.c_str(), target);
	memcpy(monMMF, buf, strlen(buf));
}

void CallNtQueueApcThread(LPVOID monMMF) {

	Form1^ form = (Form1^)Application::OpenForms[0];

	char* cp = (char*)monMMF;
	char* cp_context = NULL;
	//form->logging(gcnew System::String(cp));
	if (pFile != NULL) fprintf(pFile, "%s\n", cp);

	std::string caller_pid(strtok_s(cp, ":", &cp_context));
	std::string callee_pid(strtok_s(NULL, ":", &cp_context));
	std::string apc_routine(strtok_s(NULL, ":", &cp_context));

	char buf[MSG_SIZE] = "";
	memset(monMMF, 0, MSG_SIZE);

	if (apc_routine.compare("GlobalGetAtomNameA") == 0) {
		sprintf_s(buf, "%s:Detected:GlobalGetAtomNameA:CallNtQueueApcThread", caller_pid.c_str());
		form->logging(gcnew System::String(caller_pid.c_str()));
		form->logging(gcnew System::String(" : "));
		form->logging(gcnew System::String(callee_pid.c_str()));
		form->logging(gcnew System::String(" : NtQueueApcThread -> GlobalGetAtomNameA Detected!"));
		form->logging(gcnew System::String(""));
		form->logging(gcnew System::String("\r\n"));
		//MessageBoxA(NULL, "NtQueueApcThread - GlobalGetAtomNameA Detected!", "Detection Alert!", MB_OK | MB_ICONQUESTION);
		//memory_region_dump(std::stoi(callee_pid), "MemoryRegionDump_NtQueueApcThread_GlobalGetAtomNameA", rwxList);
		memcpy(monMMF, buf, strlen(buf));
		return;
	} else {
		DWORD64 target = (DWORD64)strtoll(apc_routine.c_str(), NULL, 16);
		auto item = rwxList.find(callee_pid);
		if (item != rwxList.end()) {
			for (auto i : item->second) {
				if (i.first <= target && (i.first + (DWORD64)i.second > target)) {
					sprintf_s(buf, "%s:Detected:%016llx:CallNtQueueApcThread", caller_pid.c_str(), target);
					form->logging(gcnew System::String(caller_pid.c_str()));
					form->logging(gcnew System::String(" : "));
					form->logging(gcnew System::String(callee_pid.c_str()));
					form->logging(gcnew System::String(" : NtQueueApcThread -> Code Injection Detected!"));
					form->logging(gcnew System::String("\r\n"));
					form->logging(gcnew System::String("\r\n"));
					MessageBoxA(NULL, "NtQueueApcThread Code Injection Detected!", "Detection Alert!", MB_OK | MB_ICONQUESTION);
					memory_region_dump(std::stoi(callee_pid), "MemoryRegionDump_NtQueueApcThread", rwxList);
					memcpy(monMMF, buf, strlen(buf));
					return;
				}
			}
		}
	}

	sprintf_s(buf, "%s:%s:CallNtQueueApcThread:Clean", caller_pid.c_str(), apc_routine.c_str());
	memcpy(monMMF, buf, strlen(buf));
}

void CallSetWindowLongPtrA(LPVOID monMMF) {

	Form1^ form = (Form1^)Application::OpenForms[0];

	char* cp = (char*)monMMF;
	char* cp_context = NULL;
	//form->logging(gcnew System::String(cp));
	if (pFile != NULL) fprintf(pFile, "%s\n", cp);

	std::string caller_pid(strtok_s(cp, ":", &cp_context));
	std::string callee_pid(strtok_s(NULL, ":", &cp_context));

	std::string addr(strtok_s(NULL, ":", &cp_context));
	DWORD64 target = (DWORD64)strtoll(addr.c_str(), NULL, 16);
	char buf[MSG_SIZE] = "";
	memset(monMMF, 0, MSG_SIZE);
	auto item = rwxList.find(callee_pid);
	if (item != rwxList.end()) {

		for (auto i : item->second) {
			if (i.first <= target && (i.first + (DWORD64)i.second > target)) {
				sprintf_s(buf, "%s:Detected:%016llx:CallSetWindowLongPtrA", caller_pid.c_str(), target);
				form->logging(gcnew System::String(caller_pid.c_str()));
				form->logging(gcnew System::String(" : "));
				form->logging(gcnew System::String(callee_pid.c_str()));
				form->logging(gcnew System::String(" : SetWindowLongPtrA -> Code Injection Detected! Addr: "));
				form->logging(gcnew System::String(addr.c_str()));
				form->logging(gcnew System::String("\r\n"));
				form->logging(gcnew System::String("\r\n"));
				MessageBoxA(NULL, "SetWindowLongPtrA Code Injection Detected!", "Detection Alert!", MB_OK | MB_ICONQUESTION);
				memory_region_dump(std::stoi(callee_pid), "MemoryRegionDump_SetWindowLongPtrA", rwxList);
				memcpy(monMMF, buf, strlen(buf));
				return;
			}
		}
	}

	sprintf_s(buf, "%s:%016llx:CallSetWindowLongPtrA:Clean", caller_pid.c_str(), target);
	memcpy(monMMF, buf, strlen(buf));

}


void CallSetPropA(LPVOID monMMF) {

	Form1^ form = (Form1^)Application::OpenForms[0];

	char* cp = (char*)monMMF;
	char* cp_context = NULL;
	//form->logging(gcnew System::String(cp));
	if (pFile != NULL) fprintf(pFile, "%s\n", cp);


	std::string pid(strtok_s(cp, ":", &cp_context));



	std::string addr(strtok_s(NULL, ":", &cp_context));
	DWORD64 target = (DWORD64)strtoll(addr.c_str(), NULL, 16);
	char buf[MSG_SIZE] = "";
	memset(monMMF, 0, MSG_SIZE);
	auto item = rwxList.find(pid);
	if (item != rwxList.end()) {

		for (auto i : item->second) {
			if (i.first <= target && (i.first + (DWORD64)i.second > target)) {
				sprintf_s(buf, "%s:Detected:%016llx:CallSetPropA", pid.c_str(), target);
				form->logging(gcnew System::String(pid.c_str()));
				form->logging(gcnew System::String(" : SetPropA -> Code Injection Detected! Addr: "));
				form->logging(gcnew System::String(addr.c_str()));
				form->logging(gcnew System::String("\r\n"));
				form->logging(gcnew System::String("\r\n"));
				MessageBoxA(NULL, "CallSetPropA Code Injection Detected!", "Detection Alert!", MB_OK | MB_ICONQUESTION);
				memcpy(monMMF, buf, strlen(buf));
				return;
			}

		}
	}

	sprintf_s(buf, "%s:%016llx:CallSetPropA:Clean", pid.c_str(), target);
	memcpy(monMMF, buf, strlen(buf));
}

void CallSleepEx(LPVOID monMMF) {

	Form1^ form = (Form1^)Application::OpenForms[0];

	char* cp = (char*)monMMF;
	char* cp_context = NULL;
	//form->logging(gcnew System::String(cp));
	if (pFile != NULL) fprintf(pFile, "%s\n", cp);


	std::string pid(strtok_s(cp, ":", &cp_context));

	if (pFile != NULL) fprintf(pFile, "%s\n", (char*)monMMF);
	std::string buf(pid);
	buf.append(":CallSleepEx:Response Sended!");
	memcpy(monMMF, buf.c_str(), buf.size());
}

