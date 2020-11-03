#include "call_api.h"
//////////////////////////////////////////////////////////////////////////////
//Hooking Handlers

extern FILE* pFile;

void CallVirtualAllocEx(LPVOID monMMF) {

	Form1^ form = (Form1^)Application::OpenForms[0];

	char* cp = (char*)monMMF;
	char* cp_context = NULL;

	if (pFile != NULL) fprintf(pFile, "%s\n", cp);


	std::string pid(strtok_s(cp, ":", &cp_context));
	form->logging(gcnew System::String(pid.c_str()));
	form->logging(gcnew System::String(" : VirtualAlloc -> Protection : PAGE_EXECUTE_READWRITE\r\n"));

	DWORD64 ret = (DWORD64)strtoll(strtok_s(NULL, ":", &cp_context), NULL, 16);
	DWORD dwSize = (DWORD)strtol(strtok_s(NULL, ":", &cp_context), NULL, 16);

	auto item = rwxList.find(pid);
	if (item != rwxList.end()) {
		item->second.push_back(std::make_pair(ret, dwSize));
	}
	else {
		std::vector<std::pair<DWORD64, DWORD >> ls = { std::make_pair(ret, dwSize) };
		rwxList.insert(std::make_pair(pid, ls));
	}

	memset(monMMF, 0, MSG_SIZE);
	char buf[MSG_SIZE] = "";
	sprintf_s(buf, "%s:%016llx:%08lx:CallVirtualAllocEx:Response Sended!", pid.c_str(), ret, dwSize);
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


	std::string pid(strtok_s(cp, ":", &cp_context));
	form->logging(gcnew System::String(pid.c_str()));

	std::string addr(strtok_s(NULL, ":", &cp_context));
	DWORD64 lpStartAddress = (DWORD64)strtoll(addr.c_str(), NULL, 16);
	DWORD64 lpParameter = (DWORD64)strtoll(strtok_s(NULL, ":", &cp_context), NULL, 16);



	char buf[MSG_SIZE] = "";
	memset(monMMF, 0, MSG_SIZE);
	auto item = rwxList.find(pid);
	if (strncmp(addr.c_str(), "LoadLibraryA", 12) == 0) {
		sprintf_s(buf, "%s:Detected:LoadLibraryA:%016llx:CallCreateRemoteThread", pid.c_str(), lpParameter);
		form->logging(gcnew System::String(" : CreateRemoteThread -> LoadLibraryA DLL Injection Detected!"));
		form->logging(gcnew System::String("\r\n"));
		form->logging(gcnew System::String("\r\n"));
		MessageBoxA(NULL, "CreateRemoteThread DLL Injection with LoadLibrary Detected!", "Detection Alert!", MB_OK | MB_ICONQUESTION);
		memcpy(monMMF, buf, strlen(buf));
		return;
	}
	else if (item != rwxList.end()) {

		for (auto i : item->second) {
			if (i.first <= lpStartAddress && (i.first + (DWORD64)i.second > lpStartAddress)) {
				sprintf_s(buf, "%s:Detected:%016llx:%016llx:CallCreateRemoteThread", pid.c_str(), lpStartAddress, lpParameter);
				form->logging(gcnew System::String(" : CreateRemoteThread -> Code Injection Detected! Addr: "));
				form->logging(gcnew System::String(addr.c_str()));
				form->logging(gcnew System::String("\r\n"));
				form->logging(gcnew System::String("\r\n"));
				MessageBoxA(NULL, "CreateRemoteThread Code Injection Detected!", "Detection Alert!", MB_OK | MB_ICONQUESTION);
				memcpy(monMMF, buf, strlen(buf));
				return;
			}
		}
	}

	sprintf_s(buf, "%s:%016llx:%016llx:CallCreateRemoteThread:Clean", pid.c_str(), lpStartAddress, lpParameter);
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

	sprintf_s(buf, "%s:%016llx:CallSetWindowLongPtrA:Clean", pid.c_str(), target);
	memcpy(monMMF, buf, strlen(buf));
}

void CallNtQueueApcThread(LPVOID monMMF) {

	Form1^ form = (Form1^)Application::OpenForms[0];

	char* cp = (char*)monMMF;
	char* cp_context = NULL;
	//form->logging(gcnew System::String(cp));
	if (pFile != NULL) fprintf(pFile, "%s\n", cp);


	std::string pid(strtok_s(cp, ":", &cp_context));

	DWORD64 target = (DWORD64)strtoll(strtok_s(NULL, ":", &cp_context), NULL, 16);
	char buf[MSG_SIZE] = "";
	memset(monMMF, 0, MSG_SIZE);
	auto item = rwxList.find(pid);
	if (item != rwxList.end()) {
		for (auto i : item->second) {
			if (i.first <= target && (i.first + (DWORD64)i.second > target))
				sprintf_s(buf, "%s:Detected:%016llx:CallNtQueueApcThread", pid.c_str(), target);
			memcpy(monMMF, buf, strlen(buf));
			return;
		}
	}

	sprintf_s(buf, "%s:%016llx:CallNtQueueApcThread:Clean", pid.c_str(), target);
	memcpy(monMMF, buf, strlen(buf));
}

void CallSetWindowLongPtrA(LPVOID monMMF) {

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
				sprintf_s(buf, "%s:Detected:%016llx:CallSetWindowLongPtrA", pid.c_str(), target);
				form->logging(gcnew System::String(pid.c_str()));
				form->logging(gcnew System::String(" : SetWindowLongPtrA -> Code Injection Detected! Addr: "));
				form->logging(gcnew System::String(addr.c_str()));
				form->logging(gcnew System::String("\r\n"));
				form->logging(gcnew System::String("\r\n"));
				MessageBoxA(NULL, "SetWindowLongPtrA Code Injection Detected!", "Detection Alert!", MB_OK | MB_ICONQUESTION);
				memcpy(monMMF, buf, strlen(buf));
				return;
			}

		}
	}

	sprintf_s(buf, "%s:%016llx:CallSetWindowLongPtrA:Clean", pid.c_str(), target);
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

