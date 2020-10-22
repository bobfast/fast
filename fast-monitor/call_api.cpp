#include "call_api.h"

void CallVirtualAllocEx(LPVOID monMMF) {

	Form1^ form = (Form1^)Application::OpenForms[0];

	char* cp = (char*)monMMF;

	fprintf(pFile, "%s\n", cp);


	std::string pid(strtok(cp, ":"));
	form->logging(gcnew System::String(pid.c_str()));
	form->logging(gcnew System::String(" : VirtualAlloc -> Protection : PAGE_EXECUTE_READWRITE\r\n"));

	DWORD64 ret = (DWORD64)strtoll(strtok(NULL, ":"), NULL, 16);
	DWORD dwSize = (DWORD)strtol(strtok(NULL, ":"), NULL, 16);

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
	sprintf_s(buf, "%s:%016x:%08x:CallVirtualAllocEx:Response Sended!", pid, ret, dwSize);
	memcpy(monMMF, buf, strlen(buf));
}

void CallQueueUserAPC(LPVOID monMMF) {

	Form1^ form = (Form1^)Application::OpenForms[0];

	char* cp = (char*)monMMF;
	//form->logging(gcnew System::String(cp));
	fprintf(pFile, "%s\n", cp);


	std::string pid(strtok(cp, ":"));

	std::string buf(pid);
	buf.append(":CallQueueUserAPC:Response Sended!");
	memcpy(monMMF, buf.c_str(), buf.size());
}

void CallWriteProcessMemory(LPVOID monMMF) {

	Form1^ form = (Form1^)Application::OpenForms[0];

	char* cp = (char*)monMMF;
	//form->logging(gcnew System::String(cp));
	fprintf(pFile, "%s\n", cp);


	std::string pid(strtok(cp, ":"));


	std::string buf(pid);
	buf.append(":CallWriteProcessMemory:Response Sended!");
	memcpy(monMMF, buf.c_str(), buf.size());
}

void CallCreateRemoteThread(LPVOID monMMF) {

	Form1^ form = (Form1^)Application::OpenForms[0];

	char* cp = (char*)monMMF;

	fprintf(pFile, "%s\n", cp);


	std::string pid(strtok(cp, ":"));
	form->logging(gcnew System::String(pid.c_str()));

	std::string addr(strtok(NULL, ":"));
	DWORD64 lpStartAddress = (DWORD64)strtoll(addr.c_str(), NULL, 16);
	DWORD64 lpParameter = (DWORD64)strtoll(strtok(NULL, ":"), NULL, 16);



	char buf[MSG_SIZE] = "";
	memset(monMMF, 0, MSG_SIZE);
	auto item = rwxList.find(pid);
	if (strncmp(addr.c_str(), "LoadLibraryA", 12) == 0) {
		sprintf_s(buf, "%s:Detected:LoadLibraryA:%016x:CallCreateRemoteThread", pid, lpParameter);
		form->logging(gcnew System::String(" : CreateRemoteThread -> LoadLibraryA DLL Injection Detected!"));
		form->logging(gcnew System::String("\r\n"));
		form->logging(gcnew System::String("\r\n"));
		MessageBoxA(NULL, "CreateRemoteThread DLL Injection with LoadLibrary Detected!", "Detection Alert!", MB_OK | MB_ICONQUESTION);
		memcpy(monMMF, buf, strlen(buf));
		return;
	}
	else if (item != rwxList.end()) {

		for (auto i : item->second) {
			if (i.first <= lpStartAddress && (i.first + (DWORD64)i.second > lpStartAddress))
				sprintf_s(buf, "%s:Detected:%016x:%016x:CallCreateRemoteThread", pid, lpStartAddress, lpParameter);
			form->logging(gcnew System::String(" : CreateRemoteThread -> Code Injection Detected! Addr: "));
			form->logging(gcnew System::String(addr.c_str()));
			form->logging(gcnew System::String("\r\n"));
			form->logging(gcnew System::String("\r\n"));
			MessageBoxA(NULL, "CreateRemoteThread Code Injection Detected!", "Detection Alert!", MB_OK | MB_ICONQUESTION);
			memcpy(monMMF, buf, strlen(buf));
			return;
		}
	}

	sprintf_s(buf, "%s:%016x:%016x:CallCreateRemoteThread:Clean", pid, lpStartAddress, lpParameter);
	memcpy(monMMF, buf, strlen(buf));

}

void CallNtMapViewOfSection(LPVOID monMMF) {

	Form1^ form = (Form1^)Application::OpenForms[0];

	char* cp = (char*)monMMF;
	//form->logging(gcnew System::String(cp));
	fprintf(pFile, "%s\n", cp);


	std::string pid(strtok(cp, ":"));

	form->logging(gcnew System::String(pid.c_str()));
	form->logging(gcnew System::String(" : NtMapViewOfSection -> Protection : PAGE_EXECUTE_READWRITE\r\n"));


	DWORD64 BaseAddress = (DWORD64)strtoll(strtok(NULL, ":"), NULL, 16);
	DWORD CommitSize = (DWORD)strtol(strtok(NULL, ":"), NULL, 16);
	fprintf(pFile, "%lu\n", BaseAddress);

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
	sprintf_s(buf, "%s:%016x:%08x:CallNtMapViewOfSection:Response Sended!", pid, BaseAddress, CommitSize);
	memcpy(monMMF, buf, strlen(buf));
}

void CallCreateFileMappingA(LPVOID monMMF) {
	Form1^ form = (Form1^)Application::OpenForms[0];

	char* cp = (char*)monMMF;
	//form->logging(gcnew System::String(cp));
	fprintf(pFile, "%s\n", cp);


	std::string pid(strtok(cp, ":"));


	std::string buf(pid);
	buf.append(":CallCreateFileMappingA:Response Sended!");
	memcpy(monMMF, buf.c_str(), buf.size());
}

void CallGetThreadContext(LPVOID monMMF) {
	Form1^ form = (Form1^)Application::OpenForms[0];

	char* cp = (char*)monMMF;
	//form->logging(gcnew System::String(cp));
	fprintf(pFile, "%s\n", cp);


	std::string pid(strtok(cp, ":"));


	std::string buf(pid);
	buf.append(":CallGetThreadContext:Response Sended!");
	memcpy(monMMF, buf.c_str(), buf.size());
}

void CallSetThreadContext(LPVOID monMMF) {

	Form1^ form = (Form1^)Application::OpenForms[0];

	char* cp = (char*)monMMF;
	//form->logging(gcnew System::String(cp));
	fprintf(pFile, "%s\n", cp);


	std::string pid(strtok(cp, ":"));

	form->logging(gcnew System::String(pid.c_str()));
	form->logging(gcnew System::String(" :SetThreadContext Called!\r\n"));


	std::string buf(pid);
	buf.append(":CallSetThreadContext:Response Sended!");
	memcpy(monMMF, buf.c_str(), buf.size());
}

void CallNtQueueApcThread(LPVOID monMMF) {

	Form1^ form = (Form1^)Application::OpenForms[0];

	char* cp = (char*)monMMF;
	//form->logging(gcnew System::String(cp));
	fprintf(pFile, "%s\n", cp);


	std::string pid(strtok(cp, ":"));

	DWORD64 target = (DWORD64)strtoll(strtok(NULL, ":"), NULL, 16);
	char buf[MSG_SIZE] = "";
	memset(monMMF, 0, MSG_SIZE);
	auto item = rwxList.find(pid);
	if (item != rwxList.end()) {
		for (auto i : item->second) {
			if (i.first <= target && (i.first + (DWORD64)i.second > target))
				sprintf_s(buf, "%s:Detected:%016x:CallNtQueueApcThread", pid, target);
			memcpy(monMMF, buf, strlen(buf));
			return;
		}
	}

	sprintf_s(buf, "%s:%016x:CallNtQueueApcThread:Clean", pid, target);
	memcpy(monMMF, buf, strlen(buf));
}

void CallSetWindowLongPtrA(LPVOID monMMF) {

	Form1^ form = (Form1^)Application::OpenForms[0];

	char* cp = (char*)monMMF;
	//form->logging(gcnew System::String(cp));
	fprintf(pFile, "%s\n", cp);


	std::string pid(strtok(cp, ":"));
	form->logging(gcnew System::String(pid.c_str()));


	std::string addr(strtok(NULL, ":"));
	DWORD64 target = (DWORD64)strtoll(addr.c_str(), NULL, 16);
	char buf[MSG_SIZE] = "";
	memset(monMMF, 0, MSG_SIZE);
	auto item = rwxList.find(pid);
	if (item != rwxList.end()) {

		for (auto i : item->second) {
			if (i.first <= target && (i.first + (DWORD64)i.second > target))
				sprintf_s(buf, "%s:Detected:%016x:CallSetWindowLongPtrA", pid, target);
			form->logging(gcnew System::String(" : SetWindowLongPtrA -> Code Injection Detected! Addr: "));
			form->logging(gcnew System::String(addr.c_str()));
			form->logging(gcnew System::String("\r\n"));
			form->logging(gcnew System::String("\r\n"));
			MessageBoxA(NULL, "SetWindowLongPtrA Code Injection Detected!", "Detection Alert!", MB_OK | MB_ICONQUESTION);
			memcpy(monMMF, buf, strlen(buf));
			return;
		}
	}

	sprintf_s(buf, "%s:%016x:CallSetWindowLongPtrA:Clean", pid, target);
	memcpy(monMMF, buf, strlen(buf));

}


void CallSleepEx(LPVOID monMMF) {

	Form1^ form = (Form1^)Application::OpenForms[0];

	char* cp = (char*)monMMF;
	//form->logging(gcnew System::String(cp));
	fprintf(pFile, "%s\n", cp);


	std::string pid(strtok(cp, ":"));

	fprintf(pFile, "%s\n", (char*)monMMF);
	std::string buf(pid);
	buf.append(":CallSleepEx:Response Sended!");
	memcpy(monMMF, buf.c_str(), buf.size());
}
