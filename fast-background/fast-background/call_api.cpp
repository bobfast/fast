#include "call_api.h"
#include <Psapi.h>


void CompareCode(int pid, int caller_pid);
BOOL calcMD5(byte* data, LPSTR md5);
DWORD64 GetModuleAddress(const char* moduleName, int pid);



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

void sendDetection(std::string callee_pid, std::vector<std::tuple<DWORD64, DWORD, std::string, UCHAR >> v) {

	FILE* fp;
	fopen_s(&fp, "C:\\fast_log.json", "w");
	if (fp == NULL)
	{
		exit(1);
	}

	fprintf(fp, "{\"fast-monitor\":[");

	for (auto tp : v) {
		fprintf(fp, "{\"callee_pid\":\"%s\",\"address\":\"0x%llx\",\"size\":\"0x%lx\",\"caller_pid\":\"%s\",\"flag\":\"%x\"},",
			callee_pid.c_str(), std::get<0>(tp), std::get<1>(tp), std::get<2>(tp).c_str(), std::get<3>(tp));
	}

	fprintf(fp, "]}");

	fclose(fp);

}

BOOL checkList(std::string callee_pid, DWORD64 target, DWORD dwSize, std::string caller_pid, UCHAR flags) {
	auto item = rwxList.find(callee_pid);
	if (item != rwxList.end()) {

		for (auto i : item->second) {
			if (std::get<0>(i[0]) <= target && (std::get<0>(i[0]) + (DWORD64)(std::get<1>(i[0])) > target)) {
				std::tuple<DWORD64, DWORD, std::string, UCHAR > tp = { std::make_tuple(target, dwSize, caller_pid, flags) };
				i.push_back(tp);
				std::get<3>(i[0]) |= flags;
				//Form1^ form = (Form1^)Application::OpenForms[0];
				//form->show_detection(callee_pid, i);
				sendDetection(callee_pid, i);
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

	//Form1^ form = (Form1^)Application::OpenForms[0];

	char* cp = (char*)monMMF;
	char* cp_context = NULL;

	if (pFile != NULL) fprintf(pFile, "%s\n", cp);

	std::string caller_pid(strtok_s(cp, ":", &cp_context));
	std::string callee_pid(strtok_s(NULL, ":", &cp_context));
	printf("%s :  %s : VirtualAllocEx ->Protection : PAGE_EXECUTE_READWRITE\r\n", caller_pid, callee_pid);

	DWORD64 ret = (DWORD64)strtoll(strtok_s(NULL, ":", &cp_context), NULL, 16);
	DWORD dwSize = (DWORD)strtol(strtok_s(NULL, ":", &cp_context), NULL, 16);
	DWORD protect = (DWORD)strtol(strtok_s(NULL, ":", &cp_context), NULL, 16);

	insertList(callee_pid, ret, dwSize, caller_pid, FLAG_VirtualAllocEx );

	memset(monMMF, 0, MSG_SIZE);
	char buf[MSG_SIZE] = "";
	//sprintf_s(buf, "%s:%016llx:%08lx:CallVirtualAllocEx:Response Sended!", callee_pid.c_str(), ret, dwSize);
	//memcpy(monMMF, buf, strlen(buf));
}

void CallQueueUserAPC(LPVOID monMMF) {

	//Form1^ form = (Form1^)Application::OpenForms[0];

	char* cp = (char*)monMMF;
	char* cp_context = NULL;


	if (pFile != NULL) fprintf(pFile, "%s\n", cp);


	std::string pid(strtok_s(cp, ":", &cp_context));

	std::string buf(pid);
	buf.append(":CallQueueUserAPC:Response Sended!");
	memcpy(monMMF, buf.c_str(), buf.size());
}

void CallWriteProcessMemory(LPVOID monMMF) {

	//Form1^ form = (Form1^)Application::OpenForms[0];

	char* cp = (char*)monMMF;
	char* cp_context = NULL;


	if (pFile != NULL) fprintf(pFile, "%s\n", cp);


	std::string pid(strtok_s(cp, ":", &cp_context));


	std::string buf(pid);
	buf.append(":CallWriteProcessMemory:Response Sended!");
	memcpy(monMMF, buf.c_str(), buf.size());
}

void CallCreateRemoteThread(LPVOID monMMF) {

	//Form1^ form = (Form1^)Application::OpenForms[0];

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
		//sprintf_s(buf, "%s:Detected:LoadLibraryA:%016llx:CallCreateRemoteThread", caller_pid.c_str(), lpParameter);
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
			
			printf("%s :  %s : CreateRemoteThread -> LoadLibraryA DLL Injection Detected!\r\n", callee_pid , caller_pid);
			printf("DLL File: %s\r\n\r\n", std::string(buf) );
			//CompareCode(std::stoi(callee_pid), std::stoi(caller_pid));

			sprintf_s(messagePrint, "CreateRemoteThread DLL Injection with LoadLibrary Detected!\nDLL File: %s", buf);
			MessageBoxA(NULL, messagePrint, "Detection Alert!", MB_OK | MB_ICONQUESTION);

			break;
		} while (1);

		//memcpy(monMMF, buf, strlen(buf));
		return;
	}
	else if (checkList(callee_pid, lpStartAddress, NULL, caller_pid, FLAG_CreateRemoteThread)) {

		//sprintf_s(buf, "%s:Detected:%016llx:%016llx:CallCreateRemoteThread", caller_pid.c_str(), lpStartAddress, lpParameter);

		printf("%s :  %s : CreateRemoteThread -> Code Injection Detected! Addr:%s\r\n", callee_pid, caller_pid, addr);
		//CompareCode(std::stoi(callee_pid), std::stoi(caller_pid));

		memory_region_dump(std::stoi(callee_pid), "MemoryRegionDump_CodeInjection", rwxList);
		//memcpy(monMMF, buf, strlen(buf));
		return;
	}

	//sprintf_s(buf, "%s:%016llx:%016llx:CallCreateRemoteThread:Clean", callee_pid.c_str(), lpStartAddress, lpParameter);
	//memcpy(monMMF, buf, strlen(buf));

}

void CallNtMapViewOfSection(LPVOID monMMF) {


	//Form1^ form = (Form1^)Application::OpenForms[0];

	char* cp = (char*)monMMF;
	char* cp_context = NULL;

	if (pFile != NULL) fprintf(pFile, "%s\n", cp);

	std::string caller_pid(strtok_s(cp, ":", &cp_context));
	std::string callee_pid(strtok_s(NULL, ":", &cp_context));


	printf("%s :  %s : NtMapViewOfSection ->Protection : PAGE_EXECUTE_READWRITE\r\n" ,callee_pid, caller_pid);

	DWORD64 ret = (DWORD64)strtoll(strtok_s(NULL, ":", &cp_context), NULL, 16);
	DWORD dwSize = (DWORD)strtol(strtok_s(NULL, ":", &cp_context), NULL, 16);
	DWORD protect = (DWORD)strtol(strtok_s(NULL, ":", &cp_context), NULL, 16);

	insertList(callee_pid, ret, dwSize, caller_pid, FLAG_NtMapViewOfSection);

	memset(monMMF, 0, MSG_SIZE);
	char buf[MSG_SIZE] = "";
	//sprintf_s(buf, "%s:%016llx:%08lx:CallNtMapViewOfSection:Response Sended!", callee_pid.c_str(), ret, dwSize);
	//memcpy(monMMF, buf, strlen(buf));
}

void CallCreateFileMappingA(LPVOID monMMF) {
	//Form1^ form = (Form1^)Application::OpenForms[0];

	char* cp = (char*)monMMF;
	char* cp_context = NULL;

	if (pFile != NULL) fprintf(pFile, "%s\n", cp);


	std::string pid(strtok_s(cp, ":", &cp_context));


	std::string buf(pid);
	buf.append(":CallCreateFileMappingA:Response Sended!");
	memcpy(monMMF, buf.c_str(), buf.size());
}

void CallGetThreadContext(LPVOID monMMF) {
	//Form1^ form = (Form1^)Application::OpenForms[0];

	char* cp = (char*)monMMF;
	char* cp_context = NULL;

	if (pFile != NULL) fprintf(pFile, "%s\n", cp);


	std::string pid(strtok_s(cp, ":", &cp_context));


	std::string buf(pid);
	buf.append(":CallGetThreadContext:Response Sended!");
	memcpy(monMMF, buf.c_str(), buf.size());
}

void CallSetThreadContext(LPVOID monMMF) {

	//Form1^ form = (Form1^)Application::OpenForms[0];
	
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
		//sprintf_s(buf, "%s:Detected:%016llx:CallSetThreadContext", callee_pid.c_str(), lpStartAddress);
		printf("%s :  %s : SetThreadContext -> Thread Hijacking Detected! Addr: %s\r\n",callee_pid, caller_pid, addr);
		//CompareCode(std::stoi(callee_pid), std::stoi(caller_pid));

		MessageBoxA(NULL, "SetThreadContext Thread Hijacking Detected!", "Detection Alert!", MB_OK | MB_ICONQUESTION);
		//memcpy(monMMF, buf, strlen(buf));
		return;
	}

	//sprintf_s(buf, "%s:%016llx:CallSetThreadContext:Clean", callee_pid.c_str(), lpStartAddress);
	//memcpy(monMMF, buf, strlen(buf));
}

void CallNtQueueApcThread(LPVOID monMMF) {

	//Form1^ form = (Form1^)Application::OpenForms[0];

	char* cp = (char*)monMMF;
	char* cp_context = NULL;

	if (pFile != NULL) fprintf(pFile, "%s\n", cp);

	std::string caller_pid(strtok_s(cp, ":", &cp_context));
	std::string callee_pid(strtok_s(NULL, ":", &cp_context));
	std::string apc_routine(strtok_s(NULL, ":", &cp_context));

	char buf[MSG_SIZE] = "";
	memset(monMMF, 0, MSG_SIZE);

	if (apc_routine.compare("GlobalGetAtomNameA") == 0) {
		//sprintf_s(buf, "%s:Detected:GlobalGetAtomNameA:CallNtQueueApcThread", callee_pid.c_str());

		printf(" : NtQueueApcThread -> GlobalGetAtomNameA Detected!\r\n");
		//CompareCode(std::stoi(callee_pid), std::stoi(caller_pid));

		//MessageBoxA(NULL, "NtQueueApcThread - GlobalGetAtomNameA Detected!", "Detection Alert!", MB_OK | MB_ICONQUESTION);
		//memory_region_dump(std::stoi(callee_pid), "MemoryRegionDump_NtQueueApcThread_GlobalGetAtomNameA", rwxList);
		//memcpy(monMMF, buf, strlen(buf));
		return;
	}
	else {
		DWORD64 target = (DWORD64)strtoll(apc_routine.c_str(), NULL, 16);
		if (checkList(callee_pid, target, NULL, caller_pid, FLAG_NtQueueApcThread )) {
					//sprintf_s(buf, "%s:Detected:%016llx:CallNtQueueApcThread", callee_pid.c_str(), target);

					printf(" : NtQueueApcThread -> Code Injection Detected!\r\n");
					//CompareCode(std::stoi(callee_pid), std::stoi(caller_pid));

					MessageBoxA(NULL, "NtQueueApcThread Code Injection Detected!", "Detection Alert!", MB_OK | MB_ICONQUESTION);
					memory_region_dump(std::stoi(callee_pid), "MemoryRegionDump_NtQueueApcThread", rwxList);
					//memcpy(monMMF, buf, strlen(buf));
					return;
			
		}
	}

	//sprintf_s(buf, "%s:%s:CallNtQueueApcThread:Clean", callee_pid.c_str(), apc_routine.c_str());
	//memcpy(monMMF, buf, strlen(buf));
}

void CallSetWindowLongPtrA(LPVOID monMMF) {

	//Form1^ form = (Form1^)Application::OpenForms[0];

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
				//sprintf_s(buf, "%s:Detected:%016llx:CallSetWindowLongPtrA", callee_pid.c_str(), lpStartAddress);
				printf("%s :  %s : SetWindowLongPtrA -> Code Injection Detected! Addr: %s\r\n", callee_pid, caller_pid, addr);
				//CompareCode(std::stoi(callee_pid), std::stoi(caller_pid));

				MessageBoxA(NULL, "SetWindowLongPtrA Code Injection Detected!", "Detection Alert!", MB_OK | MB_ICONQUESTION);
				memory_region_dump(std::stoi(callee_pid), "MemoryRegionDump_SetWindowLongPtrA", rwxList);
				//memcpy(monMMF, buf, strlen(buf));
				return;
			
	}

	//sprintf_s(buf, "%s:%016llx:CallSetWindowLongPtrA:Clean", callee_pid.c_str(), lpStartAddress);
	//memcpy(monMMF, buf, strlen(buf));

}


void CallSetPropA(LPVOID monMMF) {

	//Form1^ form = (Form1^)Application::OpenForms[0];

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
				//sprintf_s(buf, "%s:Detected:%016llx:CallSetPropA", callee_pid.c_str(), lpStartAddress);
				printf("%s :  %s : SetPropA -> Code Injection Detected! Addr: %s\r\n", callee_pid, caller_pid, addr);
				//CompareCode(std::stoi(callee_pid), std::stoi(caller_pid));

				MessageBoxA(NULL, "CallSetPropA Code Injection Detected!", "Detection Alert!", MB_OK | MB_ICONQUESTION);
				//memcpy(monMMF, buf, strlen(buf));
				return;
	}

	//sprintf_s(buf, "%s:%016llx:CallSetPropA:Clean", callee_pid.c_str(), lpStartAddress);
	//memcpy(monMMF, buf, strlen(buf));
}

void CallVirtualProtectEx(LPVOID monMMF) {

	//Form1^ form = (Form1^)Application::OpenForms[0];

	char* cp = (char*)monMMF;
	char* cp_context = NULL;

	if (pFile != NULL) fprintf(pFile, "%s\n", cp);

	std::string caller_pid(strtok_s(cp, ":", &cp_context));
	std::string callee_pid(strtok_s(NULL, ":", &cp_context));

	printf("%s :  %s : VirtualProtectEx ->Protection : PAGE_EXECUTE_READWRITE\r\n", caller_pid, callee_pid);

	DWORD64 ret = (DWORD64)strtoll(strtok_s(NULL, ":", &cp_context), NULL, 16);
	DWORD dwSize = (DWORD)strtol(strtok_s(NULL, ":", &cp_context), NULL, 16);
	DWORD protect = (DWORD)strtol(strtok_s(NULL, ":", &cp_context), NULL, 16);


	insertList(callee_pid, ret, dwSize, caller_pid, (UCHAR)0b00000100);


	memset(monMMF, 0, MSG_SIZE);
	char buf[MSG_SIZE] = "";
	//sprintf_s(buf, "%s:%016llx:%08lx:CallVirtualProtectEx:Response Sended!", callee_pid.c_str(), ret, dwSize);
	//memcpy(monMMF, buf, strlen(buf));
}


void CallSleepEx(LPVOID monMMF) {

	//Form1^ form = (Form1^)Application::OpenForms[0];

	char* cp = (char*)monMMF;
	char* cp_context = NULL;

	if (pFile != NULL) fprintf(pFile, "%s\n", cp);


	std::string pid(strtok_s(cp, ":", &cp_context));

	if (pFile != NULL) fprintf(pFile, "%s\n", (char*)monMMF);
	std::string buf(pid);
	buf.append(":CallSleepEx:Response Sended!");
	memcpy(monMMF, buf.c_str(), buf.size());
}



//////////////////////
//////////////////////
//////////////////////
//////////////////////
//////////////////////
//////////////////////


void CompareCode(int pid, int caller_pid) {

	PIMAGE_DOS_HEADER pDH = NULL;
	PIMAGE_NT_HEADERS pNTH = NULL;
	PIMAGE_FILE_HEADER pFH = NULL;
	PIMAGE_SECTION_HEADER pSH = NULL;
	HANDLE hProcessSnap;

	char filePath[256] = { 0, };
	char fileName[256] = { 0, };

	HANDLE hp = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
	if (!hp) {
		printf("FAILED OPENPROCESS\n");
		return;
	}
	else {
		GetModuleFileNameEx(hp, NULL, filePath, 256);
		GetFileTitle(filePath, fileName, 256);
	}

	void* lpBaseAddress = (void*)GetModuleAddress(fileName, pid);


	/// <summary>
	/// Process PE (Memory)
	/// </summary>
	/// <param name="argc"></param>
	/// <param name="argv"></param>
	/// <returns></returns>

	BYTE buf[700] = { 0, };
	BYTE* textAddr = NULL;
	int textSize;

	if (ReadProcessMemory(hp, lpBaseAddress, &buf, sizeof(buf), NULL)) {
		pDH = (PIMAGE_DOS_HEADER)buf;
		if (pDH->e_magic != IMAGE_DOS_SIGNATURE) {
			printf("Could not get IMAGE_DOS_HEADER\n");
			CloseHandle(hp);
			return;
		}
		else
			printf("OK IMAGE_DOS_HEADER\n");

			pNTH = (PIMAGE_NT_HEADERS)((PBYTE)pDH + pDH->e_lfanew);
		if (pNTH->Signature != IMAGE_NT_SIGNATURE) {
			printf("Could not get IMAGE_NT_HEADER\n");
			CloseHandle(hp);
			return;
		}
		else
			printf("OK IMAGE_NT_HEADER\n");

			pFH = &pNTH->FileHeader;
		pSH = IMAGE_FIRST_SECTION(pNTH);

		for (int i = 0; i < pFH->NumberOfSections; i++) {
			if (!strcmp((char*)pSH->Name, ".text")) {
				/*cout << "Section name:" << pSH->Name << endl;
				cout << "             Virtual Size:" << pSH->Misc.VirtualSize << endl;
				cout << "             Virtual address:" << pSH->VirtualAddress << endl;
				cout << "             SizeofRawData:" << pSH->SizeOfRawData << endl;
				cout << "             PointertoRelocations:" << pSH->PointerToRelocations << endl;
				cout << "             Characteristics:" << pSH->Characteristics << endl;*/

				textAddr = (BYTE*)lpBaseAddress + pSH->VirtualAddress;
				textSize = pSH->Misc.VirtualSize;
				break;
			}
			pSH++;
		}
	}
	else {
		printf("ReadProcessMemory error!");
		CloseHandle(hp);
		return;
	}

	/// <summary>
	/// File PE (Disk)
	/// </summary>
	/// <param name="argc"></param>
	/// <param name="argv"></param>
	/// <returns></returns>
	long lSize;
	BYTE* buffer;
	size_t result;
	BYTE* ftextAddr = NULL;
	int ftextSize;

	FILE* peFile;
	fopen_s(&peFile, filePath, "rb");
	if (!peFile) {
		printf("FAILED FILE OPEN : %s\n", filePath);
		CloseHandle(hp);
		exit(1);
	}
	else
		//->logging("OK Open FILE\n");

	fseek(peFile, 0, SEEK_END);
	lSize = ftell(peFile);
	rewind(peFile);

	buffer = (BYTE*)malloc(sizeof(BYTE) * lSize);
	if (buffer == NULL) {
		fputs("Memory error", stderr);
		exit(2);
	}

	result = fread(buffer, 1, lSize, peFile);
	if (result != lSize) {
		fputs("Reading error", stderr);
		exit(3);
	}

	pDH = (PIMAGE_DOS_HEADER)buffer;
	if (pDH->e_magic != IMAGE_DOS_SIGNATURE) {
		printf("Could not get IMAGE_DOS_HEADER\n");
		CloseHandle(hp);
		fclose(peFile);
		free(buffer);
		return;
	}

		pNTH = (PIMAGE_NT_HEADERS)((PBYTE)pDH + pDH->e_lfanew);
	if (pNTH->Signature != IMAGE_NT_SIGNATURE) {
		printf("Could not get IMAGE_NT_HEADER\n");
		CloseHandle(hp);
		fclose(peFile);
		free(buffer);
		return;
	}


		pFH = &pNTH->FileHeader;
	pSH = IMAGE_FIRST_SECTION(pNTH);

	for (int i = 0; i < pFH->NumberOfSections; i++) {
		if (!strcmp((char*)pSH->Name, ".text")) {
			/*cout << "Section name:" << pSH->Name << endl;
			cout << "             Virtual Size:" << pSH->Misc.VirtualSize << endl;
			cout << "             Virtual address:" << pSH->VirtualAddress << endl;
			cout << "             SizeofRawData:" << pSH->SizeOfRawData << endl;
			cout << "             PointertoRelocations:" << pSH->PointerToRelocations << endl;
			cout << "             Characteristics:" << pSH->Characteristics << endl;*/

			ftextAddr = buffer + 0x400;
			ftextSize = pSH->Misc.VirtualSize;
			break;
		}
		pSH++;
	}



	/// <summary>
	/// Hashing
	/// </summary>
	/// <param name="argc"></param>
	/// <param name="argv"></param>
	/// <returns></returns>
	BYTE textSection[512] = { 0, };
	int HashNum = (((textSize / 512) + 1) > ((ftextSize / 512) + 1)) ? (textSize / 512) + 1 : (ftextSize / 512) + 1;
	char md5[33];
	char fmd5[33];
	BYTE temp[512] = { 0, };
	BOOL resultPrint = false;
	int MinIntegrity = 0;
	int MaxIntegrity = 0;

	for (int i = 0; i < HashNum; i++) {
		if (ReadProcessMemory(hp, textAddr, &textSection, sizeof(textSection), NULL)) {

			memcpy(temp, &ftextAddr[i * 512], 512);

			if (calcMD5(textSection, md5) && calcMD5(temp, fmd5)) {
				printf("%s  %s\n", md5, fmd5);           /////////////////////////////////
				if (strcmp(md5, fmd5)) {

					for (int j = 0; j < 512; j++) {
						if ((textSection[j] != temp[j]) && (resultPrint == false)) {
							MinIntegrity = (i * 512) + j;
							char printTemp[50];
							sprintf_s(printTemp,"Code Section is changed (0x%p)", textAddr + MinIntegrity);
							std::string str(printTemp);
							printf("%s : %s : %s\r\n", caller_pid, pid, printTemp);
							resultPrint = true;
						}
						//else if ((textSection[j] == temp[j]) && (resultPrint == true)){
						//	MaxIntegrity = (i * 512) + j;
						//}
					}
				}
			}
			else
				printf("MD5 calculation failed.\n");

			textAddr += 512;
			printf("\n\n\n\n\n");
		}
		else {
			printf("ReadProcessMemory error code : %d\n", GetLastError());
			fclose(peFile);
			free(buffer);
			CloseHandle(hp);
			return;
		}
	}

	if (resultPrint == false) {
		//std::string stdpid((char*)pid);
		printf("%s : %s : Code Section is OK(not changed)\r\n", caller_pid, pid);
		printf("%d : : Code Section is OK(not changed)\n", pid);
	}

	fclose(peFile);
	free(buffer);
	CloseHandle(hp);
}


//BYTE buff[512];
BOOL calcMD5(byte* data, LPSTR md5)
{
	HCRYPTPROV hProv = 0;
	HCRYPTHASH hHash = 0;
	BYTE rgbHash[16];
	DWORD cbHash = 0;
	CHAR rgbDigits[] = "0123456789abcdef";

	// Get handle to the crypto provider
	if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
	{
		printf("ERROR: Couldn't acquire crypto context!\n");
		return FALSE;
	}

	if (!CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash))
	{
		CryptReleaseContext(hProv, 0);
		printf("ERROR: Couldn't create crypto stream!\n");
		return FALSE;
	}

	if (!CryptHashData(hHash, data, 512, 0))
	{
		CryptReleaseContext(hProv, 0);
		CryptDestroyHash(hHash);
		printf("ERROR: CryptHashData failed!\n");
		return FALSE;
	}

	cbHash = 16;
	if (CryptGetHashParam(hHash, HP_HASHVAL, rgbHash, &cbHash, 0))
	{
		for (DWORD i = 0; i < cbHash; i++)
		{
			sprintf_s((char*)(md5 + (i * 2)), 2, "%c%c", rgbDigits[rgbHash[i] >> 4], rgbDigits[rgbHash[i] & 0xf]);
		}

		CryptDestroyHash(hHash);
		CryptReleaseContext(hProv, 0);
		return TRUE;
	}
	else
	{
		printf("ERROR: CryptHashData failed!\n");
		CryptDestroyHash(hHash);
		CryptReleaseContext(hProv, 0);
		return FALSE;
	}
}


DWORD64 GetModuleAddress(const char* moduleName, int pid)
{
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
	MODULEENTRY32 moduleEntry;
	moduleEntry.dwSize = sizeof(MODULEENTRY32);

	Module32First(snapshot, &moduleEntry);
	do
	{
		if (!strcmp(moduleName, moduleEntry.szModule))
		{
			CloseHandle(snapshot);
			return (DWORD64)moduleEntry.modBaseAddr;
		}
	} while (Module32Next(snapshot, &moduleEntry));

	CloseHandle(snapshot);
}