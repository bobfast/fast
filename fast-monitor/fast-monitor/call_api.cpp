#include "call_api.h"
#include <Psapi.h>




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

void insertList(std::string callee_pid, DWORD64 ret, DWORD dwSize, std::string caller_pid, UCHAR flags, std::string caller_path) {
	std::vector<std::tuple<DWORD64, DWORD, std::string, UCHAR, std::string >> v = { std::make_tuple(ret, dwSize, caller_pid, flags,caller_path) };
	auto rwxItem = rwxList.find(callee_pid);
	if (rwxItem != rwxList.end()) {
		rwxItem->second.push_back(v);
	}
	else {
		std::vector<std::vector<std::tuple<DWORD64, DWORD, std::string, UCHAR, std::string >>> ls = { v };
		rwxList.insert(std::make_pair(callee_pid, ls));
	}
}


BOOL checkList(std::string callee_pid, DWORD64 target, DWORD dwSize, std::string caller_pid, UCHAR flags, std::string caller_path) {
	auto item = rwxList.find(callee_pid);
	if (item != rwxList.end()) {

		for (auto& i : item->second) {
			if (std::get<0>(i[0]) <= target && (std::get<0>(i[0]) + (DWORD64)(std::get<1>(i[0])) > target)) {
				std::tuple<DWORD64, DWORD, std::string, UCHAR, std::string > tp = { std::make_tuple(target, dwSize, caller_pid, flags,caller_path) };
				i.push_back(tp);

				std::get<3>(i[0]) |= flags;
				if (flags != FLAG_WriteProcessMemory) {
					Form1^ form = (Form1^)Application::OpenForms[0];
					form->show_detection(callee_pid, i);
				}
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

void exGhidraHeadless(LPCSTR filename)
{
	BOOL bShellExecute = FALSE;
	SHELLEXECUTEINFO stShellInfo = { sizeof(SHELLEXECUTEINFO) };

	if (ghidraDirectory == "") {
		return;
	}

	std::string analyzeHeadless_bat = ghidraDirectory + "\\support\\analyzeHeadless.bat";

	if (!fileExists((TCHAR*)(analyzeHeadless_bat.c_str()))) {
		MessageBoxA(NULL, (analyzeHeadless_bat + " not found.").c_str(), "Ghidra Failed.!", MB_OK | MB_ICONERROR);
		return;
	}

	stShellInfo.lpVerb = TEXT("open");
	stShellInfo.lpFile = TEXT("cmd");
	stShellInfo.lpParameters = TEXT(
		(std::string("/c \"") + analyzeHeadless_bat + "\" . GhidraMemdmpProject -import "
			+ filename).c_str()
	);
	stShellInfo.nShow = SW_SHOWNORMAL;
	bShellExecute = ShellExecuteEx(&stShellInfo);

	if (!bShellExecute) {
		MessageBoxA(NULL, "Executing Ghidra Headless Failed!", "Ghidra Failed.!", MB_OK | MB_ICONERROR);
		return;
	}

	WaitForSingleObject(stShellInfo.hProcess, INFINITE);
}

void memory_region_dump(DWORD pid, const char* name, LPVOID entryPoint, std::unordered_map<std::string, std::vector<std::vector<std::tuple<DWORD64, DWORD, std::string, UCHAR, std::string>>>>& list)
{
	if (list.find(std::to_string(pid)) == list.end()) {
		MessageBoxA(NULL, "Cannot dump memory region...", "Error", MB_OK | MB_ICONERROR);
		return;
	}

	auto recentAlloc = list[std::to_string(pid)].back();
	DWORD recentWrittenBufferSize = std::get<1>(recentAlloc[0]);
	LPVOID recentWrittenBaseAddress = (LPVOID)(std::get<0>(recentAlloc[0]));
	FILE* f = NULL, * disasm_f = NULL;
	char* buf = NULL, basefilename_memdmp[261] = "", basefilename_disasm[261] = "";
	SIZE_T buflen = 0;
	HANDLE hProcess = NULL;
	std::string filename_memdmp, filename_disasm;

	do {
		buf = new char[recentWrittenBufferSize];

		if (buf == NULL) {
			printf("Error: cannot allocate buffer for memory region dump.\n");
			break;
		}

		int i = 0;

		while (1) {
			if (i == 0) {
				sprintf_s(basefilename_memdmp, "%d_%s_%p", pid, name, recentWrittenBaseAddress);
				sprintf_s(basefilename_disasm, "%d_%s_%p_%p", pid, name, recentWrittenBaseAddress, entryPoint);
			}
			else {
				sprintf_s(basefilename_memdmp, "%d_%s_%p_(%d)", pid, name, recentWrittenBaseAddress, i);
				sprintf_s(basefilename_disasm, "%d_%s_%p_%p_(%d)", pid, name, recentWrittenBaseAddress, entryPoint, i);
			}

			filename_memdmp = std::string("[memdmp]") + std::string(basefilename_memdmp) + std::string(".bin");

			if (!fileExists((TCHAR*)(filename_memdmp.c_str()))) {
				break;
			}

			i++;
		}

		fopen_s(&f, filename_memdmp.c_str(), "wb");

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

		// capstone disassembling code
		do {
			if (entryPoint == NULL) break;

			csh cshandle;
			cs_insn* insn;
			size_t entryoffset, count;

			entryoffset = (size_t)((DWORD64)entryPoint - (DWORD64)recentWrittenBaseAddress);

			if (entryoffset >= recentWrittenBufferSize) {
				// not valid entryoffset -> disasm ignored
				break;
			}

			filename_disasm = std::string("[disasm]") + std::string(basefilename_disasm) + std::string(".txt");
			fopen_s(&disasm_f, filename_disasm.c_str(), "wt");

			if (disasm_f == NULL) {
				// file cannot create -> disasm ignored
				break;
			}

			if (cs_open(CS_ARCH_X86, CS_MODE_64, &cshandle) != CS_ERR_OK) {
				// capstone cannot open -> disasm ignored
				break;
			}

			count = cs_disasm(cshandle, (uint8_t*)buf + entryoffset, recentWrittenBufferSize - entryoffset - 1, (uint64_t)entryPoint, 0, &insn);
			if (count > 0) {
				// disassembling
				size_t j;
				for (j = 0; j < count; j++) {
					fprintf(disasm_f, "0x%" PRIx64 ":\t%s\t\t%s\n", insn[j].address, insn[j].mnemonic,
						insn[j].op_str);
				}

				cs_free(insn, count);
			}

			cs_close(&cshandle);

			break;
		} while (1);

		if (disasm_f != NULL) fclose(disasm_f);

		break;
	} while (1);

	if (buf != NULL) delete[] buf;
	if (hProcess != NULL) CloseHandle(hProcess);
	if (f != NULL) {
		fclose(f);
	}
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
	std::string caller_path(strtok_s(NULL, ":", &cp_context));

	insertList(callee_pid, ret, dwSize, caller_pid, FLAG_VirtualAllocEx ,caller_path);

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



	std::string caller_pid(strtok_s(cp, ":", &cp_context));
	std::string callee_pid(strtok_s(NULL, ":", &cp_context));
	DWORD64 lpbaseaddress = (DWORD64)strtoll(strtok_s(NULL, ":", &cp_context), NULL, 16);
	DWORD dwSize = (DWORD)strtol(strtok_s(NULL, ":", &cp_context), NULL, 16);
	std::string caller_path(strtok_s(NULL, ":", &cp_context));
	
	if (checkList(callee_pid, lpbaseaddress, dwSize, caller_pid, FLAG_WriteProcessMemory, caller_path))
		form->logging(caller_pid + " : " + callee_pid + " : WriteProcessMemory called on Executable Memory.\r\n");

	//CompareCode(std::stoi(callee_pid), std::stoi(caller_pid));

	memset(monMMF, 0, MSG_SIZE);
	char buf[MSG_SIZE] = "";
	sprintf_s(buf, "%s:%016llx:%08lx:CallWriteProcessMemory:Response Sended!", callee_pid.c_str(), lpbaseaddress, dwSize);
	memcpy(monMMF, buf, strlen(buf));
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
	std::string caller_path(strtok_s(NULL, ":", &cp_context));

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
			form->logging("DLL File: " + std::string(buf) + "\r\n");
			CompareCode(std::stoi(callee_pid), std::stoi(caller_pid));

			sprintf_s(messagePrint, "CreateRemoteThread DLL Injection with LoadLibrary Detected!\nDLL File: %s", buf);
			MessageBoxA(NULL, messagePrint, "Detection Alert!", MB_OK | MB_ICONQUESTION);

			break;
		} while (1);

		memcpy(monMMF, buf, strlen(buf));
		return;
	}
	else if (checkList(callee_pid, lpStartAddress, NULL, caller_pid, FLAG_CreateRemoteThread, caller_path)) {

		sprintf_s(buf, "%s:Detected:%016llx:%016llx:CallCreateRemoteThread", caller_pid.c_str(), lpStartAddress, lpParameter);

		form->logging(caller_pid + " : " + callee_pid + " : CreateRemoteThread -> Code Injection Detected! Addr:"+ addr+"\r\n");
		CompareCode(std::stoi(callee_pid), std::stoi(caller_pid));


		memory_region_dump(std::stoi(callee_pid), "CodeInjection", (LPVOID)lpStartAddress, rwxList);
		if (MessageBoxA(NULL, "CreateRemoteThread Code Injection Detected! Are you want to Dumpit?", "Detection Alert!", MB_YESNO | MB_ICONQUESTION) == IDYES) {
			exDumpIt();
		}

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
	std::string caller_path(strtok_s(NULL, ":", &cp_context));

	insertList(callee_pid, ret, dwSize, caller_pid, FLAG_NtMapViewOfSection, caller_path);

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
	std::string caller_path(strtok_s(NULL, ":", &cp_context));

	char buf[MSG_SIZE] = "";
	memset(monMMF, 0, MSG_SIZE);

	CompareCode(std::stoi(callee_pid), std::stoi(caller_pid));

	if (checkList(callee_pid, lpStartAddress, NULL, caller_pid, FLAG_SetThreadContext, caller_path)) {
		sprintf_s(buf, "%s:Detected:%016llx:CallSetThreadContext", callee_pid.c_str(), lpStartAddress);
		form->logging(callee_pid+" : "+ caller_pid +" : SetThreadContext -> Thread Hijacking Detected! Addr: "+ addr+"\r\n");


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
	std::string caller_path(strtok_s(NULL, ":", &cp_context));

	char buf[MSG_SIZE] = "";
	memset(monMMF, 0, MSG_SIZE);

	if (apc_routine.compare("GlobalGetAtomNameA") == 0) {
		sprintf_s(buf, "%s:Detected:GlobalGetAtomNameA:CallNtQueueApcThread", callee_pid.c_str());

		form->logging(" : NtQueueApcThread -> GlobalGetAtomNameA Detected!\r\n");
		CompareCode(std::stoi(callee_pid), std::stoi(caller_pid));

		//MessageBoxA(NULL, "NtQueueApcThread - GlobalGetAtomNameA Detected!", "Detection Alert!", MB_OK | MB_ICONQUESTION);
		//memory_region_dump(std::stoi(callee_pid), "MemoryRegionDump_NtQueueApcThread_GlobalGetAtomNameA", rwxList);
		memcpy(monMMF, buf, strlen(buf));
		return;
	}
	else {
		DWORD64 target = (DWORD64)strtoll(apc_routine.c_str(), NULL, 16);
		if (checkList(callee_pid, target, NULL, caller_pid, FLAG_NtQueueApcThread, caller_path)) {
					sprintf_s(buf, "%s:Detected:%016llx:CallNtQueueApcThread", callee_pid.c_str(), target);

					form->logging(" : NtQueueApcThread -> Code Injection Detected!\r\n");
					CompareCode(std::stoi(callee_pid), std::stoi(caller_pid));


					memory_region_dump(std::stoi(callee_pid), "NtQueueApcThread", (LPVOID)target, rwxList);
					if (MessageBoxA(NULL, "NtQueueApcThread Code Injection Detected! Are you want to Dumpit?", "Detection Alert!", MB_YESNO | MB_ICONQUESTION) == IDYES) {
						exDumpIt();
					}

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
	std::string caller_path(strtok_s(NULL, ":", &cp_context));

	char buf[MSG_SIZE] = "";
	memset(monMMF, 0, MSG_SIZE);


	if (checkList(callee_pid, lpStartAddress, NULL, caller_pid, FLAG_SetWindowLongPtrA, caller_path)) {
				sprintf_s(buf, "%s:Detected:%016llx:CallSetWindowLongPtrA", callee_pid.c_str(), lpStartAddress);
				form->logging(caller_pid+" : "+ callee_pid +" : SetWindowLongPtrA -> Code Injection Detected! Addr: "+ addr +"\r\n");
				CompareCode(std::stoi(callee_pid), std::stoi(caller_pid));

				memory_region_dump(std::stoi(callee_pid), "SetWindowLongPtrA", (LPVOID)lpStartAddress, rwxList);
				if (MessageBoxA(NULL, "SetWindowLongPtrA Code Injection Detected! Are you want to Dumpit?", "Detection Alert!", MB_YESNO | MB_ICONQUESTION) == IDYES) {
					exDumpIt();
				}

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
	std::string caller_path(strtok_s(NULL, ":", &cp_context));

	char buf[MSG_SIZE] = "";
	memset(monMMF, 0, MSG_SIZE);



	if (checkList(callee_pid, lpStartAddress, NULL, caller_pid, FLAG_SetPropA, caller_path)) {
				sprintf_s(buf, "%s:Detected:%016llx:CallSetPropA", callee_pid.c_str(), lpStartAddress);
				form->logging(caller_pid +" : "+ callee_pid+" : SetPropA -> Code Injection Detected! Addr: "+ addr+"\r\n");
				CompareCode(std::stoi(callee_pid), std::stoi(caller_pid));

				memory_region_dump(std::stoi(callee_pid), "CallSetPropA", (LPVOID)lpStartAddress, rwxList);
				if (MessageBoxA(NULL, "CallSetPropA Code Injection Detected! Are you want to Dumpit?", "Detection Alert!", MB_YESNO | MB_ICONQUESTION) == IDYES) {
					exDumpIt();
				}

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
	std::string caller_path(strtok_s(NULL, ":", &cp_context));

	insertList(callee_pid, ret, dwSize, caller_pid, FLAG_VirtualProtectEx, caller_path);


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



//////////////////////
//////////////////////
//////////////////////
//////////////////////
//////////////////////
//////////////////////


BOOLEAN CompareCode(int pid, int caller_pid) {

	Form1^ form = (Form1^)Application::OpenForms[0];
	form->logging(std::to_string(caller_pid) + " : " + std::to_string(pid) + " : Checking Code Section.\r\n");


	PIMAGE_DOS_HEADER pDH = NULL;
	PIMAGE_NT_HEADERS pNTH = NULL;
	PIMAGE_FILE_HEADER pFH = NULL;
	PIMAGE_SECTION_HEADER pSH = NULL;
	HANDLE hProcessSnap;


	char filePath[256] = { 0, };
	char fileName[256] = { 0, };

	HANDLE hp = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
	if (!hp) {
		form->logging("FAILED OPENPROCESS\r\n");
		return FALSE;
	}
	
	GetModuleFileNameEx(hp, NULL, filePath, 256);
	GetFileTitle(filePath, fileName, 256);
	

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
			form->logging("Could not get IMAGE_DOS_HEADER\n");
			CloseHandle(hp);
			return FALSE;
		}
		else
			//form->logging("OK IMAGE_DOS_HEADER\n");

			pNTH = (PIMAGE_NT_HEADERS)((PBYTE)pDH + pDH->e_lfanew);
		if (pNTH->Signature != IMAGE_NT_SIGNATURE) {
			form->logging("Could not get IMAGE_NT_HEADER\n");
			CloseHandle(hp);
			return FALSE;
		}
		else
			//form->logging("OK IMAGE_NT_HEADER\n");

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
		form->logging("1st ReadProcessMemory error!"+ std::to_string(GetLastError()) +"\r\n");
		CloseHandle(hp);
		return FALSE;
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

	FILE* pFile = fopen(filePath, "rb");
	if (!pFile) {
		form->logging("FAILED FILE OPEN : "+ std::string(filePath)+"\r\n");
		CloseHandle(hp);
		exit(1);
	}

	fseek(pFile, 0, SEEK_END);
	lSize = ftell(pFile);
	rewind(pFile);

	buffer = (BYTE*)malloc(sizeof(BYTE) * lSize);
	if (buffer == NULL) {
		fputs("Memory error", stderr);
		exit(2);
	}

	result = fread(buffer, 1, lSize, pFile);
	if (result != lSize) {
		fputs("Reading error", stderr);
		exit(3);
	}

	pDH = (PIMAGE_DOS_HEADER)buffer;
	if (pDH->e_magic != IMAGE_DOS_SIGNATURE) {
		form->logging("Could not get IMAGE_DOS_HEADER\n");
		CloseHandle(hp);
		fclose(pFile);
		free(buffer);
		return FALSE;
	}
	else
		//form->logging("OK IMAGE_DOS_HEADER\n");

		pNTH = (PIMAGE_NT_HEADERS)((PBYTE)pDH + pDH->e_lfanew);
	if (pNTH->Signature != IMAGE_NT_SIGNATURE) {
		form->logging("Could not get IMAGE_NT_HEADER\n");
		CloseHandle(hp);
		fclose(pFile);
		free(buffer);
		return FALSE;
	}
	else
		//form->logging("OK IMAGE_NT_HEADER\n");

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
	int HashNum = (((textSize / 512) + 1) < ((ftextSize / 512) + 1)) ? (textSize / 512) + 1 : (ftextSize / 512) + 1;
	char md5[33];
	char fmd5[33];
	BYTE temp[512] = { 0, };
	BOOL resultPrint = FALSE;
	unsigned int MinIntegrity = 0;
	unsigned int MaxIntegrity = 4294967295;

	BYTE* textAddrTmp = textAddr;

	for (int i = 0; i < HashNum; i++) {
		if (ReadProcessMemory(hp, textAddrTmp, &textSection, sizeof(textSection), NULL)) {

			memcpy(temp, &ftextAddr[i * 512], 512);

			if (calcMD5(textSection, md5) && calcMD5(temp, fmd5)) {
				//form->logging("%s  %s\n", md5, fmd5);           /////////////////////////////////
				if (strcmp(md5, fmd5)) {

					for (int j = 0; j < 512; j++) {
						if ((textSection[j] != temp[j]) && (resultPrint == FALSE)) {
							MinIntegrity = (i * 512) + j;
							char printTemp[50];
							sprintf_s(printTemp, "Code Section is changed (0x%p)", textAddr + MinIntegrity);
							std::string str(printTemp);
							form->logging(std::to_string(caller_pid) + " : " + std::to_string(pid) + " : " + str + "\r\n");
							resultPrint = true;
						}
						else if ((textSection[j] == temp[j]) && (resultPrint == true)) {
							if (MaxIntegrity < (i * 512) + j) {
								MaxIntegrity = (i * 512) + j;
							}
						}
					}
				}
			}
			else
				form->logging("MD5 calculation failed.\n");

			textAddrTmp += 512;
			//form->logging("\n\n\n\n\n");
		}
		else {
			form->logging("2nd ReadProcessMemory error code : "+ std::to_string(GetLastError())+"\r\n");
			fclose(pFile);
			free(buffer);
			CloseHandle(hp);
			return FALSE;
		}
	}

	char hex[6];
	if (resultPrint == FALSE) {
		form->logging(std::to_string(caller_pid) + " : " + std::to_string(pid) + " : Code Section is OK(not changed)\r\n");
	}
	else {
		unsigned int changeSize = MaxIntegrity - MinIntegrity;
		form->logging("Before : ");
		for (int i = MinIntegrity; i <= MinIntegrity + 100; i++) {
			sprintf_s(hex, "%02X ", ftextAddr[i]);
			form->logging(hex);
		}
		form->logging("\n");
		form->logging("After : ");
		BYTE* changedCode = (BYTE*)malloc(sizeof(BYTE) * 512);
		if (ReadProcessMemory(hp, textAddr + MinIntegrity, changedCode, 512, NULL)) {
			for (int i = 0; i < 100; i++) {
				sprintf_s(hex, "%02X ",changedCode[i]);
				form->logging(hex);
			}
			form->logging("\n\n");
			free(changedCode);
		}
		else {
			form->logging("FAILED 3rd ReadProcessMemory : changedCode\n");
			fclose(pFile);
			free(changedCode);
			free(buffer);
			CloseHandle(hp);
			return 0;
		}
	}

	fclose(pFile);
	free(buffer);
	CloseHandle(hp);
	return 0;
}


//BYTE buff[512];
BOOL calcMD5(byte* data, LPSTR md5)
{

	Form1^ form = (Form1^)Application::OpenForms[0];

	HCRYPTPROV hProv = 0;
	HCRYPTHASH hHash = 0;
	BYTE rgbHash[16];
	DWORD cbHash = 0;
	CHAR rgbDigits[] = "0123456789abcdef";

	// Get handle to the crypto provider
	if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
	{
		form->logging("ERROR: Couldn't acquire crypto context!\n");
		return FALSE;
	}

	if (!CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash))
	{
		CryptReleaseContext(hProv, 0);
		form->logging("ERROR: Couldn't create crypto stream!\n");
		return FALSE;
	}

	if (!CryptHashData(hHash, data, 512, 0))
	{
		CryptReleaseContext(hProv, 0);
		CryptDestroyHash(hHash);
		form->logging("ERROR: CryptHashData failed!\n");
		return FALSE;
	}

	cbHash = 16;
	if (CryptGetHashParam(hHash, HP_HASHVAL, rgbHash, &cbHash, 0))
	{
		for (DWORD i = 0; i < cbHash; i++)
		{
			sprintf(md5 + (i * 2), "%c%c", rgbDigits[rgbHash[i] >> 4], rgbDigits[rgbHash[i] & 0xf]);
		}

		CryptDestroyHash(hHash);
		CryptReleaseContext(hProv, 0);
		return TRUE;
	}
	else
	{
		form->logging("ERROR: CryptHashData failed!\n");
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