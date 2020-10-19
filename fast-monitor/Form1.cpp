#include "Form1.h"

#include <stdio.h>
#include <windows.h>
#include "tchar.h"
#include <tlhelp32.h>
#include <detours.h>
#include <string>
#include <time.h>
#include <unordered_map>
#include <utility>
#include <vector>
#pragma warning(push)
#if _MSC_VER > 1400
#pragma warning(disable : 6102 6103) // /analyze warnings
#endif
#include <strsafe.h>
#pragma warning(pop)

//////////////////////////////////////////////////////////////////////////////
//
//  Test DetourCreateProcessfast function (fast.cpp).
//
//  Microsoft Research Detours Package
//
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//
#define MSG_SIZE 256
using namespace CppCLRWinformsProjekt;

static FILE* pFile = NULL;



void init() {
	time_t t = time(NULL);
	struct tm pLocal = *localtime(&t);

	char buf[256];
	sprintf(buf, "log-%04d-%02d-%02d-%02d-%02d-%02d.txt",
		pLocal.tm_year + 1900, pLocal.tm_mon + 1, pLocal.tm_mday,
		pLocal.tm_hour, pLocal.tm_min, pLocal.tm_sec);

	pFile = fopen(buf, "w");
	if (pFile == NULL)
	{
		exit(1);
	}

	fprintf(pFile, buf);
	fprintf(pFile, "\n#####Monitor Turned on.\n");
}

void exiting() {


	fclose(pFile);
}
//////////////////////////////////////////////////////////////////////////////
//

//////////////////////////////////////////////////////////////////////////////
//
//  This code verifies that the named DLL has been configured correctly
//  to be imported into the target process.  DLLs must export a function with
//  ordinal #1 so that the import table touch-up magic works.
//
struct ExportContext
{
	BOOL fHasOrdinal1;
	ULONG nExports;
};

static BOOL CALLBACK ExportCallback(_In_opt_ PVOID pContext,
	_In_ ULONG nOrdinal,
	_In_opt_ LPCSTR pszSymbol,
	_In_opt_ PVOID pbTarget)
{
	(void)pContext;
	(void)pbTarget;
	(void)pszSymbol;

	ExportContext* pec = (ExportContext*)pContext;

	if (nOrdinal == 1)
	{
		pec->fHasOrdinal1 = TRUE;
	}
	pec->nExports++;

	return TRUE;
}

//////////////////////////////////////////////////////////////////////////////
//

//////////////////////////////////////////////////////////////////////////////
//

void TypeToString(DWORD Type, char* pszBuffer, size_t cBuffer)
{
	if (Type == MEM_IMAGE)
	{
		StringCchPrintfA(pszBuffer, cBuffer, "img");
	}
	else if (Type == MEM_MAPPED)
	{
		StringCchPrintfA(pszBuffer, cBuffer, "map");
	}
	else if (Type == MEM_PRIVATE)
	{
		StringCchPrintfA(pszBuffer, cBuffer, "pri");
	}
	else
	{
		StringCchPrintfA(pszBuffer, cBuffer, "%x", Type);
	}
}

void StateToString(DWORD State, char* pszBuffer, size_t cBuffer)
{
	if (State == MEM_COMMIT)
	{
		StringCchPrintfA(pszBuffer, cBuffer, "com");
	}
	else if (State == MEM_FREE)
	{
		StringCchPrintfA(pszBuffer, cBuffer, "fre");
	}
	else if (State == MEM_RESERVE)
	{
		StringCchPrintfA(pszBuffer, cBuffer, "res");
	}
	else
	{
		StringCchPrintfA(pszBuffer, cBuffer, "%x", State);
	}
}

void ProtectToString(DWORD Protect, char* pszBuffer, size_t cBuffer)
{
	if (Protect == 0)
	{
		StringCchPrintfA(pszBuffer, cBuffer, "");
	}
	else if (Protect == PAGE_EXECUTE)
	{
		StringCchPrintfA(pszBuffer, cBuffer, "--x");
	}
	else if (Protect == PAGE_EXECUTE_READ)
	{
		StringCchPrintfA(pszBuffer, cBuffer, "r-x");
	}
	else if (Protect == PAGE_EXECUTE_READWRITE)
	{
		StringCchPrintfA(pszBuffer, cBuffer, "rwx");
	}
	else if (Protect == PAGE_EXECUTE_WRITECOPY)
	{
		StringCchPrintfA(pszBuffer, cBuffer, "rcx");
	}
	else if (Protect == PAGE_NOACCESS)
	{
		StringCchPrintfA(pszBuffer, cBuffer, "---");
	}
	else if (Protect == PAGE_READONLY)
	{
		StringCchPrintfA(pszBuffer, cBuffer, "r--");
	}
	else if (Protect == PAGE_READWRITE)
	{
		StringCchPrintfA(pszBuffer, cBuffer, "rw-");
	}
	else if (Protect == PAGE_WRITECOPY)
	{
		StringCchPrintfA(pszBuffer, cBuffer, "rc-");
	}
	else if (Protect == (PAGE_GUARD | PAGE_EXECUTE))
	{
		StringCchPrintfA(pszBuffer, cBuffer, "g--x");
	}
	else if (Protect == (PAGE_GUARD | PAGE_EXECUTE_READ))
	{
		StringCchPrintfA(pszBuffer, cBuffer, "gr-x");
	}
	else if (Protect == (PAGE_GUARD | PAGE_EXECUTE_READWRITE))
	{
		StringCchPrintfA(pszBuffer, cBuffer, "grwx");
	}
	else if (Protect == (PAGE_GUARD | PAGE_EXECUTE_WRITECOPY))
	{
		StringCchPrintfA(pszBuffer, cBuffer, "grcx");
	}
	else if (Protect == (PAGE_GUARD | PAGE_NOACCESS))
	{
		StringCchPrintfA(pszBuffer, cBuffer, "g---");
	}
	else if (Protect == (PAGE_GUARD | PAGE_READONLY))
	{
		StringCchPrintfA(pszBuffer, cBuffer, "gr--");
	}
	else if (Protect == (PAGE_GUARD | PAGE_READWRITE))
	{
		StringCchPrintfA(pszBuffer, cBuffer, "grw-");
	}
	else if (Protect == (PAGE_GUARD | PAGE_WRITECOPY))
	{
		StringCchPrintfA(pszBuffer, cBuffer, "grc-");
	}
	else
	{
		StringCchPrintfA(pszBuffer, cBuffer, "%x", Protect);
	}
}

static BYTE buffer[65536];

typedef union
{
	struct
	{
		DWORD Signature;
		IMAGE_FILE_HEADER FileHeader;
	} ih;

	IMAGE_NT_HEADERS32 ih32;
	IMAGE_NT_HEADERS64 ih64;
} IMAGE_NT_HEADER;

struct SECTIONS
{
	PBYTE pbBeg;
	PBYTE pbEnd;
	CHAR szName[16];
} Sections[256];
DWORD SectionCount = 0;
DWORD Bitness = 0;

PCHAR FindSectionName(PBYTE pbBase, PBYTE& pbEnd)
{
	for (DWORD n = 0; n < SectionCount; n++)
	{
		if (Sections[n].pbBeg == pbBase)
		{
			pbEnd = Sections[n].pbEnd;
			return Sections[n].szName;
		}
	}
	pbEnd = NULL;
	return NULL;
}

ULONG PadToPage(ULONG Size)
{
	return (Size & 0xfff)
		? Size + 0x1000 - (Size & 0xfff)
		: Size;
}

BOOL GetSections(HANDLE hp, PBYTE pbBase)
{
	DWORD beg = 0;
	DWORD cnt = 0;
	SIZE_T done;
	IMAGE_DOS_HEADER idh;

	if (!ReadProcessMemory(hp, pbBase, &idh, sizeof(idh), &done) || done != sizeof(idh))
	{
		return FALSE;
	}

	if (idh.e_magic != IMAGE_DOS_SIGNATURE)
	{
		return FALSE;
	}

	IMAGE_NT_HEADER inh;
	if (!ReadProcessMemory(hp, pbBase + idh.e_lfanew, &inh, sizeof(inh), &done) || done != sizeof(inh))
	{
		//printf("No Read\n");
		return FALSE;
	}

	if (inh.ih.Signature != IMAGE_NT_SIGNATURE)
	{
		//printf("No NT\n");
		return FALSE;
	}

	beg = idh.e_lfanew + FIELD_OFFSET(IMAGE_NT_HEADERS, OptionalHeader) + inh.ih.FileHeader.SizeOfOptionalHeader;
	cnt = inh.ih.FileHeader.NumberOfSections;
	Bitness = (inh.ih32.OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) ? 32 : 64;
#if 0
	//printf("%d %d count=%d\n", beg, Bitness, cnt);
#endif

	IMAGE_SECTION_HEADER ish;
	for (DWORD n = 0; n < cnt; n++)
	{
		if (!ReadProcessMemory(hp, pbBase + beg + n * sizeof(ish), &ish, sizeof(ish), &done) || done != sizeof(ish))
		{
			//printf("No Read\n");
			return FALSE;
		}
		Sections[n].pbBeg = pbBase + ish.VirtualAddress;
		Sections[n].pbEnd = pbBase + ish.VirtualAddress + PadToPage(ish.Misc.VirtualSize);
		memcpy(Sections[n].szName, ish.Name, sizeof(ish.Name));
		Sections[n].szName[sizeof(ish.Name)] = '\0';
#if 0
		//printf("--- %p %s\n", Sections[n].pbBeg, Sections[n].szName);
#endif
	}
	SectionCount = cnt;

	return TRUE;
}

BOOL DumpProcess(HANDLE hp)
{
	ULONG64 base;
	ULONG64 next;

	MEMORY_BASIC_INFORMATION mbi;

	//printf("  %12s %8s %8s: %3s %3s %4s %3s : %8s\n", "Address", "Offset", "Size", "Typ", "Sta", "Prot", "Ini", "Contents");
	//printf("  %12s %8s %8s: %3s %3s %4s %3s : %8s\n", "------------", "--------", "--------", "---", "---", "----", "---", "-----------------");

	for (next = 0;;)
	{
		base = next;
		ZeroMemory(&mbi, sizeof(mbi));
		if (VirtualQueryEx(hp, (PVOID)base, &mbi, sizeof(mbi)) == 0)
		{
			break;
		}
		if ((mbi.RegionSize & 0xfff) == 0xfff)
		{
			break;
		}

		next = (ULONG64)mbi.BaseAddress + mbi.RegionSize;

		if (mbi.State == MEM_FREE)
		{
			continue;
		}

		CHAR szType[16];
		TypeToString(mbi.Type, szType, ARRAYSIZE(szType));
		CHAR szState[16];
		StateToString(mbi.State, szState, ARRAYSIZE(szState));
		CHAR szProtect[16];
		ProtectToString(mbi.Protect, szProtect, ARRAYSIZE(szProtect));
		CHAR szAllocProtect[16];
		ProtectToString(mbi.AllocationProtect, szAllocProtect, ARRAYSIZE(szAllocProtect));

		CHAR szFile[MAX_PATH];
		szFile[0] = '\0';
		DWORD cb = 0;
		PCHAR pszFile = szFile;

		if (base == (ULONG64)mbi.AllocationBase)
		{
#if 0
			cb = pfGetMappedFileName(hp, (PVOID)mbi.AllocationBase, szFile, ARRAYSIZE(szFile));
#endif
			if (GetSections(hp, (PBYTE)mbi.AllocationBase))
			{
				next = base + 0x1000;
				StringCchPrintfA(szFile, ARRAYSIZE(szFile), "%d-bit PE", Bitness);
			}
		}
		if (cb > 0)
		{
			for (DWORD c = 0; c < cb; c++)
			{
				szFile[c] = (szFile[c] >= 'a' && szFile[c] <= 'z')
					? szFile[c] - 'a' + 'A'
					: szFile[c];
			}
			szFile[cb] = '\0';
		}

		if ((pszFile = strrchr(szFile, '\\')) == NULL)
		{
			pszFile = szFile;
		}
		else
		{
			pszFile++;
		}

		PBYTE pbEnd;
		PCHAR pszSect = FindSectionName((PBYTE)base, pbEnd);
		if (pszSect != NULL)
		{
			pszFile = pszSect;
			if (next > (ULONG64)pbEnd)
			{
				next = (ULONG64)pbEnd;
			}
		}

		CHAR szDesc[128];
		ZeroMemory(&szDesc, ARRAYSIZE(szDesc));
		if (base == (ULONG64)mbi.AllocationBase)
		{
			StringCchPrintfA(szDesc, ARRAYSIZE(szDesc), "  %12I64x %8I64x %8I64x: %3s %3s %4s %3s : %s",
				(ULONG64)base,
				(ULONG64)base - (ULONG64)mbi.AllocationBase,
				(ULONG64)next - (ULONG64)base,
				szType,
				szState,
				szProtect,
				szAllocProtect,
				pszFile);
		}
		else
		{
			StringCchPrintfA(szDesc, ARRAYSIZE(szDesc), "  %12s %8I64x %8I64x: %3s %3s %4s %3s : %s",
				"-",
				(ULONG64)base - (ULONG64)mbi.AllocationBase,
				(ULONG64)next - (ULONG64)base,
				szType,
				szState,
				szProtect,
				szAllocProtect,
				pszFile);
		}
		//printf("%s\n", szDesc);
	}
	return TRUE;
}

typedef enum _SECTION_INHERIT
{
	ViewShare = 1,
	ViewUnmap = 2
} SECTION_INHERIT;

static NTSTATUS(*PNtMapViewOfSection)(
	HANDLE SectionHandle,
	HANDLE ProcessHandle,
	PVOID* BaseAddress,
	ULONG_PTR ZeroBits,
	SIZE_T CommitSize,
	PLARGE_INTEGER SectionOffset,
	PSIZE_T ViewSize,
	SECTION_INHERIT InheritDisposition,
	ULONG AllocationType,
	ULONG Win32Protect);

DWORD findPidByName(const char* pname)
{
	HANDLE h;
	PROCESSENTRY32 procSnapshot;
	h = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	procSnapshot.dwSize = sizeof(PROCESSENTRY32);

	do
	{
		if (!strcmp((const char*)procSnapshot.szExeFile, pname))
		{
			DWORD pid = procSnapshot.th32ProcessID;
			CloseHandle(h);
			return pid;
		}
	} while (Process32Next(h, &procSnapshot));

	CloseHandle(h);
	return 0;
}

HMODULE findRemoteHModule(DWORD dwProcessId, const char* szdllout)
{
	MODULEENTRY32 me = { sizeof(me) };
	BOOL bMore = FALSE;
	HANDLE hSnapshot;


	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwProcessId);
	if (hSnapshot == (HANDLE)-1) {
		//printf("CreateToolhelp32Snapshot Failed.\n");
	}
	bMore = Module32First(hSnapshot, &me);
	for (; bMore; bMore = Module32Next(hSnapshot, &me))
	{
		//printf("%s\n", (LPCSTR)me.szModule);
		//wprintf(L"%s\n", (LPCWSTR)me.szExePath);
		//printf("%s\n", szdllout);
		if (
			//!_stricmp((LPCSTR)me.szModule, szdllout) ||
			!_tcsicmp((LPCTSTR)me.szExePath, szdllout))
		{
			//printf("find!\n");
			//wprintf(L"%s\n", (LPCWSTR)me.szExePath);
			return (HMODULE)me.modBaseAddr;
		}
	}
	return NULL;
}

static std::unordered_map<std::string, std::vector<std::pair<DWORD64, DWORD >>>rwxList;


void CallVirtualAllocEx(LPVOID monMMF) {

	Form1^ form = (Form1^)Application::OpenForms[0];

	char* cp = (char*)monMMF;
	
	fprintf(pFile, "%s\n", cp);


	std::string pid(strtok(cp, ":"));
	form->logging(gcnew System::String(pid.c_str()));
	form->logging( gcnew System::String(" : VirtualAlloc -> Protection : PAGE_EXECUTE_READWRITE\r\n"));

	DWORD64 ret = (DWORD64)strtoll(strtok(NULL, ":"), NULL, 16 );
	DWORD dwSize = (DWORD)strtol(strtok(NULL, ":") , NULL, 16);

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
			if(i.first <= lpStartAddress && (i.first+(DWORD64)i.second  > lpStartAddress  ))
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
				MessageBoxA(NULL,"SetWindowLongPtrA Code Injection Detected!" , "Detection Alert!", MB_OK | MB_ICONQUESTION);
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



//////////////////////////////////////////////////////////////////////// main.
//
int CDECL mon(int isFree_)
{
	BOOLEAN isFree = (BOOLEAN)isFree_;
	BOOLEAN fVerbose = FALSE;

	LPCSTR rpszDllsRaw[1];
	LPCSTR rpszDllsOut[1];
	DWORD nDlls = 1;


	rpszDllsRaw[0] = NULL;
	rpszDllsOut[0] = NULL;


	char dlln[] = "FAST-DLL.dll";
	rpszDllsRaw[0] = (LPCSTR)dlln;





	///////////////////////////////////////////////////////// Validate DLLs.

	for (DWORD n = 0; n < nDlls; n++)
	{
		CHAR szDllPath[1024];
		PCHAR pszFilePart = NULL;

		if (!GetFullPathNameA(rpszDllsRaw[n], ARRAYSIZE(szDllPath), szDllPath, &pszFilePart))
		{
			//printf("fast.exe: Error: %s is not a valid path name..\n",
				//rpszDllsRaw[n]);
			return 9002;
		}

		DWORD c = (DWORD)strlen(szDllPath) + 1;
		PCHAR psz = new CHAR[c];
		StringCchCopyA(psz, c, szDllPath);
		rpszDllsOut[n] = psz;

		HMODULE hDll = LoadLibraryExA(rpszDllsOut[n], NULL, DONT_RESOLVE_DLL_REFERENCES);
		if (hDll == NULL)
		{
			//printf("fast.exe: Error: %s failed to load (error %ld).\n",
				//rpszDllsOut[n],
				//GetLastError());
			return 9003;
		}

		ExportContext ec;
		ec.fHasOrdinal1 = FALSE;
		ec.nExports = 0;
		DetourEnumerateExports(hDll, &ec, ExportCallback);
		FreeLibrary(hDll);

		if (!ec.fHasOrdinal1)
		{
			//printf("fast.exe: Error: %s does not export ordinal #1.\n",
				//rpszDllsOut[n]);
			//printf("             See help entry DetourCreateProcessfastEx in Detours.chm.\n");
			return 9004;
		}
	}

	CHAR szCommand[2048];


	TOKEN_PRIVILEGES tp;
	BOOL bResult = FALSE;
	HANDLE hToken = NULL;
	DWORD dwSize;

	ZeroMemory(&tp, sizeof(tp));
	tp.PrivilegeCount = 1;

	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken) &&
		LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid))
	{
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
		bResult = AdjustTokenPrivileges(hToken, FALSE, &tp, 0, NULL, &dwSize);
	}
	CloseHandle(hToken);

	HANDLE hProcess = NULL, hThread = NULL;
	HMODULE hMod = NULL;


	LPTHREAD_START_ROUTINE pThreadProc = NULL;

	HANDLE fm = NULL;
	char* map_addr;
	LPVOID lpMap = 0;
	SIZE_T viewsize = 0;
	PNtMapViewOfSection = (NTSTATUS(*)(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID * BaseAddress, ULONG_PTR ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, SECTION_INHERIT InheritDisposition, ULONG AllocationType, ULONG Win32Protect)) GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtMapViewOfSection");

	hMod = GetModuleHandleA("kernel32.dll");
	if (!hMod)
	{
		return FALSE;
	}



	LPCSTR sz = NULL;
	DWORD dwBufSize = 0;
	DWORD thispid = GetCurrentProcessId();


	if (!isFree)
	{
		//printf("Injection...\n");
		fprintf(pFile, "Hook DLLs!\n");
		pThreadProc = (LPTHREAD_START_ROUTINE)GetProcAddress(hMod, "LoadLibraryA");


	}
	else
	{
		//printf("Freeing...\n");
		fprintf(pFile, "UnHook DLLs!\n");
		pThreadProc = (LPTHREAD_START_ROUTINE)GetProcAddress(hMod, "FreeLibrary");

	}

	if (!pThreadProc)
	{
		return FALSE;
	}

	// if (fVerbose)
	// {
	//     DumpProcess(hProcess);
	// }

	// //WaitForSingleObject(hThread, INFINITE);
	// CloseHandle(hThread);
	// CloseHandle(hProcess);

	if (!isFree)
	{
		sz = rpszDllsOut[0];
		dwBufSize = (DWORD)(strlen(sz) + 1) * sizeof(char);

		fm = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE,
			0,
			(DWORD)((dwBufSize + sizeof(DWORD) + 11 * sizeof(DWORD64))), (LPCSTR)"shared");


		map_addr = (char*)MapViewOfFile(fm, FILE_MAP_ALL_ACCESS, 0, 0, 0);

		memcpy(map_addr, sz, dwBufSize);
		memcpy(map_addr + dwBufSize, &thispid, sizeof(DWORD));


		//printf("c %p\n", CallVirtualAllocEx);
		//printf("c %llu\n", CallVirtualAllocEx);
		LPVOID fp = CallVirtualAllocEx;
		memcpy(map_addr + dwBufSize + sizeof(DWORD), &fp, sizeof(DWORD64));
		//printf("%d\t%d\t%llu\n", thispid, *(DWORD*)(map_addr + dwBufSize), *(DWORD64*)(map_addr + dwBufSize + sizeof(DWORD)));

		//printf("c %p\n", CallLoadLibraryA);
		//printf("c %llu\n", CallLoadLibraryA);
		fp = CallQueueUserAPC;
		memcpy(map_addr + dwBufSize + sizeof(DWORD) + sizeof(DWORD64), &fp, sizeof(DWORD64));
		//printf("%d\t%d\t%llu\n", thispid, *(DWORD*)(map_addr + dwBufSize), *(DWORD64*)(map_addr + dwBufSize + sizeof(DWORD) + sizeof(DWORD64)));

		fp = CallWriteProcessMemory;
		memcpy(map_addr + dwBufSize + sizeof(DWORD) + 2 * sizeof(DWORD64), &fp, sizeof(DWORD64));

		fp = CallCreateRemoteThread;
		memcpy(map_addr + dwBufSize + sizeof(DWORD) + 3 * sizeof(DWORD64), &fp, sizeof(DWORD64));

		fp = CallNtMapViewOfSection;
		memcpy(map_addr + dwBufSize + sizeof(DWORD) + 4 * sizeof(DWORD64), &fp, sizeof(DWORD64));

		fp = CallCreateFileMappingA;
		memcpy(map_addr + dwBufSize + sizeof(DWORD) + 5 * sizeof(DWORD64), &fp, sizeof(DWORD64));

		fp = CallGetThreadContext;
		memcpy(map_addr + dwBufSize + sizeof(DWORD) + 6 * sizeof(DWORD64), &fp, sizeof(DWORD64));

		fp = CallSetThreadContext;
		memcpy(map_addr + dwBufSize + sizeof(DWORD) + 7 * sizeof(DWORD64), &fp, sizeof(DWORD64));

		fp = CallNtQueueApcThread;
		memcpy(map_addr + dwBufSize + sizeof(DWORD) + 8 * sizeof(DWORD64), &fp, sizeof(DWORD64));

		fp = CallSetWindowLongPtrA;
		memcpy(map_addr + dwBufSize + sizeof(DWORD) + 9 * sizeof(DWORD64), &fp, sizeof(DWORD64));

		fp = CallSleepEx;
		memcpy(map_addr + dwBufSize + sizeof(DWORD) + 10 * sizeof(DWORD64), &fp, sizeof(DWORD64));


	}

	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32 entry = { sizeof(PROCESSENTRY32) };
	Process32First(hSnap, &entry);
	do
	{

		if (thispid == entry.th32ProcessID)
			continue;
		hProcess = OpenProcess(MAXIMUM_ALLOWED, FALSE, entry.th32ProcessID);
		if (!(hProcess))
		{

			//printf("OpenProcess(%ld) failed!!! [%ld]\n", entry.th32ProcessID, GetLastError());
			continue;
		}
		//printf("OpenProcess(%ld) Succeed!!! \n", entry.th32ProcessID);
		(*PNtMapViewOfSection)(fm, hProcess, &lpMap, 0, dwBufSize,
			nullptr, &viewsize, ViewUnmap, 0, PAGE_READONLY);


		if (fVerbose)
		{
			DumpProcess(hProcess);
		}

		if (!isFree)
		{
			hThread = CreateRemoteThread(hProcess, NULL, 0, pThreadProc, lpMap, 0, NULL);
			if (!hThread)
			{
				//return FALSE;
				//printf("CreateRemoteThread(%ld) failed!!! [%ld]\n", entry.th32ProcessID, GetLastError());
				continue;
			}
		}
		else
		{
			HMODULE fdllpath = findRemoteHModule(entry.th32ProcessID, (const char*)rpszDllsOut[0]);
			if (fdllpath != NULL)
			{
				hThread = CreateRemoteThread(hProcess, NULL, 0, pThreadProc, fdllpath, 0, NULL);
				if (!hThread)
				{
					//return FALSE;
					//printf("CreateRemoteThread(%ld) failed!!! [%ld]\n", entry.th32ProcessID, GetLastError());
					continue;
				}
			}
		}

		if (fVerbose)
		{
			DumpProcess(hProcess);
		}

		//WaitForSingleObject(hThread, INFINITE);
		CloseHandle(hThread);
		CloseHandle(hProcess);

	} while (Process32Next(hSnap, &entry));

	CloseHandle(hSnap);


	//printf("fast.exe: Finished.\n");

	//if (!isFree)
	//    while (TRUE)
	//        Sleep(0);

	return 0; //dwResult;
}
//
///////////////////////////////////////////////////////////////// End of File.