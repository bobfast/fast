#pragma once
#include "Form1.h"
using namespace CppCLRWinformsProjekt;
#define MSG_SIZE 256

static std::unordered_map<std::string, std::vector<std::pair<DWORD64, DWORD>>> rwxList;
extern FILE* pFile;

int fileExists(TCHAR* file);
void memory_region_dump(DWORD pid, const char* filename, std::unordered_map<std::string, std::vector<std::pair<DWORD64, DWORD>>>& list);






//######################################################

void CallVirtualAllocEx(LPVOID monMMF);
void CallQueueUserAPC(LPVOID monMMF);
void CallWriteProcessMemory(LPVOID monMMF);
void CallCreateRemoteThread(LPVOID monMMF);
void CallNtMapViewOfSection(LPVOID monMMF);
void CallCreateFileMappingA(LPVOID monMMF);
void CallGetThreadContext(LPVOID monMMF);
void CallSetThreadContext(LPVOID monMMF);
void CallNtQueueApcThread(LPVOID monMMF);
void CallSetWindowLongPtrA(LPVOID monMMF);
void CallSetPropA(LPVOID monMMF);
void CallSleepEx(LPVOID monMMF);

//######################################################

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

//######################################################

struct ExportContext
{
	BOOL fHasOrdinal1;
	ULONG nExports;
};

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
void TypeToString(DWORD Type, char* pszBuffer, size_t cBuffer);
void StateToString(DWORD State, char* pszBuffer, size_t cBuffer);
void ProtectToString(DWORD Protect, char* pszBuffer, size_t cBuffer);
PCHAR FindSectionName(PBYTE pbBase, PBYTE& pbEnd);
ULONG PadToPage(ULONG Size);
BOOL GetSections(HANDLE hp, PBYTE pbBase);
BOOL DumpProcess(HANDLE hp);
//######################################################