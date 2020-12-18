#pragma once
#include "fast-monitor-win32.h"
#include <inttypes.h>

#define MSG_SIZE 384

static std::unordered_map<std::string, std::vector<std::vector<std::tuple<DWORD64, DWORD, std::string, UCHAR, std::string>>>> rwxList;
extern FILE* pFile;

void exDumpIt();
void insertList(std::string callee_pid, DWORD64 ret, DWORD dwSize, std::string caller_pid, UCHAR flags, std::string caller_path);
//std::string getProcessIdUsingTargetAddress(DWORD64 target);
BOOL checkList(std::string pid, DWORD64 target ,  DWORD dwSize, std::string caller_pid, UCHAR flags, std::string caller_path);

DWORD WorkAfterDetection(LPVOID lpParam);
int fileExists(TCHAR* file);
void exGhidraHeadless(LPCSTR filename);
//void memory_region_dump(DWORD pid, const char* name, LPVOID entryPoint, std::unordered_map<std::string, std::vector<std::vector<std::tuple<DWORD64, DWORD, std::string, UCHAR, std::string>>>>& list);

BOOLEAN CompareCode(int pid, int caller_pid);
BOOL calcMD5(byte* data, LPSTR md5);
DWORD64 GetModuleAddress(const char* moduleName, int pid);

typedef struct {
	BOOL runCompareCode, runMemoryRegionDump, runDumpIt, runMessageBox;
	char callee_pid[10], caller_pid[10], api_name[30];
	LPVOID entryPoint;
	char message[100];
	UINT message_type;
} WorkAfterDetectionParam;

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
void CallVirtualProtectEx(LPVOID monMMF);
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


