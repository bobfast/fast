#pragma once
#include <stdio.h>
#include <Windows.h>
#include <detours.h>
#include <strsafe.h>
#include <tlhelp32.h>
#include <tchar.h>

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

static LPCSTR rpszDllsOut = NULL;
static UINT32 hook_cnt = 0;
static DWORD thispid = GetCurrentProcessId();
static HANDLE fm = NULL;
static DWORD dwBufSize = 0;
static char* map_addr;

HMODULE findRemoteHModule(DWORD dwProcessId, const char* szdllout);
void init();
void exiting();
int mon(int isFree_);
