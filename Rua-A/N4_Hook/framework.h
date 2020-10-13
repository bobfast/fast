#pragma once
#include <windows.h>
#include <winnt.h>
#include <stdio.h>

#define DLLBASIC_API extern "C" __declspec(dllexport)
// DbgPrint Function Pointer Type
typedef NTSTATUS(NTAPI* DBGPRINT)(
	LPCSTR Format,
	...
	);

//NtSuspendThread
typedef NTSTATUS (NTAPI* NTSUSPENDTHREAD)(
	HANDLE ThreadHandle,
	PULONG PreviousSuspendCount
);

//NtGetContextThread
typedef NTSTATUS (NTAPI* NTGETCONTEXTTHREAD)(
	HANDLE ThreadHandle,
	PCONTEXT pContext
);

//NtSetContextThread
typedef NTSTATUS (NTAPI* NTSETCONTEXTTHREAD)(
	HANDLE ThreadHandle,
	PCONTEXT lpContext
);
//NtResumeThread
typedef NTSTATUS (NTAPI* RESUMETHREAD)(
	HANDLE ThreadHandle
);

// Data Types
typedef struct {
	HANDLE process;
	HANDLE thread;
	LPVOID addr;
	LPVOID entry_point;
	SIZE_T tot_write;
	SIZE_T tot_alloc;
} RUNTIME_MEM_ENTRY;
