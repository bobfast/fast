#pragma once
#include <windows.h>
#include <stdio.h>

#define DLLBASIC_API extern "C" __declspec(dllexport)

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