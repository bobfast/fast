#pragma once
#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <locale.h>
#include <tchar.h>
#include <process.h>
#include <psapi.h>
#include "dbghelp.h"
#pragma comment(lib, "psapi.lib")
#pragma comment(lib,"Dbghelp.lib")
const int MaxNameLen = 256;

#define DLLBASIC_API extern "C" __declspec(dllexport)
#define MSG_SIZE 3000
#define NT_SUCCESS(status) (((NTSTATUS)(status)) >= 0)

// Enumeration type for NtMapViewOfSection
typedef enum class _SECTION_INHERIT {
	ViewShare = 1,
	ViewUnmap = 2
} SECTION_INHERIT, * PSECTION_INHERIT;

// NtMapViewOfSection Function Pointer Type
typedef NTSTATUS(NTAPI* NTMAPVIEWOFSECTION)(
	HANDLE SectionHandle,
	HANDLE ProcessHandle,
	PVOID* BaseAddress,
	ULONG_PTR ZeroBits,
	SIZE_T CommitSize,
	PLARGE_INTEGER SectionOffset,
	PSIZE_T ViewSize,
	SECTION_INHERIT InheritDisposition,
	ULONG AllocationType,
	ULONG Win32Protect
	);

// Struct types for NtCreateThreadEx
typedef struct _UNICODE_STRING {
	WORD Length;
	WORD MaximumLength;
	WORD* Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
	ULONG Length;
	PVOID RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG Attributes;
	PVOID SecurityDescriptor;
	PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

typedef struct _THREAD_INFO {
	ULONG   Flags;
	ULONG   BufferSize;
	PVOID   lpBuffer;
	ULONG   Unknown;
} THREAD_INFO, * PTHREAD_INFO;

typedef struct _CREATE_THREAD_INFO {
	ULONG       Length;
	THREAD_INFO Client;
	THREAD_INFO TEB;
} CREATE_THREAD_INFO;

// CreateRemoteThread Function Pointer Type
typedef HANDLE(WINAPI * CREATEREMOTETHREAD)(
	HANDLE                 hProcess,
	LPSECURITY_ATTRIBUTES  lpThreadAttributes,
	SIZE_T                 dwStackSize,
	LPTHREAD_START_ROUTINE lpStartAddress,
	LPVOID                 lpParameter,
	DWORD                  dwCreationFlags,
	LPDWORD                lpThreadId
	);

// VirtualAllocEx Function Pointer Type
typedef LPVOID(WINAPI * VIRTUALALLOCEX)(
	HANDLE hProcess,
	LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD  flAllocationType,
	DWORD  flProtect
	);

// WriteProcessMemory Function Pointer Type
typedef BOOL(WINAPI * WRITEPROCESSMEMORY)(
	HANDLE  hProcess,
	LPVOID  lpBaseAddress,
	LPCVOID lpBuffer,
	SIZE_T  nSize,
	SIZE_T* lpNumberOfBytesWritten
	);

// DbgPrint Function Pointer Type
typedef NTSTATUS(NTAPI* DBGPRINT)(
	LPCSTR Format,
	...
	);

// Enumeration & struct types for NtQuerySystemInformation
typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemBasicInformation,
	SystemProcessorInformation,
	SystemPerformanceInformation,
	SystemTimeOfDayInformation,
	SystemPathInformation,
	SystemProcessInformation,
	SystemCallCountInformation,
	SystemDeviceInformation,
	SystemProcessorPerformanceInformation,
	SystemFlagsInformation,
	SystemCallTimeInformation,
	SystemModuleInformation,
	SystemLocksInformation,
	SystemStackTraceInformation,
	SystemPagedPoolInformation,
	SystemNonPagedPoolInformation,
	SystemHandleInformation,
	SystemObjectInformation,
	SystemPageFileInformation,
	SystemVdmInstemulInformation,
	SystemVdmBopInformation,
	SystemFileCacheInformation,
	SystemPoolTagInformation,
	SystemInterruptInformation,
	SystemDpcBehaviorInformation,
	SystemFullMemoryInformation,
	SystemLoadGdiDriverInformation,
	SystemUnloadGdiDriverInformation,
	SystemTimeAdjustmentInformation,
	SystemSummaryMemoryInformation,
	SystemNextEventIdInformation,
	SystemEventIdsInformation,
	SystemCrashDumpInformation,
	SystemExceptionInformation,
	SystemCrashDumpStateInformation,
	SystemKernelDebuggerInformation,
	SystemContextSwitchInformation,
	SystemRegistryQuotaInformation,
	SystemExtendServiceTableInformation,
	SystemPrioritySeperation,
	SystemPlugPlayBusInformation,
	SystemDockInformation,
	_SystemPowerInformation,
	SystemProcessorSpeedInformation,
	SystemCurrentTimeZoneInformation,
	SystemLookasideInformation
} SYSTEM_INFORMATION_CLASS, * PSYSTEM_INFORMATION_CLASS;

typedef LONG KPRIORITY;
typedef LONG KWAIT_REASON;
#define STATUS_INFO_LENGTH_MISMATCH (0xC0000004L)

typedef struct _VM_COUNTERS {
	SIZE_T PeakVirtualSize;
	SIZE_T VirtualSize;
	ULONG PageFaultCount;
	// Padding here in 64-bit
	SIZE_T PeakWorkingSetSize;
	SIZE_T WorkingSetSize;
	SIZE_T QuotaPeakPagedPoolUsage;
	SIZE_T QuotaPagedPoolUsage;
	SIZE_T QuotaPeakNonPagedPoolUsage;
	SIZE_T QuotaNonPagedPoolUsage;
	SIZE_T PagefileUsage;
	SIZE_T PeakPagefileUsage;
} VM_COUNTERS;

typedef struct _CLIENT_ID
{
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
} CLIENT_ID, * PCLIENT_ID;

typedef struct _SYSTEM_THREAD {
	LARGE_INTEGER           KernelTime;
	LARGE_INTEGER           UserTime;
	LARGE_INTEGER           CreateTime;
	ULONG                   WaitTime;
	PVOID                   StartAddress;
	CLIENT_ID               ClientId;
	KPRIORITY               Priority;
	LONG                    BasePriority;
	ULONG                   ContextSwitchCount;
	ULONG                   State;
	KWAIT_REASON            WaitReason;
} SYSTEM_THREAD, * PSYSTEM_THREAD;

typedef struct _SYSTEM_PROCESS_INFORMATION {
	ULONG            NextEntryDelta;
	ULONG            ThreadCount;
	ULONG            Reserved1[6];
	LARGE_INTEGER   CreateTime;
	LARGE_INTEGER   UserTime;
	LARGE_INTEGER   KernelTime;
	UNICODE_STRING  ProcessName;
	KPRIORITY        BasePriority;
	ULONG            ProcessId;
	ULONG            InheritedFromProcessId;
	ULONG            HandleCount;
	ULONG            Reserved2[2];
	VM_COUNTERS        VmCounters;
	IO_COUNTERS        IoCounters;
	SYSTEM_THREAD  Threads[1];
} SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;

// NtQuerySystemInformation Function Pointer Type
typedef NTSTATUS(NTAPI* NTQUERYSYSTEMINFORMATION)(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength
	);


void printStack(char buf[]) {
	BOOL    result;

	char* sp;
	sp = buf + strnlen_s(buf, MSG_SIZE);

	HMODULE hModule;
	HANDLE Process;
	HANDLE Thread;
	STACKFRAME64        stack;
	ULONG               frame;
	DWORD64             displacement;
	char buffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(TCHAR)];
	PSYMBOL_INFO pSymbol = (PSYMBOL_INFO)buffer;

	CONTEXT ctx;

	char module[MaxNameLen];


	RtlCaptureContext(&ctx);
	memset(&stack, 0, sizeof(STACKFRAME64));

	displacement = 0;
#if !defined(_M_AMD64)
	stack.AddrPC.Offset = (*ctx).Eip;
	stack.AddrPC.Mode = AddrModeFlat;
	stack.AddrStack.Offset = (*ctx).Esp;
	stack.AddrStack.Mode = AddrModeFlat;
	stack.AddrFrame.Offset = (*ctx).Ebp;
	stack.AddrFrame.Mode = AddrModeFlat;
#endif
	Process = GetCurrentProcess();
	Thread = GetCurrentThread();
	SymInitialize(Process, NULL, TRUE); //load symbols
	DWORD offset = 0;
	for (frame = 0; ; frame++)
	{
		//get next call from stack
		result = StackWalk64
		(
#if defined(_M_AMD64)
			IMAGE_FILE_MACHINE_AMD64
#else
			IMAGE_FILE_MACHINE_I386
#endif
			,
			Process,
			Thread,
			&stack,
			&ctx,
			NULL,
			SymFunctionTableAccess64,
			SymGetModuleBase64,
			NULL
		);

		if (!result) break;


		//get symbol name for address
		pSymbol->SizeOfStruct = sizeof(SYMBOL_INFO);
		pSymbol->MaxNameLen = MAX_SYM_NAME;



		if (!SymFromAddr(Process, (ULONG64)stack.AddrPC.Offset, &displacement, pSymbol)) {
			sp += sprintf_s(sp, MSG_SIZE - strnlen_s(buf, MSG_SIZE), "<br>%x\n", stack.AddrStack.Offset);
			continue;
		}

		if (frame == 0) {
			offset = stack.AddrFrame.Offset;
			continue;
		}

		//try to get line


		hModule = NULL;
		lstrcpyA(module, "");
		GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
			(LPCTSTR)(stack.AddrPC.Offset), &hModule);

		//at least print module name

		if (hModule != NULL) {
			HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, GetCurrentProcessId());

			if (hProc != NULL) {
				if (GetModuleBaseNameA(hProc, hModule, module, MaxNameLen) != 0) {
					sp += sprintf_s(sp, MSG_SIZE - strnlen_s(buf, MSG_SIZE), "\n\t<br> %s!%s +0x%x", module, pSymbol->Name, stack.AddrFrame.Offset - offset);
					CloseHandle(hProc);
				}
			}

		}


	}
	sprintf_s(sp, MSG_SIZE - strnlen_s(buf, MSG_SIZE), "*");
	SymCleanup(Process);
	CloseHandle(Thread);
	CloseHandle(Process);
}
// RtlCreateUserThread Function Pointer Type
typedef NTSTATUS(NTAPI* pfnRtlCreateUserThread)(
	IN HANDLE ProcessHandle,
	IN PSECURITY_DESCRIPTOR SecurityDescriptor OPTIONAL,
	IN BOOLEAN CreateSuspended,
	IN ULONG StackZeroBits OPTIONAL,
	IN SIZE_T StackReserve OPTIONAL,
	IN SIZE_T StackCommit OPTIONAL,
	IN PTHREAD_START_ROUTINE StartAddress,
	IN PVOID Parameter OPTIONAL,
	OUT PHANDLE ThreadHandle OPTIONAL,
	OUT PCLIENT_ID ClientId OPTIONAL);
