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
	CONTEXT pContext
);
typedef BOOL (WINAPI* GETTHREADCONTEXT)(
	HANDLE hThread,
	LPCONTEXT lpContext
);

//NtSetContextThread
typedef NTSTATUS (NTAPI* NTSETCONTEXTTHREAD)(
	HANDLE ThreadHandle,
	CONTEXT lpContext
);
typedef BOOL (WINAPI* SETTHREADCONTEXT)(
	HANDLE hThread,
	CONTEXT* lpContext
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
#include <cstdint>

/// @brief log level
#define log_level_debug         3
#define log_level_info          2
#define log_level_warn          1
#define log_level_critical      0
#define log_level_error         log_level_critical

/// @brief	ntdll::DbgPrintEx 
///			(ref) dpfilter.h
#define DPFLTR_ERROR_LEVEL 0
#define DPFLTR_WARNING_LEVEL 1
#define DPFLTR_TRACE_LEVEL 2
#define DPFLTR_INFO_LEVEL 3
#define DPFLTR_MASK 0x80000000

#define DPFLTR_IHVDRIVER_ID 77

typedef LONG_PTR(NTAPI* TrueNtUserSetWindowLongPtr)(
	HWND hWnd,
	DWORD Index,
	LONG_PTR NewValue,
	BOOL Ansi);

typedef NTSTATUS(NTAPI* TrueNtAllocateVirtualMemory)(
	HANDLE ProcessHandle,
	PVOID* BaseAddress,
	ULONG_PTR ZeroBits,
	PSIZE_T RegionSize,
	ULONG AllocationType,
	ULONG Protect
	);

typedef NTSTATUS(NTAPI* TrueNtWriteVirtualMemory)(
	HANDLE ProcessHandle,
	PVOID BaseAddress,
	PVOID Buffer,
	ULONG NumberOfBytesToWrite,
	PULONG NumberOfBytesWritten
	);

typedef enum _SECTION_INHERIT {
	ViewShare = 1,
	ViewUnmap = 2
} SECTION_INHERIT, * PSECTION_INHERIT;

// NtMapViewOfSection Function Pointer Type
typedef NTSTATUS(NTAPI* NTMAPVIEWOFSECTION)(
	HANDLE SectionHandle,
	HANDLE ProcessHandle,
	PVOID* BaseAddress,
	ULONG ZeroBits,
	ULONG CommitSize,
	PLARGE_INTEGER SectionOffset,
	PULONG ViewSize,
	SECTION_INHERIT InheritDisposition,
	ULONG AllocationType,
	ULONG Protect
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
typedef HANDLE(WINAPI* CREATEREMOTETHREAD)(
	HANDLE                 hProcess,
	LPSECURITY_ATTRIBUTES  lpThreadAttributes,
	SIZE_T                 dwStackSize,
	LPTHREAD_START_ROUTINE lpStartAddress,
	LPVOID                 lpParameter,
	DWORD                  dwCreationFlags,
	LPDWORD                lpThreadId
	);

// VirtualAllocEx Function Pointer Type
typedef LPVOID(WINAPI* VIRTUALALLOCEX)(
	HANDLE hProcess,
	LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD  flAllocationType,
	DWORD  flProtect
	);

// WriteProcessMemory Function Pointer Type
typedef BOOL(WINAPI* WRITEPROCESSMEMORY)(
	HANDLE  hProcess,
	LPVOID  lpBaseAddress,
	LPCVOID lpBuffer,
	SIZE_T  nSize,
	SIZE_T* lpNumberOfBytesWritten
	);

// NtProtectVirtualMemory Function Pointer Type
typedef NTSTATUS(NTAPI* NTPROTECTVIRTUALMEMORY)(
	HANDLE ProcessHandle,
	PVOID* BaseAddress,
	PULONG NumberOfBytesToProtect,
	ULONG NewAccessProtection,
	PULONG OldAccessProtection
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