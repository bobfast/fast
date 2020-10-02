#pragma once
#include <Windows.h>

#define DLLBASIC_API extern "C" __declspec(dllexport)

// Enumeration type for NtMapViewOfSection
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

// NtCreateThreadEx Function Pointer Type
typedef NTSTATUS(NTAPI* NTCREATETHREADEX)(
	PHANDLE ThreadHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	HANDLE ProcessHandle,
	LPTHREAD_START_ROUTINE StartAddress,
	LPVOID Parameter,
	BOOL CreateSuspended,
	DWORD StackZeroBits,
	DWORD SizeOfStackCommit,
	DWORD SizeOfStackReserve,
	CREATE_THREAD_INFO *ThreadInfo
	);

// NtAllocateVirtualMemory Function Pointer Type
typedef NTSTATUS(NTAPI* NTALLOCATEVIRTUALMEMORY)(
	HANDLE ProcessHandle,
	PVOID *BaseAddress,
	ULONG_PTR ZeroBits,
	PSIZE_T RegionSize,
	ULONG AllocationType,
	ULONG Protect
	);