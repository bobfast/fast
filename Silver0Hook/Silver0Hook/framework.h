#pragma once

//#define WIN32_LEAN_AND_MEAN             // 거의 사용되지 않는 내용을 Windows 헤더에서 제외합니다.
// Windows 헤더 파일
#include <windows.h>

/*
#define PAGE_EXECUTE_READ					(0x00000020)
#define PAGE_EXECUTE_READWRITE				(0x00000040)
#define PAGE_EXECUTE_WRITECOPY				(0x00000080)
#define PAGE_READONLY						(0x00000002)
#define PAGE_READWRITE						(0x00000004)
#define PAGE_WRITECOPY						(0x00000008)
#define SEC_COMMIT							(0x08000000)
#define SEC_IMAGE							(0x01000000)
#define SEC_IMAGE_NO_EXECUTE				(0x11000000)
#define SEC_LARGE_PAGES						(0x80000000)
#define SEC_NOCACHE							(0x10000000)
#define SEC_RESERVE							(0x04000000)
#define SEC_WRITECOMBINE					(0x40000000)
#define NUMA_NO_PREFERRED_NODE				(0xffffffff)
*/

/// <summary>
/// NtOpenProcess 
/// </summary>
typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct POBJECT_ATTRIBUTES {
	ULONG           Length;
	HANDLE          RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG           Attributes;
	PVOID           SecurityDescriptor;
	PVOID           SecurityQualityOfService;
} POBJECT_ATTRIBUTES;

typedef struct PCLIENT_ID {
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
} PCLIENT_ID;

typedef NTSTATUS(NTAPI* NTOPENPROCESS)(
	PHANDLE             ProcessHandle,
	ACCESS_MASK          AccessMask,
	POBJECT_ATTRIBUTES   ObjectAttributes,
	PCLIENT_ID           ClientId
);


/// <summary>
/// CreateFileMappingNumaW  (memoryapi.h)
/// </summary>
static HANDLE(*TrueCreateFileMappingNumaW)(
	HANDLE                hFile,
	LPSECURITY_ATTRIBUTES lpFileMappingAttributes,
	DWORD                 flProtect,
	DWORD                 dwMaximumSizeHigh,
	DWORD                 dwMaximumSizeLow,
	LPCWSTR               lpName,
	DWORD                 nndPreferred
	) = CreateFileMappingNumaW;


/// <summary>
/// NtMapViewOfSection
/// </summary>
typedef enum _SECTION_INHERIT {
	ViewShare = 1,
	ViewUnmap = 2
} SECTION_INHERIT, * PSECTION_INHERIT;

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