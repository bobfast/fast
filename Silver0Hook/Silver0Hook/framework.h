﻿#pragma once

//#define WIN32_LEAN_AND_MEAN             // 거의 사용되지 않는 내용을 Windows 헤더에서 제외합니다.
// Windows 헤더 파일
#include <windows.h>

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
	PHANDLE            ProcessHandle,
	ACCESS_MASK        DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PCLIENT_ID         ClientId
	);


/// <summary>
/// CreateFileMappingNumaW  (memoryapi.h)
/// </summary>
static HANDLE(WINAPI* TrueCreateFileMappingNumaW)(
	HANDLE                hFile,
	LPSECURITY_ATTRIBUTES lpFileMappingAttributes,
	DWORD                 flProtect,
	DWORD                 dwMaximumSizeHigh,
	DWORD                 dwMaximumSizeLow,
	LPCWSTR               lpName,
	DWORD                 nndPreferred
	) = CreateFileMappingNumaW;