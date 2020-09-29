#pragma once
#include <Windows.h>

// Datatypes for PNtMapViewOfSection
typedef enum _SECTION_INHERIT {
	ViewShare = 1,
	ViewUnmap = 2
} SECTION_INHERIT;


DWORD GetReflectiveLoaderOffset(VOID* lpReflectiveDllBuffer, const char* exportedFuncName);

HANDLE WINAPI LoadRemoteLibraryR(HANDLE hProcess, LPVOID lpBuffer, DWORD dwLength, LPVOID lpParameter, const char *exportedFuncName);

HANDLE WINAPI LoadRemoteLibraryR2(HANDLE hProcess, LPVOID lpBuffer, DWORD dwLength, LPVOID lpParameter, const char* exportedFuncName);