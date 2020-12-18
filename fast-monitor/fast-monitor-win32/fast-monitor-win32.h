#pragma once
#include <stdio.h>
#include <Windows.h>
#include "tchar.h"
#include <tlhelp32.h>
//#include <detours.h>
#include <time.h>
#include <utility>
#include <string>
#include <vector>
#include <unordered_map>
#include <tuple>
#pragma warning(push)
#if _MSC_VER > 1400
#pragma warning(disable : 6102 6103) // /analyze warnings
#endif
#include <strsafe.h>
#pragma warning(pop)
/// <summary>
/// flags
/// </summary>
#define FLAG_VirtualAllocEx 0b00000001
#define FLAG_NtMapViewOfSection 0b00000010
#define FLAG_VirtualProtectEx  0b00000100
#define FLAG_CreateRemoteThread 0b00001000
#define FLAG_RtlCreateUserThread 0b00001000
#define FLAG_SetWindowLongPtrA 0b00010000  
#define FLAG_SetPropA 0b00100000
#define FLAG_SetThreadContext 0b01000000
#define FLAG_NtQueueApcThread 0b10000000 
#define FLAG_WriteProcessMemory 0b10000000 

#define indexof( datum, data ) ( &datum - &*data.begin() )

void init();
void exiting();

static std::vector<std::vector<std::tuple<DWORD64, DWORD, std::string, UCHAR, std::string>>> detectionInfo;
static bool hooked = false;
extern std::string ghidraDirectory;
