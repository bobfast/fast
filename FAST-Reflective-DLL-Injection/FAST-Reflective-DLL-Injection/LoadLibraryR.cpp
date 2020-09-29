#include "LoadLibraryR.h"
#include <stdio.h>

DWORD Rva2Offset(DWORD dwRva, UINT_PTR uiBaseAddress)
{
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	PIMAGE_NT_HEADERS pNtHeaders = NULL;

	pNtHeaders = (PIMAGE_NT_HEADERS)(uiBaseAddress + ((PIMAGE_DOS_HEADER)uiBaseAddress)->e_lfanew);

	pSectionHeader = (PIMAGE_SECTION_HEADER)((UINT_PTR)(&pNtHeaders->OptionalHeader) + pNtHeaders->FileHeader.SizeOfOptionalHeader);

	if (dwRva < pSectionHeader[0].PointerToRawData)
	{
		return dwRva;
	}

	for (int i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++)
	{
		if (dwRva >= pSectionHeader[i].VirtualAddress && dwRva < (pSectionHeader[i].VirtualAddress + pSectionHeader[i].SizeOfRawData))
		{
			return dwRva - pSectionHeader[i].VirtualAddress + pSectionHeader[i].PointerToRawData;
		}
	}

	return 0;
}

DWORD GetReflectiveLoaderOffset(VOID* lpReflectiveDllBuffer, const char *exportedFuncName)
{
	UINT_PTR uiBaseAddress = 0, uiExportDir = 0, uiNameArray = 0,
		uiAddressArray = 0, uiNameOrdinals = 0;
	DWORD dwCounter = 0;

#ifdef _WIN64
	DWORD dwCompiledArch = 2;
#else
	DWORD dwCompiledArch = 1;
#endif

	uiBaseAddress = (UINT_PTR)lpReflectiveDllBuffer;

	// get the File Offset of the modules NT Header
	uiExportDir = uiBaseAddress + ((PIMAGE_DOS_HEADER)uiBaseAddress)->e_lfanew;

	// currently we can only process a PE file which is the same type as the one this function has
	// been compiled as, due to various offset in the PE structures being defined at compile time.
	if (((PIMAGE_NT_HEADERS)uiExportDir)->OptionalHeader.Magic == 0x010B) // PE32
	{
		if (dwCompiledArch != 1)
			return 0;
	}
	else if (((PIMAGE_NT_HEADERS)uiExportDir)->OptionalHeader.Magic == 0x020B) // PE64
	{
		if (dwCompiledArch != 2)
			return 0;
	}
	else
	{
		return 0;
	}

	// uiNameArray = the address of the modules export directory entry
	uiNameArray = (UINT_PTR)&((PIMAGE_NT_HEADERS)uiExportDir)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

	// get the File Offset of the export directory
	uiExportDir = uiBaseAddress + Rva2Offset(((PIMAGE_DATA_DIRECTORY)uiNameArray)->VirtualAddress, uiBaseAddress);

	// get the File Offset for the array of name pointers
	uiNameArray = uiBaseAddress + Rva2Offset(((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfNames, uiBaseAddress);

	/* it may need to remove */
	// get the File Offset for the array of addresses
	uiAddressArray = uiBaseAddress + Rva2Offset(((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfFunctions, uiBaseAddress);
	/**/

	// get the File Offset for the array of name ordinals
	uiNameOrdinals = uiBaseAddress + Rva2Offset(((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfNameOrdinals, uiBaseAddress);

	// get a counter for the number of exported functions...
	dwCounter = ((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->NumberOfNames;

	// loop through all the exported functions to find the ReflectiveLoader
	while (dwCounter--)
	{
		char* cpExportedFunctionName = (char*)(uiBaseAddress + Rva2Offset(*(DWORD*)(uiNameArray), uiBaseAddress));

		if (strstr(cpExportedFunctionName, exportedFuncName) != NULL)
		{
			// get the File Offset for the array of addresses
			uiAddressArray = uiBaseAddress + Rva2Offset(((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfFunctions, uiBaseAddress);

			// use the functions name ordinal as an index into the array of name pointers
			uiAddressArray += (*(WORD*)(uiNameOrdinals) * sizeof(DWORD));

			// return the File Offset to the ReflectiveLoader() functions code...
			return Rva2Offset(*(DWORD*)(uiAddressArray), uiBaseAddress);
		}
		// get the next exported function name
		uiNameArray += sizeof(DWORD);

		// get the next exported function name ordinal
		uiNameOrdinals += sizeof(WORD);
	}

	return 0;
}

HANDLE WINAPI LoadRemoteLibraryR(HANDLE hProcess, LPVOID lpBuffer, DWORD dwLength, LPVOID lpParameter, const char *exportedFuncName)
{
	HANDLE hThread = NULL;
	DWORD dwReflectiveLoaderOffset = 0;
	LPVOID lpRemoteLibraryBuffer = NULL;
	LPTHREAD_START_ROUTINE lpReflectiveLoader = NULL;
	DWORD dwThreadId = 0;

	try
	{
		if (!hProcess || !lpBuffer || !dwLength)
			return NULL;

		// check if the library has a ReflectiveLoader
		dwReflectiveLoaderOffset = GetReflectiveLoaderOffset(lpBuffer, exportedFuncName);
		if (!dwReflectiveLoaderOffset)
			return NULL;

		// alloc memory (RWX) in the host process for the image
		lpRemoteLibraryBuffer = VirtualAllocEx(hProcess, NULL, dwLength, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (!lpRemoteLibraryBuffer)
			return NULL;

		// write the image into the host process
		if (!WriteProcessMemory(hProcess, lpRemoteLibraryBuffer, lpBuffer, dwLength, NULL))
		{
			return NULL;
		}

		// add the offset to ReflectiveLoader() to the remote library address
		lpReflectiveLoader = (LPTHREAD_START_ROUTINE)((ULONG_PTR)lpRemoteLibraryBuffer + dwReflectiveLoaderOffset);

		// create a remote thread in the host process to call the ReflectiveLoader
		hThread = CreateRemoteThread(hProcess, NULL, 1024 * 1024, lpReflectiveLoader, lpParameter, (DWORD)NULL, &dwThreadId);
	}
	catch (...)
	{
		hThread = NULL;
	}

	return hThread;
}


// Global(static) variable for function pointer
static NTSTATUS(*PNtMapViewOfSection)(
	HANDLE          SectionHandle,
	HANDLE          ProcessHandle,
	PVOID* BaseAddress,
	ULONG_PTR       ZeroBits,
	SIZE_T          CommitSize,
	PLARGE_INTEGER  SectionOffset,
	PSIZE_T         ViewSize,
	SECTION_INHERIT InheritDisposition,
	ULONG           AllocationType,
	ULONG           Win32Protect
	);


HANDLE WINAPI LoadRemoteLibraryR2(HANDLE hProcess, LPVOID lpBuffer, DWORD dwLength, LPVOID lpParameter, const char* exportedFuncName)
{
	HANDLE hThread = NULL;
	HANDLE fm;
	char* map_addr;
	LPVOID lpMap = 0;
	SIZE_T viewsize = 0;
	DWORD dwReflectiveLoaderOffset = 0;
	LPVOID lpRemoteLibraryBuffer = NULL;
	LPTHREAD_START_ROUTINE lpReflectiveLoader = NULL;
	DWORD dwThreadId = 0;

	try
	{
		if (!hProcess || !lpBuffer || !dwLength)
			return NULL;

		PNtMapViewOfSection = (NTSTATUS(*)(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID * BaseAddress, ULONG_PTR ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, SECTION_INHERIT InheritDisposition, ULONG AllocationType, ULONG Win32Protect))GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtMapViewOfSection");

		fm = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_EXECUTE_READWRITE, 0, dwLength, NULL);

		// check if the library has a ReflectiveLoader
		dwReflectiveLoaderOffset = GetReflectiveLoaderOffset(lpBuffer, exportedFuncName);
		if (!dwReflectiveLoaderOffset)
			return NULL;

		map_addr = (char*)MapViewOfFile(fm, FILE_MAP_ALL_ACCESS, 0, 0, 0);
		
		memcpy(map_addr, lpBuffer, dwLength);

		(*PNtMapViewOfSection)(fm, hProcess, &lpMap, 0, dwLength, nullptr, &viewsize, ViewUnmap, 0, PAGE_EXECUTE_READWRITE);

		// add the offset to ReflectiveLoader() to the remote library address
		lpReflectiveLoader = (LPTHREAD_START_ROUTINE)((ULONG_PTR)lpMap + dwReflectiveLoaderOffset);

		// create a remote thread in the host process to call the ReflectiveLoader
		hThread = CreateRemoteThread(hProcess, NULL, 1024 * 1024, lpReflectiveLoader, lpParameter, (DWORD)NULL, &dwThreadId);
	}
	catch (...)
	{
		hThread = NULL;
	}

	return hThread;
}