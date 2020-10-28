#define _CRT_SECURE_NO_WARNINGS
#include <iostream>
#include <Windows.h>
#include <tchar.h>
#include <TlHelp32.h>

using namespace std;

VOID SetSuperPrivilege(LPCTSTR PrivilegeName);

int main(int argc, char **argv) {
	DWORD pid;
	int Buffer = 0;
	//void* IpBuffer = (void*)&Buffer;

	//pid = atoi(argv[1]);
	scanf("%d", &pid);

	HANDLE ImageBase;
	PIMAGE_DOS_HEADER pDH = NULL;
	PIMAGE_NT_HEADERS pNTH = NULL;
	PIMAGE_FILE_HEADER pFH = NULL;
	PIMAGE_SECTION_HEADER pSH = NULL;

	SYSTEM_INFO si;
	MEMORY_BASIC_INFORMATION mbi;
	LPVOID IpMem, IpBuffer;
	TCHAR szFileName[MAX_PATH];
	HANDLE hFile;
	DWORD NumberofBytesWritten;

	SetSuperPrivilege(SE_DEBUG_NAME);

	HANDLE h = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (h == NULL) {
		printf("Could not open process id\n");
		return false;
	}
	else
		printf("OK OpenProcess\n");

	GetSystemInfo(&si);

	ZeroMemory(&mbi, sizeof(MEMORY_BASIC_INFORMATION));
	IpMem = NULL;

	while (IpMem < si.lpMaximumApplicationAddress) {
		if (!VirtualQueryEx(h, IpMem, &mbi, sizeof(MEMORY_BASIC_INFORMATION))) {
			printf("Could not get VirtualQueryEx\n");
			CloseHandle(h);
			return false;
		}

		if ((mbi.BaseAddress != NULL) && (mbi.State == MEM_COMMIT)) {
			switch (mbi.Protect) {
			case PAGE_EXECUTE_READ:
			case PAGE_EXECUTE_READWRITE:
			case PAGE_EXECUTE_WRITECOPY:
			case PAGE_READONLY:
			case PAGE_READWRITE:
			case PAGE_WRITECOPY:
				IpBuffer = VirtualAlloc(NULL, mbi.RegionSize, MEM_COMMIT, PAGE_READWRITE);

				if (!ReadProcessMemory(h, mbi.BaseAddress, IpBuffer, mbi.RegionSize, NULL)) {
					printf("Failed ReadMemory\n");
					VirtualFree(IpBuffer, mbi.RegionSize, MEM_FREE);
					break;
				}
				else
					printf("Success ReadMemory\n");

				_stprintf_s(szFileName, sizeof(szFileName), _T("%X = %X.dmp"), mbi.BaseAddress, ((DWORD_PTR)mbi.BaseAddress + (DWORD_PTR)mbi.RegionSize));

				hFile = CreateFile(szFileName, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

				if (WriteFile(hFile, IpBuffer, (DWORD_PTR)mbi.RegionSize, &NumberofBytesWritten, NULL)) {
					_tprintf(_T("Dumped successfully : %s\n"), szFileName);
				}else _tprintf(_T("Failed to Dump : %s, %x\n"), szFileName, GetLastError());

				VirtualFree(IpBuffer, mbi.RegionSize, MEM_FREE);
				CloseHandle(hFile);
				break;
			default:
				break;
			}
		}
	}

	/*ImageBase = si.lpMinimumApplicationAddress;
	if (!ImageBase) {
		printf("Could not get ImageBase\n");
		CloseHandle(h);
		return false;
	}
	else
		printf("OK get ImageBase\n");

	pDH = (PIMAGE_DOS_HEADER)mbi.BaseAddress;
	printf("(2) %p\n", &mbi.BaseAddress);
	pNTH = (PIMAGE_NT_HEADERS)((DWORD)pDH + pDH->e_lfanew);
	pFH = &pNTH->FileHeader;
	pSH = IMAGE_FIRST_SECTION(pNTH);

	for (int i = 0; i < pFH->NumberOfSections; i++) {
		cout << "Section name:" << pSH->Name << endl;
		cout << "             Virtual Size:" << pSH->Misc.VirtualSize << endl;
		cout << "             Virtual address:" << pSH->VirtualAddress << endl;
		cout << "             SizeofRawData:" << pSH->SizeOfRawData << endl;
		cout << "             PointertoRelocations:" << pSH->PointerToRelocations << endl;
		cout << "             Characteristics:" << pSH->Characteristics << endl;
		pSH++;
	}*/
	
	//ReadProcessMemory(h, &pSH->VirtualAddress, &lpBuffer, pSH->Misc.VirtualSize, NULL);
	//
	//for(int i=0; i<pSH->Misc.VirtualSize; i++){
	//	printf("%#02x ", IpBuffer[i]);
	//CloseHandle(h);

	return 0;
}


VOID SetSuperPrivilege(LPCTSTR PrivilegeName) {
	HANDLE hToken = NULL;
	TOKEN_PRIVILEGES tp;

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken)) {
		printf("OpenToken Error\n");
		return;
	}
	else
		printf("OK OpenToken\n");

	__try {
		if (!LookupPrivilegeValue(NULL, PrivilegeName, &tp.Privileges[0].Luid)) {
			printf("LookupPrivilege Error\n");
			return;
		}
		else
			printf("OK LookupPrivilege\n");

		tp.PrivilegeCount = 1;
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

		if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
			printf("AdjustTokenPrivilege Error\n");
			return;
		}
		else
			printf("OK AdjustTokenPrivilege\n");
	}
	__finally {
		CloseHandle(hToken);
	}
}