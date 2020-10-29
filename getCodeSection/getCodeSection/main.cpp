//#define _CRT_SECURE_NO_WARNINGS
#include <iostream>
#include <Windows.h>

using namespace std;

int main(int argc, char** argv) {
	DWORD pid;
	int Buffer = 0;
	void* IpBuffer = (void*)&Buffer;

	HMODULE h;
	HANDLE ImageBase;
	PIMAGE_DOS_HEADER pDH = NULL;
	PIMAGE_NT_HEADERS pNTH = NULL;
	PIMAGE_FILE_HEADER pFH = NULL;
	PIMAGE_SECTION_HEADER pSH = NULL;

	if ((h = GetModuleHandle(NULL)) == NULL) {
		printf("Could net get getmodulehandle\n");
	}
	else
		printf("OK GetModuleHandle\n");
	
	ImageBase = h;

	pDH = (PIMAGE_DOS_HEADER)ImageBase;
	if (pDH->e_magic != IMAGE_DOS_SIGNATURE) {
		printf("Could not get IMAGE_DOS_HEADER\n");
		CloseHandle(h);
		return false;
	}
	else
		printf("OK IMAGE_DOS_HEADER\n");


	pNTH = (PIMAGE_NT_HEADERS)((PBYTE)pDH + pDH->e_lfanew);
	if (pNTH->Signature != IMAGE_NT_SIGNATURE) {
		printf("Could not get IMAGE_NT_HEADER\n");
		CloseHandle(h);
		return false;
	}
	else
		printf("OK IMAGE_NT_HEADER\n");

	pFH = &pNTH->FileHeader;
	pSH = IMAGE_FIRST_SECTION(pNTH);

	for (int i = 0; i < pFH->NumberOfSections; i++) {
		if (!strcmp((char*)pSH->Name, ".text")) {
			/*cout << "Section name:" << pSH->Name << endl;
			cout << "             Virtual Size:" << pSH->Misc.VirtualSize << endl;
			cout << "             Virtual address:" << pSH->VirtualAddress << endl;
			cout << "             SizeofRawData:" << pSH->SizeOfRawData << endl;
			cout << "             PointertoRelocations:" << pSH->PointerToRelocations << endl;
			cout << "             Characteristics:" << pSH->Characteristics << endl;*/
			
			BYTE* temp = (BYTE*)ImageBase + pSH->VirtualAddress;
			for (int i = 0; i <= (int)pSH->Misc.VirtualSize; i++) {
				printf("%02X ", temp[i]);
			}
		}
		pSH++;
	}

	return 0;
}

