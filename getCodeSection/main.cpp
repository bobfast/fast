#define _CRT_SECURE_NO_WARNINGS
#include <iostream>
#include <Windows.h>
#include <wincrypt.h>
#include <Psapi.h>
#include <tlhelp32.h>

#define ESUCCESS	0
#define ENOPROC		1
#define ENONAME		2

using namespace std;

BOOL calcMD5(byte* data, LPSTR md5);
DWORD64 GetModuleAddress(const char* moduleName, int pid);


int main(int argc, char** argv) {

	PIMAGE_DOS_HEADER pDH = NULL;
	PIMAGE_NT_HEADERS pNTH = NULL;
	PIMAGE_FILE_HEADER pFH = NULL;
	PIMAGE_SECTION_HEADER pSH = NULL;
	HANDLE hProcessSnap;

	int pid = atoi(argv[1]);

	char filePath[256] = { 0, };
	char fileName[256] = { 0, };

	HANDLE hp = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
	if (!hp) {
		printf("FAILED OPENPROCESS\n");
		return false;
	}
	else {
		GetModuleFileNameEx(hp, NULL, filePath, 256);
		GetFileTitle(filePath, fileName, 256);
	}

	void* lpBaseAddress = (void*)GetModuleAddress(fileName, pid);


	/// <summary>
	/// Process PE (Memory)
	/// </summary>
	/// <param name="argc"></param>
	/// <param name="argv"></param>
	/// <returns></returns>

	BYTE buf[700] = { 0, };
	BYTE* textAddr = NULL;
	int textSize;

	if (ReadProcessMemory(hp, lpBaseAddress, &buf, sizeof(buf), NULL)) {
		pDH = (PIMAGE_DOS_HEADER)buf;
		if (pDH->e_magic != IMAGE_DOS_SIGNATURE) {
			printf("Could not get IMAGE_DOS_HEADER\n");
			CloseHandle(hp);
			return false;
		}
		else
			//printf("OK IMAGE_DOS_HEADER\n");

		pNTH = (PIMAGE_NT_HEADERS)((PBYTE)pDH + pDH->e_lfanew);
		if (pNTH->Signature != IMAGE_NT_SIGNATURE) {
			printf("Could not get IMAGE_NT_HEADER\n");
			CloseHandle(hp);
			return false;
		}
		else
			//printf("OK IMAGE_NT_HEADER\n");

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

				textAddr = (BYTE*)lpBaseAddress + pSH->VirtualAddress;
				textSize = pSH->Misc.VirtualSize;
				break;
			}
			pSH++;
		}
	}
	else {
		printf("ReadProcessMemory error code : %d\n", GetLastError());
		CloseHandle(hp);
		return false;
	}

	/// <summary>
	/// File PE (Disk)
	/// </summary>
	/// <param name="argc"></param>
	/// <param name="argv"></param>
	/// <returns></returns>
	long lSize;
	BYTE* buffer;
	size_t result;
	BYTE* ftextAddr = NULL;
	int ftextSize;

	FILE* pFile = fopen(filePath, "rb");
	if (!pFile) {
		printf("FAILED FILE OPEN : %s\n", filePath);
		CloseHandle(hp);
		exit(1);
	}

	fseek(pFile, 0, SEEK_END);
	lSize = ftell(pFile);
	rewind(pFile);

	buffer = (BYTE*)malloc(sizeof(BYTE) * lSize);
	if (buffer == NULL) {
		fputs("Memory error", stderr);
		exit(2);
	}

	result = fread(buffer, 1, lSize, pFile);
	if (result != lSize) {
		fputs("Reading error", stderr);
		exit(3);
	}

	pDH = (PIMAGE_DOS_HEADER)buffer;
	if (pDH->e_magic != IMAGE_DOS_SIGNATURE) {
		printf("Could not get IMAGE_DOS_HEADER\n");
		CloseHandle(hp);
		fclose(pFile);
		free(buffer);
		return false;
	}
	else
		//printf("OK IMAGE_DOS_HEADER\n");

	pNTH = (PIMAGE_NT_HEADERS)((PBYTE)pDH + pDH->e_lfanew);
	if (pNTH->Signature != IMAGE_NT_SIGNATURE) {
		printf("Could not get IMAGE_NT_HEADER\n");
		CloseHandle(hp);
		fclose(pFile);
		free(buffer);
		return false;
	}
	else
		//printf("OK IMAGE_NT_HEADER\n");

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

			ftextAddr = buffer + 0x400;
			ftextSize = pSH->Misc.VirtualSize;
			break;
		}
		pSH++;
	}



	/// <summary>
	/// Hashing
	/// </summary>
	/// <param name="argc"></param>
	/// <param name="argv"></param>
	/// <returns></returns>
	BYTE textSection[512] = { 0, };
	int HashNum = (((textSize / 512) + 1) < ((ftextSize / 512) + 1)) ? (textSize / 512) + 1 : (ftextSize / 512) + 1;
	char md5[33];
	char fmd5[33];
	BYTE temp[512] = { 0, };
	BOOL resultPrint = false;
	unsigned int MinIntegrity = 0;
	unsigned int MaxIntegrity = 4294967295;

	for(int i=0; i< HashNum; i++){
		if (ReadProcessMemory(hp, textAddr, &textSection, sizeof(textSection), NULL)) {

			memcpy(temp, &ftextAddr[i*512], 512);
			
			if (calcMD5(textSection, md5) && calcMD5(temp, fmd5)) {
				//printf("%s  %s\n", md5, fmd5);           /////////////////////////////////
				if (strcmp(md5,fmd5)) {

					for (int j = 0; j < 512; j++) {
						if ((textSection[j]!=temp[j]) && (resultPrint == false)) {
							MinIntegrity = (i * 512) + j;
							printf("%d :: Code Section is changed (0x%p)\n", pid, textAddr + MinIntegrity);
							resultPrint = true;
						}
						else if ((textSection[j] == temp[j]) && (resultPrint == true)){
							if (MaxIntegrity < (i * 512) + j) {
								MaxIntegrity = (i * 512) + j;
							}
						}
					}
				}
			}
			else
				printf("MD5 calculation failed.\n"); 

			textAddr += 512;
			//printf("\n\n\n\n\n");
		}
		else {
			printf("ReadProcessMemory error code : %d\n", GetLastError());
			fclose(pFile);
			free(buffer);
			CloseHandle(hp);
			return false;
		}
	}


	if (resultPrint == false) {
		printf("%d :: Code Section is OK(not changed)\n", pid);
	}
	else {
		unsigned int changeSize = MaxIntegrity - MinIntegrity;
		/*printf("Before : ");
		for (int i = MinIntegrity; i <= MaxIntegrity; i++) {
			printf("%02X ", ftextAddr[i]);
		}
		printf("\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n");*/
		printf("After : ");
		BYTE *changedCode = (BYTE*)malloc(changeSize);
		if (ReadProcessMemory(hp, textAddr + MinIntegrity, &changedCode, changeSize, NULL)) {
			for (int i = 0; i < changeSize; i++) {
				printf("%02X ", changedCode[i]);
			}
			printf("\n\n");
			free(changedCode);
		}
		else {
			printf("FAILED ReadProcessMemory : changedCode\n");
			fclose(pFile);
			free(changedCode);
			free(buffer);
			CloseHandle(hp);
			return 0;
		}
	}

	fclose(pFile);
	free(buffer);
	CloseHandle(hp);
	return 0;
}


//BYTE buff[512];
BOOL calcMD5(byte* data, LPSTR md5)
{
	HCRYPTPROV hProv = 0;
	HCRYPTHASH hHash = 0;
	BYTE rgbHash[16];
	DWORD cbHash = 0;
	CHAR rgbDigits[] = "0123456789abcdef";

	// Get handle to the crypto provider
	if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
	{
		printf("ERROR: Couldn't acquire crypto context!\n");
		return FALSE;
	}

	if (!CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash))
	{
		CryptReleaseContext(hProv, 0);
		printf("ERROR: Couldn't create crypto stream!\n");
		return FALSE;
	}

	if (!CryptHashData(hHash, data, 512, 0))
	{
		CryptReleaseContext(hProv, 0);
		CryptDestroyHash(hHash);
		printf("ERROR: CryptHashData failed!\n");
		return FALSE;
	}

	cbHash = 16;
	if (CryptGetHashParam(hHash, HP_HASHVAL, rgbHash, &cbHash, 0))
	{
		for (DWORD i = 0; i < cbHash; i++)
		{
			sprintf(md5 + (i * 2), "%c%c", rgbDigits[rgbHash[i] >> 4], rgbDigits[rgbHash[i] & 0xf]);
		}

		CryptDestroyHash(hHash);
		CryptReleaseContext(hProv, 0);
		return TRUE;
	}
	else
	{
		printf("ERROR: CryptHashData failed!\n");
		CryptDestroyHash(hHash);
		CryptReleaseContext(hProv, 0);
		return FALSE;
	}
}


DWORD64 GetModuleAddress(const char* moduleName, int pid)
{
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
	MODULEENTRY32 moduleEntry;
	moduleEntry.dwSize = sizeof(MODULEENTRY32);

	Module32First(snapshot, &moduleEntry);
	do
	{
		if (!strcmp(moduleName, moduleEntry.szModule))
		{
			CloseHandle(snapshot);
			return (DWORD64)moduleEntry.modBaseAddr;
		}
	} while (Module32Next(snapshot, &moduleEntry));

	CloseHandle(snapshot);
}

