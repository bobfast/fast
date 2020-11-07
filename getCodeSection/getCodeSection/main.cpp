#define _CRT_SECURE_NO_WARNINGS
#include <iostream>
#include <Windows.h>
#include <wincrypt.h>

#define BYTES_TO_HASH 512

using namespace std;

BOOL calcMD5(byte* data, LPSTR md5);
char* md5List;

int main(int argc, char** argv) {
	//int Buffer = 0;
    char* Buffer;

	HANDLE ImageBase;
	PIMAGE_DOS_HEADER pDH = NULL;
	PIMAGE_NT_HEADERS pNTH = NULL;
	PIMAGE_FILE_HEADER pFH = NULL;
	PIMAGE_SECTION_HEADER pSH = NULL;

	if ((ImageBase = GetModuleHandle(NULL)) == NULL) {
		printf("Could net get getmodulehandle\n");
	}
	else
		//printf("OK GetModuleHandle\n");
	
	pDH = (PIMAGE_DOS_HEADER)ImageBase;
	if (pDH->e_magic != IMAGE_DOS_SIGNATURE) {
		printf("Could not get IMAGE_DOS_HEADER\n");
		CloseHandle(ImageBase);
		return false;
	}
	else
		//printf("OK IMAGE_DOS_HEADER\n");

	pNTH = (PIMAGE_NT_HEADERS)((PBYTE)pDH + pDH->e_lfanew);
	if (pNTH->Signature != IMAGE_NT_SIGNATURE) {
		printf("Could not get IMAGE_NT_HEADER\n");
		CloseHandle(ImageBase);
		return false;
	}
	else
		//printf("OK IMAGE_NT_HEADER\n");

	pFH = &pNTH->FileHeader;
	pSH = IMAGE_FIRST_SECTION(pNTH);
	char md5[33];
	BYTE buff[512];

	for (int i = 0; i < pFH->NumberOfSections; i++) {
		if (!strcmp((char*)pSH->Name, ".text")) {
			/*cout << "Section name:" << pSH->Name << endl;
			cout << "             Virtual Size:" << pSH->Misc.VirtualSize << endl;
			cout << "             Virtual address:" << pSH->VirtualAddress << endl;
			cout << "             SizeofRawData:" << pSH->SizeOfRawData << endl;
			cout << "             PointertoRelocations:" << pSH->PointerToRelocations << endl;
			cout << "             Characteristics:" << pSH->Characteristics << endl;*/

			md5List = (char*)malloc(sizeof(md5)*(((int)pSH->Misc.VirtualSize/512)+1));
			
			BYTE* temp = (BYTE*)ImageBase + pSH->VirtualAddress;
			for (int i = 0; i < (int)pSH->Misc.VirtualSize; i+=512) {
				//printf("%02X ", temp[i]);

				memcpy(buff, &temp[i], 512);
				/*for (int j = 0; j < 512; j++) {
					printf("%02X ", buff[j]);
				}
				printf("\n\n\n\n\n");*/

				if (calcMD5(buff, md5)){
					printf("MD5: %s\n", md5);
					//md5List[i] = (char*)md5;
				}else
					printf("MD5 calculation failed.\n");
			}
			break;
		}
		pSH++;
	}
	ImageBase = NULL;
	CloseHandle(ImageBase);
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

	if (!CryptHashData(hHash, data, BYTES_TO_HASH, 0))
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