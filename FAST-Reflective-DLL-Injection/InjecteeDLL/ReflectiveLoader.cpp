#include "ReflectiveLoader.h"

HINSTANCE hAppInstance = NULL;

#pragma intrinsic(_ReturnAddress)
__declspec(noinline) ULONG_PTR caller(void) {
	return (ULONG_PTR)_ReturnAddress();
}

__declspec(dllexport) ULONG_PTR WINAPI ReflectiveLoader(void)
{
	ULONG_PTR uiLibraryAddress = caller();
	ULONG_PTR uiHeaderValue;

	while (true)
	{
		if (((PIMAGE_DOS_HEADER)uiLibraryAddress)->e_magic == IMAGE_DOS_SIGNATURE)
		{
			uiHeaderValue = ((PIMAGE_DOS_HEADER)uiLibraryAddress)->e_lfanew;

			if (uiHeaderValue >= sizeof(IMAGE_DOS_HEADER) && uiHeaderValue < 1024)
			{

			}
		}
	}
}