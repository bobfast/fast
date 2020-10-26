#include <windows.h>

#define DLL_QUERY_HMODULE 6

typedef BOOL(WINAPI* DLLMAIN)(HINSTANCE, DWORD, LPVOID);
