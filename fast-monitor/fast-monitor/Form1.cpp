#include "call_api.h"

<<<<<<< Updated upstream
//////////////////////////////////////////////////////////////////////////////
//
//  Test DetourCreateProcessfast function (fast.cpp).
//
//  Microsoft Research Detours Package
//
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//
#define MSG_SIZE 256
using namespace CppCLRWinformsProjekt;
=======
FILE* pFile;
std::string ghidraDirectory = "";
static HANDLE fm32 = NULL;
static HANDLE fm64 = NULL;
static char* map_addr32;
static char* map_addr64;
static DWORD dwBufSize32 = 0;
static DWORD dwBufSize64 = 0;
static DWORD thispid = GetCurrentProcessId();
static LPCSTR rpszDllsOut32 = NULL;
static LPCSTR rpszDllsOut64 = NULL;
>>>>>>> Stashed changes

void init() {
	time_t t = time(NULL);
	struct tm pLocal;
	localtime_s(&pLocal, &t);

	char buf[256];
	sprintf_s(buf, "log-%04d-%02d-%02d-%02d-%02d-%02d.txt",
		pLocal.tm_year + 1900, pLocal.tm_mon + 1, pLocal.tm_mday,
		pLocal.tm_hour, pLocal.tm_min, pLocal.tm_sec);

	fopen_s(&pFile, buf, "w");
	if (pFile == NULL)
	{
		exit(1);
	}

	fprintf(pFile, buf);
	fprintf(pFile, "\n#####Monitor Turned on.\n");
<<<<<<< Updated upstream
}

void exiting() {


=======


	// Turn on the SeDebugPrivilege.

	TOKEN_PRIVILEGES tp;
	BOOL bResult = FALSE;
	HANDLE hToken = NULL;
	DWORD dwSize;

	ZeroMemory(&tp, sizeof(tp));
	tp.PrivilegeCount = 1;

	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken) &&
		LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid))
	{
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
		bResult = AdjustTokenPrivileges(hToken, FALSE, &tp, 0, NULL, &dwSize);
	}
	CloseHandle(hToken);


	/////////////////////////////////////////////////////////
	// Getting the DLL's full path.

	LPCSTR rpszDllsRaw32 = (LPCSTR)"FAST-DLL-32.dll";

	CHAR szDllPath32[1024];
	PCHAR pszFilePart32 = NULL;

	if (!GetFullPathNameA(rpszDllsRaw32, ARRAYSIZE(szDllPath32), szDllPath32, &pszFilePart32))
	{
		return;
	}

	DWORD c32 = (DWORD)strlen(szDllPath32) + 1;
	PCHAR psz32 = new CHAR[c32];
	StringCchCopyA(psz32, c32, szDllPath32);
	rpszDllsOut32 = psz32;



	LPCSTR rpszDllsRaw64 = (LPCSTR)"FAST-DLL-64.dll";

	CHAR szDllPath64[1024];
	PCHAR pszFilePart64 = NULL;

	if (!GetFullPathNameA(rpszDllsRaw64, ARRAYSIZE(szDllPath64), szDllPath64, &pszFilePart64))
	{
		return;
	}

	DWORD c64 = (DWORD)strlen(szDllPath64) + 1;
	PCHAR psz64 = new CHAR[c64];
	StringCchCopyA(psz64, c64, szDllPath64);
	rpszDllsOut64 = psz64;



	/////////////////////////////////////////////////////////
	// Making shared memory.

	dwBufSize32 = (DWORD)(strlen(rpszDllsOut32) + 1) * sizeof(char);

	fm32 = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE,
		0,
		(DWORD)((dwBufSize32 + sizeof(DWORD) + 13 * sizeof(DWORD64))), (LPCSTR)"shared32");


	map_addr32 = (char*)MapViewOfFile(fm32, FILE_MAP_ALL_ACCESS, 0, 0, 0);

	memcpy(map_addr32, rpszDllsOut32, dwBufSize32);
	memcpy(map_addr32 + dwBufSize32, &thispid, sizeof(DWORD));


	dwBufSize64 = (DWORD)(strlen(rpszDllsOut64) + 1) * sizeof(char);

	fm64 = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE,
		0,
		(DWORD)((dwBufSize64 + sizeof(DWORD) + 13 * sizeof(DWORD64))), (LPCSTR)"shared64");


	map_addr64 = (char*)MapViewOfFile(fm64, FILE_MAP_ALL_ACCESS, 0, 0, 0);

	memcpy(map_addr64, rpszDllsOut64, dwBufSize64);
	memcpy(map_addr64 + dwBufSize64, &thispid, sizeof(DWORD));



	LPVOID fp = CallVirtualAllocEx;
	memcpy(map_addr32 + dwBufSize32 + sizeof(DWORD), &fp, sizeof(DWORD64));
	memcpy(map_addr64 + dwBufSize64 + sizeof(DWORD), &fp, sizeof(DWORD64));

	fp = CallQueueUserAPC;
	memcpy(map_addr32 + dwBufSize32 + sizeof(DWORD) + sizeof(DWORD64), &fp, sizeof(DWORD64));
	memcpy(map_addr64 + dwBufSize64 + sizeof(DWORD) + sizeof(DWORD64), &fp, sizeof(DWORD64));

	fp = CallWriteProcessMemory;
	memcpy(map_addr32 + dwBufSize32 + sizeof(DWORD) + 2 * sizeof(DWORD64), &fp, sizeof(DWORD64));
	memcpy(map_addr64 + dwBufSize64 + sizeof(DWORD) + 2 * sizeof(DWORD64), &fp, sizeof(DWORD64));

	fp = CallCreateRemoteThread;
	memcpy(map_addr32 + dwBufSize32 + sizeof(DWORD) + 3 * sizeof(DWORD64), &fp, sizeof(DWORD64));
	memcpy(map_addr64 + dwBufSize64 + sizeof(DWORD) + 3 * sizeof(DWORD64), &fp, sizeof(DWORD64));

	fp = CallNtMapViewOfSection;
	memcpy(map_addr32 + dwBufSize32 + sizeof(DWORD) + 4 * sizeof(DWORD64), &fp, sizeof(DWORD64));
	memcpy(map_addr64 + dwBufSize64 + sizeof(DWORD) + 4 * sizeof(DWORD64), &fp, sizeof(DWORD64));

	fp = CallCreateFileMappingA;
	memcpy(map_addr32 + dwBufSize32 + sizeof(DWORD) + 5 * sizeof(DWORD64), &fp, sizeof(DWORD64));
	memcpy(map_addr64 + dwBufSize64 + sizeof(DWORD) + 5 * sizeof(DWORD64), &fp, sizeof(DWORD64));

	fp = CallGetThreadContext;
	memcpy(map_addr32 + dwBufSize32 + sizeof(DWORD) + 6 * sizeof(DWORD64), &fp, sizeof(DWORD64));
	memcpy(map_addr64 + dwBufSize64 + sizeof(DWORD) + 6 * sizeof(DWORD64), &fp, sizeof(DWORD64));

	fp = CallSetThreadContext;
	memcpy(map_addr32 + dwBufSize32 + sizeof(DWORD) + 7 * sizeof(DWORD64), &fp, sizeof(DWORD64));
	memcpy(map_addr64 + dwBufSize64 + sizeof(DWORD) + 7 * sizeof(DWORD64), &fp, sizeof(DWORD64));

	fp = CallNtQueueApcThread;
	memcpy(map_addr32 + dwBufSize32 + sizeof(DWORD) + 8 * sizeof(DWORD64), &fp, sizeof(DWORD64));
	memcpy(map_addr64 + dwBufSize64 + sizeof(DWORD) + 8 * sizeof(DWORD64), &fp, sizeof(DWORD64));

	fp = CallSetWindowLongPtrA;
	memcpy(map_addr32 + dwBufSize32 + sizeof(DWORD) + 9 * sizeof(DWORD64), &fp, sizeof(DWORD64));
	memcpy(map_addr64 + dwBufSize64 + sizeof(DWORD) + 9 * sizeof(DWORD64), &fp, sizeof(DWORD64));

	fp = CallSetPropA;
	memcpy(map_addr32 + dwBufSize32 + sizeof(DWORD) + 10 * sizeof(DWORD64), &fp, sizeof(DWORD64));
	memcpy(map_addr64 + dwBufSize64 + sizeof(DWORD) + 10 * sizeof(DWORD64), &fp, sizeof(DWORD64));

	fp = CallVirtualProtectEx;
	memcpy(map_addr32 + dwBufSize32 + sizeof(DWORD) + 11 * sizeof(DWORD64), &fp, sizeof(DWORD64));
	memcpy(map_addr64 + dwBufSize64 + sizeof(DWORD) + 11 * sizeof(DWORD64), &fp, sizeof(DWORD64));

	fp = CallSleepEx;
	memcpy(map_addr32 + dwBufSize32 + sizeof(DWORD) + 12 * sizeof(DWORD64), &fp, sizeof(DWORD64));
	memcpy(map_addr64 + dwBufSize64 + sizeof(DWORD) + 12 * sizeof(DWORD64), &fp, sizeof(DWORD64));



	//Initial Hooking.
	//mon(0);

}

void exiting() {
	//Close Everything.
	UnmapViewOfFile(map_addr32);
	UnmapViewOfFile(map_addr64);
	CloseHandle(fm32);
	CloseHandle(fm64);
>>>>>>> Stashed changes
	fclose(pFile);
}




DWORD findPidByName(const char* pname)
{
<<<<<<< Updated upstream
	HANDLE h;
	PROCESSENTRY32 procSnapshot;
	h = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	procSnapshot.dwSize = sizeof(PROCESSENTRY32);
=======
	Form1^ form = (Form1^)Application::OpenForms[0];

	if (SDL_Init(SDL_INIT_VIDEO | SDL_INIT_TIMER) != 0)
	{
		form->logging("ImGui Error: " + std::string(SDL_GetError()) + "\n");
		return;
	}

#if __APPLE__
	// GL 3.2 Core + GLSL 150
	const char* glsl_version = "#version 150";
	SDL_GL_SetAttribute(
		SDL_GL_CONTEXT_FLAGS,
		SDL_GL_CONTEXT_FORWARD_COMPATIBLE_FLAG); // Always required on Mac
	SDL_GL_SetAttribute(SDL_GL_CONTEXT_PROFILE_MASK, SDL_GL_CONTEXT_PROFILE_CORE);
	SDL_GL_SetAttribute(SDL_GL_CONTEXT_MAJOR_VERSION, 3);
	SDL_GL_SetAttribute(SDL_GL_CONTEXT_MINOR_VERSION, 2);
#else
	// GL 3.0 + GLSL 130
	const char* glsl_version = "#version 130";
	SDL_GL_SetAttribute(SDL_GL_CONTEXT_FLAGS, 0);
	SDL_GL_SetAttribute(SDL_GL_CONTEXT_PROFILE_MASK, SDL_GL_CONTEXT_PROFILE_CORE);
	SDL_GL_SetAttribute(SDL_GL_CONTEXT_MAJOR_VERSION, 3);
	SDL_GL_SetAttribute(SDL_GL_CONTEXT_MINOR_VERSION, 0);
#endif

	SDL_GL_SetAttribute(SDL_GL_DOUBLEBUFFER, 1);
	SDL_GL_SetAttribute(SDL_GL_DEPTH_SIZE, 24);
	SDL_GL_SetAttribute(SDL_GL_STENCIL_SIZE, 8);
	SDL_DisplayMode current;
	SDL_GetCurrentDisplayMode(0, &current);
	SDL_Window* window = SDL_CreateWindow(
		"Injection flow",
		SDL_WINDOWPOS_CENTERED,
		SDL_WINDOWPOS_CENTERED,
		1280,
		720,
		SDL_WINDOW_OPENGL | SDL_WINDOW_RESIZABLE | SDL_WINDOW_ALLOW_HIGHDPI);
	SDL_GLContext gl_context = SDL_GL_CreateContext(window);
	SDL_GL_MakeCurrent(window, gl_context);
	SDL_GL_SetSwapInterval(1); // Enable vsync

	if (gl3wInit())
	{
		fprintf(stderr, "Failed to initialize OpenGL loader!\n");
		return;
	}

	IMGUI_CHECKVERSION();
	ImGui::CreateContext();

	ImGui_ImplSDL2_InitForOpenGL(window, gl_context);
	ImGui_ImplOpenGL3_Init(glsl_version);

	imnodes::Initialize();

	// Setup style
	ImGui::StyleColorsDark();
	imnodes::StyleColorsDark();

	bool done = false;
	bool initialized = false;

	{
		const ImVec4 clear_color = ImVec4(0.45f, 0.55f, 0.60f, 1.00f);
		glClearColor(clear_color.x, clear_color.y, clear_color.z, clear_color.w);
	}
>>>>>>> Stashed changes

	do
	{
		if (!strcmp((const char*)procSnapshot.szExeFile, pname))
		{
<<<<<<< Updated upstream
			DWORD pid = procSnapshot.th32ProcessID;
			CloseHandle(h);
			return pid;
=======
			initialized = true;
			Show_node::NodeEditorInitialize((unsigned int)v.size());
>>>>>>> Stashed changes
		}
	} while (Process32Next(h, &procSnapshot));

	CloseHandle(h);
	return 0;
}

HMODULE findRemoteHModule(DWORD dwProcessId, const char* szdllout)
{
	MODULEENTRY32 me = { sizeof(me) };
	BOOL bMore = FALSE;
	HANDLE hSnapshot;


	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwProcessId);
	if (hSnapshot == (HANDLE)-1) {
		//printf("CreateToolhelp32Snapshot Failed.\n");
	}
	bMore = Module32First(hSnapshot, &me);
	for (; bMore; bMore = Module32Next(hSnapshot, &me))
	{
		//printf("%s\n", (LPCSTR)me.szModule);
		//wprintf(L"%s\n", (LPCWSTR)me.szExePath);
		//printf("%s\n", szdllout);
		if (
			//!_stricmp((LPCSTR)me.szModule, szdllout) ||
			!_tcsicmp((LPCTSTR)me.szExePath, szdllout))
		{
			//printf("find!\n");
			//wprintf(L"%s\n", (LPCWSTR)me.szExePath);
			return (HMODULE)me.modBaseAddr;
		}
	}
	return NULL;
}


<<<<<<< Updated upstream


//////////////////////////////////////////////////////////////////////// main.
//
int CDECL mon(int isFree_)
{
	BOOLEAN isFree = (BOOLEAN)isFree_;
	BOOLEAN fVerbose = FALSE;

	LPCSTR rpszDllsRaw[1];
	LPCSTR rpszDllsOut[1];
	DWORD nDlls = 1;


	rpszDllsRaw[0] = NULL;
	rpszDllsOut[0] = NULL;


	char dlln[] = "FAST-DLL.dll";
	rpszDllsRaw[0] = (LPCSTR)dlln;





	///////////////////////////////////////////////////////// Validate DLLs.

	for (DWORD n = 0; n < nDlls; n++)
	{
		CHAR szDllPath[1024];
		PCHAR pszFilePart = NULL;

		if (!GetFullPathNameA(rpszDllsRaw[n], ARRAYSIZE(szDllPath), szDllPath, &pszFilePart))
		{
			//printf("fast.exe: Error: %s is not a valid path name..\n",
				//rpszDllsRaw[n]);
			return 9002;
		}

		DWORD c = (DWORD)strlen(szDllPath) + 1;
		PCHAR psz = new CHAR[c];
		StringCchCopyA(psz, c, szDllPath);
		rpszDllsOut[n] = psz;

		HMODULE hDll = LoadLibraryExA(rpszDllsOut[n], NULL, DONT_RESOLVE_DLL_REFERENCES);
		if (hDll == NULL)
		{
			//printf("fast.exe: Error: %s failed to load (error %ld).\n",
				//rpszDllsOut[n],
				//GetLastError());
			return 9003;
		}

		ExportContext ec;
		ec.fHasOrdinal1 = FALSE;
		ec.nExports = 0;
		DetourEnumerateExports(hDll, &ec, ExportCallback);
		FreeLibrary(hDll);

		if (!ec.fHasOrdinal1)
		{
			//printf("fast.exe: Error: %s does not export ordinal #1.\n",
				//rpszDllsOut[n]);
			//printf("             See help entry DetourCreateProcessfastEx in Detours.chm.\n");
			return 9004;
		}
	}

	// CHAR szCommand[2048];


	TOKEN_PRIVILEGES tp;
	BOOL bResult = FALSE;
	HANDLE hToken = NULL;
	DWORD dwSize;

	ZeroMemory(&tp, sizeof(tp));
	tp.PrivilegeCount = 1;

	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken) &&
		LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid))
	{
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
		bResult = AdjustTokenPrivileges(hToken, FALSE, &tp, 0, NULL, &dwSize);
	}
	CloseHandle(hToken);

	HANDLE hProcess = NULL, hThread = NULL;
	HMODULE hMod = NULL;


	LPTHREAD_START_ROUTINE pThreadProc = NULL;

	HANDLE fm = NULL;
	char* map_addr;
	LPVOID lpMap = 0;
	SIZE_T viewsize = 0;
	PNtMapViewOfSection = (NTSTATUS(*)(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID * BaseAddress, ULONG_PTR ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, SECTION_INHERIT InheritDisposition, ULONG AllocationType, ULONG Win32Protect)) GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtMapViewOfSection");

	hMod = GetModuleHandleA("kernel32.dll");
	if (!hMod)
	{
		return FALSE;
	}



	LPCSTR sz = NULL;
	DWORD dwBufSize = 0;
	DWORD thispid = GetCurrentProcessId();


	if (!isFree)
	{
		//printf("Injection...\n");
		fprintf(pFile, "Hook DLLs!\n");
		pThreadProc = (LPTHREAD_START_ROUTINE)GetProcAddress(hMod, "LoadLibraryA");


	}
	else
	{
		//printf("Freeing...\n");
		fprintf(pFile, "UnHook DLLs!\n");
		pThreadProc = (LPTHREAD_START_ROUTINE)GetProcAddress(hMod, "FreeLibrary");

	}

	if (!pThreadProc)
	{
		return FALSE;
	}

	// if (fVerbose)
	// {
	//     DumpProcess(hProcess);
	// }

	// //WaitForSingleObject(hThread, INFINITE);
	// CloseHandle(hThread);
	// CloseHandle(hProcess);

	if (!isFree)
	{
		sz = rpszDllsOut[0];
		dwBufSize = (DWORD)(strlen(sz) + 1) * sizeof(char);

		fm = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE,
			0,
			(DWORD)((dwBufSize + sizeof(DWORD) + 11 * sizeof(DWORD64))), (LPCSTR)"shared");


		map_addr = (char*)MapViewOfFile(fm, FILE_MAP_ALL_ACCESS, 0, 0, 0);

		memcpy(map_addr, sz, dwBufSize);
		memcpy(map_addr + dwBufSize, &thispid, sizeof(DWORD));


		//printf("c %p\n", CallVirtualAllocEx);
		//printf("c %llu\n", CallVirtualAllocEx);
		LPVOID fp = CallVirtualAllocEx;
		memcpy(map_addr + dwBufSize + sizeof(DWORD), &fp, sizeof(DWORD64));
		//printf("%d\t%d\t%llu\n", thispid, *(DWORD*)(map_addr + dwBufSize), *(DWORD64*)(map_addr + dwBufSize + sizeof(DWORD)));

		//printf("c %p\n", CallLoadLibraryA);
		//printf("c %llu\n", CallLoadLibraryA);
		fp = CallQueueUserAPC;
		memcpy(map_addr + dwBufSize + sizeof(DWORD) + sizeof(DWORD64), &fp, sizeof(DWORD64));
		//printf("%d\t%d\t%llu\n", thispid, *(DWORD*)(map_addr + dwBufSize), *(DWORD64*)(map_addr + dwBufSize + sizeof(DWORD) + sizeof(DWORD64)));

		fp = CallWriteProcessMemory;
		memcpy(map_addr + dwBufSize + sizeof(DWORD) + 2 * sizeof(DWORD64), &fp, sizeof(DWORD64));

		fp = CallCreateRemoteThread;
		memcpy(map_addr + dwBufSize + sizeof(DWORD) + 3 * sizeof(DWORD64), &fp, sizeof(DWORD64));

		fp = CallNtMapViewOfSection;
		memcpy(map_addr + dwBufSize + sizeof(DWORD) + 4 * sizeof(DWORD64), &fp, sizeof(DWORD64));

		fp = CallCreateFileMappingA;
		memcpy(map_addr + dwBufSize + sizeof(DWORD) + 5 * sizeof(DWORD64), &fp, sizeof(DWORD64));

		fp = CallGetThreadContext;
		memcpy(map_addr + dwBufSize + sizeof(DWORD) + 6 * sizeof(DWORD64), &fp, sizeof(DWORD64));

		fp = CallSetThreadContext;
		memcpy(map_addr + dwBufSize + sizeof(DWORD) + 7 * sizeof(DWORD64), &fp, sizeof(DWORD64));

		fp = CallNtQueueApcThread;
		memcpy(map_addr + dwBufSize + sizeof(DWORD) + 8 * sizeof(DWORD64), &fp, sizeof(DWORD64));

		fp = CallSetWindowLongPtrA;
		memcpy(map_addr + dwBufSize + sizeof(DWORD) + 9 * sizeof(DWORD64), &fp, sizeof(DWORD64));

		fp = CallSleepEx;
		memcpy(map_addr + dwBufSize + sizeof(DWORD) + 10 * sizeof(DWORD64), &fp, sizeof(DWORD64));


	}

	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32 entry = { sizeof(PROCESSENTRY32) };
	Process32First(hSnap, &entry);
	do
	{

		if (thispid == entry.th32ProcessID)
			continue;
		hProcess = OpenProcess(MAXIMUM_ALLOWED, FALSE, entry.th32ProcessID);
		if (!(hProcess))
		{

			//printf("OpenProcess(%ld) failed!!! [%ld]\n", entry.th32ProcessID, GetLastError());
			continue;
		}
		//printf("OpenProcess(%ld) Succeed!!! \n", entry.th32ProcessID);
		(*PNtMapViewOfSection)(fm, hProcess, &lpMap, 0, dwBufSize,
			nullptr, &viewsize, ViewUnmap, 0, PAGE_READONLY);


		if (fVerbose)
		{
			DumpProcess(hProcess);
		}

		if (!isFree)
		{
			hThread = CreateRemoteThread(hProcess, NULL, 0, pThreadProc, lpMap, 0, NULL);
			if (!hThread)
			{
				//return FALSE;
				//printf("CreateRemoteThread(%ld) failed!!! [%ld]\n", entry.th32ProcessID, GetLastError());
				continue;
			}
		}
		else
		{
			HMODULE fdllpath = findRemoteHModule(entry.th32ProcessID, (const char*)rpszDllsOut[0]);
			if (fdllpath != NULL)
			{
				hThread = CreateRemoteThread(hProcess, NULL, 0, pThreadProc, fdllpath, 0, NULL);
				if (!hThread)
				{
					//return FALSE;
					//printf("CreateRemoteThread(%ld) failed!!! [%ld]\n", entry.th32ProcessID, GetLastError());
					continue;
				}
			}
		}

		if (fVerbose)
		{
			DumpProcess(hProcess);
		}

		//WaitForSingleObject(hThread, INFINITE);
		CloseHandle(hThread);
		hThread = NULL;
		CloseHandle(hProcess);
		hProcess = NULL;

	} while (Process32Next(hSnap, &entry));

	CloseHandle(hSnap);


	//printf("fast.exe: Finished.\n");

	//if (!isFree)
	//    while (TRUE)
	//        Sleep(0);
=======
System::Void Form1::runGhidraToolStripMenuItem_Click(System::Object^ sender, System::EventArgs^ e) {
	if (ghidraDirectory == "") {
		MessageBox::Show("You must set your Ghidra directory", "New Ghidra Project Failed!", MessageBoxButtons::OK, MessageBoxIcon::Error);
		return;
	}

	array<String^>^ currentdirfiles = IO::Directory::GetFiles(".");
	bool thereIsBinFile = false;

	String^ analyzeHeadless_bat = gcnew String((ghidraDirectory + "\\support\\analyzeHeadless.bat").c_str());
	String^ args = gcnew String(". GhidraMemdmpProject -import ");

	if (!IO::File::Exists(analyzeHeadless_bat)) {
		MessageBox::Show(analyzeHeadless_bat + " not found.", "New Ghidra Project Failed!", MessageBoxButtons::OK, MessageBoxIcon::Error);
		return;
	}

	for (int i = 0; i < currentdirfiles->Length; i++) {
		String^ elem = (String^)(currentdirfiles->GetValue(i));

		// find .bin files
		if (elem->LastIndexOf(".bin") == elem->Length - 4) {
			thereIsBinFile = true;
			args = args + "\"" + elem + "\" ";
		}
	}

	if (thereIsBinFile) {
		Diagnostics::Process^ proc = Diagnostics::Process::Start(analyzeHeadless_bat, args);  // RUN analyzeHeadless.bat with arguments
		proc->WaitForExit();
	}
	else {
		MessageBox::Show("There is no dumped *.bin file.", "New Ghidra Project Failed!", MessageBoxButtons::OK, MessageBoxIcon::Error);
		return;
	}
>>>>>>> Stashed changes

	return 0; //dwResult;
}
//
///////////////////////////////////////////////////////////////// End of File.