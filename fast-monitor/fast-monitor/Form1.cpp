#include "call_api.h"


FILE* pFile;
std::string ghidraDirectory = "";
static UINT32 hook_cnt = 0;
static 	HANDLE fm = NULL;
static char* map_addr;
static DWORD dwBufSize = 0;
static DWORD thispid = GetCurrentProcessId();
static LPCSTR rpszDllsOut = NULL;

void init() {
	//Initialize the log file.

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

	LPCSTR rpszDllsRaw = (LPCSTR)"FAST-DLL.dll";;

	CHAR szDllPath[1024];
	PCHAR pszFilePart = NULL;

	if (!GetFullPathNameA(rpszDllsRaw, ARRAYSIZE(szDllPath), szDllPath, &pszFilePart))
	{
		return;
	}

	DWORD c = (DWORD)strlen(szDllPath) + 1;
	PCHAR psz = new CHAR[c];
	StringCchCopyA(psz, c, szDllPath);
	rpszDllsOut = psz;



	/////////////////////////////////////////////////////////
	// Making shared memory.

	dwBufSize = (DWORD)(strlen(rpszDllsOut) + 1) * sizeof(char);

	fm = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE,
		0,
		(DWORD)((dwBufSize + sizeof(DWORD) + 13 * sizeof(DWORD64))), (LPCSTR)"shared");


	map_addr = (char*)MapViewOfFile(fm, FILE_MAP_ALL_ACCESS, 0, 0, 0);

	memcpy(map_addr, rpszDllsOut, dwBufSize);
	memcpy(map_addr + dwBufSize, &thispid, sizeof(DWORD));



	LPVOID fp = CallVirtualAllocEx;
	memcpy(map_addr + dwBufSize + sizeof(DWORD), &fp, sizeof(DWORD64));

	fp = CallQueueUserAPC;
	memcpy(map_addr + dwBufSize + sizeof(DWORD) + sizeof(DWORD64), &fp, sizeof(DWORD64));

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

	fp = CallSetPropA;
	memcpy(map_addr + dwBufSize + sizeof(DWORD) + 10 * sizeof(DWORD64), &fp, sizeof(DWORD64));

	fp = CallVirtualProtectEx;
	memcpy(map_addr + dwBufSize + sizeof(DWORD) + 11 * sizeof(DWORD64), &fp, sizeof(DWORD64));

	fp = CallSleepEx;
	memcpy(map_addr + dwBufSize + sizeof(DWORD) + 12 * sizeof(DWORD64), &fp, sizeof(DWORD64));



	//Initial Hooking.
	//mon(0);

}

void exiting() {

	//UnHooking All.
	for (int i = 0; i < hook_cnt; i++)
		mon(1);


	//Close Everything.
	UnmapViewOfFile(map_addr);
	CloseHandle(fm);
	fclose(pFile);
}


void vol(char* path, int op) {

	std::string str;
	if (op == 0)
		str = "windows.malfind.Malfind";
	if (op == 1)
		str = "yarascan.YaraScan";

	char cmd[512] = "";
	sprintf_s(cmd, "/C vol.exe -f %s  %s", path, str.c_str());
	Form1^ form = (Form1^)Application::OpenForms[0];
	form->logging(std::string(cmd)+"\r\n");

	HANDLE vh = ShellExecute(NULL, "open", "cmd.exe", cmd, ".", SW_NORMAL);
	if (!vh)
		MessageBoxA(NULL, "Executing Volatility.exe Failed!", "Volatility.exe Failed.!", MB_OK | MB_ICONQUESTION);


}




void imgui(std::vector<std::tuple<DWORD64, DWORD, std::string, UCHAR, std::string>> v)
{
	if (SDL_Init(SDL_INIT_VIDEO | SDL_INIT_TIMER) != 0)
	{
		printf("Error: %s\n", SDL_GetError());
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

	while (!done)
	{
		SDL_Event event;
		while (SDL_PollEvent(&event))
		{
			ImGui_ImplSDL2_ProcessEvent(&event);
			if (event.type == SDL_QUIT)
				done = true;
			if (event.type == SDL_WINDOWEVENT && event.window.event == SDL_WINDOWEVENT_CLOSE &&
				event.window.windowID == SDL_GetWindowID(window))
				done = true;
		}

		// Start the Dear ImGui frame
		ImGui_ImplOpenGL3_NewFrame();
		ImGui_ImplSDL2_NewFrame(window);
		ImGui::NewFrame();

		if (!initialized)
		{
			initialized = true;
			Show_node::NodeEditorInitialize(v.size());
		}

		Show_node::NodeEditorShow(v);

		// Rendering
		ImGui::Render();

		int fb_width, fb_height;
		SDL_GL_GetDrawableSize(window, &fb_width, &fb_height);
		glViewport(0, 0, fb_width, fb_height);
		glClear(GL_COLOR_BUFFER_BIT);

		ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
		SDL_GL_SwapWindow(window);
	}

	Show_node::NodeEditorShutdown();
	imnodes::Shutdown();

	ImGui_ImplOpenGL3_Shutdown();
	ImGui_ImplSDL2_Shutdown();
	ImGui::DestroyContext();

	SDL_GL_DeleteContext(gl_context);
	SDL_DestroyWindow(window);
	SDL_Quit();

	return;
}


// Find injected 'FAST-DLL.dll' handle from monitored process.
HMODULE findRemoteHModule(DWORD dwProcessId, const char* szdllout)
{
	MODULEENTRY32 me = { sizeof(me) };
	BOOL bMore = FALSE;
	HANDLE hSnapshot;


	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwProcessId);
	if (hSnapshot == (HANDLE)-1) {
		;
	}
	bMore = Module32First(hSnapshot, &me);
	for (; bMore; bMore = Module32Next(hSnapshot, &me))
	{
		if (!_tcsicmp((LPCTSTR)me.szExePath, szdllout))
		{
			return (HMODULE)me.modBaseAddr;
		}
	}
	return NULL;
}




// main.
//
int CDECL mon(int isFree_)
{
	// Hook/Unhook flag 
	BOOLEAN isFree = (BOOLEAN)isFree_;



	///////////////////////////////////////////////////////// Validate DLLs. (get the full path name.)

	HMODULE hDll = LoadLibraryExA(rpszDllsOut, NULL, DONT_RESOLVE_DLL_REFERENCES);
	if (hDll == NULL)
	{
		return 1;
	}

	ExportContext ec;
	ec.fHasOrdinal1 = FALSE;
	ec.nExports = 0;
	DetourEnumerateExports(hDll, &ec, ExportCallback);
	FreeLibrary(hDll);

	if (!ec.fHasOrdinal1)
	{
		return 1;
	}


	/////////////////////////////////////////////////////////




	HANDLE hProcess = NULL, hThread = NULL;
	HMODULE hMod = NULL;


	LPTHREAD_START_ROUTINE pThreadProc = NULL;


	LPVOID lpMap = 0;
	SIZE_T viewsize = 0;

	PNtMapViewOfSection = (NTSTATUS(*)(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID * BaseAddress, ULONG_PTR ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, SECTION_INHERIT InheritDisposition, ULONG AllocationType, ULONG Win32Protect)) GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtMapViewOfSection");


	hMod = GetModuleHandleA("kernel32.dll");
	if (!hMod)
	{
		return 1;
	}




	if (!isFree)
	{
		hook_cnt++;
		fprintf(pFile, "Hook DLLs!\n");
		pThreadProc = (LPTHREAD_START_ROUTINE)GetProcAddress(hMod, "LoadLibraryA");


	}
	else
	{
		if (hook_cnt > 0)
			hook_cnt--;
		fprintf(pFile, "UnHook DLLs!\n");
		pThreadProc = (LPTHREAD_START_ROUTINE)GetProcAddress(hMod, "FreeLibrary");

	}

	if (!pThreadProc)
	{
		return 1;
	}




	/////////////////////////////////////////////////////////
	// Traversing the process list, inject the dll to processes. 
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
			continue;
		}

		PNtMapViewOfSection(fm, hProcess, &lpMap, 0, dwBufSize,
			nullptr, &viewsize, ViewUnmap, 0, PAGE_READONLY);




		if (!isFree)
		{
			hThread = CreateRemoteThread(hProcess, NULL, 0, pThreadProc, lpMap, 0, NULL);
			if (!hThread)
			{
				CloseHandle(hProcess);
				continue;
			}
		}
		else
		{
			HMODULE fdllpath = findRemoteHModule(entry.th32ProcessID, (const char*)rpszDllsOut);
			if (fdllpath != NULL)
			{
				hThread = CreateRemoteThread(hProcess, NULL, 0, pThreadProc, fdllpath, 0, NULL);
				if (!hThread)
				{
					CloseHandle(hProcess);
					continue;
				}
			}
		}

		CloseHandle(hThread);
		hThread = NULL;
		CloseHandle(hProcess);
		hProcess = NULL;

	} while (Process32Next(hSnap, &entry));

	CloseHandle(hSnap);


	return 0;
}


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
		Diagnostics::Process^ proc =  Diagnostics::Process::Start(analyzeHeadless_bat, args);  // RUN analyzeHeadless.bat with arguments
		proc->WaitForExit();
	}
	else
		MessageBox::Show("There is no dumped *.bin file.", "New Ghidra Project Failed!", MessageBoxButtons::OK, MessageBoxIcon::Error);


	if (!IO::File::Exists("GhidraMemdmpProject.gpr")) {
		MessageBox::Show("There is no Ghidra project (GhidraMemdmpProject.gpr) file.", "Running Ghidra Failed!", MessageBoxButtons::OK, MessageBoxIcon::Error);
		return;
	}

	String^ ghidraRun_bat = gcnew String((ghidraDirectory + "\\ghidraRun.bat").c_str());

	if (!IO::File::Exists(ghidraRun_bat)) {
		MessageBox::Show(ghidraRun_bat + " not found.", "Running Ghidra Failed!", MessageBoxButtons::OK, MessageBoxIcon::Error);
		return;
	}

	Diagnostics::Process::Start(ghidraRun_bat, IO::Path::GetFullPath("GhidraMemdmpProject.gpr"));
}
