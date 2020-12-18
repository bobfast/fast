// dllmain.cpp : DLL 애플리케이션의 진입점을 정의합니다.

#include "framework.h"
#include "detours.h"
#include <string>
#include <psapi.h>

#pragma comment(lib, "psapi.lib")

static NTMAPVIEWOFSECTION pNtMapViewOfSection;
static NTMAPVIEWOFSECTION TrueNtMapViewOfSection;
static CREATEREMOTETHREAD pCreateRemoteThread = CreateRemoteThread;
static VIRTUALALLOCEX pVirtualAllocEx = VirtualAllocEx;
static WRITEPROCESSMEMORY pWriteProcessMemory = WriteProcessMemory;
static DBGPRINT pDbgPrint;  // for debug printing 
HMODULE hMod = NULL;

bool isDetectedRWXPageWhenInitializing = false;

// For detection in WriteProcessMemory

//#####################################

static HANDLE hMonProcess = NULL;

static LPCSTR dll_path = NULL;

static LPVOID monMMF = NULL;
static LPVOID dllMMF = NULL;

static LPTHREAD_START_ROUTINE  CallVirtualAllocEx = NULL;
static LPTHREAD_START_ROUTINE  CallQueueUserAPC = NULL;
static LPTHREAD_START_ROUTINE  CallWriteProcessMemory = NULL;
static LPTHREAD_START_ROUTINE  CallCreateRemoteThread = NULL;
static LPTHREAD_START_ROUTINE  CallNtMapViewOfSection = NULL;
static LPTHREAD_START_ROUTINE  CallCreateFileMappingA = NULL;
static LPTHREAD_START_ROUTINE  CallGetThreadContext = NULL;
static LPTHREAD_START_ROUTINE  CallSetThreadContext = NULL;
static LPTHREAD_START_ROUTINE  CallNtQueueApcThread = NULL;
static LPTHREAD_START_ROUTINE  CallSetWindowLongPtrA = NULL;
static LPTHREAD_START_ROUTINE  CallSetPropA = NULL;
static LPTHREAD_START_ROUTINE CallVirtualProtectEx = NULL;
static LPTHREAD_START_ROUTINE  CallSleepEx = NULL;

//#####################################
void printStack(char buf[]) {
    BOOL    result;

    char* sp;
    sp = buf + strnlen_s(buf, MSG_SIZE);

    HMODULE hModule;
    HANDLE Process;
    HANDLE Thread;
    STACKFRAME64        stack;
    ULONG               frame;
    DWORD64             displacement;
    char buffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(TCHAR)];
    PSYMBOL_INFO pSymbol = (PSYMBOL_INFO)buffer;

    CONTEXT ctx;

    char module[MaxNameLen];


    RtlCaptureContext(&ctx);
    memset(&stack, 0, sizeof(STACKFRAME64));

    displacement = 0;
#if !defined(_M_AMD64)
    stack.AddrPC.Offset = (*ctx).Eip;
    stack.AddrPC.Mode = AddrModeFlat;
    stack.AddrStack.Offset = (*ctx).Esp;
    stack.AddrStack.Mode = AddrModeFlat;
    stack.AddrFrame.Offset = (*ctx).Ebp;
    stack.AddrFrame.Mode = AddrModeFlat;
#endif
    Process = GetCurrentProcess();
    Thread = GetCurrentThread();
    SymInitialize(Process, NULL, TRUE); //load symbols
    DWORD offset = 0;
    for (frame = 0; ; frame++)
    {
        //get next call from stack
        result = StackWalk64
        (
#if defined(_M_AMD64)
            IMAGE_FILE_MACHINE_AMD64
#else
            IMAGE_FILE_MACHINE_I386
#endif
            ,
            Process,
            Thread,
            &stack,
            &ctx,
            NULL,
            SymFunctionTableAccess64,
            SymGetModuleBase64,
            NULL
        );

        if (!result) break;

      
        //get symbol name for address
        pSymbol->SizeOfStruct = sizeof(SYMBOL_INFO);
        pSymbol->MaxNameLen = MAX_SYM_NAME;

       

        if (!SymFromAddr(Process, (ULONG64)stack.AddrPC.Offset, &displacement, pSymbol)) {
           // sp+= sprintf_s(sp, MSG_SIZE - strnlen_s(buf, MSG_SIZE), "getlasterror:%d, %x\n",GetLastError(),stack.AddrStack.Offset );
            continue;
        } 

        if (frame == 0) {
            offset = stack.AddrFrame.Offset;
            continue;
        }

        //try to get line


        hModule = NULL;
        lstrcpyA(module, "");
        GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            (LPCTSTR)(stack.AddrPC.Offset), &hModule);

        //at least print module name

        if (hModule != NULL) {
            HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, GetCurrentProcessId());

            if (hProc != NULL) {
                if (GetModuleBaseNameA(hProc, hModule, module, MaxNameLen) != 0) {
                    sp += sprintf_s(sp, MSG_SIZE - strnlen_s(buf, MSG_SIZE), "\n\t %s!%s +0x%x", module, pSymbol->Name,stack.AddrFrame.Offset-offset);
                    CloseHandle(hProc);
                }
            }

        }


    }
    sprintf_s(sp, MSG_SIZE - strnlen_s(buf, MSG_SIZE), "*");
    SymCleanup(Process);
    CloseHandle(Thread);
    CloseHandle(Process);
}
static BOOL(WINAPI* TrueCreateProcessA)(
    LPCSTR                lpApplicationName,
    LPSTR                 lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL                  bInheritHandles,
    DWORD                 dwCreationFlags,
    LPVOID                lpEnvironment,
    LPCSTR                lpCurrentDirectory,
    LPSTARTUPINFOA        lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation
    ) = CreateProcessA;

DLLBASIC_API BOOL WINAPI HookCreateProcessA(
    LPCSTR                lpApplicationName,
    LPSTR                 lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL                  bInheritHandles,
    DWORD                 dwCreationFlags,
    LPVOID                lpEnvironment,
    LPCSTR                lpCurrentDirectory,
    LPSTARTUPINFOA        lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation)
{
    char* pValue2 = NULL;
    size_t len = NULL;
    _dupenv_s(&pValue2, &len, "expHDll");
    return DetourCreateProcessWithDllExA(lpApplicationName,
        lpCommandLine,
        lpProcessAttributes,
        lpThreadAttributes,
        bInheritHandles,
        dwCreationFlags,
        lpEnvironment,
        lpCurrentDirectory,
        lpStartupInfo,
        lpProcessInformation,
        dll_path,
        TrueCreateProcessA);
}


//#####################################

static BOOL(WINAPI* TrueCreateProcessW)(
    LPCWSTR               lpApplicationName,
    LPWSTR                lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL                  bInheritHandles,
    DWORD                 dwCreationFlags,
    LPVOID                lpEnvironment,
    LPCWSTR               lpCurrentDirectory,
    LPSTARTUPINFOW        lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation
    ) = CreateProcessW;


DLLBASIC_API BOOL WINAPI HookCreateProcessW(
    LPCWSTR               lpApplicationName,
    LPWSTR                lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL                  bInheritHandles,
    DWORD                 dwCreationFlags,
    LPVOID                lpEnvironment,
    LPCWSTR               lpCurrentDirectory,
    LPSTARTUPINFOW        lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation
)
{
    char* pValue2 = NULL;
    size_t len = NULL;
    _dupenv_s(&pValue2, &len, "expHDll");

    return DetourCreateProcessWithDllExW(lpApplicationName,
        lpCommandLine,
        lpProcessAttributes,
        lpThreadAttributes,
        bInheritHandles,
        dwCreationFlags,
        lpEnvironment,
        lpCurrentDirectory,
        lpStartupInfo,
        lpProcessInformation,
        dll_path,
        TrueCreateProcessW);

}

//#####################################
static DWORD(WINAPI* TrueQueueUserAPC)(
    PAPCFUNC  pfnAPC,
    HANDLE    hThread,
    ULONG_PTR dwData
    ) = QueueUserAPC;

DLLBASIC_API BOOL WINAPI MyQueueUserAPC(
    PAPCFUNC  pfnAPC,
    HANDLE    hThread,
    ULONG_PTR dwData
) {
    memset(dllMMF, 0, MSG_SIZE);



    HANDLE hMonThread = NULL;
    char buf[MSG_SIZE] = "";
    //sprintf_s(buf, "%d:CallNtQueueApcThread:IPC Successful!", GetProcessIdOfThread(ThreadHandle));

    LPVOID fp = pfnAPC;
    sprintf_s(buf, "%d:%p:CallQueueUserAPC:IPC Successful!", GetCurrentProcessId(), fp);


    memcpy(dllMMF, buf, strlen(buf));
    hMonThread = pCreateRemoteThread(hMonProcess, NULL, 0, (LPTHREAD_START_ROUTINE)CallQueueUserAPC, monMMF, 0, NULL);
    WaitForSingleObject(hMonThread, INFINITE);
    CloseHandle(hMonThread);
    printf("%s\n", (char*)dllMMF);
    return TrueQueueUserAPC(
        pfnAPC,
        hThread,
        dwData
    );
}


//#####################################
// NtMapViewOfSection Hooking Function


DLLBASIC_API NTSTATUS NTAPI MyNtMapViewOfSection(
    HANDLE SectionHandle,
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    SIZE_T CommitSize,
    PLARGE_INTEGER SectionOffset,
    PSIZE_T ViewSize,
    SECTION_INHERIT InheritDisposition,
    ULONG AllocationType,
    ULONG Win32Protect
)
{
    DWORD target_pid;
    DWORD64 realBaseAddr = (DWORD64)BaseAddress;
    SIZE_T readbyte;
    memset(dllMMF, 0, MSG_SIZE);
    char buf[MSG_SIZE] = "";
    HANDLE hMonThread = NULL;

    TCHAR szImagePath[MAX_PATH] = { 0, };
    DWORD dwLen = 0;
    ZeroMemory(szImagePath, sizeof(szImagePath));
    dwLen = sizeof(szImagePath) / sizeof(TCHAR);
    QueryFullProcessImageName(GetCurrentProcess(), 1, szImagePath, &dwLen);

    NTSTATUS res;

    if (Win32Protect == PAGE_EXECUTE_READWRITE) {
        res = TrueNtMapViewOfSection(
            SectionHandle,
            ProcessHandle,
            BaseAddress,
            ZeroBits,
            CommitSize,
            SectionOffset,
            ViewSize,
            InheritDisposition,
            AllocationType,
            Win32Protect);

        // GetProcessId(ProcessHandle) failed, maybe...
        // because PROCESS_VM_READ exists
        // but PROCESS_QUERY_(LIMITED)_INFORMATION doesn't exist in ProcessHandle.
        // If failed, target_pid can be 0.
        target_pid = GetProcessId(ProcessHandle);

        // Getting PID using DuplicateHandle
        HANDLE hProcessDuplicated = NULL;
        DWORD duplicateHandleResult = 0;

        if (target_pid == 0) {
            duplicateHandleResult = DuplicateHandle(GetCurrentProcess(), ProcessHandle, GetCurrentProcess(),
                &hProcessDuplicated, PROCESS_QUERY_INFORMATION, FALSE, 0);

            if (duplicateHandleResult != 0) {
                target_pid = GetProcessId(hProcessDuplicated);

                CloseHandle(hProcessDuplicated);
            }
        }

        if (!ReadProcessMemory(GetCurrentProcess(), BaseAddress, &realBaseAddr, sizeof(realBaseAddr), &readbyte)) {
            printf("Error: cannot read target process memory to get real base address.\n");
        }
        else {
            sprintf_s(buf, "%lu:%lu:%016llx:%08lx:%08lx:CallNtMapViewOfSection:IPC Successful!",
                GetCurrentProcessId(), target_pid, realBaseAddr,
                (DWORD)CommitSize, Win32Protect);
            memcpy(dllMMF, buf, strlen(buf));
            hMonThread = pCreateRemoteThread(hMonProcess, NULL, 0, CallNtMapViewOfSection, monMMF, 0, NULL);
            WaitForSingleObject(hMonThread, INFINITE);
            CloseHandle(hMonThread);
            printf("%s\n", (char*)dllMMF);
        }

        return res;
    }
    else {
        return TrueNtMapViewOfSection(
            SectionHandle,
            ProcessHandle,
            BaseAddress,
            ZeroBits,
            CommitSize,
            SectionOffset,
            ViewSize,
            InheritDisposition,
            AllocationType,
            Win32Protect);
    }
}



//#####################################
// My CreateRemoteThread Hooking Function
DLLBASIC_API HANDLE WINAPI MyCreateRemoteThread(
    HANDLE                 hProcess,
    LPSECURITY_ATTRIBUTES  lpThreadAttributes,
    SIZE_T                 dwStackSize,
    LPTHREAD_START_ROUTINE lpStartAddress,
    LPVOID                 lpParameter,
    DWORD                  dwCreationFlags,
    LPDWORD                lpThreadId)
{
    memset(dllMMF, 0, MSG_SIZE);

    char buf[MSG_SIZE] = "";
    HANDLE hMonThread = NULL;

    TCHAR szImagePath[MAX_PATH] = { 0, };
    DWORD dwLen = 0;
    ZeroMemory(szImagePath, sizeof(szImagePath));
    dwLen = sizeof(szImagePath) / sizeof(TCHAR);
    QueryFullProcessImageName(GetCurrentProcess(), 1, szImagePath, &dwLen);

    DWORD target_pid = GetProcessId(hProcess);

    // Getting PID using DuplicateHandle
    HANDLE hProcessDuplicated = NULL;
    DWORD duplicateHandleResult = 0;

    if (target_pid == 0) {
        duplicateHandleResult = DuplicateHandle(GetCurrentProcess(), hProcess, GetCurrentProcess(),
            &hProcessDuplicated, PROCESS_QUERY_INFORMATION, FALSE, 0);

        if (duplicateHandleResult != 0) {
            target_pid = GetProcessId(hProcessDuplicated);

            CloseHandle(hProcessDuplicated);
        }
    }

    if (lpStartAddress == (LPTHREAD_START_ROUTINE)LoadLibraryA) {

        if (!ReadProcessMemory(hProcess, lpParameter, buf, MSG_SIZE, NULL))
        {

            //printf("ReadProcessMemory(%ld) failed!!! [%ld]\n", GetCurrentProcessId(), GetLastError());

        }

        sprintf_s(buf, "%lu:%lu:LoadLibraryA:%p:CallCreateRemoteThread:IPC Successful!     ", GetCurrentProcessId(), target_pid, lpParameter);
        //sprintf_s(buf, "%lu:LoadLibraryA::CallCreateRemoteThread:IPC Successful!     ", GetProcessId(hProcess));
    }
    else {


        //MessageBoxA(NULL, (std::string("target : ") + std::to_string(GetProcessId(hProcess))).c_str(), "test", MB_OK);
        if (!(GetProcessId(hProcess)))
        {

            printf("GetProcessId(%ld) failed!!! [%ld]\n", GetProcessId(hProcess), GetLastError());

        }
        //sprintf_s(buf, "%lu:%016x:%016x:CallCreateRemoteThread:IPC Successful!     ", GetProcessId(hProcess), lpStartAddress, lpParameter);
        sprintf_s(buf, "%lu:%lu:%p:%p:%s:CallCreateRemoteThread:IPC Successful!     ", GetCurrentProcessId(), target_pid, lpStartAddress, lpParameter, szImagePath);
    }
    printStack(buf);
    memcpy(dllMMF, buf, strlen(buf));
    hMonThread = pCreateRemoteThread(hMonProcess, NULL, 0, CallCreateRemoteThread, monMMF, 0, NULL);
    WaitForSingleObject(hMonThread, INFINITE);
    CloseHandle(hMonThread);
    printf("%s\n", (char*)dllMMF);

    char* cp = (char*)dllMMF;
    char* context = NULL;
    std::string pid(strtok_s(cp, ":", &context));
    std::string res(strtok_s(NULL, ":", &context));
    if (strncmp(res.c_str(), "Detected", 8) == 0) {
        printf("CreateRemoteThread : Process Injection Attack Detected and Prevented!\n");

        return NULL;
    }


    return pCreateRemoteThread(
        hProcess,
        lpThreadAttributes,
        dwStackSize,
        lpStartAddress,
        lpParameter,
        dwCreationFlags,
        lpThreadId
    );
}


//#####################################
// My VirtualAllocEx Hooking Function
DLLBASIC_API LPVOID WINAPI MyVirtualAllocEx(
    HANDLE hProcess,
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD  flAllocationType,
    DWORD  flProtect)
{
    memset(dllMMF, 0, MSG_SIZE);
    char buf[MSG_SIZE] = "";
    HANDLE hMonThread = NULL;

    TCHAR szImagePath[MAX_PATH] = { 0, };
    DWORD dwLen = 0;
    ZeroMemory(szImagePath, sizeof(szImagePath));
    dwLen = sizeof(szImagePath) / sizeof(TCHAR);
    QueryFullProcessImageName(GetCurrentProcess(), 1, szImagePath, &dwLen);

    if (flProtect == (PAGE_EXECUTE_READWRITE)) {

        LPVOID ret = pVirtualAllocEx(
            hProcess,
            lpAddress,
            dwSize,
            flAllocationType,
            flProtect
        );

        sprintf_s(buf, "%lu:%lu:%016llx:%08lx:%08lx:%s:CallVirtualAllocEx:IPC Successful!", GetCurrentProcessId(), GetProcessId(hProcess), (DWORD64)ret, (DWORD)dwSize, flProtect, szImagePath);
        printStack(buf);
        memcpy(dllMMF, buf, strlen(buf));
        hMonThread = pCreateRemoteThread(hMonProcess, NULL, 0, CallVirtualAllocEx, monMMF, 0, NULL);
        WaitForSingleObject(hMonThread, INFINITE);
        CloseHandle(hMonThread);
        printf("%s\n", (char*)dllMMF);
        return ret;
    }
    else
        return pVirtualAllocEx(
            hProcess,
            lpAddress,
            dwSize,
            flAllocationType,
            flProtect
        );
}

//#####################################
// My WriteProcessMemory Hooking Function
DLLBASIC_API BOOL WINAPI MyWriteProcessMemory(
    HANDLE  hProcess,
    LPVOID  lpBaseAddress,
    LPCVOID lpBuffer,
    SIZE_T  nSize,
    SIZE_T* lpNumberOfBytesWritten)
{
    memset(dllMMF, 0, MSG_SIZE);

    char buf[MSG_SIZE] = "";
    HANDLE hMonThread = NULL;

    TCHAR szImagePath[MAX_PATH] = { 0, };
    DWORD dwLen = 0;
    ZeroMemory(szImagePath, sizeof(szImagePath));
    dwLen = sizeof(szImagePath) / sizeof(TCHAR);
    QueryFullProcessImageName(GetCurrentProcess(), 1, szImagePath, &dwLen);

    sprintf_s(buf, "%lu:%lu:%016llx:%08lx:%s:MyWriteProcessMemory:IPC Successful!", GetCurrentProcessId(), GetProcessId(hProcess), (DWORD64)lpBaseAddress, (DWORD)nSize, szImagePath);
    printStack(buf);
    memcpy(dllMMF, buf, strlen(buf));
    hMonThread = pCreateRemoteThread(hMonProcess, NULL, 0, CallWriteProcessMemory, monMMF, 0, NULL);
    WaitForSingleObject(hMonThread, INFINITE);
    CloseHandle(hMonThread);
    printf("%s\n", (char*)dllMMF);


    return pWriteProcessMemory(
        hProcess,
        lpBaseAddress,
        lpBuffer,
        nSize,
        lpNumberOfBytesWritten
    );
}



//#####################################

static HANDLE(WINAPI* TrueCreateFileMappingA)(
    HANDLE               hFile,
    LPSECURITY_ATTRIBUTES   lpFileMappingAttributes,
    DWORD               flProtect,
    DWORD               dwMaximumSizeHigh,
    DWORD               dwMaximumSizeLow,
    LPCSTR               lpName
    ) = CreateFileMappingA;

DLLBASIC_API HANDLE   WINAPI MyCreateFileMappingA(
    HANDLE                hFile,
    LPSECURITY_ATTRIBUTES lpFileMappingAttributes,
    DWORD                 flProtect,
    DWORD                 dwMaximumSizeHigh,
    DWORD                 dwMaximumSizeLow,
    LPCSTR                lpName
)
{
    //printf("CreateFileMappingA is HOOKED!!\n");
    if ((hFile == INVALID_HANDLE_VALUE)
        ) {//&& (flProtect == PAGE_EXECUTE_READWRITE)) {
        memset(dllMMF, 0, MSG_SIZE);

        HANDLE hThread = NULL;
        char buf[MSG_SIZE] = "";
        sprintf_s(buf, "%lu:CallCreateFileMappingA:IPC Successful!     ", GetCurrentProcessId());
        printStack(buf);
        memcpy(dllMMF, buf, strlen(buf));
        hThread = pCreateRemoteThread(hMonProcess, NULL, 0, (LPTHREAD_START_ROUTINE)CallCreateFileMappingA, monMMF, 0, NULL);
        WaitForSingleObject(hThread, INFINITE);
        CloseHandle(hThread);
        printf("%s\n", (char*)dllMMF);  //#####
    }
    HANDLE check_map = NULL;
    check_map = TrueCreateFileMappingA(hFile, lpFileMappingAttributes, flProtect, dwMaximumSizeHigh, dwMaximumSizeLow, lpName);
    return check_map;
}


//#####################################

typedef NTSTATUS(NTAPI* pNtQueueApcThread)(
    _In_ HANDLE ThreadHandle,
    _In_ PVOID ApcRoutine,
    _In_ PVOID ApcRoutineContext OPTIONAL,
    _In_ PVOID ApcStatusBlock OPTIONAL,
    _In_ PVOID ApcReserved OPTIONAL
    );

static pNtQueueApcThread NtQueueApcThread = NULL;



DLLBASIC_API NTSTATUS NTAPI MyNtQueueApcThread(
    HANDLE ThreadHandle,
    PVOID ApcRoutine,
    PVOID ApcRoutineContext OPTIONAL,
    PVOID ApcStatusBlock OPTIONAL,
    PVOID ApcReserved OPTIONAL
) {
    memset(dllMMF, 0, MSG_SIZE);


    DWORD target_pid = GetProcessIdOfThread(ThreadHandle);
    HANDLE hThread = NULL;
    char buf[MSG_SIZE] = "";

    TCHAR szImagePath[MAX_PATH] = { 0, };
    DWORD dwLen = 0;
    ZeroMemory(szImagePath, sizeof(szImagePath));
    dwLen = sizeof(szImagePath) / sizeof(TCHAR);
    QueryFullProcessImageName(GetCurrentProcess(), 1, szImagePath, &dwLen);

    if (ApcRoutine == GlobalGetAtomNameA)
        sprintf_s(buf, "%lu:%lu:GlobalGetAtomNameA:%s:CallNtQueueApcThread:IPC Successful!", GetCurrentProcessId(), target_pid, szImagePath);
    else
        sprintf_s(buf, "%lu:%lu:%p:%s:CallNtQueueApcThread:IPC Successful!", GetCurrentProcessId(), target_pid, ApcRoutine, szImagePath);
    printStack(buf);
    memcpy(dllMMF, buf, strlen(buf));
    hThread = pCreateRemoteThread(hMonProcess, NULL, 0, (LPTHREAD_START_ROUTINE)CallNtQueueApcThread, monMMF, 0, NULL);
    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);
    printf("%s\n", (char*)dllMMF);

    char* cp = (char*)dllMMF;
    char* context = NULL;
    std::string pid(strtok_s(cp, ":", &context));
    std::string res(strtok_s(NULL, ":", &context));
    if (strncmp(res.c_str(), "Detected", 8) == 0) {
        printf("NtQueueApcThread : Process Injection Attack Detected and Prevented!\n");

        return NULL;
    }

    return NtQueueApcThread(ThreadHandle,
        ApcRoutine,
        ApcRoutineContext OPTIONAL,
        ApcStatusBlock OPTIONAL,
        ApcReserved OPTIONAL);
}


//#####################################


static BOOL(WINAPI* TrueSetThreadContext)(
    HANDLE        hThread,
    const CONTEXT* lpContext
    ) = SetThreadContext;

DLLBASIC_API BOOL WINAPI MySetThreadContext(
    HANDLE        hThread,
    const CONTEXT* lpContext
) {
    memset(dllMMF, 0, MSG_SIZE);

    // GetProcessIdOfThread(hThread) failed, maybe...
    // because THREAD_SET_CONTEXT exists
    // but THREAD_QUERY_(LIMITED)_INFORMATION doesn't exist in hThread.
    // If failed, target_pid can be 0.
    DWORD target_pid = GetProcessIdOfThread(hThread);
    char buf[MSG_SIZE] = "";
    HANDLE hMonThread = NULL;

    // Getting PID using DuplicateHandle
    HANDLE hThreadDuplicated = NULL;
    DWORD duplicateHandleResult = 0;

    if (target_pid == 0) {
        duplicateHandleResult = DuplicateHandle(GetCurrentProcess(), hThread, GetCurrentProcess(),
            &hThreadDuplicated, THREAD_QUERY_INFORMATION, FALSE, 0);

        if (duplicateHandleResult != 0) {
            target_pid = GetProcessIdOfThread(hThreadDuplicated);

            CloseHandle(hThreadDuplicated);
        }
    }

    TCHAR szImagePath[MAX_PATH] = { 0, };
    DWORD dwLen = 0;
    ZeroMemory(szImagePath, sizeof(szImagePath));
    dwLen = sizeof(szImagePath) / sizeof(TCHAR);
    QueryFullProcessImageName(GetCurrentProcess(), 1, szImagePath, &dwLen);

#ifdef _X86_
    if (lpContext->Eip == 0) {
        sprintf_s(buf, "%lu:%lu:%016llx:%s:CallSetThreadContext:IPC Successful!", GetCurrentProcessId(), target_pid, (ULONGLONG)lpContext->Eax, szImagePath);
    }
    else {
        sprintf_s(buf, "%lu:%lu:%016llx:%s:CallSetThreadContext:IPC Successful!", GetCurrentProcessId(), target_pid, (ULONGLONG)lpContext->Eip, szImagePath);
    }
#endif
#ifdef _AMD64_
    if (lpContext->Rip == 0) {
        sprintf_s(buf, "%lu:%lu:%016llx:%s:CallSetThreadContext:IPC Successful!", GetCurrentProcessId(), target_pid, lpContext->Rax, szImagePath);
    }
    else {
        sprintf_s(buf, "%lu:%lu:%016llx:%s:CallSetThreadContext:IPC Successful!", GetCurrentProcessId(), target_pid, lpContext->Rip, szImagePath);
    }
#endif
    printStack(buf);
    memcpy(dllMMF, buf, strlen(buf));
    hMonThread = pCreateRemoteThread(hMonProcess, NULL, 0, (LPTHREAD_START_ROUTINE)CallSetThreadContext, monMMF, 0, NULL);
    WaitForSingleObject(hMonThread, INFINITE);
    CloseHandle(hMonThread);
    printf("%s\n", (char*)dllMMF);

    char* cp = (char*)dllMMF;
    char* context = NULL;
    std::string pid(strtok_s(cp, ":", &context));
    std::string res(strtok_s(NULL, ":", &context));
    if (strncmp(res.c_str(), "Detected", 8) == 0) {
        printf("CallSetThreadContext : Thread Hijacking Attack Detected and Prevented!\n");
        return NULL;
    }
    return TrueSetThreadContext(
        hThread,
        lpContext
    );
}



//#####################################

static LONG_PTR(WINAPI* TrueSetWindowLongPtrA) (
    HWND     hWnd,
    int      nIndex,
    LONG_PTR dwNewLong
    ) = SetWindowLongPtrA;

DLLBASIC_API LONG_PTR WINAPI MySetWindowLongPtrA
(HWND     hWnd,
    int      nIndex,
    LONG_PTR dwNewLong) {

    memset(dllMMF, 0, MSG_SIZE);


    char buf[MSG_SIZE] = "";
    HANDLE hThread = NULL;
    DWORD dwpid = NULL;
    GetWindowThreadProcessId(hWnd, &dwpid);

    TCHAR szImagePath[MAX_PATH] = { 0, };
    DWORD dwLen = 0;
    ZeroMemory(szImagePath, sizeof(szImagePath));
    dwLen = sizeof(szImagePath) / sizeof(TCHAR);
    QueryFullProcessImageName(GetCurrentProcess(), 1, szImagePath, &dwLen);

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwpid);
    if (!hProcess)
    {
        printf("OpenProcess(%ld) failed!!! [%ld]\n", GetCurrentProcessId(), GetLastError());
        return NULL;
    }

    DWORD64 p1 = NULL, p2 = NULL;

    if (!ReadProcessMemory(hProcess, (LPCVOID)dwNewLong, (LPVOID)&p1, sizeof(LPVOID), NULL))
    {
        printf("ReadProcessMemory(%ld) failed!!! [%ld]\n", GetCurrentProcessId(), GetLastError());
        return NULL;
    }
    if (!ReadProcessMemory(hProcess, (LPCVOID)p1, (LPVOID)&p2, sizeof(LPVOID), NULL))
    {
        printf("ReadProcessMemory(%ld) failed!!! [%ld]\n", GetCurrentProcessId(), GetLastError());
        return NULL;
    }

    CloseHandle(hProcess);

    printf("%016llx\n", dwNewLong);
    sprintf_s(buf, "%lu:%lu:%016llx:%s:CallSetWindowLongPtrA:IPC Successful!", GetCurrentProcessId(), dwpid, p2, szImagePath);
    printStack(buf);
    memcpy(dllMMF, buf, strlen(buf));
    hThread = pCreateRemoteThread(hMonProcess, NULL, 0, (LPTHREAD_START_ROUTINE)CallSetWindowLongPtrA, monMMF, 0, NULL);
    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);
    printf("%s\n", (char*)dllMMF);

    char* cp = (char*)dllMMF;
    char* context = NULL;
    std::string pid(strtok_s(cp, ":", &context));
    std::string res(strtok_s(NULL, ":", &context));
    if (strncmp(res.c_str(), "Detected", 8) == 0) {
        printf("SetWindowLongPtrA : Windows Attribute Injection Attack Detected and Prevented!\n");
        return NULL;
    }
    return TrueSetWindowLongPtrA(hWnd, nIndex, dwNewLong);
}


//#####################################



static BOOL(WINAPI* TrueSetPropA)(
    HWND   hWnd,
    LPCSTR lpString,
    HANDLE hData
    ) = SetPropA;

DLLBASIC_API BOOL WINAPI  MySetPropA(
    HWND   hWnd,
    LPCSTR lpString,
    HANDLE hData
) {
    memset(dllMMF, 0, MSG_SIZE);


    char buf[MSG_SIZE] = "";
    HANDLE hThread = NULL;
    DWORD dwpid = NULL;
    GetWindowThreadProcessId(hWnd, &dwpid);


    TCHAR szImagePath[MAX_PATH] = { 0, };
    DWORD dwLen = 0;
    ZeroMemory(szImagePath, sizeof(szImagePath));
    dwLen = sizeof(szImagePath) / sizeof(TCHAR);
    QueryFullProcessImageName(GetCurrentProcess(), 1, szImagePath, &dwLen);

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwpid);
    if (!hProcess)
    {
        printf("OpenProcess(%ld) failed!!! [%ld]\n", GetCurrentProcessId(), GetLastError());
        return NULL;
    }

    DWORD64 ptr = NULL;

    if (!ReadProcessMemory(hProcess, (LPCVOID)((DWORD64)hData + 0x18), (LPVOID)&ptr, sizeof(LPVOID), NULL))
    {
        printf("ReadProcessMemory(%ld) failed!!! [%ld]\n", GetCurrentProcessId(), GetLastError());
        return NULL;
    }


    sprintf_s(buf, "%lu:%lu:%016llx:%s:CallSetPropA:IPC Successful!", GetCurrentProcessId(), dwpid, ptr, szImagePath);
    printStack(buf);
    memcpy(dllMMF, buf, strlen(buf));
    hThread = pCreateRemoteThread(hMonProcess, NULL, 0, (LPTHREAD_START_ROUTINE)CallSetPropA, monMMF, 0, NULL);
    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);
    printf("%s\n", (char*)dllMMF);

    char* cp = (char*)dllMMF;
    char* context = NULL;
    std::string pid(strtok_s(cp, ":", &context));
    std::string res(strtok_s(NULL, ":", &context));
    if (strncmp(res.c_str(), "Detected", 8) == 0) {
        printf("SetPropA : Windows Property Injection Attack Detected and Prevented!\n");
        return NULL;
    }
    return TrueSetPropA(
        hWnd,
        lpString,
        hData
    );

}

//#####################################

static BOOL(WINAPI* TrueVirtualProtectEx)(
    HANDLE hProcess,
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD  flNewProtect,
    PDWORD lpflOldProtect
    ) = VirtualProtectEx;

DLLBASIC_API BOOL WINAPI  MyVirtualProtectEx(
    HANDLE hProcess,
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD  flNewProtect,
    PDWORD lpflOldProtect)
{
    memset(dllMMF, 0, MSG_SIZE);
    char buf[MSG_SIZE] = "";
    HANDLE hMonThread = NULL;

    TCHAR szImagePath[MAX_PATH] = { 0, };
    DWORD dwLen = 0;
    ZeroMemory(szImagePath, sizeof(szImagePath));
    dwLen = sizeof(szImagePath) / sizeof(TCHAR);
    QueryFullProcessImageName(GetCurrentProcess(), 1, szImagePath, &dwLen);


    if (flNewProtect == (PAGE_EXECUTE_READWRITE)) {

        sprintf_s(buf, "%lu:%lu:%016llx:%08lx:%08lx:%s:MyVirtualProtectEx:IPC Successful!", GetCurrentProcessId(), GetProcessId(hProcess), (DWORD64)lpAddress, (DWORD)dwSize, flNewProtect, szImagePath);
        printStack(buf);
        memcpy(dllMMF, buf, strlen(buf));
        hMonThread = pCreateRemoteThread(hMonProcess, NULL, 0, CallVirtualProtectEx, monMMF, 0, NULL);
        WaitForSingleObject(hMonThread, INFINITE);
        CloseHandle(hMonThread);
        printf("%s\n", (char*)dllMMF);
    }

    return TrueVirtualProtectEx(
        hProcess,
        lpAddress,
        dwSize,
        flNewProtect,
        lpflOldProtect);
}
//#####################################

static LONG dwSlept = 0;
static DWORD(WINAPI* TrueSleepEx)(DWORD dwMilliseconds, BOOL bAlertable) = SleepEx;

DWORD WINAPI TimedSleepEx(DWORD dwMilliseconds, BOOL bAlertable)
{
    //printf("sleep5.exe: is Hooked.\n");
    ULONGLONG dwBeg = GetTickCount64();
    DWORD ret = TrueSleepEx(dwMilliseconds, bAlertable);
    ULONGLONG dwEnd = GetTickCount64();

    InterlockedExchangeAdd(&dwSlept, LONG(dwEnd - dwBeg));

    memset(dllMMF, 0, MSG_SIZE);

    HANDLE hThread = NULL;
    char buf[MSG_SIZE] = "";
    sprintf_s(buf, "%lu:CallSleepEx:IPC Successful!     ", GetCurrentProcessId());
    printStack(buf);
    memcpy(dllMMF, buf, strlen(buf));
    hThread = pCreateRemoteThread(hMonProcess, NULL, 0, CallSleepEx, monMMF, 0, NULL);
    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);
    printf("%s\n", (char*)dllMMF);


    return ret;
}


//#####################################

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD dwReason, LPVOID reserved)
{
    hinst;
    dwReason;
    reserved;

    HANDLE hMemoryMap = NULL;
    LPBYTE pMemoryMap = NULL;

    HANDLE fm = NULL;
    char* map_addr = nullptr;
    NTSTATUS mapview_stat;
    LPVOID lpMap = 0;
    SIZE_T viewsize = 0;
    size_t sz;

    switch (dwReason)
    {
    case DLL_PROCESS_ATTACH:

        if (DetourIsHelperProcess()) {
            OutputDebugStringA("FAST-DLL: It is helper process. Quit.\n");
            return TRUE;
        }

        //#############################

#ifdef _X86_
        hMemoryMap = OpenFileMapping(FILE_MAP_READ, FALSE, (LPCSTR)"shared32");
#endif
#ifdef _AMD64_
        hMemoryMap = OpenFileMapping(FILE_MAP_READ, FALSE, (LPCSTR)"shared64");
#endif

        pMemoryMap = (BYTE*)MapViewOfFile(
            hMemoryMap, FILE_MAP_READ,
            0, 0, 0
        );
        if (!pMemoryMap)
        {
            CloseHandle(hMemoryMap);
            OutputDebugStringA("FAST-DLL: MapViewOfFile Failed.");
            return FALSE;
        }

        sz = strlen((char*)pMemoryMap) + 1;

        dll_path = (LPCSTR)pMemoryMap;

        //printf("%s\n", (char*)pMemoryMap);
        //printf("%lu\n", *(DWORD*)((char*)pMemoryMap + sz));

        // get ntdll module
        hMod = GetModuleHandleA("ntdll.dll");
        if (hMod == NULL) {
            OutputDebugStringA("FAST-DLL: Error - cannot get ntdll.dll module.");
            return 1;
        }

        // get functions in ntdll
        TrueNtMapViewOfSection = (NTMAPVIEWOFSECTION)GetProcAddress(hMod, "NtMapViewOfSection");
        if (TrueNtMapViewOfSection == NULL) {
            OutputDebugStringA("FAST-DLL: Failed to get NtMapViewOfSection.");
            return 1;
        }
        pNtMapViewOfSection = (NTMAPVIEWOFSECTION)GetProcAddress(hMod, "NtMapViewOfSection");
        if (pNtMapViewOfSection == NULL) {
            OutputDebugStringA("FAST-DLL: Error - cannot get NtMapViewOfSection's address.");
            return 1;
        }

        NtQueueApcThread = (pNtQueueApcThread)GetProcAddress(hMod, "NtQueueApcThread");
        if (NtQueueApcThread == NULL) {
            OutputDebugStringA("FAST-DLL: GetProcAddress NtQueueApcThread Failed.");
            return 1;
        }

        pDbgPrint = (DBGPRINT)GetProcAddress(hMod, "DbgPrint");
        if (pDbgPrint == NULL) {
            OutputDebugStringA("FAST-DLL: Error - cannot get DbgPrint's address.");
            return 1;
        }

        fm = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, MSG_SIZE, NULL);
        if (fm == NULL) {
            OutputDebugStringA("FAST-DLL: Error - cannot create file mapping.");
            return 1;
        }
        map_addr = (char*)MapViewOfFile(fm, FILE_MAP_ALL_ACCESS, 0, 0, 0);
        if (!map_addr) {
            OutputDebugStringA((std::string("FAST-DLL: Cannot map view of a file. Error code = ") + std::to_string(GetLastError())).c_str());
            return FALSE;
        }

        hMonProcess = OpenProcess(PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD, FALSE, *(DWORD*)((char*)pMemoryMap + sz));

        if (!hMonProcess) {
            OutputDebugStringA((std::string("FAST-DLL: Cannot open monitor process. Error code = ") + std::to_string(GetLastError())).c_str());
            return FALSE;
        }

        mapview_stat = pNtMapViewOfSection(fm, hMonProcess, &lpMap, 0, MSG_SIZE, nullptr, &viewsize, SECTION_INHERIT::ViewUnmap, 0, PAGE_READWRITE); // "The default behavior for executable pages allocated is to be marked valid call targets for CFG." (https://docs.microsoft.com/en-us/windows/desktop/api/memoryapi/nf-memoryapi-mapviewoffile)
        if (!NT_SUCCESS(mapview_stat)) {
            OutputDebugStringA("FAST-DLL: Cannot get map view of section of monitor process.");
            return FALSE;
        }

        monMMF = (LPVOID)lpMap;
        dllMMF = (LPVOID)map_addr;

        CallVirtualAllocEx = (LPTHREAD_START_ROUTINE)(*(DWORD64*)(pMemoryMap + sz + sizeof(DWORD)));
        CallQueueUserAPC = (LPTHREAD_START_ROUTINE)(*(DWORD64*)(pMemoryMap + sz + sizeof(DWORD) + sizeof(DWORD64)));
        CallWriteProcessMemory = (LPTHREAD_START_ROUTINE)(*(DWORD64*)(pMemoryMap + sz + sizeof(DWORD) + 2 * sizeof(DWORD64)));
        CallCreateRemoteThread = (LPTHREAD_START_ROUTINE)(*(DWORD64*)(pMemoryMap + sz + sizeof(DWORD) + 3 * sizeof(DWORD64)));
        CallNtMapViewOfSection = (LPTHREAD_START_ROUTINE)(*(DWORD64*)(pMemoryMap + sz + sizeof(DWORD) + 4 * sizeof(DWORD64)));
        CallCreateFileMappingA = (LPTHREAD_START_ROUTINE)(*(DWORD64*)(pMemoryMap + sz + sizeof(DWORD) + 5 * sizeof(DWORD64)));
        CallGetThreadContext = (LPTHREAD_START_ROUTINE)(*(DWORD64*)(pMemoryMap + sz + sizeof(DWORD) + 6 * sizeof(DWORD64)));
        CallSetThreadContext = (LPTHREAD_START_ROUTINE)(*(DWORD64*)(pMemoryMap + sz + sizeof(DWORD) + 7 * sizeof(DWORD64)));
        CallNtQueueApcThread = (LPTHREAD_START_ROUTINE)(*(DWORD64*)(pMemoryMap + sz + sizeof(DWORD) + 8 * sizeof(DWORD64)));
        CallSetWindowLongPtrA = (LPTHREAD_START_ROUTINE)(*(DWORD64*)(pMemoryMap + sz + sizeof(DWORD) + 9 * sizeof(DWORD64)));
        CallSetPropA = (LPTHREAD_START_ROUTINE)(*(DWORD64*)(pMemoryMap + sz + sizeof(DWORD) + 10 * sizeof(DWORD64)));
        CallVirtualProtectEx = (LPTHREAD_START_ROUTINE)(*(DWORD64*)(pMemoryMap + sz + sizeof(DWORD) + 11 * sizeof(DWORD64)));
        CallSleepEx = (LPTHREAD_START_ROUTINE)(*(DWORD64*)(pMemoryMap + sz + sizeof(DWORD) + 12 * sizeof(DWORD64)));

        //printf("%llu\n", *(DWORD64*)(pMemoryMap + sz + sizeof(DWORD)));




        //#############################

        DetourRestoreAfterWith();
        DisableThreadLibraryCalls(hinst);

        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());

        // TODO: attaching
        DetourAttach(&(PVOID&)TrueCreateProcessA, HookCreateProcessA);
        DetourAttach(&(PVOID&)TrueCreateProcessW, HookCreateProcessW);
        DetourAttach(&(PVOID&)pCreateRemoteThread, MyCreateRemoteThread);
        DetourAttach(&(PVOID&)pVirtualAllocEx, MyVirtualAllocEx);
        //DetourAttach(&(PVOID&)TrueQueueUserAPC, MyQueueUserAPC);
        DetourAttach(&(PVOID&)pWriteProcessMemory, MyWriteProcessMemory);
        DetourAttach(&(PVOID&)TrueNtMapViewOfSection, MyNtMapViewOfSection);
        DetourAttach(&(PVOID&)TrueCreateFileMappingA, MyCreateFileMappingA);
        DetourAttach(&(PVOID&)NtQueueApcThread, MyNtQueueApcThread);
        DetourAttach(&(PVOID&)TrueSetThreadContext, MySetThreadContext);
        DetourAttach(&(PVOID&)TrueSetWindowLongPtrA, MySetWindowLongPtrA);
        DetourAttach(&(PVOID&)TrueSetPropA, MySetPropA);
        DetourAttach(&(PVOID&)TrueVirtualProtectEx, MyVirtualProtectEx);
        //DetourAttach(&(PVOID&)TrueSleepEx, TimedSleepEx);

        DetourTransactionCommit();

        printf("FAST-DLL: Process attached.\n");
        break;

    case DLL_THREAD_ATTACH:
        printf("FAST-DLL: Thread attached.\n");
        break;

    case DLL_THREAD_DETACH:
        printf("FAST-DLL: Thread detached.\n");
        break;

    case DLL_PROCESS_DETACH:



        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());

        // TODO: detaching
        DetourDetach(&(PVOID&)TrueCreateProcessA, HookCreateProcessA);
        DetourDetach(&(PVOID&)TrueCreateProcessW, HookCreateProcessW);
        DetourDetach(&(PVOID&)pCreateRemoteThread, MyCreateRemoteThread);
        DetourDetach(&(PVOID&)pVirtualAllocEx, MyVirtualAllocEx);
        //DetourDetach(&(PVOID&)TrueQueueUserAPC, MyQueueUserAPC);
        DetourDetach(&(PVOID&)pWriteProcessMemory, MyWriteProcessMemory);
        DetourDetach(&(PVOID&)TrueNtMapViewOfSection, MyNtMapViewOfSection);
        DetourDetach(&(PVOID&)TrueCreateFileMappingA, MyCreateFileMappingA);
        DetourDetach(&(PVOID&)NtQueueApcThread, MyNtQueueApcThread);
        DetourDetach(&(PVOID&)TrueSetThreadContext, MySetThreadContext);
        DetourDetach(&(PVOID&)TrueSetWindowLongPtrA, MySetWindowLongPtrA);
        DetourDetach(&(PVOID&)TrueSetPropA, MySetPropA);
        DetourDetach(&(PVOID&)TrueVirtualProtectEx, MyVirtualProtectEx);
        //DetourDetach(&(PVOID&)TrueSleepEx, TimedSleepEx);
        DetourTransactionCommit();

        CloseHandle(hMonProcess);
        UnmapViewOfFile(pMemoryMap);
        UnmapViewOfFile(map_addr);
        CloseHandle(fm);

        printf("FAST-DLL: Process detached.\n");
        break;
    }

    return TRUE;
}