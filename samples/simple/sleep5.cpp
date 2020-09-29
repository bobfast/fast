//////////////////////////////////////////////////////////////////////////////
//
//  Detours Test Program (sleep5.cpp of sleep5.exe)
//
//  Microsoft Research Detours Package
//
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

int __cdecl main(int argc, char ** argv)
{
    if (argc == 2) {
        Sleep(atoi(argv[1]) * 1000);
    }
    else {
        printf("sleep5.exe: Ready...\n");

        SleepEx(10000, FALSE);

        printf("sleep5.exe: Starting.\n");
        STARTUPINFO si;

       PROCESS_INFORMATION pi;

 

       ZeroMemory(&si, sizeof(si));

       si.cb = sizeof(si);

       ZeroMemory(&pi, sizeof(pi));

       if ( !CreateProcessA(NULL, "setdll.exe", NULL, NULL, FALSE, 0, NULL, NULL, (LPSTARTUPINFOA)&si, &pi) )

       {

             printf("CreateProcess failed (%ld)\n", GetLastError());

             return 1;

       }



       WaitForSingleObject(pi.hProcess, INFINITE);



       CloseHandle(pi.hProcess);

       CloseHandle(pi.hThread);

        SleepEx(5000, FALSE);

        printf("sleep5.exe: Done sleeping.\n");
    }
    return 0;
}
//
///////////////////////////////////////////////////////////////// End of File.
