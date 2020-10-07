#pragma once


typedef LONG_PTR(NTAPI* TrueNtUserSetWindowLongPtr)(
    HWND hWnd,
    DWORD Index,
    LONG_PTR NewValue,
    BOOL Ansi);