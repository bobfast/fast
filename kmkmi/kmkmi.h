#pragma once
#include <cstdint>

/// @brief log level
#define log_level_debug         3
#define log_level_info          2
#define log_level_warn          1
#define log_level_critical      0
#define log_level_error         log_level_critical

/// @brief	ntdll::DbgPrintEx 
///			(ref) dpfilter.h
#define DPFLTR_ERROR_LEVEL 0
#define DPFLTR_WARNING_LEVEL 1
#define DPFLTR_TRACE_LEVEL 2
#define DPFLTR_INFO_LEVEL 3
#define DPFLTR_MASK 0x80000000

#define DPFLTR_IHVDRIVER_ID 77

typedef LONG_PTR(NTAPI* TrueNtUserSetWindowLongPtr)(
    HWND hWnd,
    DWORD Index,
    LONG_PTR NewValue,
    BOOL Ansi);


