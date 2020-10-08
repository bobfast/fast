#include <winternl.h>
#include <Windows.h>
typedef NTSTATUS(NTAPI* pNtQueueApcThread)(
    _In_ HANDLE ThreadHandle,
    _In_ PVOID ApcRoutine,
    _In_ PVOID ApcRoutineContext OPTIONAL,
    _In_ PVOID ApcStatusBlock OPTIONAL,
    _In_ PVOID ApcReserved OPTIONAL
    );