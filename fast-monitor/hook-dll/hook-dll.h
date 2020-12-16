#pragma once
#include <stdio.h>
#include <Windows.h>
//#include <ntdef.h>
#include <ImageHlp.h>
#include <detours.h>
#include <strsafe.h>
#include <tlhelp32.h>
#include <tchar.h>

#define OBJ_INHERIT                         0x00000002L
#define OBJ_PERMANENT                       0x00000010L
#define OBJ_EXCLUSIVE                       0x00000020L
#define OBJ_CASE_INSENSITIVE                0x00000040L
#define OBJ_OPENIF                          0x00000080L
#define OBJ_OPENLINK                        0x00000100L
#define OBJ_KERNEL_HANDLE                   0x00000200L
#define OBJ_FORCE_ACCESS_CHECK              0x00000400L
#define OBJ_IGNORE_IMPERSONATED_DEVICEMAP   0x00000800L
#define OBJ_DONT_REPARSE                    0x00001000L
#define OBJ_VALID_ATTRIBUTES                0x00001FF2L

#define RtlOffsetToPointer(Base, Offset) ((PCHAR)(((PCHAR)(Base)) + ((ULONG_PTR)(Offset))))
#define RtlPointerToOffset(Base, Pointer) ((ULONG)(((PCHAR)(Pointer)) - ((PCHAR)(Base))))

#define echo(x) x 
#define label(x) echo(x)__LINE__ 
#define RTL_CONSTANT_STRINGW(s) { sizeof( s ) - sizeof( (s)[0] ), sizeof( s ),(PWSTR)(s) } 

#define STATIC_UNICODE_STRING(name, str) static const WCHAR label(__)[] = L##str; static const UNICODE_STRING name = RTL_CONSTANT_STRINGW(label(__))

#define STATIC_OBJECT_ATTRIBUTES(oa, name) STATIC_UNICODE_STRING(label(m), name); static OBJECT_ATTRIBUTES oa = { sizeof oa, 0, (PUNICODE_STRING)&label(m), OBJ_CASE_INSENSITIVE }

#define NtCurrentProcess() ( (HANDLE)(LONG_PTR) -1 )

typedef enum _SECTION_INHERIT
{
	ViewShare = 1,
	ViewUnmap = 2
} SECTION_INHERIT;

static NTSTATUS(*PNtMapViewOfSection)(
	HANDLE SectionHandle,
	HANDLE ProcessHandle,
	PVOID* BaseAddress,
	ULONG_PTR ZeroBits,
	SIZE_T CommitSize,
	PLARGE_INTEGER SectionOffset,
	PSIZE_T ViewSize,
	SECTION_INHERIT InheritDisposition,
	ULONG AllocationType,
	ULONG Win32Protect);

struct ExportContext
{
	BOOL fHasOrdinal1;
	ULONG nExports;
};

static PIMAGE_NT_HEADERS(*PRtlImageNtHeader)(
	PVOID ModuleAddress
	);

static PVOID(*PRtlImageDirectoryEntryToData)(
	PVOID BaseAddress,
	BOOLEAN MappedAsImage,
	USHORT Directory,
	PULONG Size);

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
#ifdef MIDL_PASS
	[size_is(MaximumLength / 2), length_is((Length) / 2)] USHORT* Buffer;
#else // MIDL_PASS
	_Field_size_bytes_part_opt_(MaximumLength, Length) PWCH   Buffer;
#endif // MIDL_PASS
} UNICODE_STRING;
typedef UNICODE_STRING* PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
	ULONG Length;
	HANDLE RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG Attributes;
	PVOID SecurityDescriptor;        // Points to type SECURITY_DESCRIPTOR
	PVOID SecurityQualityOfService;  // Points to type SECURITY_QUALITY_OF_SERVICE
} OBJECT_ATTRIBUTES;
typedef OBJECT_ATTRIBUTES* POBJECT_ATTRIBUTES;
typedef CONST OBJECT_ATTRIBUTES* PCOBJECT_ATTRIBUTES;

static NTSTATUS(*PNtOpenSection)(
	PHANDLE SectionHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes
	);

typedef struct _SECTION_IMAGE_INFORMATION {
	PVOID                   EntryPoint;
	ULONG                   StackZeroBits;
	ULONG                   StackReserved;
	ULONG                   StackCommit;
	ULONG                   ImageSubsystem;
	WORD                    SubSystemVersionLow;
	WORD                    SubSystemVersionHigh;
	ULONG                   Unknown1;
	ULONG                   ImageCharacteristics;
	ULONG                   ImageMachineType;
	ULONG                   Unknown2[3];
} SECTION_IMAGE_INFORMATION, * PSECTION_IMAGE_INFORMATION;

typedef enum _SECTION_INFORMATION_CLASS {
	SectionBasicInformation,
	SectionImageInformation
} SECTION_INFORMATION_CLASS, * PSECTION_INFORMATION_CLASS;

static NTSTATUS(*PNtQuerySection)(
	HANDLE               SectionHandle,
	SECTION_INFORMATION_CLASS InformationClass,
	PVOID                InformationBuffer,
	ULONG                InformationBufferSize,
	PULONG               ResultLength);

static NTSTATUS(*PNtUnmapViewOfSection)(
	HANDLE               ProcessHandle,
	PVOID                BaseAddress);

static NTSTATUS(*PNtClose)(
	HANDLE               ObjectHandle);

static BOOL CALLBACK ExportCallback(_In_opt_ PVOID pContext,
	_In_ ULONG nOrdinal,
	_In_opt_ LPCSTR pszSymbol,
	_In_opt_ PVOID pbTarget)
{
	(void)pContext;
	(void)pbTarget;
	(void)pszSymbol;

	ExportContext* pec = (ExportContext*)pContext;

	if (nOrdinal == 1)
	{
		pec->fHasOrdinal1 = TRUE;
	}
	pec->nExports++;

	return TRUE;
}

static LPCSTR rpszDllsOut32 = NULL, rpszDllsOut64 = NULL;
static UINT32 hook_cnt = 0;
static DWORD thispid = GetCurrentProcessId();
static HANDLE fm32 = NULL, fm64 = NULL;
static DWORD dwBufSize32 = 0, dwBufSize64 = 0;
static char* map_addr32, *map_addr64;

HMODULE findRemoteHModule(DWORD dwProcessId, const char* szdllout, BOOL isWoW64);
//PVOID getRVA(PVOID Base, ULONG_PTR BaseAddress, PCSTR Name);
void init();
void exiting();
int mon(int isFree_);
