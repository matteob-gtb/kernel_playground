#pragma once 

#include <windef.h>


#define PLM4_ENTRY_INDEX_MASK 0xff8000000000 //bits [39,47]
#define DIRECTORY_POINTER_MASK 0x7fc0000000 //bits [30,38]
#define DIRECTORY_MASK 0x3fe00000 //bits [21,29]
#define TABLE_MASK 0xff000// bits [12,20]
#define OFFSET_MASK  0xfff//bits [0,11]

#define SANITY_CHECK_VIRTUAL_ADDRESS_MASKS PLM4_ENTRY_INDEX_MASK&DIRECTORY_POINTER_MASK&DIRECTORY_MASK&TABLE_MASK&OFFSET_MASK
#define SYSTEM_PROCESS_INFORMATION 0x05
#define SYSTEM_MODULE_INFORMATION 0x0B

#define MAPPED_DRIVER_PATH L"\\DosDevices\\Z:\\MappedDriver\\x64\\Release\\MappedDriver.sys"

#define IMPORT_ORDINAL_MASK_PE64 ((ULONG64) 1<<63)
#define IS_ORDINAL(a) (((PIMPORT_LOOKUP_TABLE)a)->entry[0]& ORDINAL_MASK_PE64)  

VOID
DriverUnload(PDRIVER_OBJECT DriverObject);
DRIVER_DISPATCH DispatchControl;
DRIVER_DISPATCH DispatchCreateClose;


void discover_paging_mode();
void navigate_cr3();

NTSTATUS loadExecutableInKernelMemory(_In_ PUNICODE_STRING fileName, _Inout_ void* executableStart, _Inout_ ULONG64* fileSize);

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath);

NTSTATUS parsePEHeader(_In_ ULONG64 executableStartAddress);

NTSTATUS trashPEHeader(_In_ PVOID executableStartAddress);


ULONG64 findPattern(ULONG64 kernelBase, unsigned char* pattern, SHORT patternLength);

BOOLEAN isSubstringUnicode(_In_ PUNICODE_STRING original, _In_ PUNICODE_STRING substring);
BOOLEAN isSubstringChar(_In_ PUCHAR original, _In_ PUCHAR substring);
ULONG64 findPattern(_In_ ULONG64 kernelBase, _In_ unsigned char* pattern, _In_ SHORT patternLength);

NTSTATUS findModuleByName(_In_ PUCHAR targetName, _Inout_ PULONG64 address);

NTSTATUS writeVirtualProcessMemory(READ_FROM_PROCESS_REQUEST* request);

void detachFromProcess();

void attachToProcess(UINT32 pid);

typedef NTSTATUS(*ZwQuerySystemInformation)(unsigned short,
	PVOID,
	ULONG,
	PULONG);

typedef NTSTATUS(*MmCopyVirtualMemory)
(
	PEPROCESS SourceProcess,
	PVOID SourceAddress,
	PEPROCESS TargetProcess,
	PVOID TargetAddress,
	SIZE_T BufferSize,
	KPROCESSOR_MODE PreviousMode,
	PSIZE_T ReturnSize
	);


typedef struct _PE_HEADER_STRUCT {
	UINT32 mMagic; // PE\0\0 or 0x00004550
	UINT16 mMachine;
	UINT16 mNumberOfSections;
	UINT32 mTimeDateStamp;
	UINT32 mPointerToSymbolTable;
	UINT32 mNumberOfSymbols;
	UINT16 mSizeOfOptionalHeader;
	UINT16 mCharacteristics;
}PE_HEADER, * PPE_HEADER;

typedef struct _IMAGE_DATA_DIRECTORY {
	DWORD   VirtualAddressOffset;
	DWORD   Size;
} IMAGE_DATA_DIRECTORY, * PIMAGE_DATA_DIRECTORY;

#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES 20

typedef struct _IMAGE_OPTIONAL_HEADER64 {
	WORD        Magic;
	BYTE        MajorLinkerVersion;
	BYTE        MinorLinkerVersion;
	DWORD       SizeOfCode;
	DWORD       SizeOfInitializedData;
	DWORD       SizeOfUninitializedData;
	DWORD       AddressOfEntryPoint;
	DWORD       BaseOfCode;
	ULONGLONG   ImageBase;
	DWORD       SectionAlignment;
	DWORD       FileAlignment;
	WORD        MajorOperatingSystemVersion;
	WORD        MinorOperatingSystemVersion;
	WORD        MajorImageVersion;
	WORD        MinorImageVersion;
	WORD        MajorSubsystemVersion;
	WORD        MinorSubsystemVersion;
	DWORD       Win32VersionValue;
	DWORD       SizeOfImage;
	DWORD       SizeOfHeaders;
	DWORD       CheckSum;
	WORD        Subsystem;
	WORD        DllCharacteristics;
	ULONGLONG   SizeOfStackReserve;
	ULONGLONG   SizeOfStackCommit;
	ULONGLONG   SizeOfHeapReserve;
	ULONGLONG   SizeOfHeapCommit;
	DWORD       LoaderFlags;
	DWORD       NumberOfRvaAndSizes;
	IMAGE_DATA_DIRECTORY imageDataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER, * PIMAGE_OPTIONAL_HEADER;

typedef struct _IMAGE_IMPORT_DESCRIPTOR {

	ULONG importLookupTableRVA;
	ULONG TimeDateStamp;
	ULONG ForwarderChain;
	ULONG Name;
	ULONG importAddressRVA;
} IMPORT_DIRECTORY_ENTRY, * PIMAGE_IMPORT_DIRECTORY_ENTRY;

typedef struct _IMPORT_LOOKUP_TABLE {
	ULONG64 entry[1];
}IMPORT_LOOKUP_TABLE, * PIMPORT_LOOKUP_TABLE;
typedef struct _IMPORT_ADDRESS_TABLE {
	ULONG64 entry[1];
}IMPORT_ADDRESS_TABLE, * PIMPORT_ADDRESS_TABLE;



#define IMPORT_TABLE_ORDINAL_MASK (1<<31)
typedef struct _IMPORT_TABLE_BREAKDOWN {
	union _ANON_32 {
		struct _AN_32_s {
			UINT16 ordinalNumber; //bits 0-15
			UINT16 topHalf; // bits 16-30

		} ordinalStruct;
		UINT32 nameRVA;
	} lowest32bits;
	UINT32 highestBit32;
} IMPORT_TABLE_BREAKDOWN, * PIMPORT_TABLE_BREAKDOWN;


#define IMAGE_SIZEOF_SHORT_NAME 8
typedef struct _IMAGE_SECTION_HEADER {
	CHAR  Name[IMAGE_SIZEOF_SHORT_NAME];
	union {
		DWORD PhysicalAddress;
		DWORD VirtualSize;
	} Misc;
	DWORD VirtualAddress;
	DWORD SizeOfRawData;
	DWORD PointerToRawData;
	DWORD PointerToRelocations;
	DWORD PointerToLinenumbers;
	WORD  NumberOfRelocations;
	WORD  NumberOfLinenumbers;
	DWORD Characteristics;
} IMAGE_SECTION_HEADER, * PIMAGE_SECTION_HEADER;


typedef struct _IMAGE_DOS_HEADER {      // DOS .EXE header
	WORD   e_magic;                     // Magic number
	WORD   e_cblp;                      // Bytes on last page of file
	WORD   e_cp;                        // Pages in file
	WORD   e_crlc;                      // Relocations
	WORD   e_cparhdr;                   // Size of header in paragraphs
	WORD   e_minalloc;                  // Minimum extra paragraphs needed
	WORD   e_maxalloc;                  // Maximum extra paragraphs needed
	WORD   e_ss;                        // Initial (relative) SS value
	WORD   e_sp;                        // Initial SP value
	WORD   e_csum;                      // Checksum
	WORD   e_ip;                        // Initial IP value
	WORD   e_cs;                        // Initial (relative) CS value
	WORD   e_lfarlc;                    // File address of relocation table
	WORD   e_ovno;                      // Overlay number
	WORD   e_res[4];                    // Reserved words
	WORD   e_oemid;                     // OEM identifier (for e_oeminfo)
	WORD   e_oeminfo;                   // OEM information; e_oemid specific
	WORD   e_res2[10];                  // Reserved words
	LONG   e_lfanew;                    // File address of new exe header
} IMAGE_DOS_HEADER, * PIMAGE_DOS_HEADER;

typedef struct _PE_HEADER {
	IMAGE_DOS_HEADER dos_header;
} DOS_HEADER, * PDOS_HEADER;


typedef struct __PE_HEADER {
	PE_HEADER standardHeader;
	IMAGE_OPTIONAL_HEADER optionalHeader;
} PE_HEADER_FULL, * PPE_HEADER_FULL;



typedef struct _PE_EXPORT_DIRECTORY_TABLE {

	UINT32 Characteristics;
	UINT32 TimeDateStamp;
	UINT16 MajorVersion;
	UINT16 MinorVersion;
	UINT32 Name;
	UINT32 Base;
	UINT32 NumberOfFunctions;
	UINT32 NumberOfNames; //size of the array pointer by address of names
	UINT32 AddressOfFunctionsRVA;
	UINT32 AddressOfNamesRVA;
	UINT32 AddressOfNameOrdinalsRVA;
} EXPORT_DIRECTORY_TABLE, * PEXPORT_DIRECTORY_TABLE;

typedef struct _PE_EXPORT_ADDRESS_TABLE {
	union _ANON
	{
		UINT32 ExportRVA;
		UINT32 ForwarderRVA;
	};
} EXPORT_ADDRESS_TABLE, * PEXPORT_ADDRESS_TABLE;

typedef struct _PE_EXPORT_NAME_TABLE {

	UINT32 NameRVA;

} EXPORT_NAME_TABLE, * PEXPORT_NAME_TABLE;

typedef struct _PE_ORDINAL_EXPORT_TABLE {
	UINT16 functionIndex;
} EXPORT_ORDINAL_TABLE,* PEXPORT_ORDINAL_TABLE;




#define EXPORT_DIRECTORY_INDEX 0
#define IMPORT_TABLE_INDEX 1
#define IAT_TABLE_OFFSET_RAW 120
#define PE_32_PLUS_DIRECTORY_START_OFFSET 112
#define PE_32_PLUS_DIRECTORY_END_OFFSET 232