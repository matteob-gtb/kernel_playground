#pragma once
#include "defs.h"

static ULONG64 keys[10];
void initKeys();

#define SPOOF	*(unsigned long long*)_AddressOfReturnAddress() = *(ULONG64*)_AddressOfReturnAddress() ^ keys[(ULONG64)_AddressOfReturnAddress() % 10];
#define UNSPOOF SPOOF




BOOLEAN isSubstringChar(_In_ PUCHAR original, _In_ PUCHAR substring) {
	PUCHAR copySub = substring;
	BOOLEAN equal = FALSE;
	if (!original || !substring)

	{
#ifdef DEBUG_UTILS
		DbgPrint("[SKYNET] : bad pointers passed to isSubString\n");
#endif // DEBUG
		return FALSE;
	}
	USHORT matchRegion = 1;
	while (*original && *original++ != *substring);
	substring++;
	while ((*original && *substring) && (*original++ == *substring++))
		matchRegion++;
	if (matchRegion == (substring - copySub)) return TRUE;
	return FALSE;



}

/*string must point to a buffer of at least 64 + 1 bytes*/
VOID getBinaryRepresentation(_In_ ULONG64 value, _Inout_ unsigned char* string) {
	unsigned char* byteEquivalent;
	ULONG64 valueCopy = value;
	byteEquivalent = &valueCopy;
	short i = 0;
	string += sizeof(ULONG64) * 8; //start from the end, write right-to-left
	string[1] = '\x00';
	for (; i < 8; i++) {
		string -= 8;
		for (short j = 7; j >= 0; j--) {
			//work on the i-th byte of the value
			string[j] = (byteEquivalent[i] & (1 << (7 - j))) ? '1' : '0'; //either 1 or 0 
		}
	}

}

NTSTATUS parsePEHeader(_In_ ULONG64 executableStartAddress) {

	BYTE* ptr = (BYTE*)executableStartAddress;
	unsigned int offset = *((unsigned int*)(ptr + 0x3c));
	ptr += offset; // should point to PE\0\0
	PPE_HEADER peHeader = (PPE_HEADER)ptr;
	if (peHeader->mMagic != 0x00004550 || peHeader->mSizeOfOptionalHeader == 0)
	{
#ifdef DEBUG
		DbgPrint("Wrong PE header signature\n");
#endif // DEBUG
		return STATUS_UNSUCCESSFUL;
	}
	PIMAGE_OPTIONAL_HEADER optionalHeader = (PIMAGE_OPTIONAL_HEADER)(peHeader + 1);
	if (optionalHeader->Magic != 0x20b) { //PE32+
#ifdef DEBUG
		DbgPrint("Wrong PE optional header signature\n");
#endif // DEBUG
		return STATUS_UNSUCCESSFUL;
	}
	void* properlyMappedImage = ExAllocatePool(POOL_FLAG_NON_PAGED_EXECUTE, optionalHeader->SizeOfImage);
	if (!properlyMappedImage) {
#ifdef DEBUG
		DbgPrint("[SKYNET] : failed to allocate memory for the image\n");
		return STATUS_INSUFFICIENT_RESOURCES;
#endif // DEBUG

	}
	DbgPrintEx(0, 0, "[SKYNET] : image size [%d]\n", optionalHeader->SizeOfImage);

	//BYTE* dot_text = (BYTE*)(executableStartAddress + optionalHeader->BaseOfCode);
	short nDataEntries = optionalHeader->NumberOfRvaAndSizes;
	short nSections = peHeader->mNumberOfSections;
	PIMAGE_SECTION_HEADER sectionsStart = (PIMAGE_SECTION_HEADER)(&optionalHeader->imageDataDirectory[nDataEntries]);
	for (auto i = 0; i < nSections; i++)
	{
		DbgPrintEx(0, 0, "[SKYNET] - Section [%s], virtual address [%#lx]\n", sectionsStart->Name, sectionsStart->VirtualAddress);
		sectionsStart++;
	}
	for (auto j = 0; j < nDataEntries; j++) {
		DbgPrintEx(0, 0, "[SKYNET] - Data directory #%d - offset [%#lx], size [%d]\n", j, optionalHeader->imageDataDirectory[j].VirtualAddressOffset, optionalHeader->imageDataDirectory[j].Size);
	}

	//rebase sections
	PIMAGE_SECTION_HEADER currentSection = sectionsStart - nSections; //reset the pointer
	ULONG64 oldStart = 0, newStart = 0;
	UINT32 sectionSize = 0;
	ULONG64 imageBase = properlyMappedImage;
	for (auto i = 0; i < nSections; i++)
	{
		sectionSize = currentSection->SizeOfRawData;
		newStart = imageBase + currentSection->VirtualAddress;
		oldStart = executableStartAddress + currentSection->PointerToRawData;
		DbgPrintEx(0, 0, "[SKYNET] - Section [%s], virtual address [%#lx], size [%d]\n", currentSection->Name, currentSection->VirtualAddress, sectionSize);
		memcpy(newStart, oldStart, sectionSize);
		RtlZeroMemory(oldStart, sectionSize);
		DbgPrintEx(0, 0, "[SKYNET] : Section [%s] [Old start] [%#llx] - [New start] [%#llx]", currentSection->Name, oldStart, newStart);
		currentSection++;
	}
	PIMAGE_IMPORT_DIRECTORY_ENTRY importDirectoryTable = (PIMAGE_IMPORT_DIRECTORY_ENTRY)(imageBase + optionalHeader->imageDataDirectory[IMPORT_TABLE_INDEX].VirtualAddressOffset);
	PIMPORT_LOOKUP_TABLE importLookupTable;
	PIMPORT_ADDRESS_TABLE importAddressTable;
	PIMPORT_TABLE_BREAKDOWN lookupBreakdown;
	char* currentHint;
	char* dependencyModuleName;
#define IS_VALID_IMPORT(a) a->importLookupTableRVA != 0
	DbgPrintEx(0, 0, "isValidimport %d\n", IS_VALID_IMPORT(importDirectoryTable));
	auto i = 0;
	auto j = 0;
	while (IS_VALID_IMPORT(importDirectoryTable) && i++ < 2) {
		dependencyModuleName = (char*)(imageBase + importDirectoryTable->Name);
		importLookupTable = (PIMPORT_LOOKUP_TABLE)(imageBase + importDirectoryTable->importLookupTableRVA);
		importAddressTable = (PIMPORT_ADDRESS_TABLE)(imageBase + importDirectoryTable->importAddressRVA);
		lookupBreakdown = (PIMPORT_TABLE_BREAKDOWN)importLookupTable;
		j = 0;
		ULONG64 currentRow = importLookupTable->entry[j];
		DbgPrintEx(0, 0, "current %#llx", currentRow);
		while (currentRow != NULL) {
			if (currentRow & (ORDINAL_MASK_PE64)) DbgPrintEx(0, 0, "[SKYNET] [current import IS ordinal] [#%d]\n", lookupBreakdown->ordinalNumber);
			else
			{
				currentHint = ((char*)lookupBreakdown->hintNameRVA) + 2;
				DbgPrintEx(0, 0, "[SKYNET] [module][%s] [current hint][%s]\n", dependencyModuleName, currentHint);
			}
			currentRow = importLookupTable->entry[++j];
		}
		importDirectoryTable++;
		__debugbreak();
	}
	return STATUS_SUCCESS;
}





#define KERNEL_IMAGE_SIZE 10'854'240
ULONG64 findPattern(ULONG64 kernelBaseAddress, unsigned char* pattern, SHORT patternLength) {
	//dumb version starting from the base of the kernel
	//a pattern cannot start with a ?
	//iterating past the kernel image -> should it be considered if the pattern is valid?
	unsigned char* ntosKrnlPtr;
	ULONG64 start; USHORT matchRegion;
	ULONG64 upperLimit = kernelBaseAddress + KERNEL_IMAGE_SIZE;
	ntosKrnlPtr = (unsigned char*)kernelBaseAddress;
	if (!ntosKrnlPtr) return 0;
	unsigned char* orig = pattern;

	while (ntosKrnlPtr < upperLimit)
	{
		pattern = orig;
		while ((*ntosKrnlPtr != *pattern)) //iterate until you find the first byte of the pattern
			ntosKrnlPtr++;
		start = ntosKrnlPtr; //start address of the pattern
		matchRegion = 0;
		//iterate until you find matching bytes
		while (((*pattern == '?') || (*pattern == *ntosKrnlPtr)) && matchRegion < patternLength)
		{
			pattern++;
			ntosKrnlPtr++;
			matchRegion++;
		}
		if (matchRegion == patternLength) return start;
	}
	return 0;
}

BOOLEAN isSubstringUnicode(_In_ PUNICODE_STRING original, _In_ PUNICODE_STRING substring) {
	BOOLEAN equal = FALSE;
	if (!original || !substring)

	{
#ifdef DEBUG_UTILS
		DbgPrint("[SKYNET] : bad pointers passed to isSubString\n");
#endif // DEBUG_UTILS

		return FALSE;
	}
	unsigned char* orig = (unsigned char*)original->Buffer, * sub = (unsigned char*)substring->Buffer;
	short maxLength = min(original->Length, substring->Length);
	if (maxLength == 0 && substring->Length != 0) return FALSE;
	while (maxLength-- && *orig == *sub) { orig++; sub++; };
	return maxLength == -1 ? TRUE : FALSE;
}