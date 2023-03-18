#pragma once
#include  <ntifs.h>

#define PLM4_ENTRY_INDEX_MASK 0xff8000000000 //bits [39,47]
#define DIRECTORY_POINTER_MASK 0x7fc0000000 //bits [30,38]
#define DIRECTORY_MASK 0x3fe00000 //bits [21,29]
#define TABLE_MASK 0xff000// bits [12,20]
#define OFFSET_MASK  0xfff//bits [0,11]

#define SANITY_CHECK_VIRTUAL_ADDRESS_MASKS PLM4_ENTRY_INDEX_MASK&DIRECTORY_POINTER_MASK&DIRECTORY_MASK&TABLE_MASK&OFFSET_MASK

static ULONG64 keys[10];
void initKeys() {
	srand(time(NULL) ^ 1337 + GetProcessId(NULL) * 17);
	for (USHORT i = 0; i < 10; i++)
	{
		keys[i] = ((ULONG64)rand() << 32) | ((ULONG64)rand() << 16) | rand();
		printf("XOR Key [%d] is [%llx]\n", i, keys[i]);
	}
}

#define SPOOF	*(unsigned long long*)_AddressOfReturnAddress() = *(ULONG64*)_AddressOfReturnAddress() ^ keys[(ULONG64)_AddressOfReturnAddress() % 10];
#define UNSPOOF SPOOF




BOOLEAN isSubstring(_In_ PUNICODE_STRING original, _In_ PUNICODE_STRING substring);
BOOLEAN isSubstringChar(_In_ PUCHAR original, _In_ PUCHAR substring);
ULONG64 findPattern(_In_ ULONG64 kernelBase,_In_ unsigned char* pattern, _In_ SHORT patternLength);

 
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
#ifdef DEBUG_UTILS
		DbgPrintEx(0, 0, "[SKYNET] : current byte [%hhx]\n", byteEquivalent[i]);
#endif // DEBUG_UTILS
		for (short j = 7; j >= 0; j--) {
			//work on the i-th byte of the value
			string[j] = (byteEquivalent[i] & (1 << (7 - j))) ? '1' : '0'; //either 1 or 0 
#ifdef DEBUG_UTILS
			DbgPrintEx(0, 0, "[SKYNET] : resulting bit #%d [%1c]\n", (7 - j), string[j]);
#endif // DEBUG_UTILS



		}
	}

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

BOOLEAN isSubstring(_In_ PUNICODE_STRING original, _In_ PUNICODE_STRING substring) {
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