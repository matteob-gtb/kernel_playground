#pragma once
#include  <ntifs.h>

BOOLEAN isSubstring(_In_ PUNICODE_STRING original, _In_ PUNICODE_STRING substring);
BOOLEAN isSubstringClassic(_In_ PUCHAR original, _In_ PUCHAR substring);

#define DEBUG_UTILS

BOOLEAN isSubstringClassic(_In_ PUCHAR original, _In_ PUCHAR substring) {
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

BOOLEAN isSubstring(_In_ PUNICODE_STRING original, _In_ PUNICODE_STRING substring) {
	BOOLEAN equal = FALSE;
	if (!original || !substring)

	{
		DbgPrint("[SKYNET] : bad pointers passed to isSubString\n");
		return FALSE;
	}
	unsigned char* orig = (unsigned char*)original->Buffer, * sub = (unsigned char*)substring->Buffer;
	short maxLength = min(original->Length, substring->Length);
	if (maxLength == 0 && substring->Length != 0) return FALSE;
	while (maxLength-- && *orig == *sub) { orig++; sub++; };
	return maxLength == -1 ? TRUE : FALSE;
}