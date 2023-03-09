#pragma once
#include  <ntifs.h>

BOOLEAN isSubstring(_In_ PUNICODE_STRING original, _In_ PUNICODE_STRING substring) {
	BOOLEAN equal = FALSE;
	if (!original || !substring)

	{
		DbgPrint("[SKYNET] : bad pointers passed to isSubString\n");
		return FALSE;
	}
	DbgPrintEx(0, 0, "[SKYNET] : First [%wZ] Second [%wZ]\n", original, substring);
	unsigned char* orig = (unsigned char*)original->Buffer, * sub = (unsigned char*)substring->Buffer;
	short maxLength = min(original->Length, substring->Length);
	if (maxLength == 0 && substring->Length != 0) return FALSE;
	while (maxLength-- && *orig == *sub) { orig++; sub++; };
	return maxLength == -1 ? TRUE : FALSE;
}