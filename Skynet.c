#include <ntifs.h>
#include <wdf.h>
#include <wdm.h>    
#include "offsets.h"
#include "Common.h"
#include "Utils.h"
#include "patterns.h"
#include "SharedData.h"
//#include "defs.h"


#define DEBUG 



static BOOLEAN isAttached;
static PEPROCESS attachedProcess;






#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, DriverUnload)


 




NTSTATUS DispatchControl(
	PDEVICE_OBJECT DeviceObject,
	PIRP Irp
);
NTSTATUS DispatchCreateClose(
	PDEVICE_OBJECT DeviceObject,
	PIRP Irp
);

#define MODULE_BUFFER_SIZE 1024*1024*10 
NTSTATUS findModuleByName(_In_ PUCHAR targetName, _Inout_ PULONG64 address) {
#ifdef DEBUG
	DbgPrintEx(0, 0, "[SKYNET]: target name %s\n", targetName);
#endif // DEBUG
	UNICODE_STRING zwquery;
	RtlInitUnicodeString(&zwquery, L"ZwQuerySystemInformation");
	ZwQuerySystemInformation pointer;
	PVOID zwQueryAddr = MmGetSystemRoutineAddress(&zwquery);
	ULONG length = 0;
	if (zwQueryAddr)
	{
#ifdef DEBUG
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "[SKYNET]: Found ZwQuerySystemInformation at [0x%lp]\n", zwQueryAddr);
#endif // DEBUG
		pointer = (ZwQuerySystemInformation)zwQueryAddr;
		PVOID buffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, MODULE_BUFFER_SIZE, DRIVER_MEM_TAG);
		if (!buffer)
			return STATUS_INSUFFICIENT_RESOURCES;


		NTSTATUS outcome = (*pointer) (SYSTEM_MODULE_INFORMATION, buffer, MODULE_BUFFER_SIZE, &length);
		if (!NT_SUCCESS(outcome)) {
			ExFreePoolWithTag(buffer, DRIVER_MEM_TAG);
			return STATUS_UNSUCCESSFUL;
		}
		RTL_PROCESS_MODULES* processModules = (RTL_PROCESS_MODULES*)buffer;
		RTL_PROCESS_MODULE_INFORMATION* modulesArray = (RTL_PROCESS_MODULE_INFORMATION*)processModules->Modules;
		unsigned long i = 0;
		for (; i < processModules->NumberOfModules; i++) {
#ifdef DEBUG
			DbgPrintEx(0, 0, "[Skynet] : Module name [%s]\n", ((char*)modulesArray->FullPathName + modulesArray->OffsetToFileName));
			DbgPrintEx(0, 0, "[Skynet] : Module Base Address [%llx], Image Size [%li]\n", modulesArray->ImageBase, modulesArray->ImageSize);

#endif // DEBUG 
			if (strstr(modulesArray->FullPathName, targetName)/*isSubstringClassic(modulesArray->FullPathName, targetName)*/)
			{
				*address = modulesArray->ImageBase;
				break;
			}
			modulesArray++;
		}
		ExFreePoolWithTag(buffer, DRIVER_MEM_TAG);

	}
	return STATUS_SUCCESS;
}


NTSTATUS writeVirtualProcessMemory(READ_FROM_PROCESS_REQUEST* request) {
#ifdef DEBUG
	DbgPrintEx(0, 0, "[SKYNET]: handling request to read from process [%d] at virtual address[0x%x]\n", request->procID, request->startVirtualAddress);
#endif // DEBUG

	PEPROCESS targetProcess;
	PEPROCESS thisProcess = PsGetCurrentProcess();
	NTSTATUS outcome = PsLookupProcessByProcessId(request->procID, &targetProcess);
	if (!NT_SUCCESS(outcome)) {
#ifdef DEBUG
		DbgPrintEx(0, 0, "[SKYNET] : failed to find the process [%d]\n", request->procID);
#endif // DEBUG
		return STATUS_ACCESS_DENIED;
	}
	void* buffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, request->bytesCount, DRIVER_MEM_TAG);
	if (!buffer) {
#ifdef DEBUG
		DbgPrint("Failed to allocate memory\n");
#endif // DEBUG
		return STATUS_INSUFFICIENT_RESOURCES;

	}
	MM_COPY_ADDRESS address;
	SIZE_T bytesRead;
	address.VirtualAddress = request->startVirtualAddress;
	NTSTATUS readOutcome = MmCopyMemory(buffer, address, request->bytesCount, MM_COPY_MEMORY_VIRTUAL, &bytesRead);

	if (!NT_SUCCESS(readOutcome)) {

#ifdef DEBUG
		DbgPrint("[SKYNET]: Failed to read process memory\n");
#endif // DEBUG
		goto free;
	}
#ifdef DEBUG
	DbgPrintEx(0, 0, "[SKYNET]: read [%d] bytes, read the value [0x%x]\n", bytesRead, *((unsigned int*)buffer));
#endif // DEBUG

free:
	ExFreePool(buffer);
	return STATUS_SUCCESS;


}

void attachToProcess(UINT32 pid) {
	PEPROCESS copy;
	NTSTATUS outcome = PsLookupProcessByProcessId(pid, &attachedProcess);
	copy = attachedProcess;
	if (!NT_SUCCESS(outcome))
	{
#ifdef DEBUG
		DbgPrintEx(0, 0, "[SKYNET]: Failed to find process with pid [%d]", pid);
#endif // DEBUG
		return;
	}
#ifdef DEBUG
	else DbgPrint("[SKYNET] : Found the target process");
#endif // DEBUG

	KAPC_STATE  state;
	KeStackAttachProcess(attachedProcess, &state);
#ifdef DEBUG
	DbgPrint("[SKYNET] : Attached to the target process");
#endif // DEBUG


	isAttached = TRUE;
}

void detachFromProcess() {
	if (isAttached)
	{
		ObDereferenceObject(attachedProcess);
		KeDetachProcess();
	}

}


NTSTATUS
DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	UNREFERENCED_PARAMETER(RegistryPath);
	NTSTATUS       NtStatus = STATUS_SUCCESS;
	PDEVICE_OBJECT DeviceObject = NULL;
	UNICODE_STRING DriverName, DosDeviceName;
#ifdef DEBUG
	DbgPrint("[SKYNET]: Loading Skynet");
#endif // DEBUG




	RtlInitUnicodeString(&DriverName, L"\\Device\\SKYNET");
	RtlInitUnicodeString(&DosDeviceName, L"\\DosDevices\\SKYNET");

	NtStatus = IoCreateDevice(DriverObject, 0, &DriverName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &DeviceObject);

	if (NtStatus == STATUS_SUCCESS)
	{
		DriverObject->DriverUnload = DriverUnload;
		DriverObject->MajorFunction[IRP_MJ_CREATE] = DispatchCreateClose;
		DriverObject->MajorFunction[IRP_MJ_CLOSE] = DispatchCreateClose;
		DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchControl;
		DeviceObject->Flags |= IO_TYPE_DEVICE;
		DeviceObject->Flags &= (~DO_DEVICE_INITIALIZING);
		IoCreateSymbolicLink(&DosDeviceName, &DriverName);
	}
	else return STATUS_FAILED_DRIVER_ENTRY;
	//	discover_paging_mode();
	//	navigate_cr3();
	// 
	//	ULONG64 krnlAddress = 0;
	//	unsigned char kernelName[] = "ntoskrnl.exe\0";
	//#ifdef DEBUG
	//	DbgPrintEx(0, 0, "[SKYNET] : Target name is [%s]\n", kernelName);
	//#endif // DEBUG
	//
	//	NTSTATUS kernelBaseFound = findModuleByName(kernelName, &krnlAddress);
	//	if (!NT_SUCCESS(kernelBaseFound)) {
	//#ifdef DEBUG
	//		DbgPrint("[SKYNET] : Failed to find kernel module");
	//#endif // DEBUG
	//		goto skip;
	//	}
	//
	//	ULONG64 patternAddress = findPattern(krnlAddress, MmCopyVirtualMemoryPattern, sizeof(MmCopyVirtualMemoryPattern));
	//	DbgPrintEx(0, 0, "[SKYNET] : findPattern returned [0x%llx]\n", patternAddress);
	UNICODE_STRING fileName;
	RtlInitUnicodeString(&fileName, MAPPED_DRIVER_PATH);
	ULONG64 ntoskrnlBase = 0;
	NTSTATUS kernelBaseOutcome = findModuleByName(L"ntoskrnl.exe", &KERNEL_BASE);
	if (!NT_SUCCESS(kernelBaseOutcome))
	{
#ifdef DEBUG
		DbgPrint("[SKYNET] : failed to find kernel module address\n");
#endif // 
		return STATUS_SUCCESS;
	}


	ULONG64 executableStartAddress = 0;
	ULONG64 fileSize;
	NTSTATUS loadOutcome = loadExecutableInKernelMemory(&fileName, &executableStartAddress, &fileSize);
	if (!NT_SUCCESS(loadOutcome)) {
#ifdef DEBUG
		DbgPrint("[SKYNET] : Failed to load manually mapped driver\n");
		goto free;
#endif // DEBUG

	}
	parsePEHeader(executableStartAddress);

free:
	if (executableStartAddress) ExFreePool(executableStartAddress);
skip:

	return STATUS_SUCCESS;
}
/*
the RAW image is mapped in memory --> call parsePEHeader to map it properly and resolve
dependencies walking the IAT table
*/

NTSTATUS loadExecutableInKernelMemory(_In_ PUNICODE_STRING fileName, _Inout_ ULONG64* executableStart, _Inout_ ULONG64* fileSize) {
	OBJECT_ATTRIBUTES  objAttr;
	HANDLE fileHandle;
	IO_STATUS_BLOCK    ioStatusBlock;

	InitializeObjectAttributes(&objAttr, fileName,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
		NULL, NULL);
	if (KeGetCurrentIrql() != PASSIVE_LEVEL)
		return STATUS_INVALID_DEVICE_STATE;
	NTSTATUS getHandleOutcome = ZwOpenFile(&fileHandle,
		GENERIC_READ,
		&objAttr,
		&ioStatusBlock,
		NULL,
		FILE_SYNCHRONOUS_IO_NONALERT);

	if (!NT_SUCCESS(getHandleOutcome)) {
#ifdef DEBUG
		DbgPrint("[SKYNET] : failed to open a handle to the file\n");
#endif
		return STATUS_UNSUCCESSFUL;
	}
	unsigned char* fileInformationBuffer[sizeof(FILE_DIRECTORY_INFORMATION) + 1024];
	FILE_DIRECTORY_INFORMATION array[4];
	IO_STATUS_BLOCK    secIoStatusBlock;
	//	NTSTATUS informationOutcome = ZwQueryDirectoryFile(
	//		fileHandle,
	//		NULL, NULL, NULL,
	//		&ioStatusBlock,
	//		array,
	//		sizeof(array),
	//		FileDirectoryInformation,TRUE, fileName, TRUE
	//	);
	//	__debugbreak();
	//	if (!NT_SUCCESS(informationOutcome)) {
	//#ifdef DEBUG
	//		DbgPrint("[SKYNET] : failed to query file information\n");
	//#endif // DEBUG
	//		ZwClose(fileHandle);
	//		return STATUS_UNSUCCESSFUL;
	//	}
	//	FILE_DIRECTORY_INFORMATION* infoPtr = (FILE_DIRECTORY_INFORMATION*)fileInformationBuffer;
	//	SIZE_T size = infoPtr->AllocationSize.QuadPart;
	//	LARGE_INTEGER readHead;
		/*
		research alternatives here -> mmallocateindipendentpages -> look up side effects
		*/
	SIZE_T fileBufferSize = 1024 * 1024;
	void* fileContentBuffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, fileBufferSize, DRIVER_MEM_TAG);
	if (!fileContentBuffer) {
#ifdef DEBUG
		DbgPrint("[SKYNET] : Failed to allocate memory\n");
#endif // DEBUG
		ZwClose(fileHandle);
		return STATUS_INSUFFICIENT_RESOURCES;

	}
	LARGE_INTEGER readHead;
	readHead.QuadPart = 0;
	NTSTATUS fileReadOutcome = ZwReadFile(
		fileHandle,
		NULL,
		NULL,
		NULL,
		&ioStatusBlock,
		fileContentBuffer,
		fileBufferSize,
		&readHead,
		NULL
	);
	if (!NT_SUCCESS(fileReadOutcome)) {
#ifdef DEBUG
		DbgPrint("[SKYNET] : failed to read the file\n");
		DbgPrint("[SKYNET] : failed to read the file\n");
#endif // DEBUG
		ZwClose(fileHandle);
		return STATUS_UNSUCCESSFUL;
	}
	else {
		*executableStart = fileContentBuffer;
		*fileSize = ioStatusBlock.Information;
	}
#ifdef DEBUG
	DbgPrintEx(0, 0, "[SKYNET] : Read [%lld] bytes from disk\n", ioStatusBlock.Information);
#endif // DEBUG

cleanup:
	ZwClose(fileHandle);

}




NTSTATUS listRunningProcesses() {
	ZwQuerySystemInformation pointer;
	UNICODE_STRING zwquery;
	RtlInitUnicodeString(&zwquery, L"ZwQuerySystemInformation");
	PVOID zwQueryAddr = MmGetSystemRoutineAddress(&zwquery);
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "Result of getsysroutine on ZwQuerySystemInformation [%lp]\n", zwQueryAddr);
	if (zwQueryAddr)
	{
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "Found ZwQuerySystemInformation at [0x%lp]\n", zwQueryAddr);
		pointer = (ZwQuerySystemInformation)zwQueryAddr;
		PVOID buffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, PROCESS_INFO_BUFFER_SIZE, DRIVER_MEM_TAG);
		if (!buffer) {
			DbgPrint("Buffer allocation from non paged memory failed\n");
			return STATUS_INSUFFICIENT_RESOURCES;
		}
		NTSTATUS outcome;
		__try {
			ULONG length = 0;
			USHORT  tryN = 0;
			//ZWquery call
			outcome = (*pointer) (SYSTEM_PROCESS_INFORMATION, buffer, PROCESS_INFO_BUFFER_SIZE, &length);
			if (!NT_SUCCESS(outcome) && length > 0) {
				while (!NT_SUCCESS(outcome) && tryN < MAX_ALLOC_RETRY) {
					DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "[ERROR] more memory was needed to store the result,trying again [%d]\n", tryN);
					ULONG newLength = length + 1024;
					ExFreePoolWithTag(buffer, DRIVER_MEM_TAG);
					buffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, newLength, DRIVER_MEM_TAG);
					outcome = (*pointer) (SYSTEM_PROCESS_INFORMATION, buffer, PROCESS_INFO_BUFFER_SIZE, &length);
					tryN++;
				}
				if (!NT_SUCCESS(outcome) || tryN >= MAX_ALLOC_RETRY) return STATUS_UNSUCCESSFUL;
			}


			SYSTEM_PROCESS_INFORMATION_STRUCT* currentProcessInfo = (SYSTEM_PROCESS_INFORMATION_STRUCT*)buffer;
			SYSTEM_THREAD_INFORMATION* threads;
			ULONG counter = 0;
			unsigned int currentThread;

			while (1) {
				threads = currentProcessInfo->Threads;
				DbgPrintEx(0, 0, "[SKYNET]: Current Process PID [%d]\n", currentProcessInfo->UniqueProcessId);
				DbgPrintEx(0, 0, "[SKYNET]: Current Process name :[%wZ]\n", currentProcessInfo->ImageName);
				DbgPrintEx(0, 0, "[SKYNET]: Number of threads [%d]\n", currentProcessInfo->NumberOfThreads);

				currentThread = 0;
				while (currentThread < currentProcessInfo->NumberOfThreads)
				{
					DbgPrintEx(0, 0, "[SKYNET]: currentProcesses' thread[%d] state is [%ll]\n", currentThread++, threads->ThreadState);
					DbgPrintEx(0, 0, "[SKYNET]: currentProcesses' thread[%d] start address is [%ull]\n", currentThread++, threads->StartAddress);
					threads++;
				}
				if (currentProcessInfo->NextEntryOffset == 0) break;
				currentProcessInfo = (SYSTEM_PROCESS_INFORMATION_STRUCT*)(((BYTE*)currentProcessInfo) + currentProcessInfo->NextEntryOffset);
				counter++;
			}
		}

		__finally {
			if (!NT_SUCCESS(outcome))
				ExFreePoolWithTag(buffer, DRIVER_MEM_TAG);
		}



	}
	return  STATUS_SUCCESS;
}






NTSTATUS findProcessByName(PUNICODE_STRING name, _Inout_ PINT32 pid) {
	ZwQuerySystemInformation pointer;
	UNICODE_STRING zwquery;
	RtlInitUnicodeString(&zwquery, L"ZwQuerySystemInformation");
	PVOID zwQueryAddr = MmGetSystemRoutineAddress(&zwquery);

	ULONG outLength = 0;
	if (!zwQueryAddr)

	{
#ifdef DEBUG
		DbgPrint("[Skynet] : findProcessByModuleName : failed to find ZwQuerySystemInformation");
#endif // DEBUG
		return STATUS_INTERNAL_ERROR;

	}
	pointer = (ZwQuerySystemInformation)zwQueryAddr;
	SIZE_T BUFFER_SIZE = MODULE_BUFFER_SIZE * 10;

	PVOID buffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, BUFFER_SIZE, DRIVER_MEM_TAG);
	if (!buffer) {

		DbgPrint("[SKYNET] : failed to allocate memory\n");
		return STATUS_INSUFFICIENT_RESOURCES;

	}
	NTSTATUS outcome = (*pointer) (SYSTEM_PROCESS_INFORMATION, buffer, BUFFER_SIZE, &outLength);
	if (!NT_SUCCESS(outcome)) {
#ifdef DEBUG
		DbgPrintEx(0, 0, "[SKYNET] : Failed to query ZwQuerySystemInformation status code :[%d] lenght [%ul]\n", outcome, outLength);
		if (outLength)
			DbgPrintEx(0, 0, "[SKYNET] Buffer size mismatch of [%lld]\n", outLength - BUFFER_SIZE);
#endif // DEBUG
		goto free;
	}
#ifdef DEBUG
	if (outLength)
		DbgPrintEx(0, 0, "[SKYNET] ZwQuerySystemInformation returned an outlength value of [%ld]\n", outLength);
#endif // DEBUG

	SYSTEM_PROCESS_INFORMATION_STRUCT* currentProcessInfo = (SYSTEM_PROCESS_INFORMATION_STRUCT*)buffer;
	while (1) {
		//DbgPrintEx(0, 0, "[SKYNET] : currentProcess [%wZ]\n", currentProcessInfo->ImageName);
		//if (RtlCompareUnicodeString(&currentProcessInfo->ImageName, name, TRUE) == 0)
		//	__debugbreak();
		if (isSubstringUnicode(&currentProcessInfo->ImageName, name)) {
			*pid = currentProcessInfo->UniqueProcessId;
			//	DbgPrintEx(0, 0, "[SKYNET] : found the target process, pid [%d]\n", *pid);
			goto free;
		}
		if (!currentProcessInfo->NextEntryOffset) break;
		currentProcessInfo = (SYSTEM_PROCESS_INFORMATION_STRUCT*)(((BYTE*)currentProcessInfo) + currentProcessInfo->NextEntryOffset);
	}
free:
	ExFreePool(buffer);
	return *pid == 0 ? STATUS_FAIL_CHECK : STATUS_SUCCESS;
}


NTSTATUS MmWritePhysical(PVOID targetAddress, PVOID sourceAddress, size_t size)
{
	PHYSICAL_ADDRESS address = { 0 };
	address.QuadPart = (LONGLONG)targetAddress;
	PVOID mappedSpace = MmMapIoSpace(address, size, MmNonCached);

	if (mappedSpace)
	{
		memcpy(mappedSpace, sourceAddress, size);
		MmUnmapIoSpace(mappedSpace, size);
		return STATUS_SUCCESS;
	}
	return STATUS_UNSUCCESSFUL;
}

#define IA32_EFER_ID 0xC0000080 //architecture-specific identifier
#define PAE (1<<5)
#define PAGING_BIT (1<<31)
#define LME (1<<8)
void discover_paging_mode() {
	UINT64 cr0 = __readcr0();
	UINT64 cr2 = __readcr2();
	unsigned long long cr3 = __readcr3();
	UINT64 cr4 = __readcr4();
	UINT64 IA32 = __readmsr(IA32_EFER_ID);

#ifdef DEBUG

	DbgPrintEx(0, 0, "[SKYNET]: read values from register [cr0]-[0x%llx]", cr0);
	DbgPrintEx(0, 0, "[SKYNET]: read values from register [cr2]-[0x%llx]", cr2);
	DbgPrintEx(0, 0, "[SKYNET]: read values from register [cr3]-[0x%llx]", cr3);
	DbgPrintEx(0, 0, "[SKYNET]: read values from register [cr4]-[0x%llx]", cr4);


#endif // DEBUG



	// true if CR0.PG == 1 & CR4.PAE == 0, expected false 
	UINT64 PAGING_32 = (cr0 & PAGING_BIT) && !(cr4 & PAE);
	// true if CR0.PG == 1 & CR4.PAE == 1 && IA32_EFER.LME = 0,, expected false 

	UINT64 PAE_ENABLED = (cr0 & PAGING_BIT) && ((cr4 & PAE) && !(IA32 & LME));
	// IA-32e paging  If CR0.PG = 1, CR4.PAE = 1, and IA32_EFER.LME = 1,
	UINT64 IA_32e_PAGING = (cr0 & PAGING_BIT) && ((cr4 & PAE) && (IA32 & LME));

	if (PAGING_32) {
		DbgPrint("[SKYNET]: 32-Bit paging is enabled");
	}
	else if (PAE_ENABLED) {
		DbgPrint("[SKYNET]: PAE paging is enabled");
	}
	else if (IA_32e_PAGING) {
		DbgPrint("[SKYNET]: IA_32e paging is enabled");
	}

}

#define PCIDE_BIT (1<<17)
void navigate_cr3() {
	UINT32 pid = 0;
	UNICODE_STRING targetProcessName;
	RtlInitUnicodeString(&targetProcessName, L"victim_3R4T.exe");
	NTSTATUS outcome = findProcessByName(&targetProcessName, &pid);
	if (!NT_SUCCESS(outcome)) {
		DbgPrintEx(0, 0, "[SKYNET]: failed to find target process [%wZ]", &targetProcessName);
		return;
	}

	attachToProcess(pid); //should always be Dbgview.exe 

	UINT64 cr3 = __readcr3();
	UINT64 PCID_ENABLED = __readcr4() && PCIDE_BIT;
	if (PCID_ENABLED) DbgPrint("[SKYNET] : PCID enabled");
	else DbgPrint("[SKYNET] : PCIDs disabled");
	//discover CR4.PCIDE
	//bits 52-11 determine the physical address of the table
	UINT64 physical_table_address = cr3 & (0xFFFFFFFFFFFF00);
	DbgPrintEx(0, 0, "[SKYNET] : value of cr3 [0x%llx]", cr3);
	DbgPrintEx(0, 0, "[SKYNET] : Physical address of the PLM4 table [0x%llx]", physical_table_address);
#define PLM4_BUFF_SIZE 0x1000
	ULONG64* buffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, PLM4_BUFF_SIZE, DRIVER_MEM_TAG);
	if (!buffer)

	{
		DbgPrint("[SKYNET] : Failed to allocate memory");
		return;
	}

	MM_COPY_ADDRESS phys_addr_MM;
	PHYSICAL_ADDRESS p_add;
	p_add.QuadPart = physical_table_address;
	phys_addr_MM.PhysicalAddress = p_add;
	SIZE_T out;
	NTSTATUS memAccessOutcome = MmCopyMemory(buffer, phys_addr_MM, PLM4_BUFF_SIZE, MM_COPY_MEMORY_PHYSICAL, &out);
	if (!NT_SUCCESS(memAccessOutcome))
	{
		DbgPrint("[SKYNET] : Failed to read physical memory address");
		goto free;
	}
	else DbgPrint("[SKYNET] : Accessed physical memory successfully");
	unsigned short i = 0;
	ULONG64* plm4e_buffer = (ULONG64*)buffer;
	ULONG64 val = 0;
	for (; i < out / sizeof(ULONG64); i++)
	{
		val = *plm4e_buffer++;
		if (val)
			DbgPrintEx(0, 0, "[SKYNET] : PLM4 entry [%d] : [0x%llx]\n", i, val);
	}
	DbgPrintEx(0, 0, "[SKYNET] : PLM4 raw address : [%lli]\n", cr3);



	detachFromProcess();
free:
	ExFreePoolWithTag(buffer, DRIVER_MEM_TAG);
}


void requestLogger(ULONG controlCode) {
	UNICODE_STRING out;
	switch (controlCode) {
	case IOCTL_IRP_READ_FROM_USERSPACE:
		RtlInitUnicodeString(&out, L"IOCTL_IRP_READ_FROM_USERSPACE");
		break;
	case IOCTL_QUERY_PROCESSES:
		RtlInitUnicodeString(&out, L"IOCTL_QUERY_PROCESSES");
		break;
	case IOCTL_QUERY_MODULES:
		RtlInitUnicodeString(&out, L"IOCTL_QUERY_MODULES");
		break;
	case IOCTL_READ_PROCESS:
		RtlInitUnicodeString(&out, L"IOCTL_READ_PROCESS");
		break;
	default:
#ifdef DEBUG
		DbgPrintEx(0, 0, "[SKYNET]: [ERROR] UNKNOWN IOCTL CODE", out);
#endif // DEBUG

		return;
	}
#ifdef DEBUG
	DbgPrintEx(0, 0, "[SKYNET]: Handled a [%zW]\n", &out);
#endif // DEBUG

}
NTSTATUS DispatchControl(
	PDEVICE_OBJECT DeviceObject,
	PIRP irp
) {
	DbgPrint("DeviceType [0x%x]", DeviceObject->DeviceType);
	const IO_STACK_LOCATION irpStack = *IoGetCurrentIrpStackLocation(irp);
	UNREFERENCED_PARAMETER(DeviceObject);
	DbgPrint("Dispatched an IRP_MJ_DEVICE_CONTROL");
	unsigned long REQ_FROM_USER = irpStack.Parameters.DeviceIoControl.IoControlCode;
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "IOCTL code [%d]\n", REQ_FROM_USER);
	requestLogger(REQ_FROM_USER);
	ULONG targetProcessID = -1;
	READ_FROM_PROCESS_REQUEST r_request;
	WRITE_TO_PROCESS_REQUEST w_request;
	switch (REQ_FROM_USER) {
	case IOCTL_IRP_READ_FROM_USERSPACE:
		DbgPrint("[SkyNet] : receiving kernel base address...\n");
		KERNEL_BASE = *((ULONGLONG*)irp->AssociatedIrp.SystemBuffer);
		ULONGLONG mmcopyaddr = MmCopyMemory;
#ifdef DEBUG

		DbgPrintEx(0, 0, "[Skynet] : Reading KernelBase from userspace [%lp]\n", KERNEL_BASE);
		DbgPrintEx(0, 0, "[Skynet] : MmCopyVirtualMemory should be at [%lp]\n", KERNEL_BASE + MM_COPY_VIRTUAL_MEMORY_OFFSET);

#endif // DEBUG
		break;
	case IOCTL_QUERY_PROCESSES:
		listRunningProcesses();
		break;
	case IOCTL_QUERY_MODULES:
		break;
	case IOCTL_READ_PROCESS:
#ifdef DEBUG
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "Read request outcome [%d]\n", writeVirtualProcessMemory(irp->AssociatedIrp.SystemBuffer));
#endif // DEBUG
		break;
	case IOCTL_CR3_MANIPULATION:
		discover_paging_mode();
		break;
	}
end:
	irp->IoStatus.Status = STATUS_SUCCESS;
	irp->IoStatus.Information = irpStack.Parameters.DeviceIoControl.OutputBufferLength;
	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS DispatchCreateClose(
	PDEVICE_OBJECT DeviceObject,
	PIRP Irp
) {
	UNREFERENCED_PARAMETER(DeviceObject);
	DbgPrint("Dispatched an IRP_MJ_CREATE or CLOSE");
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}







VOID
DriverUnload(PDRIVER_OBJECT DriverObject)
{
	UNICODE_STRING DosDeviceName;
	DbgPrint("[SKYNET]: SkyNet out!");
	/*timeToStop = 1;
	KeWaitForSingleObject(
		ThreadObject,
		Executive,
		KernelMode,
		FALSE,
		NULL);
	ObDereferenceObject(ThreadObject);*/
	RtlInitUnicodeString(&DosDeviceName, L"\\DosDevices\\SKYNET");
	IoDeleteSymbolicLink(&DosDeviceName);
	IoDeleteDevice(DriverObject->DeviceObject);
}