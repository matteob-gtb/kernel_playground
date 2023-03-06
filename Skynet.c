#include <ntifs.h>
#include <wdf.h>
#include <wdm.h>    
#include "offsets.h"
#include "Common.h"

#define SYSTEM_PROCESS_INFORMATION 0x05
#define SYSTEM_MODULE_INFORMATION 0x0B

#define DBG_LOG_LEVEL 31

static void* functions[1];

static BOOLEAN isAttached;
static PEPROCESS attachedProcess;

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

VOID threadFunction(PVOID context);

NTSTATUS
DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath);

VOID
DriverUnload(PDRIVER_OBJECT DriverObject);

#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, DriverUnload)


static PUNICODE_STRING targetProcessName;

static ULONGLONG KERNEL_BASE = 0;

void discover_paging_mode();
void navigate_cr3();


DRIVER_DISPATCH DispatchControl;
DRIVER_DISPATCH DispatchCreateClose;



NTSTATUS DispatchControl(
	PDEVICE_OBJECT DeviceObject,
	PIRP Irp
);
NTSTATUS DispatchCreateClose(
	PDEVICE_OBJECT DeviceObject,
	PIRP Irp
);

#define MODULE_BUFFER_SIZE 1024*1024*10 
NTSTATUS getLoadedModules() {
	UNICODE_STRING zwquery;

	RtlInitUnicodeString(&zwquery, L"ZwQuerySystemInformation");
	ZwQuerySystemInformation pointer;
	PVOID zwQueryAddr = MmGetSystemRoutineAddress(&zwquery);
	ULONG length = 0;
	if (zwQueryAddr)
	{
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DBG_LOG_LEVEL, "[SKYNET]: Found ZwQuerySystemInformation at [0x%lp]\n", zwQueryAddr);
		pointer = (ZwQuerySystemInformation)zwQueryAddr;
		PVOID buffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, MODULE_BUFFER_SIZE, DRIVER_MEM_TAG);
		NTSTATUS outcome = (*pointer) (SYSTEM_MODULE_INFORMATION, buffer, MODULE_BUFFER_SIZE, &length);
		if (!NT_SUCCESS(outcome)) {
			ExFreePoolWithTag(buffer, DRIVER_MEM_TAG);
			return STATUS_UNSUCCESSFUL;
		}
		RTL_PROCESS_MODULES* processModules = (RTL_PROCESS_MODULES*)buffer;
		RTL_PROCESS_MODULE_INFORMATION* modulesArray = (RTL_PROCESS_MODULE_INFORMATION*)processModules->Modules;
		unsigned long i = 0;
		for (; i < processModules->NumberOfModules; i++) {
			DbgPrintEx(0, 0, "Module name [%s]\n", ((char*)modulesArray->FullPathName + modulesArray->OffsetToFileName));
			modulesArray++;
		}

		ExFreePoolWithTag(buffer, DRIVER_MEM_TAG);

	}
	return STATUS_SUCCESS;
}


NTSTATUS writeVirtualProcessMemory(READ_FROM_PROCESS_REQUEST* request) {

	DbgPrintEx(0, 0, "[SKYNET]: handling request to read from process [%d] at virtual address[0x%x]\n", request->procID, request->startVirtualAddress);
	PEPROCESS targetProcess;
	PEPROCESS thisProcess = PsGetCurrentProcess();
	NTSTATUS outcome = PsLookupProcessByProcessId(request->procID, &targetProcess);
	if (!NT_SUCCESS(outcome)) {
		DbgPrintEx(0, 0, "[SKYNET] : failed to find the process [%d]\n", request->procID);
		return STATUS_ACCESS_DENIED;
	}
	void* buffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, request->bytesCount, DRIVER_MEM_TAG);
	if (!buffer) {
		DbgPrint("Failed to allocate memory\n");
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	MM_COPY_ADDRESS address;
	SIZE_T bytesRead;
	address.VirtualAddress = request->startVirtualAddress;
	NTSTATUS readOutcome = MmCopyMemory(buffer, address, request->bytesCount, MM_COPY_MEMORY_VIRTUAL, &bytesRead);

	if (!NT_SUCCESS(readOutcome)) {
		DbgPrint("[SKYNET]: Failed to read process memory\n");
		goto free;
	}
	DbgPrintEx(0, 0, "[SKYNET]: read [%d] bytes, read the value [0x%x]\n", bytesRead, *((unsigned int*)buffer));
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
		DbgPrintEx(0, 0, "[SKYNET]: Failed to find process with pid [%d]", pid);
		return;
	}
	else DbgPrint("[SKYNET] : Found the target process");
	KAPC_STATE  state;
	KeStackAttachProcess(attachedProcess, &state);
	DbgPrint("[SKYNET] : Attached to the target process");
	isAttached = TRUE;
}

void detachFromProcess() {
	if (isAttached)
	{
		ObDereferenceObject(attachedProcess);
		KeDetachProcess();
		DbgPrint("Detached successfully");
	}

}


NTSTATUS
DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	UNREFERENCED_PARAMETER(RegistryPath);
	NTSTATUS       NtStatus = STATUS_SUCCESS;
	PDEVICE_OBJECT DeviceObject = NULL;
	UNICODE_STRING DriverName, DosDeviceName;
	DbgPrint("[SKYNET]: Loading Skynet");


	RtlInitUnicodeString(targetProcessName, L"dummy.exe");

	RtlInitUnicodeString(&DriverName, L"\\Device\\SKYNET");
	RtlInitUnicodeString(&DosDeviceName, L"\\DosDevices\\SKYNET");

	NtStatus = IoCreateDevice(DriverObject, 0, &DriverName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &DeviceObject);

	if (NtStatus == STATUS_SUCCESS)
	{
		DbgPrint("Skynet loaded");
		DriverObject->DriverUnload = DriverUnload;
		DriverObject->MajorFunction[IRP_MJ_CREATE] = DispatchCreateClose;
		DriverObject->MajorFunction[IRP_MJ_CLOSE] = DispatchCreateClose;
		DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchControl;
		DeviceObject->Flags |= IO_TYPE_DEVICE;
		DeviceObject->Flags &= (~DO_DEVICE_INITIALIZING);
		IoCreateSymbolicLink(&DosDeviceName, &DriverName);
	}
	else return STATUS_FAILED_DRIVER_ENTRY;
	discover_paging_mode();
	navigate_cr3();
	return STATUS_SUCCESS;
}


NTSTATUS listRunningProcesses() {
	ZwQuerySystemInformation pointer;
	UNICODE_STRING zwquery;
	RtlInitUnicodeString(&zwquery, L"ZwQuerySystemInformation");
	PVOID zwQueryAddr = MmGetSystemRoutineAddress(&zwquery);
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DBG_LOG_LEVEL, "Result of getsysroutine on ZwQuerySystemInformation [%lp]\n", zwQueryAddr);
	if (zwQueryAddr)
	{
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DBG_LOG_LEVEL, "Found ZwQuerySystemInformation at [0x%lp]\n", zwQueryAddr);
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
					DbgPrintEx(DPFLTR_IHVDRIVER_ID, DBG_LOG_LEVEL, "[ERROR] more memory was needed to store the result,trying again [%d]\n", tryN);
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

UINT32 findProcessByModuleName(PUNICODE_STRING name) {
	ZwQuerySystemInformation pointer;
	UINT32 pid;
	UNICODE_STRING zwquery;
	RtlInitUnicodeString(&zwquery, L"ZwQuerySystemInformation");
	PVOID zwQueryAddr = MmGetSystemRoutineAddress(&zwquery);
	ULONG outLength;
	if (!zwQueryAddr)

	{
		DbgPrint("[Skynet_findProcessByModuleName] : failed to find ZwQuerySystemInformation");
		return STATUS_INTERNAL_ERROR;

	}
	pointer = (ZwQuerySystemInformation)zwQueryAddr;
	PVOID buffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, MODULE_BUFFER_SIZE, DRIVER_MEM_TAG);
	NTSTATUS outcome = (*pointer) (SYSTEM_PROCESS_INFORMATION, buffer, MODULE_BUFFER_SIZE, &outLength);
	if (!NT_SUCCESS(outcome)) {
		ExFreePoolWithTag(buffer, DRIVER_MEM_TAG);
		return 0;
	}
	SYSTEM_PROCESS_INFORMATION_STRUCT* currentProcessInfo = (SYSTEM_PROCESS_INFORMATION_STRUCT*)buffer;
	while (1) {
		if (wcsstr(&currentProcessInfo->ImageName, targetProcessName)) {
			pid = currentProcessInfo->UniqueProcessId;
			DbgPrint("[SKYNET] : found the target process, pid [%d]\n", pid);
			goto free;
		}
		if (!currentProcessInfo->NextEntryOffset) break;
		currentProcessInfo = (SYSTEM_PROCESS_INFORMATION_STRUCT*)((BYTE*)currentProcessInfo + currentProcessInfo->NextEntryOffset);
	}
free:
	ExFreePool(buffer);
	return pid;
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

	DbgPrintEx(0, 0, "[SKYNET]: read values from register [cr0]-[0x%llx]", cr0);
	DbgPrintEx(0, 0, "[SKYNET]: read values from register [cr2]-[0x%llx]", cr2);
	DbgPrintEx(0, 0, "[SKYNET]: read values from register [cr3]-[0x%llx]", cr3);
	DbgPrintEx(0, 0, "[SKYNET]: read values from register [cr4]-[0x%llx]", cr4);



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

//TODO make this dynamic by walking the process list
#define PCIDE_BIT (1<<17)
void navigate_cr3() {
	UINT32 pid = findProcessByModuleName(targetProcessName);
	attachToProcess(pid); //should always be System.exe
	UINT64 cr3 = __readcr3();
	UINT64 PCID_ENABLED = __readcr4() && PCIDE_BIT;
	if (PCID_ENABLED) DbgPrint("[SKYNET] PCID disabled");
	else DbgPrint("[SKYNET] PCIDs disabled");
	//discover CR4.PCIDE
	//bits 52-11 determine the physical address of the table
	UINT64 physical_table_address = cr3 & (0xFFFFFFFFFF000000);
	DbgPrintEx(0, 0, "[SKYNET] value of cr3 [0x%llx]", cr3);
	DbgPrintEx(0, 0, "[SKYNET] Physical address of the PLM4 table [0x%llx]", physical_table_address);
#define PLM4_BUFF_SIZE 0x1000
	void* buffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, PLM4_BUFF_SIZE, DRIVER_MEM_TAG);
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
	unsigned long long* walkableBuffer = (unsigned long long*) buffer;

	PPML4E plm4_table = (PPML4E)walkableBuffer;
	DbgPrintEx(0, 0, "[SKYNET] Reading [0x%llx] in the PLM4 table", plm4_table->Value);	/*for (unsigned short i = 0; i < PLM4_BUFF_SIZE / sizeof(unsigned long long); i++)
		DbgPrintEx(0, 0, "[SKYNET] Reading [%d] [0x%llx]", i, *walkableBuffer++);*/

	detachFromProcess();
free:
	ExFreePool(buffer);
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
		DbgPrintEx(0, 0, "[SKYNET]: [ERROR] UNKNOWN IOCTL CODE", out);
		return;
	}
	DbgPrintEx(0, 0, "[SKYNET]: Handled a [%zW]\n", &out);
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
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DBG_LOG_LEVEL, "IOCTL code [%d]\n", REQ_FROM_USER);
	requestLogger(REQ_FROM_USER);
	ULONG targetProcessID = -1;
	READ_FROM_PROCESS_REQUEST r_request;
	WRITE_TO_PROCESS_REQUEST w_request;
	switch (REQ_FROM_USER) {
	case IOCTL_IRP_READ_FROM_USERSPACE:
		DbgPrint("[SkyNet] : receiving kernel base address...\n");
		KERNEL_BASE = *((ULONGLONG*)irp->AssociatedIrp.SystemBuffer);
		ULONGLONG mmcopyaddr = MmCopyMemory;
		DbgPrintEx(0, 0, "[Skynet] : Reading KernelBase from userspace [%lp]\n", KERNEL_BASE);
		DbgPrintEx(0, 0, "[Skynet] : MmCopyVirtualMemory should be at [%lp]\n", KERNEL_BASE + MM_COPY_VIRTUAL_MEMORY_OFFSET);
		break;
	case IOCTL_QUERY_PROCESSES:
		listRunningProcesses();
		break;
	case IOCTL_QUERY_MODULES:
		getLoadedModules();
		break;
	case IOCTL_READ_PROCESS:
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DBG_LOG_LEVEL, "Read request outcome [%d]\n", writeVirtualProcessMemory(irp->AssociatedIrp.SystemBuffer));
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