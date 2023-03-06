//include <intrin.h>
//
//#include "PhysicalMemory.h"
//
//DRIVER_INITIALIZE DriverEntry;
//
//#ifdef ALLOC_PRAGMA
//#pragma alloc_text( INIT, DriverEntry )
//#endif // ALLOC_PRAGMA
//
//// NTSTATUS ReadPhysicalAddress(PVOID TargetAddress, PVOID lpBuffer, SIZE_T Size, SIZE_T *BytesRead)
//BOOLEAN
//ReadPhysicalAddress(
//    _In_ UINT64 Source,
//    _In_ PVOID  Destination,
//    _In_ UINT32 Length
//)
//{
//    /*
//     * This function is just a wrapper to call MmCopyMemory
//     */
//
//    NTSTATUS status = STATUS_SUCCESS;
//
//    SIZE_T bytesCopied = 0;
//    MM_COPY_ADDRESS copyAddress = { 0 };
//
//    copyAddress.PhysicalAddress.QuadPart = Source;
//
//    status = MmCopyMemory(
//        Destination,
//        copyAddress,
//        Length,
//        MM_COPY_MEMORY_PHYSICAL,
//        &bytesCopied
//    );
//
//    return NT_SUCCESS(status);
//}
//
//// uint64_t TranslateLinearAddress( uint64_t directoryTableBase, uint64_t virtualAddress )
//UINT64
//TranslateLinearAddress(
//    _In_ UINT64 DirectoryTableBase,
//    _In_ UINT64 VirtualAddress
//)
//{
//    VIRTUAL_ADDRESS virtAddr = { 0 };
//
//    DIR_TABLE_BASE  dirTableBase = { 0 };
//    PML4E           pml4e = { 0 };
//    PDPTE           pdpte = { 0 };
//    PDPTE_LARGE     pdpteLarge = { 0 };
//    PDE             pde = { 0 };
//    PDE_LARGE       pdeLarge = { 0 };
//    PTE             pte = { 0 };
//
//    /*
//     * We start off by splitting up our virtual address into the
//     *  indexing parts
//     */
//
//    virtAddr.All = VirtualAddress;
//
//    /*
//     * Now, we derive our PML4E address by parsing the value that's
//     *  held by our directory table base or CR3 (which is the PML4
//     *  table base address), and add an 8-byte index based on the
//     *  corresponding bits of the virtual address.
//     *
//     * As we recall, each of our paging structures is a 4KB allocation,
//     *  therefore, we use 12-bits to index these structures. Additionally,
//     *  be sure to brush up on the notes within the header file if the
//     *  below bit-shifts are a little confusing. The value of
//     *  `PhysicalAddress` within the below structures skips the first
//     *  12-bits, so we shift the value held within the `PhysicalAddress`
//     *  structure member to add 12-bits worth of zeros on the end, before
//     *  ultimately adding our index into the page table.
//     */
//
//    dirTableBase.All = DirectoryTableBase;
//
//    if (ReadPhysicalAddress(
//        /* This calculation results in the PML4E address */
//        (dirTableBase.Bits.PhysicalAddress << PAGE_4KB_SHIFT) + (virtAddr.Bits.Pml4Index * 8),
//        &pml4e,
//        sizeof(PML4E)) == FALSE)
//    {
//        return 0;
//    }
//
//    /*
//     * Always ensure we can proceed with our translation process. It may
//     *  also be wise to check the read result of our MmCopyMemory wrapper.
//     */
//
//    if (pml4e.Bits.Present == 0)
//    {
//        return 0;
//    }
//
//    /*
//     * Now that we have our PML4E value, implicitly, just like with the
//     *  directory table base or CR3 (which hold the address of the PML4 table),
//     *  the value of our PML4E holds the address of our next paging table (PDPT).
//     *  So we perform the same calculation as always to obtain our PDPTE value.
//     */
//
//    if (ReadPhysicalAddress(
//        /* This calculation results in the PDPTE address */
//        (pml4e.Bits.PhysicalAddress << PAGE_4KB_SHIFT) + (virtAddr.Bits.PdptIndex * 8),
//        &pdpte,
//        sizeof(PDPTE)) == FALSE)
//    {
//        return 0;
//    }
//
//    if (pdpte.Bits.Present == 0)
//    {
//        return 0;
//    }
//
//    /*
//     * Remember: PDPTEs can point to huge pages (1GB allocations). Here, we
//     *  will check to see whether or not that is the case for this PDPTE.
//     */
//
//    if (IS_LARGE_PAGE(pdpte.All) == TRUE)
//    {
//        /*
//         * We know now the seventh bit is set within this PDPTE value, which
//         *  tells us that this PDPTE points to a 1GB mapping of memory. If you
//         *  end up here, your translation process is finished. All you have to
//         *  do is parse out the address of the physical page, and then add a
//         *  (larger) offset from the virtual address to index your data.
//         */
//
//        pdpteLarge.All = pdpte.All;
//
//        return (pdpteLarge.Bits.PhysicalAddress << PAGE_1GB_SHIFT)
//            + PAGE_1GB_OFFSET(VirtualAddress);
//    }
//
//    /*
//     * So, we had a PDPTE, and it didn't point to a huge page of data.
//     *  Now, we continue with the process just like before, and obtain
//     *  the PDE value.
//     */
//
//    if (ReadPhysicalAddress(
//        /* This calculation results in the PDE address */
//        (pdpte.Bits.PhysicalAddress << PAGE_4KB_SHIFT) + (virtAddr.Bits.PdIndex * 8),
//        &pde,
//        sizeof(PDE)) == FALSE)
//    {
//        return 0;
//    }
//
//    if (pde.Bits.Present == 0)
//    {
//        return 0;
//    }
//
//    /*
//     * Remember: PDEs can point to large pages (2MB allocations). Here, we
//     *  will check to see whether or not that is the case for this PDE.
//     */
//
//    if (IS_LARGE_PAGE(pde.All) == TRUE)
//    {
//        /*
//         * We know now the seventh bit is set within this PDE value, which
//         *  tells us that this PDE points to a 2MB mapping of memory. If you
//         *  end up here, your translation process is finished. All you have to
//         *  do is parse out the address of the physical page, and then add a
//         *  (larger) offset from the virtual address to index your data.
//         */
//
//        pdeLarge.All = pde.All;
//
//        return (pdeLarge.Bits.PhysicalAddress << PAGE_2MB_SHIFT)
//            + PAGE_2MB_OFFSET(VirtualAddress);
//    }
//
//    /*
//     * So, we had a PDE, and it didn't point to a large page of data.
//     *  Now, we continue with the process just like before, and obtain
//     *  the PTE value.
//     */
//
//    if (ReadPhysicalAddress(
//        /* This calculation results in the PTE address */
//        (pde.Bits.PhysicalAddress << PAGE_4KB_SHIFT) + (virtAddr.Bits.PtIndex * 8),
//        &pte,
//        sizeof(PTE)) == FALSE)
//    {
//        return 0;
//    }
//
//    if (pte.Bits.Present == 0)
//    {
//        return 0;
//    }
//
//    /*
//     * Now that we have the PTE value, and we know it's present, we
//     *  have completed the translation process. The base address held
//     *  by this PTE is the base address for the underlying 4KB chunk
//     *  of physical memory.
//     */
//
//    return (pte.Bits.PhysicalAddress << PAGE_4KB_SHIFT)
//        + virtAddr.Bits.PageIndex;
//}
//
//NTSTATUS
//DriverEntry(
//    _In_ PDRIVER_OBJECT  DriverObject,
//    _In_ PUNICODE_STRING RegistryPath
//)
//{
//    UNREFERENCED_PARAMETER(DriverObject);
//    UNREFERENCED_PARAMETER(RegistryPath);
//
//    __debugbreak();
//
//    UINT8 value = 0xAA;
//
//    UINT64 dirTableBase = __readcr3();
//    UINT64 virtAddr = (UINT64)&value;
//
//    UINT64 physAddr = TranslateLinearAddress(dirTableBase, virtAddr);
//
//    KdPrint((
//        "Translated virtual address (0x%llX -> 0x%llX)\r\n",
//        virtAddr, physAddr
//        ));
//
//    return STATUS_UNSUCCESSFUL;
//}