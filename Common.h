#pragma once
//typedef struct _OBJECT_ATTRIBUTES {
//	ULONG           Length;
//	HANDLE          RootDirectory;
//	PUNICODE_STRING ObjectName;
//	ULONG           Attributes;
//	PVOID           SecurityDescriptor;
//	PVOID           SecurityQualityOfService;
//} OBJECT_ATTRIBUTES;
//typedef struct _SYSTEM_THREAD_INFORMATION {
//	LARGE_INTEGER Reserved1[3];
//	ULONG Reserved2;
//	PVOID StartAddress;
//	CLIENT_ID ClientId;
//	KPRIORITY Priority;
//	LONG BasePriority;
//	ULONG Reserved3;
//	ULONG ThreadState;
//	ULONG WaitReason;
//} SYSTEM_THREAD_INFORMATION, * PSYSTEM_THREAD_INFORMATION;
// typedef struct _SYSTEM_PROCESS_INFORMATION {
//	ULONG NextEntryOffset;
//	ULONG NumberOfThreads;
//	BYTE Reserved1[48];
//	UNICODE_STRING ImageName;
//	KPRIORITY BasePriority;
//	HANDLE UniqueProcessId;
//	PVOID Reserved2;
//	ULONG HandleCount;
//	ULONG SessionId;
//	PVOID Reserved3;
//	SIZE_T PeakVirtualSize;
//	SIZE_T VirtualSize;
//	ULONG Reserved4;
//	SIZE_T PeakWorkingSetSize;
//	SIZE_T WorkingSetSize;
//	PVOID Reserved5;
//	SIZE_T QuotaPagedPoolUsage;
//	PVOID Reserved6;
//	SIZE_T QuotaNonPagedPoolUsage;
//	SIZE_T PagefileUsage;
//	SIZE_T PeakPagefileUsage;
//	SIZE_T PrivatePageCount;
//	LARGE_INTEGER Reserved7[6];
//	SYSTEM_THREAD_INFORMATION* threads;
//} SYSTEM_PROCESS_INFORMATION_STRUCT, * PSYSTEM_PROCESS_INFORMATION_STRUCT;

typedef struct _PML4E
{
	union
	{
		struct
		{
			ULONG64 Present : 1;              // Must be 1, region invalid if 0.
			ULONG64 ReadWrite : 1;            // If 0, writes not allowed.
			ULONG64 UserSupervisor : 1;       // If 0, user-mode accesses not allowed.
			ULONG64 PageWriteThrough : 1;     // Determines the memory type used to access PDPT.
			ULONG64 PageCacheDisable : 1;     // Determines the memory type used to access PDPT.
			ULONG64 Accessed : 1;             // If 0, this entry has not been used for translation.
			ULONG64 Ignored1 : 1;
			ULONG64 PageSize : 1;             // Must be 0 for PML4E.
			ULONG64 Ignored2 : 4;
			ULONG64 PageFrameNumber : 36;     // The page frame number of the PDPT of this PML4E.
			ULONG64 Reserved : 4;
			ULONG64 Ignored3 : 11;
			ULONG64 ExecuteDisable : 1;       // If 1, instruction fetches not allowed.
		};
		ULONG64 Value;
	};
} PML4E, * PPML4E;
typedef struct _PDPTE
{
	union
	{
		struct
		{
			ULONG64 Present : 1;              // Must be 1, region invalid if 0.
			ULONG64 ReadWrite : 1;            // If 0, writes not allowed.
			ULONG64 UserSupervisor : 1;       // If 0, user-mode accesses not allowed.
			ULONG64 PageWriteThrough : 1;     // Determines the memory type used to access PD.
			ULONG64 PageCacheDisable : 1;     // Determines the memory type used to access PD.
			ULONG64 Accessed : 1;             // If 0, this entry has not been used for translation.
			ULONG64 Ignored1 : 1;
			ULONG64 PageSize : 1;             // If 1, this entry maps a 1GB page.
			ULONG64 Ignored2 : 4;
			ULONG64 PageFrameNumber : 36;     // The page frame number of the PD of this PDPTE.
			ULONG64 Reserved : 4;
			ULONG64 Ignored3 : 11;
			ULONG64 ExecuteDisable : 1;       // If 1, instruction fetches not allowed.
		};
		ULONG64 Value;
	};
} PDPTE, * PPDPTE;
typedef struct _SYSTEM_THREAD_INFORMATION
{
	LARGE_INTEGER KernelTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER CreateTime;
	ULONG WaitTime;
	PVOID StartAddress;
	CLIENT_ID ClientId;
	KPRIORITY Priority;
	LONG BasePriority;
	ULONG ContextSwitches;
	ULONG ThreadState;
	KWAIT_REASON WaitReason;
} SYSTEM_THREAD_INFORMATION, * PSYSTEM_THREAD_INFORMATION;


//0xa40 bytes (sizeof)
//struct _EPROCESS
//{
//    struct _KPROCESS Pcb;                                                   //0x0
//    struct _EX_PUSH_LOCK ProcessLock;                                       //0x438
//    VOID* UniqueProcessId;                                                  //0x440
//    struct _LIST_ENTRY ActiveProcessLinks;                                  //0x448
//    struct _EX_RUNDOWN_REF RundownProtect;                                  //0x458
//    union
//    {
//        ULONG Flags2;                                                       //0x460
//        struct
//        {
//            ULONG JobNotReallyActive : 1;                                     //0x460
//            ULONG AccountingFolded : 1;                                       //0x460
//            ULONG NewProcessReported : 1;                                     //0x460
//            ULONG ExitProcessReported : 1;                                    //0x460
//            ULONG ReportCommitChanges : 1;                                    //0x460
//            ULONG LastReportMemory : 1;                                       //0x460
//            ULONG ForceWakeCharge : 1;                                        //0x460
//            ULONG CrossSessionCreate : 1;                                     //0x460
//            ULONG NeedsHandleRundown : 1;                                     //0x460
//            ULONG RefTraceEnabled : 1;                                        //0x460
//            ULONG PicoCreated : 1;                                            //0x460
//            ULONG EmptyJobEvaluated : 1;                                      //0x460
//            ULONG DefaultPagePriority : 3;                                    //0x460
//            ULONG PrimaryTokenFrozen : 1;                                     //0x460
//            ULONG ProcessVerifierTarget : 1;                                  //0x460
//            ULONG RestrictSetThreadContext : 1;                               //0x460
//            ULONG AffinityPermanent : 1;                                      //0x460
//            ULONG AffinityUpdateEnable : 1;                                   //0x460
//            ULONG PropagateNode : 1;                                          //0x460
//            ULONG ExplicitAffinity : 1;                                       //0x460
//            ULONG ProcessExecutionState : 2;                                  //0x460
//            ULONG EnableReadVmLogging : 1;                                    //0x460
//            ULONG EnableWriteVmLogging : 1;                                   //0x460
//            ULONG FatalAccessTerminationRequested : 1;                        //0x460
//            ULONG DisableSystemAllowedCpuSet : 1;                             //0x460
//            ULONG ProcessStateChangeRequest : 2;                              //0x460
//            ULONG ProcessStateChangeInProgress : 1;                           //0x460
//            ULONG InPrivate : 1;                                              //0x460
//        };
//    };
//    union
//    {
//        ULONG Flags;                                                        //0x464
//        struct
//        {
//            ULONG CreateReported : 1;                                         //0x464
//            ULONG NoDebugInherit : 1;                                         //0x464
//            ULONG ProcessExiting : 1;                                         //0x464
//            ULONG ProcessDelete : 1;                                          //0x464
//            ULONG ManageExecutableMemoryWrites : 1;                           //0x464
//            ULONG VmDeleted : 1;                                              //0x464
//            ULONG OutswapEnabled : 1;                                         //0x464
//            ULONG Outswapped : 1;                                             //0x464
//            ULONG FailFastOnCommitFail : 1;                                   //0x464
//            ULONG Wow64VaSpace4Gb : 1;                                        //0x464
//            ULONG AddressSpaceInitialized : 2;                                //0x464
//            ULONG SetTimerResolution : 1;                                     //0x464
//            ULONG BreakOnTermination : 1;                                     //0x464
//            ULONG DeprioritizeViews : 1;                                      //0x464
//            ULONG WriteWatch : 1;                                             //0x464
//            ULONG ProcessInSession : 1;                                       //0x464
//            ULONG OverrideAddressSpace : 1;                                   //0x464
//            ULONG HasAddressSpace : 1;                                        //0x464
//            ULONG LaunchPrefetched : 1;                                       //0x464
//            ULONG Background : 1;                                             //0x464
//            ULONG VmTopDown : 1;                                              //0x464
//            ULONG ImageNotifyDone : 1;                                        //0x464
//            ULONG PdeUpdateNeeded : 1;                                        //0x464
//            ULONG VdmAllowed : 1;                                             //0x464
//            ULONG ProcessRundown : 1;                                         //0x464
//            ULONG ProcessInserted : 1;                                        //0x464
//            ULONG DefaultIoPriority : 3;                                      //0x464
//            ULONG ProcessSelfDelete : 1;                                      //0x464
//            ULONG SetTimerResolutionLink : 1;                                 //0x464
//        };
//    };
//    union _LARGE_INTEGER CreateTime;                                        //0x468
//    ULONGLONG ProcessQuotaUsage[2];                                         //0x470
//    ULONGLONG ProcessQuotaPeak[2];                                          //0x480
//    ULONGLONG PeakVirtualSize;                                              //0x490
//    ULONGLONG VirtualSize;                                                  //0x498
//    struct _LIST_ENTRY SessionProcessLinks;                                 //0x4a0
//    union
//    {
//        VOID* ExceptionPortData;                                            //0x4b0
//        ULONGLONG ExceptionPortValue;                                       //0x4b0
//        ULONGLONG ExceptionPortState : 3;                                     //0x4b0
//    };
//    struct _EX_FAST_REF Token;                                              //0x4b8
//    ULONGLONG MmReserved;                                                   //0x4c0
//    struct _EX_PUSH_LOCK AddressCreationLock;                               //0x4c8
//    struct _EX_PUSH_LOCK PageTableCommitmentLock;                           //0x4d0
//    struct _ETHREAD* RotateInProgress;                                      //0x4d8
//    struct _ETHREAD* ForkInProgress;                                        //0x4e0
//    struct _EJOB* volatile CommitChargeJob;                                 //0x4e8
//    struct _RTL_AVL_TREE CloneRoot;                                         //0x4f0
//    volatile ULONGLONG NumberOfPrivatePages;                                //0x4f8
//    volatile ULONGLONG NumberOfLockedPages;                                 //0x500
//    VOID* Win32Process;                                                     //0x508
//    struct _EJOB* volatile Job;                                             //0x510
//    VOID* SectionObject;                                                    //0x518
//    VOID* SectionBaseAddress;                                               //0x520
//    ULONG Cookie;                                                           //0x528
//    struct _PAGEFAULT_HISTORY* WorkingSetWatch;                             //0x530
//    VOID* Win32WindowStation;                                               //0x538
//    VOID* InheritedFromUniqueProcessId;                                     //0x540
//    volatile ULONGLONG OwnerProcessId;                                      //0x548
//    struct _PEB* Peb;                                                       //0x550
//    struct _MM_SESSION_SPACE* Session;                                      //0x558
//    VOID* Spare1;                                                           //0x560
//    struct _EPROCESS_QUOTA_BLOCK* QuotaBlock;                               //0x568
//    struct _HANDLE_TABLE* ObjectTable;                                      //0x570
//    VOID* DebugPort;                                                        //0x578
//    struct _EWOW64PROCESS* WoW64Process;                                    //0x580
//    VOID* DeviceMap;                                                        //0x588
//    VOID* EtwDataSource;                                                    //0x590
//    ULONGLONG PageDirectoryPte;                                             //0x598
//    struct _FILE_OBJECT* ImageFilePointer;                                  //0x5a0
//    UCHAR ImageFileName[15];                                                //0x5a8
//    UCHAR PriorityClass;                                                    //0x5b7
//    VOID* SecurityPort;                                                     //0x5b8
//    struct _SE_AUDIT_PROCESS_CREATION_INFO SeAuditProcessCreationInfo;      //0x5c0
//    struct _LIST_ENTRY JobLinks;                                            //0x5c8
//    VOID* HighestUserAddress;                                               //0x5d8
//    struct _LIST_ENTRY ThreadListHead;                                      //0x5e0
//    volatile ULONG ActiveThreads;                                           //0x5f0
//    ULONG ImagePathHash;                                                    //0x5f4
//    ULONG DefaultHardErrorProcessing;                                       //0x5f8
//    LONG LastThreadExitStatus;                                              //0x5fc
//    struct _EX_FAST_REF PrefetchTrace;                                      //0x600
//    VOID* LockedPagesList;                                                  //0x608
//    union _LARGE_INTEGER ReadOperationCount;                                //0x610
//    union _LARGE_INTEGER WriteOperationCount;                               //0x618
//    union _LARGE_INTEGER OtherOperationCount;                               //0x620
//    union _LARGE_INTEGER ReadTransferCount;                                 //0x628
//    union _LARGE_INTEGER WriteTransferCount;                                //0x630
//    union _LARGE_INTEGER OtherTransferCount;                                //0x638
//    ULONGLONG CommitChargeLimit;                                            //0x640
//    volatile ULONGLONG CommitCharge;                                        //0x648
//    volatile ULONGLONG CommitChargePeak;                                    //0x650
//    struct _MMSUPPORT_FULL Vm;                                              //0x680
//    struct _LIST_ENTRY MmProcessLinks;                                      //0x7c0
//    ULONG ModifiedPageCount;                                                //0x7d0
//    LONG ExitStatus;                                                        //0x7d4
//    struct _RTL_AVL_TREE VadRoot;                                           //0x7d8
//    VOID* VadHint;                                                          //0x7e0
//    ULONGLONG VadCount;                                                     //0x7e8
//    volatile ULONGLONG VadPhysicalPages;                                    //0x7f0
//    ULONGLONG VadPhysicalPagesLimit;                                        //0x7f8
//    struct _ALPC_PROCESS_CONTEXT AlpcContext;                               //0x800
//    struct _LIST_ENTRY TimerResolutionLink;                                 //0x820
//    struct _PO_DIAG_STACK_RECORD* TimerResolutionStackRecord;               //0x830
//    ULONG RequestedTimerResolution;                                         //0x838
//    ULONG SmallestTimerResolution;                                          //0x83c
//    union _LARGE_INTEGER ExitTime;                                          //0x840
//    struct _INVERTED_FUNCTION_TABLE* InvertedFunctionTable;                 //0x848
//    struct _EX_PUSH_LOCK InvertedFunctionTableLock;                         //0x850
//    ULONG ActiveThreadsHighWatermark;                                       //0x858
//    ULONG LargePrivateVadCount;                                             //0x85c
//    struct _EX_PUSH_LOCK ThreadListLock;                                    //0x860
//    VOID* WnfContext;                                                       //0x868
//    struct _EJOB* ServerSilo;                                               //0x870
//    UCHAR SignatureLevel;                                                   //0x878
//    UCHAR SectionSignatureLevel;                                            //0x879
//    struct _PS_PROTECTION Protection;                                       //0x87a
//    UCHAR HangCount : 3;                                                      //0x87b
//    UCHAR GhostCount : 3;                                                     //0x87b
//    UCHAR PrefilterException : 1;                                             //0x87b
//    union
//    {
//        ULONG Flags3;                                                       //0x87c
//        struct
//        {
//            ULONG Minimal : 1;                                                //0x87c
//            ULONG ReplacingPageRoot : 1;                                      //0x87c
//            ULONG Crashed : 1;                                                //0x87c
//            ULONG JobVadsAreTracked : 1;                                      //0x87c
//            ULONG VadTrackingDisabled : 1;                                    //0x87c
//            ULONG AuxiliaryProcess : 1;                                       //0x87c
//            ULONG SubsystemProcess : 1;                                       //0x87c
//            ULONG IndirectCpuSets : 1;                                        //0x87c
//            ULONG RelinquishedCommit : 1;                                     //0x87c
//            ULONG HighGraphicsPriority : 1;                                   //0x87c
//            ULONG CommitFailLogged : 1;                                       //0x87c
//            ULONG ReserveFailLogged : 1;                                      //0x87c
//            ULONG SystemProcess : 1;                                          //0x87c
//            ULONG HideImageBaseAddresses : 1;                                 //0x87c
//            ULONG AddressPolicyFrozen : 1;                                    //0x87c
//            ULONG ProcessFirstResume : 1;                                     //0x87c
//            ULONG ForegroundExternal : 1;                                     //0x87c
//            ULONG ForegroundSystem : 1;                                       //0x87c
//            ULONG HighMemoryPriority : 1;                                     //0x87c
//            ULONG EnableProcessSuspendResumeLogging : 1;                      //0x87c
//            ULONG EnableThreadSuspendResumeLogging : 1;                       //0x87c
//            ULONG SecurityDomainChanged : 1;                                  //0x87c
//            ULONG SecurityFreezeComplete : 1;                                 //0x87c
//            ULONG VmProcessorHost : 1;                                        //0x87c
//            ULONG VmProcessorHostTransition : 1;                              //0x87c
//            ULONG AltSyscall : 1;                                             //0x87c
//            ULONG TimerResolutionIgnore : 1;                                  //0x87c
//            ULONG DisallowUserTerminate : 1;                                  //0x87c
//        };
//    };
//    LONG DeviceAsid;                                                        //0x880
//    VOID* SvmData;                                                          //0x888
//    struct _EX_PUSH_LOCK SvmProcessLock;                                    //0x890
//    ULONGLONG SvmLock;                                                      //0x898
//    struct _LIST_ENTRY SvmProcessDeviceListHead;                            //0x8a0
//    ULONGLONG LastFreezeInterruptTime;                                      //0x8b0
//    struct _PROCESS_DISK_COUNTERS* DiskCounters;                            //0x8b8
//    VOID* PicoContext;                                                      //0x8c0
//    VOID* EnclaveTable;                                                     //0x8c8
//    ULONGLONG EnclaveNumber;                                                //0x8d0
//    struct _EX_PUSH_LOCK EnclaveLock;                                       //0x8d8
//    ULONG HighPriorityFaultsAllowed;                                        //0x8e0
//    struct _PO_PROCESS_ENERGY_CONTEXT* EnergyContext;                       //0x8e8
//    VOID* VmContext;                                                        //0x8f0
//    ULONGLONG SequenceNumber;                                               //0x8f8
//    ULONGLONG CreateInterruptTime;                                          //0x900
//    ULONGLONG CreateUnbiasedInterruptTime;                                  //0x908
//    ULONGLONG TotalUnbiasedFrozenTime;                                      //0x910
//    ULONGLONG LastAppStateUpdateTime;                                       //0x918
//    ULONGLONG LastAppStateUptime : 61;                                        //0x920
//    ULONGLONG LastAppState : 3;                                               //0x920
//    volatile ULONGLONG SharedCommitCharge;                                  //0x928
//    struct _EX_PUSH_LOCK SharedCommitLock;                                  //0x930
//    struct _LIST_ENTRY SharedCommitLinks;                                   //0x938
//    union
//    {
//        struct
//        {
//            ULONGLONG AllowedCpuSets;                                       //0x948
//            ULONGLONG DefaultCpuSets;                                       //0x950
//        };
//        struct
//        {
//            ULONGLONG* AllowedCpuSetsIndirect;                              //0x948
//            ULONGLONG* DefaultCpuSetsIndirect;                              //0x950
//        };
//    };
//    VOID* DiskIoAttribution;                                                //0x958
//    VOID* DxgProcess;                                                       //0x960
//    ULONG Win32KFilterSet;                                                  //0x968
//    union  _PS_INTERLOCKED_TIMER_DELAY_VALUES ProcessTimerDelay;     //0x970
//    volatile ULONG KTimerSets;                                              //0x978
//    volatile ULONG KTimer2Sets;                                             //0x97c
//    volatile ULONG ThreadTimerSets;                                         //0x980
//    ULONGLONG VirtualTimerListLock;                                         //0x988
//    struct _LIST_ENTRY VirtualTimerListHead;                                //0x990
//    union
//    {
//        struct _WNF_STATE_NAME WakeChannel;                                 //0x9a0
//        struct _PS_PROCESS_WAKE_INFORMATION WakeInfo;                       //0x9a0
//    };
//    union
//    {
//        ULONG MitigationFlags;                                              //0x9d0
//        struct
//        {
//            ULONG ControlFlowGuardEnabled : 1;                                //0x9d0
//            ULONG ControlFlowGuardExportSuppressionEnabled : 1;               //0x9d0
//            ULONG ControlFlowGuardStrict : 1;                                 //0x9d0
//            ULONG DisallowStrippedImages : 1;                                 //0x9d0
//            ULONG ForceRelocateImages : 1;                                    //0x9d0
//            ULONG HighEntropyASLREnabled : 1;                                 //0x9d0
//            ULONG StackRandomizationDisabled : 1;                             //0x9d0
//            ULONG ExtensionPointDisable : 1;                                  //0x9d0
//            ULONG DisableDynamicCode : 1;                                     //0x9d0
//            ULONG DisableDynamicCodeAllowOptOut : 1;                          //0x9d0
//            ULONG DisableDynamicCodeAllowRemoteDowngrade : 1;                 //0x9d0
//            ULONG AuditDisableDynamicCode : 1;                                //0x9d0
//            ULONG DisallowWin32kSystemCalls : 1;                              //0x9d0
//            ULONG AuditDisallowWin32kSystemCalls : 1;                         //0x9d0
//            ULONG EnableFilteredWin32kAPIs : 1;                               //0x9d0
//            ULONG AuditFilteredWin32kAPIs : 1;                                //0x9d0
//            ULONG DisableNonSystemFonts : 1;                                  //0x9d0
//            ULONG AuditNonSystemFontLoading : 1;                              //0x9d0
//            ULONG PreferSystem32Images : 1;                                   //0x9d0
//            ULONG ProhibitRemoteImageMap : 1;                                 //0x9d0
//            ULONG AuditProhibitRemoteImageMap : 1;                            //0x9d0
//            ULONG ProhibitLowILImageMap : 1;                                  //0x9d0
//            ULONG AuditProhibitLowILImageMap : 1;                             //0x9d0
//            ULONG SignatureMitigationOptIn : 1;                               //0x9d0
//            ULONG AuditBlockNonMicrosoftBinaries : 1;                         //0x9d0
//            ULONG AuditBlockNonMicrosoftBinariesAllowStore : 1;               //0x9d0
//            ULONG LoaderIntegrityContinuityEnabled : 1;                       //0x9d0
//            ULONG AuditLoaderIntegrityContinuity : 1;                         //0x9d0
//            ULONG EnableModuleTamperingProtection : 1;                        //0x9d0
//            ULONG EnableModuleTamperingProtectionNoInherit : 1;               //0x9d0
//            ULONG RestrictIndirectBranchPrediction : 1;                       //0x9d0
//            ULONG IsolateSecurityDomain : 1;                                  //0x9d0
//        } MitigationFlagsValues;                                            //0x9d0
//    };
//    union
//    {
//        ULONG MitigationFlags2;                                             //0x9d4
//        struct
//        {
//            ULONG EnableExportAddressFilter : 1;                              //0x9d4
//            ULONG AuditExportAddressFilter : 1;                               //0x9d4
//            ULONG EnableExportAddressFilterPlus : 1;                          //0x9d4
//            ULONG AuditExportAddressFilterPlus : 1;                           //0x9d4
//            ULONG EnableRopStackPivot : 1;                                    //0x9d4
//            ULONG AuditRopStackPivot : 1;                                     //0x9d4
//            ULONG EnableRopCallerCheck : 1;                                   //0x9d4
//            ULONG AuditRopCallerCheck : 1;                                    //0x9d4
//            ULONG EnableRopSimExec : 1;                                       //0x9d4
//            ULONG AuditRopSimExec : 1;                                        //0x9d4
//            ULONG EnableImportAddressFilter : 1;                              //0x9d4
//            ULONG AuditImportAddressFilter : 1;                               //0x9d4
//            ULONG DisablePageCombine : 1;                                     //0x9d4
//            ULONG SpeculativeStoreBypassDisable : 1;                          //0x9d4
//            ULONG CetUserShadowStacks : 1;                                    //0x9d4
//            ULONG AuditCetUserShadowStacks : 1;                               //0x9d4
//            ULONG AuditCetUserShadowStacksLogged : 1;                         //0x9d4
//            ULONG UserCetSetContextIpValidation : 1;                          //0x9d4
//            ULONG AuditUserCetSetContextIpValidation : 1;                     //0x9d4
//            ULONG AuditUserCetSetContextIpValidationLogged : 1;               //0x9d4
//            ULONG CetUserShadowStacksStrictMode : 1;                          //0x9d4
//            ULONG BlockNonCetBinaries : 1;                                    //0x9d4
//            ULONG BlockNonCetBinariesNonEhcont : 1;                           //0x9d4
//            ULONG AuditBlockNonCetBinaries : 1;                               //0x9d4
//            ULONG AuditBlockNonCetBinariesLogged : 1;                         //0x9d4
//            ULONG Reserved1 : 1;                                              //0x9d4
//            ULONG Reserved2 : 1;                                              //0x9d4
//            ULONG Reserved3 : 1;                                              //0x9d4
//            ULONG Reserved4 : 1;                                              //0x9d4
//            ULONG Reserved5 : 1;                                              //0x9d4
//            ULONG CetDynamicApisOutOfProcOnly : 1;                            //0x9d4
//            ULONG UserCetSetContextIpValidationRelaxedMode : 1;               //0x9d4
//        } MitigationFlags2Values;                                           //0x9d4
//    };
//    VOID* PartitionObject;                                                  //0x9d8
//    ULONGLONG SecurityDomain;                                               //0x9e0
//    ULONGLONG ParentSecurityDomain;                                         //0x9e8
//    VOID* CoverageSamplerContext;                                           //0x9f0
//    VOID* MmHotPatchContext;                                                //0x9f8
//    struct _RTL_AVL_TREE DynamicEHContinuationTargetsTree;                  //0xa00
//    struct _EX_PUSH_LOCK DynamicEHContinuationTargetsLock;                  //0xa08
//    struct _PS_DYNAMIC_ENFORCED_ADDRESS_RANGES DynamicEnforcedCetCompatibleRanges; //0xa10
//    ULONG DisabledComponentFlags;                                           //0xa20
//};
//


typedef struct _SYSTEM_PROCESS_INFORMATION
{
	ULONG NextEntryOffset;
	ULONG NumberOfThreads;
	LARGE_INTEGER WorkingSetPrivateSize; // since VISTA
	ULONG HardFaultCount; // since WIN7
	ULONG NumberOfThreadsHighWatermark; // since WIN7
	ULONGLONG CycleTime; // since WIN7
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ImageName;
	KPRIORITY BasePriority;
	HANDLE UniqueProcessId;
	HANDLE InheritedFromUniqueProcessId;
	ULONG HandleCount;
	ULONG SessionId;
	ULONG_PTR UniqueProcessKey; // since VISTA (requires SystemExtendedProcessInformation)
	SIZE_T PeakVirtualSize;
	SIZE_T VirtualSize;
	ULONG PageFaultCount;
	SIZE_T PeakWorkingSetSize;
	SIZE_T WorkingSetSize;
	SIZE_T QuotaPeakPagedPoolUsage;
	SIZE_T QuotaPagedPoolUsage;
	SIZE_T QuotaPeakNonPagedPoolUsage;
	SIZE_T QuotaNonPagedPoolUsage;
	SIZE_T PagefileUsage;
	SIZE_T PeakPagefileUsage;
	SIZE_T PrivatePageCount;
	LARGE_INTEGER ReadOperationCount;
	LARGE_INTEGER WriteOperationCount;
	LARGE_INTEGER OtherOperationCount;
	LARGE_INTEGER ReadTransferCount;
	LARGE_INTEGER WriteTransferCount;
	LARGE_INTEGER OtherTransferCount;
	SYSTEM_THREAD_INFORMATION Threads[1];
} SYSTEM_PROCESS_INFORMATION_STRUCT, * PSYSTEM_PROCESS_INFORMATION;

typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
	HANDLE Section; //not filled in
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES
{
	ULONG NumberOfModules;
	RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;


typedef struct _NON_PAGED_DEBUG_INFO                                            // 9 elements; 0x0020 Bytes
{
	UINT16                      Signature;                                      // 0x0000; 0x0002 Bytes
	UINT16                      Flags;                                          // 0x0002; 0x0002 Bytes
	ULONG32                     Size;                                           // 0x0004; 0x0004 Bytes
	UINT16                      Machine;                                        // 0x0008; 0x0002 Bytes
	UINT16                      Characteristics;                                // 0x000A; 0x0002 Bytes
	ULONG32                     TimeDateStamp;                                  // 0x000C; 0x0004 Bytes
	ULONG32                     CheckSum;                                       // 0x0010; 0x0004 Bytes
	ULONG32                     SizeOfImage;                                    // 0x0014; 0x0004 Bytes
	UINT64                      ImageBase;                                      // 0x0018; 0x0008 Bytes
} NON_PAGED_DEBUG_INFO, * PNON_PAGED_DEBUG_INFO;

typedef struct _KLDR_DATA_TABLE_ENTRY                                           // 22 elements; 0x00A0 Bytes
{
	LIST_ENTRY InLoadOrderLinks;                                                // 0x0000; 0x0010 Bytes
	PVOID                       ExceptionTable;                                 // 0x0010; 0x0008 Bytes
	ULONG32                     ExceptionTableSize;                             // 0x0018; 0x0004 Bytes
	UINT8                       _PADDING0_[4];                                  // 0x001C; 0x0004 Bytes
	PVOID                       GpValue;                                        // 0x0020; 0x0008 Bytes
	PNON_PAGED_DEBUG_INFO       NonPagedDebugInfo;                              // 0x0028; 0x0008 Bytes
	PVOID                       DllBase;                                        // 0x0030; 0x0008 Bytes
	PVOID                       EntryPoint;                                     // 0x0038; 0x0008 Bytes
	ULONG32                     SizeOfImage;                                    // 0x0040; 0x0004 Bytes
	UINT8                       _PADDING1_[4];                                  // 0x0044; 0x0004 Bytes
	UNICODE_STRING FullDllName;                                                 // 0x0048; 0x0010 Bytes
	UNICODE_STRING BaseDllName;                                                 // 0x0058; 0x0010 Bytes
	ULONG32                     Flags;                                          // 0x0068; 0x0004 Bytes
	UINT16                      LoadCount;                                      // 0x006C; 0x0002 Bytes
	union                                                                       // 0x006E; 6 elements; 0x0002 Bytes
	{
		UINT16                  SignatureLevel : 4; // 0x006E; Bits:  0 -  3
		UINT16                  SignatureType : 3; // 0x006E; Bits:  4 -  6
		UINT16                  Frozen : 2; // 0x006E; Bits:  7 -  8
		UINT16                  HotPatch : 1; // 0x006E; Bit:   9
		UINT16                  Unused : 6; // 0x006E; Bits: 10 - 15
		UINT16                  EntireField;                                    // 0x006E; 0x0002 Bytes
	} u1;                                                                       // 0x006E; 0x0002 Bytes
	PVOID                       SectionPointer;                                 // 0x0070; 0x0008 Bytes
	ULONG32                     CheckSum;                                       // 0x0078; 0x0004 Bytes
	ULONG32                     CoverageSectionSize;                            // 0x007C; 0x0004 Bytes
	PVOID                       CoverageSection;                                // 0x0080; 0x0008 Bytes
	PVOID                       LoadedImports;                                  // 0x0088; 0x0008 Bytes
	union                                                                       // 0x0090; 2 elements; 0x0008 Bytes
	{
		PVOID                   Spare;                                          // 0x0090; 0x0008 Bytes
		PVOID/*PKLDR_DATA_TABLE_ENTRY*/  NtDataTableEntry;                               // 0x0090; 0x0008 Bytes
	};
	ULONG32                     SizeOfImageNotRounded;                          // 0x0098; 0x0004 Bytes
	ULONG32                     TimeDateStamp;                                  // 0x009C; 0x0004 Bytes
} KLDR_DATA_TABLE_ENTRY, * PKLDR_DATA_TABLE_ENTRY;

#define DRIVER_MEM_TAG 'skyn'


#define PROCESS_INFO_BUFFER_SIZE 1024*1024
#define MAX_ALLOC_RETRY 6 
#define DEVICE_DRIVER_TYPE 0x22
#define IOCTL_IRP_READ_FROM_USERSPACE CTL_CODE(DEVICE_DRIVER_TYPE, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define  IOCTL_QUERY_PROCESSES CTL_CODE(DEVICE_DRIVER_TYPE, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define  IOCTL_QUERY_MODULES CTL_CODE(DEVICE_DRIVER_TYPE, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define  IOCTL_READ_PROCESS CTL_CODE(DEVICE_DRIVER_TYPE, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define  IOCTL_WRITE_PROCESS CTL_CODE(DEVICE_DRIVER_TYPE, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_CR3_MANIPULATION CTL_CODE(DEVICE_DRIVER_TYPE, 0x806, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct REQUEST {
	ULONG procID;
	PVOID startVirtualAddress;
	ULONG bytesCount;
} READ_FROM_PROCESS_REQUEST;

typedef struct PATTERN {
	BYTE* BYTES;
	UINT32* WILDMARKS_INDEXES;
	SIZE_T PATTERN_LENGTH;
} PATTERN_STRUCT;

typedef  READ_FROM_PROCESS_REQUEST WRITE_TO_PROCESS_REQUEST;