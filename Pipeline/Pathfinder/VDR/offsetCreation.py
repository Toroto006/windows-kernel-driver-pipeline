
# Structure size in bytes
PVOID_SIZE = 8 #bytes

def calculate_offsets(struct_definition):
    # Split the structure definition by lines
    lines = struct_definition.strip().split("\n")

    # Extract member names from each line
    members = [line.split(';')[0].split()[-1].rstrip(':') for line in lines if ';' in line and 'PVOID' in line]

    # Calculate offsets
    offsets = [i * PVOID_SIZE for i in range(len(members))]

    # Combine member names and offsets into a dictionary
    member_offsets = {
        offset: member for offset, member in zip(offsets, members)
    }

    return member_offsets

# Input structure definition
struct_definition = """
typedef struct _WDFFUNCTIONS {
    PVOID                                    pfnWdfChildListCreate;
    PVOID                                 pfnWdfChildListGetDevice;
    PVOID                               pfnWdfChildListRetrievePdo;
    PVOID                pfnWdfChildListRetrieveAddressDescription;
    PVOID                                 pfnWdfChildListBeginScan;
    PVOID                                   pfnWdfChildListEndScan;
    PVOID                            pfnWdfChildListBeginIteration;
    PVOID                        pfnWdfChildListRetrieveNextDevice;
    PVOID                              pfnWdfChildListEndIteration;
    PVOID      pfnWdfChildListAddOrUpdateChildDescriptionAsPresent;
    PVOID           pfnWdfChildListUpdateChildDescriptionAsMissing;
    PVOID       pfnWdfChildListUpdateAllChildDescriptionsAsPresent;
    PVOID                         pfnWdfChildListRequestChildEject;
    PVOID                                   pfnWdfCollectionCreate;
    PVOID                                 pfnWdfCollectionGetCount;
    PVOID                                      pfnWdfCollectionAdd;
    PVOID                                   pfnWdfCollectionRemove;
    PVOID                               pfnWdfCollectionRemoveItem;
    PVOID                                  pfnWdfCollectionGetItem;
    PVOID                             pfnWdfCollectionGetFirstItem;
    PVOID                              pfnWdfCollectionGetLastItem;
    PVOID                                 pfnWdfCommonBufferCreate;
    PVOID               pfnWdfCommonBufferGetAlignedVirtualAddress;
    PVOID               pfnWdfCommonBufferGetAlignedLogicalAddress;
    PVOID                              pfnWdfCommonBufferGetLength;
    PVOID                          pfnWdfControlDeviceInitAllocate; // 0xC8
    PVOID           pfnWdfControlDeviceInitSetShutdownNotification;
    PVOID                          pfnWdfControlFinishInitializing;
    PVOID                               pfnWdfDeviceGetDeviceState;
    PVOID                               pfnWdfDeviceSetDeviceState;
    PVOID                        pfnWdfWdmDeviceGetWdfDeviceHandle;
    PVOID                           pfnWdfDeviceWdmGetDeviceObject;
    PVOID                         pfnWdfDeviceWdmGetAttachedDevice;
    PVOID                         pfnWdfDeviceWdmGetPhysicalDevice;
    PVOID                   pfnWdfDeviceWdmDispatchPreprocessedIrp;
    PVOID                pfnWdfDeviceAddDependentUsageDeviceObject;
    PVOID            pfnWdfDeviceAddRemovalRelationsPhysicalDevice;
    PVOID         pfnWdfDeviceRemoveRemovalRelationsPhysicalDevice;
    PVOID                 pfnWdfDeviceClearRemovalRelationsDevices;
    PVOID                                    pfnWdfDeviceGetDriver;
    PVOID                           pfnWdfDeviceRetrieveDeviceName;
    PVOID                        pfnWdfDeviceAssignMofResourceName;
    PVOID                                  pfnWdfDeviceGetIoTarget;
    PVOID                            pfnWdfDeviceGetDevicePnpState;
    PVOID                          pfnWdfDeviceGetDevicePowerState;
    PVOID                    pfnWdfDeviceGetDevicePowerPolicyState;
    PVOID                         pfnWdfDeviceAssignS0IdleSettings;
    PVOID                         pfnWdfDeviceAssignSxWakeSettings;
    PVOID                              pfnWdfDeviceOpenRegistryKey;
    PVOID                        pfnWdfDeviceSetSpecialFileSupport;
    PVOID                           pfnWdfDeviceSetCharacteristics;
    PVOID                           pfnWdfDeviceGetCharacteristics;
    PVOID                      pfnWdfDeviceGetAlignmentRequirement;
    PVOID                      pfnWdfDeviceSetAlignmentRequirement;
    PVOID                                     pfnWdfDeviceInitFree;
    PVOID                pfnWdfDeviceInitSetPnpPowerEventCallbacks;
    PVOID             pfnWdfDeviceInitSetPowerPolicyEventCallbacks;
    PVOID                  pfnWdfDeviceInitSetPowerPolicyOwnership;
    PVOID           pfnWdfDeviceInitRegisterPnpStateChangeCallback;
    PVOID         pfnWdfDeviceInitRegisterPowerStateChangeCallback;
    PVOID    pfnWdfDeviceInitRegisterPowerPolicyStateChangeCallback;
    PVOID                                pfnWdfDeviceInitSetIoType;
    PVOID                             pfnWdfDeviceInitSetExclusive;
    PVOID                      pfnWdfDeviceInitSetPowerNotPageable;
    PVOID                         pfnWdfDeviceInitSetPowerPageable;
    PVOID                           pfnWdfDeviceInitSetPowerInrush;
    PVOID                            pfnWdfDeviceInitSetDeviceType;
    PVOID                               pfnWdfDeviceInitAssignName;
    PVOID                         pfnWdfDeviceInitAssignSDDLString; //0x220
    PVOID                           pfnWdfDeviceInitSetDeviceClass;
    PVOID                       pfnWdfDeviceInitSetCharacteristics;
    PVOID                      pfnWdfDeviceInitSetFileObjectConfig;
    PVOID                     pfnWdfDeviceInitSetRequestAttributes;
    PVOID           pfnWdfDeviceInitAssignWdmIrpPreprocessCallback; // 248h
    PVOID             pfnWdfDeviceInitSetIoInCallerContextCallback; // 250h
    PVOID                                       pfnWdfDeviceCreate; // 258h
    PVOID                          pfnWdfDeviceSetStaticStopRemove;
    PVOID                        pfnWdfDeviceCreateDeviceInterface; // 268h
    PVOID                      pfnWdfDeviceSetDeviceInterfaceState;
    PVOID                pfnWdfDeviceRetrieveDeviceInterfaceString;
    PVOID                           pfnWdfDeviceCreateSymbolicLink; // 0x280
    PVOID                                pfnWdfDeviceQueryProperty;
    PVOID                        pfnWdfDeviceAllocAndQueryProperty;
    PVOID                           pfnWdfDeviceSetPnpCapabilities;
    PVOID                         pfnWdfDeviceSetPowerCapabilities;
    PVOID                 pfnWdfDeviceSetBusInformationForChildren;
    PVOID                           pfnWdfDeviceIndicateWakeStatus;
    PVOID                                    pfnWdfDeviceSetFailed;
    PVOID                              pfnWdfDeviceStopIdleNoTrack;
    PVOID                            pfnWdfDeviceResumeIdleNoTrack;
    PVOID                                pfnWdfDeviceGetFileObject;
    PVOID                               pfnWdfDeviceEnqueueRequest;
    PVOID                              pfnWdfDeviceGetDefaultQueue;
    PVOID                  pfnWdfDeviceConfigureRequestDispatching;
    PVOID                                   pfnWdfDmaEnablerCreate;
    PVOID                         pfnWdfDmaEnablerGetMaximumLength;
    PVOID          pfnWdfDmaEnablerGetMaximumScatterGatherElements;
    PVOID          pfnWdfDmaEnablerSetMaximumScatterGatherElements;
    PVOID                               pfnWdfDmaTransactionCreate;
    PVOID                           pfnWdfDmaTransactionInitialize;
    PVOID               pfnWdfDmaTransactionInitializeUsingRequest;
    PVOID                              pfnWdfDmaTransactionExecute;
    PVOID                              pfnWdfDmaTransactionRelease;
    PVOID                         pfnWdfDmaTransactionDmaCompleted;
    PVOID               pfnWdfDmaTransactionDmaCompletedWithLength;
    PVOID                    pfnWdfDmaTransactionDmaCompletedFinal;
    PVOID                  pfnWdfDmaTransactionGetBytesTransferred;
    PVOID                     pfnWdfDmaTransactionSetMaximumLength;
    PVOID                           pfnWdfDmaTransactionGetRequest;
    PVOID          pfnWdfDmaTransactionGetCurrentDmaTransferLength;
    PVOID                            pfnWdfDmaTransactionGetDevice;
    PVOID                                          pfnWdfDpcCreate;
    PVOID                                         pfnWdfDpcEnqueue;
    PVOID                                          pfnWdfDpcCancel;
    PVOID                                 pfnWdfDpcGetParentObject;
    PVOID                                       pfnWdfDpcWdmGetDpc;
    PVOID                                       pfnWdfDriverCreate;
    PVOID                              pfnWdfDriverGetRegistryPath;
    PVOID                           pfnWdfDriverWdmGetDriverObject;
    PVOID                    pfnWdfDriverOpenParametersRegistryKey;
    PVOID                        pfnWdfWdmDriverGetWdfDriverHandle;
    PVOID                            pfnWdfDriverRegisterTraceInfo;
    PVOID                        pfnWdfDriverRetrieveVersionString;
    PVOID                           pfnWdfDriverIsVersionAvailable;
    PVOID                        pfnWdfFdoInitWdmGetPhysicalDevice;
    PVOID                             pfnWdfFdoInitOpenRegistryKey;
    PVOID                               pfnWdfFdoInitQueryProperty;
    PVOID                       pfnWdfFdoInitAllocAndQueryProperty;
    PVOID                           pfnWdfFdoInitSetEventCallbacks;
    PVOID                                   pfnWdfFdoInitSetFilter;
    PVOID                   pfnWdfFdoInitSetDefaultChildListConfig;
    PVOID                               pfnWdfFdoQueryForInterface;
    PVOID                             pfnWdfFdoGetDefaultChildList;
    PVOID                                  pfnWdfFdoAddStaticChild;
    PVOID                 pfnWdfFdoLockStaticChildListForIteration;
    PVOID                         pfnWdfFdoRetrieveNextStaticChild;
    PVOID              pfnWdfFdoUnlockStaticChildListFromIteration;
    PVOID                              pfnWdfFileObjectGetFileName;
    PVOID                                 pfnWdfFileObjectGetFlags;
    PVOID                                pfnWdfFileObjectGetDevice;
    PVOID                         pfnWdfFileObjectWdmGetFileObject;
    PVOID                                    pfnWdfInterruptCreate;
    PVOID                            pfnWdfInterruptQueueDpcForIsr;
    PVOID                               pfnWdfInterruptSynchronize;
    PVOID                               pfnWdfInterruptAcquireLock;
    PVOID                               pfnWdfInterruptReleaseLock;
    PVOID                                    pfnWdfInterruptEnable;
    PVOID                                   pfnWdfInterruptDisable;
    PVOID                           pfnWdfInterruptWdmGetInterrupt;
    PVOID                                   pfnWdfInterruptGetInfo;
    PVOID                                 pfnWdfInterruptSetPolicy;
    PVOID                                 pfnWdfInterruptGetDevice;
    PVOID                                      pfnWdfIoQueueCreate; // 4C0h
    PVOID                                    pfnWdfIoQueueGetState;
    PVOID                                       pfnWdfIoQueueStart;
    PVOID                                        pfnWdfIoQueueStop;
    PVOID                           pfnWdfIoQueueStopSynchronously;
    PVOID                                   pfnWdfIoQueueGetDevice;
    PVOID                         pfnWdfIoQueueRetrieveNextRequest;
    PVOID                 pfnWdfIoQueueRetrieveRequestByFileObject;
    PVOID                                 pfnWdfIoQueueFindRequest;
    PVOID                        pfnWdfIoQueueRetrieveFoundRequest;
    PVOID                          pfnWdfIoQueueDrainSynchronously;
    PVOID                                       pfnWdfIoQueueDrain;
    PVOID                          pfnWdfIoQueuePurgeSynchronously;
    PVOID                                       pfnWdfIoQueuePurge;
    PVOID                                 pfnWdfIoQueueReadyNotify;
    PVOID                                     pfnWdfIoTargetCreate;
    PVOID                                       pfnWdfIoTargetOpen;
    PVOID                        pfnWdfIoTargetCloseForQueryRemove;
    PVOID                                      pfnWdfIoTargetClose;
    PVOID                                      pfnWdfIoTargetStart;
    PVOID                                       pfnWdfIoTargetStop;
    PVOID                                   pfnWdfIoTargetGetState;
    PVOID                                  pfnWdfIoTargetGetDevice;
    PVOID                        pfnWdfIoTargetQueryTargetProperty;
    PVOID                pfnWdfIoTargetAllocAndQueryTargetProperty;
    PVOID                          pfnWdfIoTargetQueryForInterface;
    PVOID                   pfnWdfIoTargetWdmGetTargetDeviceObject;
    PVOID                 pfnWdfIoTargetWdmGetTargetPhysicalDevice;
    PVOID                     pfnWdfIoTargetWdmGetTargetFileObject;
    PVOID                     pfnWdfIoTargetWdmGetTargetFileHandle;
    PVOID                      pfnWdfIoTargetSendReadSynchronously;
    PVOID                       pfnWdfIoTargetFormatRequestForRead;
    PVOID                     pfnWdfIoTargetSendWriteSynchronously;
    PVOID                      pfnWdfIoTargetFormatRequestForWrite;
    PVOID                     pfnWdfIoTargetSendIoctlSynchronously;
    PVOID                      pfnWdfIoTargetFormatRequestForIoctl;
    PVOID             pfnWdfIoTargetSendInternalIoctlSynchronously;
    PVOID              pfnWdfIoTargetFormatRequestForInternalIoctl;
    PVOID       pfnWdfIoTargetSendInternalIoctlOthersSynchronously;
    PVOID        pfnWdfIoTargetFormatRequestForInternalIoctlOthers;
    PVOID                                       pfnWdfMemoryCreate;
    PVOID                           pfnWdfMemoryCreatePreallocated;
    PVOID                                    pfnWdfMemoryGetBuffer;
    PVOID                                 pfnWdfMemoryAssignBuffer;
    PVOID                                 pfnWdfMemoryCopyToBuffer;
    PVOID                               pfnWdfMemoryCopyFromBuffer;
    PVOID                                pfnWdfLookasideListCreate;
    PVOID                          pfnWdfMemoryCreateFromLookaside;
    PVOID                               pfnWdfDeviceMiniportCreate;
    PVOID                               pfnWdfDriverMiniportUnload;
    PVOID                        pfnWdfObjectGetTypedContextWorker;
    PVOID                              pfnWdfObjectAllocateContext;
    PVOID                             pfnWdfObjectContextGetObject;
    PVOID                              pfnWdfObjectReferenceActual;
    PVOID                            pfnWdfObjectDereferenceActual;
    PVOID                                       pfnWdfObjectCreate;
    PVOID                                       pfnWdfObjectDelete;
    PVOID                                        pfnWdfObjectQuery;
    PVOID                                    pfnWdfPdoInitAllocate;
    PVOID                           pfnWdfPdoInitSetEventCallbacks;
    PVOID                              pfnWdfPdoInitAssignDeviceID;
    PVOID                            pfnWdfPdoInitAssignInstanceID;
    PVOID                               pfnWdfPdoInitAddHardwareID;
    PVOID                             pfnWdfPdoInitAddCompatibleID;
    PVOID                               pfnWdfPdoInitAddDeviceText;
    PVOID                            pfnWdfPdoInitSetDefaultLocale;
    PVOID                             pfnWdfPdoInitAssignRawDevice;
    PVOID                                     pfnWdfPdoMarkMissing;
    PVOID                                    pfnWdfPdoRequestEject;
    PVOID                                       pfnWdfPdoGetParent;
    PVOID               pfnWdfPdoRetrieveIdentificationDescription;
    PVOID                      pfnWdfPdoRetrieveAddressDescription;
    PVOID                        pfnWdfPdoUpdateAddressDescription;
    PVOID              pfnWdfPdoAddEjectionRelationsPhysicalDevice;
    PVOID           pfnWdfPdoRemoveEjectionRelationsPhysicalDevice;
    PVOID                   pfnWdfPdoClearEjectionRelationsDevices;
    PVOID                            pfnWdfDeviceAddQueryInterface;
    PVOID                                    pfnWdfRegistryOpenKey;
    PVOID                                  pfnWdfRegistryCreateKey;
    PVOID                                      pfnWdfRegistryClose;
    PVOID                               pfnWdfRegistryWdmGetHandle;
    PVOID                                  pfnWdfRegistryRemoveKey;
    PVOID                                pfnWdfRegistryRemoveValue;
    PVOID                                 pfnWdfRegistryQueryValue;
    PVOID                                pfnWdfRegistryQueryMemory;
    PVOID                           pfnWdfRegistryQueryMultiString;
    PVOID                         pfnWdfRegistryQueryUnicodeString;
    PVOID                                pfnWdfRegistryQueryString;
    PVOID                                 pfnWdfRegistryQueryULong;
    PVOID                                pfnWdfRegistryAssignValue;
    PVOID                               pfnWdfRegistryAssignMemory;
    PVOID                          pfnWdfRegistryAssignMultiString;
    PVOID                        pfnWdfRegistryAssignUnicodeString;
    PVOID                               pfnWdfRegistryAssignString;
    PVOID                                pfnWdfRegistryAssignULong;
    PVOID                                      pfnWdfRequestCreate;
    PVOID                               pfnWdfRequestCreateFromIrp;
    PVOID                                       pfnWdfRequestReuse;
    PVOID                                pfnWdfRequestChangeTarget;
    PVOID               pfnWdfRequestFormatRequestUsingCurrentType;
    PVOID                 pfnWdfRequestWdmFormatUsingStackLocation;
    PVOID                                        pfnWdfRequestSend;
    PVOID                                   pfnWdfRequestGetStatus;
    PVOID                              pfnWdfRequestMarkCancelable;
    PVOID                            pfnWdfRequestUnmarkCancelable;
    PVOID                                  pfnWdfRequestIsCanceled;
    PVOID                           pfnWdfRequestCancelSentRequest;
    PVOID                          pfnWdfRequestIsFrom32BitProcess;
    PVOID                        pfnWdfRequestSetCompletionRoutine;
    PVOID                         pfnWdfRequestGetCompletionParams;
    PVOID                               pfnWdfRequestAllocateTimer;
    PVOID                                    pfnWdfRequestComplete;
    PVOID                   pfnWdfRequestCompleteWithPriorityBoost;
    PVOID                     pfnWdfRequestCompleteWithInformation;
    PVOID                               pfnWdfRequestGetParameters;
    PVOID                         pfnWdfRequestRetrieveInputMemory;
    PVOID                        pfnWdfRequestRetrieveOutputMemory;
    PVOID                         pfnWdfRequestRetrieveInputBuffer;
    PVOID                        pfnWdfRequestRetrieveOutputBuffer;
    PVOID                         pfnWdfRequestRetrieveInputWdmMdl;
    PVOID                        pfnWdfRequestRetrieveOutputWdmMdl;
    PVOID               pfnWdfRequestRetrieveUnsafeUserInputBuffer;
    PVOID              pfnWdfRequestRetrieveUnsafeUserOutputBuffer;
    PVOID                              pfnWdfRequestSetInformation;
    PVOID                              pfnWdfRequestGetInformation;
    PVOID                               pfnWdfRequestGetFileObject;
    PVOID               pfnWdfRequestProbeAndLockUserBufferForRead;
    PVOID              pfnWdfRequestProbeAndLockUserBufferForWrite;
    PVOID                            pfnWdfRequestGetRequestorMode;
    PVOID                            pfnWdfRequestForwardToIoQueue;
    PVOID                                  pfnWdfRequestGetIoQueue;
    PVOID                                     pfnWdfRequestRequeue;
    PVOID                             pfnWdfRequestStopAcknowledge;
    PVOID                                   pfnWdfRequestWdmGetIrp;
    PVOID            pfnWdfIoResourceRequirementsListSetSlotNumber;
    PVOID         pfnWdfIoResourceRequirementsListSetInterfaceType;
    PVOID          pfnWdfIoResourceRequirementsListAppendIoResList;
    PVOID          pfnWdfIoResourceRequirementsListInsertIoResList;
    PVOID                 pfnWdfIoResourceRequirementsListGetCount;
    PVOID             pfnWdfIoResourceRequirementsListGetIoResList;
    PVOID                   pfnWdfIoResourceRequirementsListRemove;
    PVOID        pfnWdfIoResourceRequirementsListRemoveByIoResList;
    PVOID                               pfnWdfIoResourceListCreate;
    PVOID                     pfnWdfIoResourceListAppendDescriptor;
    PVOID                     pfnWdfIoResourceListInsertDescriptor;
    PVOID                     pfnWdfIoResourceListUpdateDescriptor;
    PVOID                             pfnWdfIoResourceListGetCount;
    PVOID                        pfnWdfIoResourceListGetDescriptor;
    PVOID                               pfnWdfIoResourceListRemove;
    PVOID                   pfnWdfIoResourceListRemoveByDescriptor;
    PVOID                     pfnWdfCmResourceListAppendDescriptor;
    PVOID                     pfnWdfCmResourceListInsertDescriptor;
    PVOID                             pfnWdfCmResourceListGetCount;
    PVOID                        pfnWdfCmResourceListGetDescriptor;
    PVOID                               pfnWdfCmResourceListRemove;
    PVOID                   pfnWdfCmResourceListRemoveByDescriptor;
    PVOID                                       pfnWdfStringCreate;
    PVOID                             pfnWdfStringGetUnicodeString;
    PVOID                                  pfnWdfObjectAcquireLock;
    PVOID                                  pfnWdfObjectReleaseLock;
    PVOID                                     pfnWdfWaitLockCreate;
    PVOID                                    pfnWdfWaitLockAcquire;
    PVOID                                    pfnWdfWaitLockRelease;
    PVOID                                     pfnWdfSpinLockCreate;
    PVOID                                    pfnWdfSpinLockAcquire;
    PVOID                                    pfnWdfSpinLockRelease;
    PVOID                                        pfnWdfTimerCreate;
    PVOID                                         pfnWdfTimerStart;
    PVOID                                          pfnWdfTimerStop;
    PVOID                               pfnWdfTimerGetParentObject;
    PVOID                              pfnWdfUsbTargetDeviceCreate;
    PVOID                 pfnWdfUsbTargetDeviceRetrieveInformation;
    PVOID                 pfnWdfUsbTargetDeviceGetDeviceDescriptor;
    PVOID            pfnWdfUsbTargetDeviceRetrieveConfigDescriptor;
    PVOID                         pfnWdfUsbTargetDeviceQueryString;
    PVOID                 pfnWdfUsbTargetDeviceAllocAndQueryString;
    PVOID              pfnWdfUsbTargetDeviceFormatRequestForString;
    PVOID                    pfnWdfUsbTargetDeviceGetNumInterfaces;
    PVOID                        pfnWdfUsbTargetDeviceSelectConfig;
    PVOID           pfnWdfUsbTargetDeviceWdmGetConfigurationHandle;
    PVOID          pfnWdfUsbTargetDeviceRetrieveCurrentFrameNumber;
    PVOID    pfnWdfUsbTargetDeviceSendControlTransferSynchronously;
    PVOID     pfnWdfUsbTargetDeviceFormatRequestForControlTransfer;
    PVOID              pfnWdfUsbTargetDeviceIsConnectedSynchronous;
    PVOID              pfnWdfUsbTargetDeviceResetPortSynchronously;
    PVOID              pfnWdfUsbTargetDeviceCyclePortSynchronously;
    PVOID           pfnWdfUsbTargetDeviceFormatRequestForCyclePort;
    PVOID                pfnWdfUsbTargetDeviceSendUrbSynchronously;
    PVOID                 pfnWdfUsbTargetDeviceFormatRequestForUrb;
    PVOID                        pfnWdfUsbTargetPipeGetInformation;
    PVOID                          pfnWdfUsbTargetPipeIsInEndpoint;
    PVOID                         pfnWdfUsbTargetPipeIsOutEndpoint;
    PVOID                               pfnWdfUsbTargetPipeGetType;
    PVOID           pfnWdfUsbTargetPipeSetNoMaximumPacketSizeCheck;
    PVOID                    pfnWdfUsbTargetPipeWriteSynchronously;
    PVOID                 pfnWdfUsbTargetPipeFormatRequestForWrite;
    PVOID                     pfnWdfUsbTargetPipeReadSynchronously;
    PVOID                  pfnWdfUsbTargetPipeFormatRequestForRead;
    PVOID                pfnWdfUsbTargetPipeConfigContinuousReader;
    PVOID                    pfnWdfUsbTargetPipeAbortSynchronously;
    PVOID                 pfnWdfUsbTargetPipeFormatRequestForAbort;
    PVOID                    pfnWdfUsbTargetPipeResetSynchronously;
    PVOID                 pfnWdfUsbTargetPipeFormatRequestForReset;
    PVOID                  pfnWdfUsbTargetPipeSendUrbSynchronously;
    PVOID                   pfnWdfUsbTargetPipeFormatRequestForUrb;
    PVOID                     pfnWdfUsbInterfaceGetInterfaceNumber;
    PVOID                        pfnWdfUsbInterfaceGetNumEndpoints;
    PVOID                          pfnWdfUsbInterfaceGetDescriptor;
    PVOID                          pfnWdfUsbInterfaceSelectSetting;
    PVOID                 pfnWdfUsbInterfaceGetEndpointInformation;
    PVOID                        pfnWdfUsbTargetDeviceGetInterface;
    PVOID              pfnWdfUsbInterfaceGetConfiguredSettingIndex;
    PVOID                  pfnWdfUsbInterfaceGetNumConfiguredPipes;
    PVOID                      pfnWdfUsbInterfaceGetConfiguredPipe;
    PVOID                      pfnWdfUsbTargetPipeWdmGetPipeHandle;
    PVOID                              pfnWdfVerifierDbgBreakPoint;
    PVOID                                 pfnWdfVerifierKeBugCheck;
    PVOID                                  pfnWdfWmiProviderCreate;
    PVOID                               pfnWdfWmiProviderGetDevice;
    PVOID                               pfnWdfWmiProviderIsEnabled;
    PVOID                        pfnWdfWmiProviderGetTracingHandle;
} WDFFUNCTIONS, *PWDFFUNCTIONS;
"""

# Calculate offsets
offsets = calculate_offsets(struct_definition)

def print_offsets(offsets):
    # Print the dictionary
    for offset, member in offsets.items():
        # print emmber with hex offset
        print(f"{member}: {hex(offset)}")

print_offsets(offsets)
