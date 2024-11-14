#include "Queue.h"
#include "Hook.h"

static VOID QueryProcessorCountWorkItem(WDFWORKITEM WorkItem); // Has to be here otherwise we cant add it to ALLOC_PRAGMA

#ifdef ALLOC_PRAGMA
#pragma alloc_text (PAGE, QueryProcessorCountWorkItem)
#pragma alloc_text (PAGE, QueryProcessorCount) // 'PAGE' means this code section can be paged out while we are waiting for it to run (only works at IRQL of 0 aka Passive Level)
#pragma alloc_text (PAGE, QueueInitialize) // Paging code out helps reduce memory consumption
#endif;

static volatile BOOLEAN configured = FALSE; // Easy way to prevent duplicate IOCTL calls from running without needing to lock


/// <summary> Don't directly call this!! Use 'WdfWorkItemEnqueue(workItem)' when wanting to run 'QueryProcessorCount' from a higher IRQL level. </summary>
static VOID QueryProcessorCountWorkItem(WDFWORKITEM WorkItem) {
    PAGED_CODE();

    DebugMessage("New CoreCount: %lu \n", QueryProcessorCount(8));
    WdfObjectDelete(WorkItem);
}


///  Make sure you call this at IRQL level of 0 otherwise it will fail. This means you need to downgrade your IRQL when you call this from an IOCTL queue.
/// Note this function queries 'NtQuerySystemInformation' in order to pull processor count.
UCHAR QueryProcessorCount(UCHAR defaultCoreCount) {
    PAGED_CODE();

    SYSTEM_BASIC_INFORMATION tempSysInfo;
    ULONG returnLength = 0;

    // Initial call to NtQuerySystemInformation with a static buffer
    NTSTATUS status = NtQuerySystemInformation(SystemBasicInformation, &tempSysInfo, sizeof(tempSysInfo), &returnLength);

    if (status == STATUS_INFO_LENGTH_MISMATCH) {
        PSYSTEM_BASIC_INFORMATION sysInfo = (PSYSTEM_BASIC_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, returnLength, 'SysI');
        if (sysInfo == NULL) {
            DebugMessage("Memory allocation failed for SYSTEM_BASIC_INFORMATION\n");
            return defaultCoreCount;
        }

        // Second call to NtQuerySystemInformation with correctly sized buffer
        status = NtQuerySystemInformation(SystemBasicInformation, sysInfo, returnLength, &returnLength);
        if (NT_SUCCESS(status)) {
            return sysInfo->NumberOfProcessors;
        }
        else {
            DebugMessage("NtQuerySystemInformation failed on second call: 0x%x  Length:%lu \n", status, returnLength);
        }

        ExFreePoolWithTag(sysInfo, 'SysI');
    }
    else {
        DebugMessage("NtQuerySystemInformation failed on initial call: 0x%x  Length:%lu \n", status, returnLength);
    }
    return defaultCoreCount;
}

VOID QueueEvtIoDeviceControl(_In_ WDFQUEUE Queue, _In_ WDFREQUEST Request, _In_ size_t OutputBufferLength, _In_ size_t InputBufferLength, _In_ ULONG IoControlCode) {
    UNREFERENCED_PARAMETER(OutputBufferLength);

    WDFDEVICE device = WdfIoQueueGetDevice(Queue); // This will equal gDevice
    PDEVICE_EXTENSION deviceExtension = GetDeviceExtension(device); 
    NTSTATUS status = STATUS_SUCCESS;

    if (IoControlCode == IOCTL_SET_CORES) {
        PVOID buffer = NULL;
        size_t inputBufferLength;

        if (!NT_SUCCESS(status = WdfRequestRetrieveInputBuffer(Request, sizeof(USER_INPUT_DATA), &buffer, &inputBufferLength))) {
            DebugMessage("Failed to retrieve input buffer or size mismatch\n");
            WdfRequestComplete(Request, status);
            return;
        }

        if (buffer == NULL) {
            DebugMessage("Input buffer is null\n");
            WdfRequestComplete(Request, STATUS_INVALID_PARAMETER);
            return;
        }

        if (inputBufferLength != sizeof(USER_INPUT_DATA) || InputBufferLength < sizeof(USER_INPUT_DATA)) {
            DebugMessage("First Incorrect buffer size: expected %zu, got %zu or got %zu\n", sizeof(USER_INPUT_DATA), inputBufferLength, InputBufferLength);
            WdfRequestComplete(Request, STATUS_INVALID_BUFFER_SIZE);
            return;
        }

        __try {
            PUSER_INPUT_DATA inputData = (PUSER_INPUT_DATA)buffer;

            if (inputData->Length < sizeof(USER_INPUT_DATA)) {
                DebugMessage("Second Incorrect buffer size: expected %zu, got %hu\n", sizeof(USER_INPUT_DATA), inputData->Length);
                WdfRequestComplete(Request, STATUS_INVALID_BUFFER_SIZE);
                return;
            }

            deviceExtension->CoreCount = inputData->CoreCount; // Set core count in device extension
            DebugMessage("QueueEvtIoDeviceControl Received CoreCount: %d\n", deviceExtension->CoreCount);

            if (deviceExtension->CoreCount > 0 && deviceExtension->CoreCount < 100) {
                if (!configured) { // We could use a lock here but it does not really matter for our application
                    configured = TRUE;
                    InstallHook();
                }
            }

#pragma region Downgrade our IRQL level so we can see if the core count was updated
            if (KeGetCurrentIrql() == PASSIVE_LEVEL) {
                DebugMessage("Cannot handle request at current IRQL New CoreCount:%lu \n", QueryProcessorCount(8));
                WdfRequestComplete(Request, STATUS_INVALID_DEVICE_REQUEST);
                return;
            }

            WDFWORKITEM workItem;
            if (!NT_SUCCESS(status = WdfWorkItemCreate(&deviceExtension->workitemConfig, &deviceExtension->attributes, &workItem))) {
                DebugMessage("Failed to create work item: 0x%x\n", status);
                WdfRequestComplete(Request, STATUS_INSUFFICIENT_RESOURCES);
                return;
            }

            WdfWorkItemEnqueue(workItem); // Queue the work item for execution at PASSIVE_LEVEL
#pragma endregion

            WdfRequestComplete(Request, STATUS_SUCCESS);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            status = GetExceptionCode();
            DebugMessage("Exception occurred while accessing user buffer: 0x%x\n", status);
            WdfRequestComplete(Request, status);
        }
    }
    else {
        DebugMessage("Unsupported IOCTL code %lu \n", IoControlCode);
        WdfRequestComplete(Request, STATUS_INVALID_DEVICE_REQUEST);
    }
}

NTSTATUS QueueInitialize(_In_ WDFDEVICE Device) {
    PAGED_CODE();

    WDF_IO_QUEUE_CONFIG queueConfig;
    WDF_OBJECT_ATTRIBUTES queueAttributes;
    WDFQUEUE queue;
    NTSTATUS status;

    DECLARE_CONST_UNICODE_STRING(symbolicLinkName, SYMBOLIC_NAME_STRING);
    DebugMessage("Initializing Queue \n");

    if (!NT_SUCCESS(status = WdfDeviceCreateSymbolicLink(Device, &symbolicLinkName))) {
        DebugMessage("Failed to create symbolic link: 0x%x\n", status);
        return status;
    }

    // Initialize the queue configuration
    WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&queueConfig, WdfIoQueueDispatchParallel);
    queueConfig.EvtIoDeviceControl = QueueEvtIoDeviceControl;

    WDF_OBJECT_ATTRIBUTES_INIT(&queueAttributes);
    queueAttributes.SynchronizationScope = WdfSynchronizationScopeDevice;

    if (!NT_SUCCESS(status = WdfIoQueueCreate(Device, &queueConfig, &queueAttributes, &queue))) {
        DebugMessage("Failed to create IOCTL queue: 0x%x\n", status);
        return status;
    }

#pragma region Configure WorkerItems so that my IOCTL queue can downgrade its IRQL level
    PDEVICE_EXTENSION deviceExtension = GetDeviceExtension(gDevice);

    WDF_WORKITEM_CONFIG_INIT(&deviceExtension->workitemConfig, QueryProcessorCountWorkItem);
    WDF_OBJECT_ATTRIBUTES_INIT(&deviceExtension->attributes);
    deviceExtension->attributes.ParentObject = Device;
#pragma endregion
    return STATUS_SUCCESS;
}