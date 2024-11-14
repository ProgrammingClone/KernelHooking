#include "Driver.h"
#include "Queue.h"
#include "Hook.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text (INIT, DriverEntry)  // After DriverEntry runs all code denoted by 'INIT' will be discarded
#pragma alloc_text (PAGE, DriverUnload) // 'PAGE' means this code section can be paged out while we are waiting for it to run (only works at IRQL of 0 aka Passive Level)
#endif;


NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);

    WDF_OBJECT_ATTRIBUTES deviceAttributes;
    WDF_DRIVER_CONFIG config;
    WDFDRIVER driver;
    NTSTATUS status;

    // Initlaize the global fields in our header files
    myTrampolineMemory = NULL;
    myTrampolineMDL = NULL;
    myTrampoline = NULL;
    gDevice = NULL;
    KeInitializeEvent(&HookConfiguredEvent, NotificationEvent, FALSE);

    DECLARE_CONST_UNICODE_STRING(ntDeviceName, NTDEVICE_NAME);
    WDF_DRIVER_CONFIG_INIT(&config, WDF_NO_EVENT_CALLBACK);

    if (!NT_SUCCESS(status = WdfDriverCreate(DriverObject, RegistryPath, WDF_NO_OBJECT_ATTRIBUTES, &config, &driver))) {
        DebugMessage("WdfDriverCreate failed: 0x%x\n", status);
        return status;
    }

    PWDFDEVICE_INIT pDeviceInit = WdfControlDeviceInitAllocate(driver, &SDDL_DEVOBJ_SYS_ALL_ADM_RWX_WORLD_RW_RES_R);
    if (pDeviceInit == NULL) {
        DebugMessage("WdfControlDeviceInitAllocate failed\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    WdfDeviceInitSetExclusive(pDeviceInit, TRUE); // Ensure we are the only queue for this device

    if (!NT_SUCCESS(status = WdfDeviceInitAssignName(pDeviceInit, &ntDeviceName))) {
        DebugMessage("Failed to create symbolic link: 0x%x\n", status);
        WdfDeviceInitFree(pDeviceInit);
        return status;
    }

    WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&deviceAttributes, DEVICE_EXTENSION);

    if (!NT_SUCCESS(status = WdfDeviceCreate(&pDeviceInit, &deviceAttributes, &gDevice)) || gDevice == NULL) { // This will auto handle freeing 'pDeviceInit'
        DebugMessage("WdfDeviceCreate failed: 0x%x\n", status);
        return status;
    }

    UCHAR cores = QueryProcessorCount(8); // You can change this default value if you would like
    DebugMessage("Starting CoreCount: %lu \n", cores);

    PDEVICE_EXTENSION deviceExtension = GetDeviceExtension(gDevice);
    deviceExtension->CoreCount = cores;

    if (!NT_SUCCESS(status = QueueInitialize(gDevice))) { // Initialize the IOCTL queue
        DebugMessage("Queue initialization failed: 0x%x\n", status);
        return status;
    }

    DriverObject->DriverUnload = DriverUnload; // Lastly, register our unload function
    return STATUS_SUCCESS;
}


VOID DriverUnload(PDRIVER_OBJECT DriverObject) {
    UNREFERENCED_PARAMETER(DriverObject);
    PAGED_CODE();

    RemoveHook();
}
