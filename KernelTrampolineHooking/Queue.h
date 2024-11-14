#pragma once

#ifndef Queue_H
#define Queue_H

#include "Common.h"

#define IOCTL_SET_CORES CTL_CODE(FILE_DEVICE_UNKNOWN, 0x700, METHOD_BUFFERED, FILE_WRITE_DATA)

// This is what we refernce from user land to talk to our driver via IOCTL
#define NTDEVICE_NAME         L"\\Device\\KernelTrampolineHook"     
#define SYMBOLIC_NAME_STRING  L"\\DosDevices\\KernelTrampolineHook"

typedef struct _DEVICE_EXTENSION {
    UCHAR CoreCount; // Store core count from user input
    WDF_WORKITEM_CONFIG workitemConfig;
    WDF_OBJECT_ATTRIBUTES attributes;
} DEVICE_EXTENSION, * PDEVICE_EXTENSION;

typedef struct _USER_INPUT_DATA {
    UCHAR CoreCount;

    USHORT Length; // Length of this struct
} USER_INPUT_DATA, * PUSER_INPUT_DATA;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(DEVICE_EXTENSION, GetDeviceExtension)


VOID QueueEvtIoDeviceControl(_In_ WDFQUEUE Queue, _In_ WDFREQUEST Request, _In_ size_t OutputBufferLength, _In_ size_t InputBufferLength, _In_ ULONG IoControlCode);
NTSTATUS QueueInitialize(_In_ WDFDEVICE Device);


WDFDEVICE gDevice;

#endif // Queue_H