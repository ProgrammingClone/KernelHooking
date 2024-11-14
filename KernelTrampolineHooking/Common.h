#pragma once

#ifndef Common_H
#define Common_H

#include <ntifs.h>
#include <ntddk.h>
#include <wdm.h> 
#include <wdf.h>

#define DebugMessage(x, ...) DbgPrintEx(0, 0, x, __VA_ARGS__)

typedef struct _SYSTEM_BASIC_INFORMATION {
    ULONG Reserved;
    ULONG TimerResolution;
    ULONG PageSize;
    ULONG NumberOfPhysicalPages;
    ULONG LowestPhysicalPageNumber;
    ULONG HighestPhysicalPageNumber;
    ULONG AllocationGranularity;
    ULONG MinimumUserModeAddress;
    ULONG MaximumUserModeAddress;
    KAFFINITY ActiveProcessorsAffinityMask;
    UCHAR NumberOfProcessors;  // This is the field we will modify
} SYSTEM_BASIC_INFORMATION, * PSYSTEM_BASIC_INFORMATION;


typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemBasicInformation = 0,
    // Theres a lot more of these but I deleted them to save space since we wont be using them
} SYSTEM_INFORMATION_CLASS;


typedef NTSTATUS(*NtQuerySystemInformation_t)(SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG);


KEVENT HookConfiguredEvent; // Used to prevent other threads from using the function we are hooking while making the hook

#endif // Common_H
