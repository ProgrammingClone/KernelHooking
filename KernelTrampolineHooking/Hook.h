#pragma once

#ifndef Hook_H
#define Hook_H

#include "Common.h"

NTSTATUS NTAPI NtQuerySystemInformation(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
);

NTSTATUS HookedNtQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);
UCHAR QueryProcessorCount(UCHAR defaultCoreCount);

VOID InstallHook();
VOID RemoveHook();

NtQuerySystemInformation_t OriginalNtQuerySystemInformation;

PVOID myTrampolineMemory;
PMDL myTrampolineMDL;
PVOID myTrampoline;

#endif // Hook_H
