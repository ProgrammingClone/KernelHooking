#include "Hook.h"
#include "Queue.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, RemoveHook)
#endif;

#define TRAMPOLINE_SIZE 32 // Extra bytes are added for alignment

NTSTATUS HookedNtQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength) {
    NTSTATUS status = STATUS_SUCCESS;
    __try {
        // Wait for the event to be signaled, with an optional timeout if desired
        KeWaitForSingleObject(&HookConfiguredEvent, Executive, KernelMode, FALSE, NULL);

        if (myTrampoline == NULL) {
            return STATUS_UNSUCCESSFUL;
        }

        status = ((NtQuerySystemInformation_t)myTrampoline)(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);

        if (NT_SUCCESS(status) && gDevice != NULL) {
            PDEVICE_EXTENSION deviceExtension = GetDeviceExtension(gDevice);

            if (SystemInformationClass == SystemBasicInformation && deviceExtension->CoreCount > 0 && deviceExtension->CoreCount <= 128) {
                PSYSTEM_BASIC_INFORMATION pInfo = (PSYSTEM_BASIC_INFORMATION)SystemInformation;
                pInfo->NumberOfProcessors = deviceExtension->CoreCount;
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        NTSTATUS exceptionCode = GetExceptionCode();
        DebugMessage("Exception occurred in HookedNtQuerySystemInformation: 0x%x\n", exceptionCode);
    }

    return status;
}



static VOID PrintFunctionBytes(PVOID address, SIZE_T size) {
    PUCHAR bytePtr = (PUCHAR)address;
    DebugMessage("First %Iu bytes at address %p:\n", size, address);
    for (SIZE_T i = 0; i < size; i++) {
        DebugMessage("0x%02X ", bytePtr[i]);
    }
    DebugMessage("\n");
}

static PVOID AllocateAlignedExecutableMemory(SIZE_T size, ULONG tag) {
    PVOID alignedMemory = NULL;
    ULONG_PTR alignedSize = (size + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);  // Round up to page size

    // Allocate the memory, ensuring it’s executable and cache-aligned
    alignedMemory = ExAllocatePoolWithTag(NonPagedPoolExecute, alignedSize, tag);
    if (alignedMemory == NULL) {
        return NULL;
    }

    // Ensure it’s aligned to a page boundary
    if ((ULONG_PTR)alignedMemory % PAGE_SIZE != 0) {
        ExFreePool(alignedMemory);
        alignedMemory = ExAllocatePoolWithTag(NonPagedPoolExecute | POOL_COLD_ALLOCATION, alignedSize, tag);
    }
    return alignedMemory;
}

static VOID WriteToReadOnlyMemory(PVOID target, PVOID source, SIZE_T size) {
    PMDL mdl = IoAllocateMdl(target, (ULONG)size, FALSE, FALSE, NULL);

    if (mdl == NULL) {
        DebugMessage("Failed to allocate MDL\n");
        return;
    }

    MmBuildMdlForNonPagedPool(mdl); // Builds the MDL for the given non-paged memory.

    __try {
        PVOID mappedAddress = MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmNonCached, NULL, FALSE, NormalPagePriority);

        if (mappedAddress != NULL) {
            RtlCopyMemory(mappedAddress, source, size);
            MmUnmapLockedPages(mappedAddress, mdl);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        NTSTATUS exceptionCode = GetExceptionCode();
        DebugMessage("Exception occurred while writing to read-only memory: 0x%x\n", exceptionCode);
    }

    IoFreeMdl(mdl);
}


VOID InstallHook() {
    const UCHAR bytesRemoved = 12;

    // Get the address of NtQuerySystemInformation
    UNICODE_STRING routineName = RTL_CONSTANT_STRING(L"NtQuerySystemInformation");
    OriginalNtQuerySystemInformation = (NtQuerySystemInformation_t)MmGetSystemRoutineAddress(&routineName);

    if (OriginalNtQuerySystemInformation) {
        // Allocate memory for the trampoline using an MDL for cross-context access
        myTrampolineMemory = AllocateAlignedExecutableMemory(TRAMPOLINE_SIZE, 'Hook');
        if (myTrampolineMemory == NULL) {
            DebugMessage("Failed to allocate trampoline memory\n");
            return;
        }

        // Create an MDL to describe trampolineMemory
        myTrampolineMDL = IoAllocateMdl(myTrampolineMemory, TRAMPOLINE_SIZE, FALSE, FALSE, NULL);
        if (myTrampolineMDL == NULL) {
            ExFreePool(myTrampolineMemory);
            myTrampolineMemory = NULL;
            DebugMessage("Failed to allocate MDL for trampoline\n");
            return;
        }

        // Map the MDL pages for trampolineMemory
        MmBuildMdlForNonPagedPool(myTrampolineMDL);
        MmProtectMdlSystemAddress(myTrampolineMDL, PAGE_EXECUTE_READWRITE);  // Set execute, read, and write permissions
        myTrampoline = MmMapLockedPagesSpecifyCache(myTrampolineMDL, KernelMode, MmNonCached, NULL, FALSE, NormalPagePriority);

        if (myTrampoline == NULL) {
            ExFreePool(myTrampolineMemory);
            IoFreeMdl(myTrampolineMDL);
            DebugMessage("Failed to map trampoline pages\n");
            return;
        }

        ULONGLONG offsetBackToOriginal = (ULONGLONG)((uintptr_t)(PUCHAR)OriginalNtQuerySystemInformation + bytesRemoved);

        RtlZeroMemory(myTrampoline, TRAMPOLINE_SIZE); // Clear the trampoline memory to avoid unexpected execution of the last unused bytes
        RtlCopyMemory(myTrampoline, (PVOID)OriginalNtQuerySystemInformation, bytesRemoved); // Copy the first bytes from NtQuerySystemInformation to trampoline

         // MOV REX, offsetBackToOriginal -> <OriginalNtQuerySystemInformation>
        *((PUCHAR)myTrampoline + bytesRemoved) = 0x48;      // REX
        *((PUCHAR)myTrampoline + bytesRemoved + 1) = 0xB8;  // mov
        *((ULONGLONG*)((PUCHAR)myTrampoline + bytesRemoved + 2)) = offsetBackToOriginal; // mov (8 bytes)

        // Indrect JMP to RAX aka `offsetBackToOriginal` (we cant use 0xE9 since that is a relative jump and only works in an address space of 32 bit)
        *((PUCHAR)myTrampoline + bytesRemoved + 10) = 0xFF;
        *((PUCHAR)myTrampoline + bytesRemoved + 11) = 0xE0;


        // Define the new jump instruction to `HookedNtQuerySystemInformation`
        UCHAR jump[12] = { 0 };

        // Step 1: MOV RAX, <HookedNtQuerySystemInformation>
        jump[0] = 0x48;   // REX prefix for 64-bit operand
        jump[1] = 0xB8;   // Opcode for `mov rax, <64-bit immediate>`
        *((ULONGLONG*)(jump + 2)) = (ULONGLONG)HookedNtQuerySystemInformation; // 64-bit address to jump to

        // Step 2: JMP RAX (indirect jump)
        jump[10] = 0xFF;  // Opcode for indirect jump
        jump[11] = 0xE0;  // ModR/M byte for `jmp rax`

        // Apply the hook by writing the jump instruction at the start of NtQuerySystemInformation
        WriteToReadOnlyMemory((PVOID)OriginalNtQuerySystemInformation, jump, sizeof(jump));
        KeInvalidateAllCaches();

        // Signal the event to indicate hook configuration is complete
        KeSetEvent(&HookConfiguredEvent, 0, FALSE);
    }
    else {
        DebugMessage("Failed to retrieve address for NtQuerySystemInformation\n");
    }
}


VOID RemoveHook() {
    PAGED_CODE();

    if (myTrampoline) {
        KeClearEvent(&HookConfiguredEvent); // make our hook wait while we change its code

        if (myTrampoline != NULL) {
            WriteToReadOnlyMemory((PVOID)OriginalNtQuerySystemInformation, myTrampoline, 6); // Restore the original bytes in NtQuerySystemInformation
            ExFreePoolWithTag(myTrampoline, 'Hook');
            myTrampoline = NULL;
        }

        if (myTrampolineMemory != NULL) {
            ExFreePool(myTrampolineMemory);
            myTrampolineMemory = NULL;
        }

        if (myTrampolineMDL != NULL) {
            IoFreeMdl(myTrampolineMDL);
            myTrampolineMDL = NULL;
        }

        DebugMessage("NtQuerySystemInformation unhooked successfully\n");
        KeSetEvent(&HookConfiguredEvent, 0, FALSE); // Let any threads stuck on waiting continue but exit with STATUS_UNSUCCESSFUL
    }
}