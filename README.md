# Kernel-Function Detour Trampoline Hooking Example
This repo was designed to show the basics of how to hook kernel functions from a driver. This specific example uses a trampoline, but I could have done without it but maybe I can showcase that next.
Anyways this driver is fairly basic all it contains is an IOCTL queue so I can trigger it from a userland application and the actual hooking code that’s it. Once my userland application sends an
IOCTL request it also includes the processor count we want to spoof aka the core count. Of course, this does not fully spoof the core count since there’s a lot more things that need to happen. Also
please note if you run this driver, it will cause a BSOD after a while if you have PatchGuard running. This is because PatchGuard will detect us hooking `NtQuerySystemInformation` so if you want to
mess around with this driver make sure you use a VM and disable PatchGuard unless you are fine with crashing every 10ish min.

## Overview
The general concept is we first find the target function in this case its `NtQuerySystemInformation`. Next, we write an absolute Jump statement to the start of the function that will jump to our own drivers 
function which I called `HookedNtQuerySystemInformation`. Next, this `HookedNtQuerySystemInformation` function will then point to an exectuable block of memory `myTrampoline` which contains the first few bytes
we overwritten from `NtQuerySystemInformation` followed up by an absolute jump statement back to the original `NtQuerySystemInformation` function. Then once `NtQuerySystemInformation` returns its status our
hooked function can then modify the output before returning its status. This status then gets reported back to the original caller of `NtQuerySystemInformation`.

### Creating the trampoline
The first thing to note here is that in the kernel we dont have to worry about our function having a different address space like you do in userland when you are working with VirtualMemory. However, this also
means the address space is very vast so relative jumps using the `0xE9` assembly instruction will not work becuase that only takes in a 4 byte relative address and our jumps can be larger than that in x64. 
Furthermore, the general idea is to allocate non-pagable executable memory that is page aligned. I also aligned this memory to a multiple of 16 for cache alignement purposes. 

Anyways, I first zerod the memory then copied 12 bytes from the start of `NtQuerySystemInformation` into my trampoline. Now please be very carful when doing this because you MUST NOT copy bytes half way through 
an instruction otherwise you will ruin things. That being said I got lucky in this instance and everything lined up which you can see from my debug of `NtQuerySystemInformation` bellow.
```
0x40 0x53                     ; push rbx
0x48 0x83 0xEC 0x30           ; sub rsp, 0x30
0x45 0x33 0xD2                ; xor r10d, r10d
0x45 0x8B 0xD8                ; mov r11d, r8d
0x66 0x44 0x89 0x54 0x24 0x40 ; mov [rsp+0x40], r10w
```
One more thing to note here is that instead of using assembly instructions I had to type the instruction in machine code cause trying to line everything up using assembly would also be annoying. Having said that no
one actually memorizes the hex code for every assembly operation  :rofl:  so I just looked up the conversions to make it easier on myself.
```
        ULONGLONG offsetBackToOriginal = (ULONGLONG)((uintptr_t)(PUCHAR)OriginalNtQuerySystemInformation + bytesRemoved);

        RtlZeroMemory(myTrampoline, TRAMPOLINE_SIZE); 
        RtlCopyMemory(myTrampoline, (PVOID)OriginalNtQuerySystemInformation, bytesRemoved); // Copy the first 12 bytes from NtQuerySystemInformation into trampoline

         // MOV REX, offsetBackToOriginal -> <OriginalNtQuerySystemInformation>
        *((PUCHAR)myTrampoline + bytesRemoved) = 0x48;      
        *((PUCHAR)myTrampoline + bytesRemoved + 1) = 0xB8;  
        *((ULONGLONG*)((PUCHAR)myTrampoline + bytesRemoved + 2)) = offsetBackToOriginal; // mov (8 bytes)

        // Indrect JMP to RAX aka `offsetBackToOriginal` 
        *((PUCHAR)myTrampoline + bytesRemoved + 10) = 0xFF;
        *((PUCHAR)myTrampoline + bytesRemoved + 11) = 0xE0;
```
Now that is all done our trampoline will contain the missing `NtQuerySystemInformation` instructions followed by an absolute jump back to `NtQuerySystemInformation`.

### Hooking our target function
Next up we need to actually hook our target function aka `NtQuerySystemInformation`. To do this we have created a local 12-byte buffer which shows how many bytes it takes to write an absolute jump. This part is fairly simple but 
we do have to remember that this function will be read only so we need to write to it in a different way.
```
        UCHAR jump[12] = { 0 };

        // Step 1: MOV RAX, <HookedNtQuerySystemInformation>
        jump[0] = 0x48;   
        jump[1] = 0xB8;   
        *((ULONGLONG*)(jump + 2)) = (ULONGLONG)HookedNtQuerySystemInformation; 

        // Step 2: JMP RAX (indirect jump)
        jump[10] = 0xFF;  
        jump[11] = 0xE0;  

        WriteToReadOnlyMemory((PVOID)OriginalNtQuerySystemInformation, jump, sizeof(jump));
```
Once that is done `HookedNtQuerySystemInformation` which is a function we created inside the driver will call `status = ((NtQuerySystemInformation_t)myTrampoline)(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);`
which is what makes all of this work. One more thing I would like to add is that these absolute JMP calls will cause code execution to not return unlike normal function CALL statements. This is why we dont get a gross loop of code execution.

## Memory examples
When running this driver on my VM I used WinDbg to network debug the kernel of my VM which is how I got the following memory dumpes of our hooks so you can see how it works from a low level.

### Memory dump of our trampoline
Bellow you can observe that the first 12-bytes match the original 12 bytes of `NtQuerySystemInformation`. From there you an observe the jump clause back to `NtQuerySystemInformation`
```
kd> u FFFFB7010DB5B000
ffffb701`0db5b000 4053            push    rbx
ffffb701`0db5b002 4883ec30        sub     rsp,30h
ffffb701`0db5b006 4533d2          xor     r10d,r10d
ffffb701`0db5b009 458bd8          mov     r11d,r8d
ffffb701`0db5b00c 48b8dc98e13804f8ffff mov rax,offset nt!NtQuerySystemInformation+0xc (fffff804`38e198dc)
ffffb701`0db5b016 ffe0            jmp     rax
ffffb701`0db5b018 0000            add     byte ptr [rax],al
ffffb701`0db5b01a 0000            add     byte ptr [rax],al
```

### Memory dump of NtQuerySystemInformation
Below you can observe the `NtQuerySystemInformation` function and you can see the jump statement to our `HookedNtQuerySystemInformation` function at the very start.
```
kd> u FFFFF80438E198D0 L20
nt!NtQuerySystemInformation:
fffff804`38e198d0 48b8001054380af8ffff mov rax,offset KernelTrampolineHooking!HookedNtQuerySystemInformation (fffff80a`38541000)
fffff804`38e198da ffe0            jmp     rax
fffff804`38e198dc 664489542440    mov     word ptr [rsp+40h],r10w
fffff804`38e198e2 488bda          mov     rbx,rdx
fffff804`38e198e5 83f94a          cmp     ecx,4Ah
fffff804`38e198e8 7c24            jl      nt!NtQuerySystemInformation+0x3e (fffff804`38e1990e)
fffff804`38e198ea 83f953          cmp     ecx,53h
fffff804`38e198ed 7d1f            jge     nt!NtQuerySystemInformation+0x3e (fffff804`38e1990e)
```


### Memory dump of HookedNtQuerySystemInformation
Lastly, below you can see the memory dump of our custom `HookedNtQuerySystemInformation` function! Now this one has a lot more instructions at the start since I needed to ensure its thread safe but at the very bottom
you can observe it does a conditional JNE jump to `myTrampoline`. 
```
kd> u FFFFF80A38541000 L30
KernelTrampolineHooking!HookedNtQuerySystemInformation [\source\repos\KernelHooking\KernelTrampolineHooking\Hook.c @ 10]:
fffff80a`38541000 488bc4          mov     rax,rsp
fffff80a`38541003 48895808        mov     qword ptr [rax+8],rbx
fffff80a`38541007 48897010        mov     qword ptr [rax+10h],rsi
fffff80a`3854100b 48897818        mov     qword ptr [rax+18h],rdi
fffff80a`3854100f 4156            push    r14
fffff80a`38541011 4883ec40        sub     rsp,40h
fffff80a`38541015 498bd9          mov     rbx,r9
fffff80a`38541018 458bf0          mov     r14d,r8d
fffff80a`3854101b 488bfa          mov     rdi,rdx
fffff80a`3854101e 8bf1            mov     esi,ecx
fffff80a`38541020 8360e800        and     dword ptr [rax-18h],0
fffff80a`38541024 488360d800      and     qword ptr [rax-28h],0
fffff80a`38541029 4533c9          xor     r9d,r9d
fffff80a`3854102c 4533c0          xor     r8d,r8d
fffff80a`3854102f 33d2            xor     edx,edx
fffff80a`38541031 488d0d08330000  lea     rcx,[KernelTrampolineHooking!HookConfiguredEvent (fffff80a`38544340)]
fffff80a`38541038 ff15ea1f0000    call    qword ptr [KernelTrampolineHooking!_imp_KeWaitForSingleObject (fffff80a`38543028)]
fffff80a`3854103e 488b05d3320000  mov     rax,qword ptr [KernelTrampolineHooking!myTrampoline (fffff80a`38544318)]
fffff80a`38541045 4885c0          test    rax,rax
fffff80a`3854109c 750c            jne     KernelTrampolineHooking!HookedNtQuerySystemInformation+0xaa (fffff80a`385410aa)
```
