#pragma once
#include <ntddk.h>

struct __nt_kprocess
{
    DISPATCHER_HEADER Header;                                       //0x0
    LIST_ENTRY ProfileListHead;                                     //0x18
    ULONGLONG DirectoryTableBase;
};

typedef struct _KAPC_STATE {
    LIST_ENTRY ApcListHead[MaximumMode];
    struct _KPROCESS* Process;
    union {
        UCHAR InProgressFlags;
        struct {
            BOOLEAN KernelApcInProgress : 1;
            BOOLEAN SpecialApcInProgress : 1;
        };
    };

    BOOLEAN KernelApcPending;
    union {
        BOOLEAN UserApcPendingAll;
        struct {
            BOOLEAN SpecialUserApcPending : 1;
            BOOLEAN UserApcPending : 1;
        };
    };
} KAPC_STATE, * PKAPC_STATE, * PRKAPC_STATE;

extern "C"
{
    void NTAPI KeGenericCallDpc(_In_ PKDEFERRED_ROUTINE Routine, PVOID Context);
    void NTAPI KeSignalCallDpcDone(_In_ PVOID SystemArgument1);
    BOOLEAN NTAPI KeSignalCallDpcSynchronize(_In_ PVOID SystemArgument2);
}