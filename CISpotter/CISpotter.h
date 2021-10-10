#pragma once

#include <ntifs.h>

typedef NTSTATUS (NTAPI *ZwQueryInformationProcess_t)(
    _In_      HANDLE           ProcessHandle,
    _In_      PROCESSINFOCLASS ProcessInformationClass,
    _Out_     PVOID            ProcessInformation,
    _In_      ULONG            ProcessInformationLength,
    _Out_opt_ PULONG           ReturnLength
);

typedef enum _SECTION_INFORMATION_CLASS {
    SectionBasicInformation,
    SectionImageInformation
} SECTION_INFORMATION_CLASS, * PSECTION_INFORMATION_CLASS;

typedef NTSTATUS (NTAPI * ZwQuerySection_t)(
    IN HANDLE               SectionHandle,
    IN SECTION_INFORMATION_CLASS InformationClass,
    OUT PVOID               InformationBuffer,
    IN ULONG                InformationBufferSize,
    OUT PULONG              ResultLength OPTIONAL);

EXTERN_C
_Must_inspect_result_
NTSYSAPI
PVOID
PsGetProcessSectionBaseAddress(
    __in PEPROCESS Process
);

#pragma warning(push)
#pragma warning(disable: 4201) // warning C4201: nonstandard extension used: nameless struct/union
#pragma warning(disable: 4214) // warning C4214: nonstandard extension used: bit field types other than int

// From https://docs.microsoft.com/en-us/windows/win32/procthread/zwqueryinformationprocess
typedef enum _PS_PROTECTED_TYPE {
    PsProtectedTypeNone = 0,
    PsProtectedTypeProtectedLight = 1,
    PsProtectedTypeProtected = 2
} PS_PROTECTED_TYPE, * PPS_PROTECTED_TYPE;

typedef enum _PS_PROTECTED_SIGNER {
    PsProtectedSignerNone = 0,
    PsProtectedSignerAuthenticode,
    PsProtectedSignerCodeGen,
    PsProtectedSignerAntimalware,
    PsProtectedSignerLsa,
    PsProtectedSignerWindows,
    PsProtectedSignerWinTcb,
    PsProtectedSignerWinSystem,
    PsProtectedSignerApp,
    PsProtectedSignerMax
} PS_PROTECTED_SIGNER, * PPS_PROTECTED_SIGNER;

typedef struct _PS_PROTECTION {
    union {
        UCHAR Level;
        struct {
            UCHAR Type : 3;
            UCHAR Audit : 1;                  // Reserved
            UCHAR Signer : 4;
        };
    };
} PS_PROTECTION, * PPS_PROTECTION;

typedef struct _SECTION_IMAGE_INFORMATION {
    PVOID TransferAddress;
    char Reserved[256];
} SECTION_IMAGE_INFORMATION, * PSECTION_IMAGE_INFORMATION;

#pragma warning(pop)
