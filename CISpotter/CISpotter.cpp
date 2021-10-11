#include "CISpotter.h"

static BOOLEAN bCallbackRegistered = FALSE;
static PVOID gNtdllBaseAddress = NULL;

DECLARE_CONST_UNICODE_STRING(gzuZwQueryInformationProcess, L"ZwQueryInformationProcess");
static ZwQueryInformationProcess_t gZwQueryInformationProcess = NULL;

DECLARE_CONST_UNICODE_STRING(gzuZwQuerySection, L"ZwQuerySection");
static ZwQuerySection_t gZwQuerySection = NULL;

void MyLoadImageNotifyRoutine(
    PUNICODE_STRING FullImageName,
    HANDLE ProcessId,
    PIMAGE_INFO ImageInfo
)
{
    NTSTATUS ntStatus = STATUS_SUCCESS;
    OBJECT_ATTRIBUTES objAttr = { 0, };
    CLIENT_ID cid = { ProcessId, 0 };
    PS_PROTECTION protection = { 0 };
    HANDLE hProcess = NULL;
    ULONG returnLength = 0;
    PEPROCESS pProcess = NULL;

    UNREFERENCED_PARAMETER(FullImageName);
    UNREFERENCED_PARAMETER(ProcessId);

    // Sanity check
    if (!ProcessId ||
        !ImageInfo ||
        !ImageInfo->ImageBase ||
        !ImageInfo->ExtendedInfoPresent)
    {
        goto Cleanup;
    }

    // Exclude NTDLL, which is missing signer information
    if (gNtdllBaseAddress == ImageInfo->ImageBase)
    {
        goto Cleanup;
    }

    // PID => HANDLE
    InitializeObjectAttributes(&objAttr, NULL, OBJ_KERNEL_HANDLE, 0, 0);
    ntStatus = ZwOpenProcess(&hProcess, 0, &objAttr, &cid);
    if (!NT_SUCCESS(ntStatus))
    {
        goto Cleanup;
    }

    // HANDLE => PEPROCESS
    ntStatus = ObReferenceObjectByHandle(hProcess, 0, *PsProcessType, KernelMode, (PVOID*)&pProcess, NULL);
    if (!NT_SUCCESS(ntStatus))
    {
        goto Cleanup;
    }

    // Exclude the main EXE, which is missing signer information
    if (PsGetProcessSectionBaseAddress(pProcess) == ImageInfo->ImageBase)
    {
        goto Cleanup;
    }

    // Get protection level
    ntStatus = gZwQueryInformationProcess(hProcess, ProcessProtectionInformation, &protection, sizeof(protection), &returnLength);
    if (!NT_SUCCESS(ntStatus))
    {
        goto Cleanup;
    }

    // CI only applies to PPL
    if (PsProtectedTypeProtectedLight != protection.Type)
    {
        goto Cleanup;
    }

    // Only enforce CI for PPL >= AntiMalware
    switch (protection.Signer)
    {
    case PsProtectedSignerAntimalware:
    case PsProtectedSignerLsa:
    case PsProtectedSignerWindows:
    case PsProtectedSignerWinTcb:
    case PsProtectedSignerWinSystem:
        break;
    default:
        goto Cleanup;
    }
    
    // Is the image unsigned or is the signature level too low?
    if ((0 == ImageInfo->ImageSignatureType) ||
        (ImageInfo->ImageSignatureLevel < SE_SIGNING_LEVEL_ANTIMALWARE))
    {
        // This callback can sometimes execute with special APCs disabled
        // ZwTerminateProcess uses a special APC.  Calling it can deadlock in such cases.
        if (!KeAreAllApcsDisabled())
        {
            // Prove we stopped the CI violation by termination
            // This can leak memory per MSDN, but this is a POC
            (void)ZwTerminateProcess(hProcess, STATUS_INVALID_SIGNATURE);
        }
    }

Cleanup:
    if (hProcess)
    {
        ZwClose(hProcess);
    }
    if (pProcess)
    {
        ObDereferenceObject(pProcess);
    }
    return;
}

NTSTATUS GetNtdllBaseAddress()
{
    NTSTATUS ntStatus = STATUS_SUCCESS;
    OBJECT_ATTRIBUTES objAttr = { 0, };
    HANDLE hSection = NULL;
    SECTION_IMAGE_INFORMATION sii = { 0, };

    DECLARE_CONST_UNICODE_STRING(knownDllsNtdll, L"\\KnownDlls\\ntdll.dll");
    InitializeObjectAttributes(&objAttr, (PUNICODE_STRING)&knownDllsNtdll, OBJ_KERNEL_HANDLE, 0, 0);

    ntStatus = ZwOpenSection(&hSection, SECTION_QUERY, &objAttr);
    if (!NT_SUCCESS(ntStatus))
    {
        goto Cleanup;
    }

    ntStatus = gZwQuerySection(hSection, SectionImageInformation, &sii, sizeof(sii), 0);
    if (!NT_SUCCESS(ntStatus))
    {
        goto Cleanup;
    }

    gNtdllBaseAddress = sii.TransferAddress;

Cleanup:
    if (hSection)
    {
        ZwClose(hSection);
    }

    return ntStatus;
}

void DriverUnload(_DRIVER_OBJECT* DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);

    if (bCallbackRegistered)
    {
        (void)PsRemoveLoadImageNotifyRoutine(MyLoadImageNotifyRoutine);
        bCallbackRegistered = FALSE;
    }
}

EXTERN_C NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT  DriverObject,
    _In_ PUNICODE_STRING RegistryPath
)
{
    NTSTATUS ntStatus = STATUS_SUCCESS;
    
    UNREFERENCED_PARAMETER(RegistryPath);

    DriverObject->DriverUnload = DriverUnload;

    // Resolve imports
    {
        gZwQueryInformationProcess = (ZwQueryInformationProcess_t)MmGetSystemRoutineAddress((PUNICODE_STRING)&gzuZwQueryInformationProcess);
        if (!gZwQueryInformationProcess)
        {
            ntStatus = STATUS_PROCEDURE_NOT_FOUND;
            goto Cleanup;
        }

        gZwQuerySection = (ZwQuerySection_t)MmGetSystemRoutineAddress((PUNICODE_STRING)&gzuZwQuerySection);
        if (!gZwQuerySection)
        {
            ntStatus = STATUS_PROCEDURE_NOT_FOUND;
            goto Cleanup;
        }
    }

    ntStatus = PsSetLoadImageNotifyRoutineEx(MyLoadImageNotifyRoutine, 0);
    if (!NT_SUCCESS(ntStatus))
    {
        goto Cleanup;
    }
    bCallbackRegistered = TRUE;

    ntStatus = GetNtdllBaseAddress();
    if (!NT_SUCCESS(ntStatus))
    {
        goto Cleanup;
    }

Cleanup:

    if (!NT_SUCCESS(ntStatus))
    {
        DriverUnload(DriverObject);
    }

    return ntStatus;
}