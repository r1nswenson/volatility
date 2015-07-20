
#include "winpmem.h"

BOOLEAN OpenProcessId(ULONG processId, PEPROCESS *eprocess) {
  NTSTATUS ntStatus = STATUS_UNSUCCESSFUL;
  ntStatus = PsLookupProcessByProcessId((HANDLE)processId, eprocess);
  if (NT_SUCCESS(ntStatus))
    return TRUE;
  else {
    WinDbgPrint(ATAG("Error: PsLookupProcessByProcessId failed to open processId:%x status:x\n"), processId, ntStatus);
    return FALSE;
  }
}

BOOLEAN UserlandAddressIsValid(PVOID virtualAddress) {
  BOOLEAN valid = FALSE;
  __try {
    volatile UCHAR ch;
    ProbeForRead(virtualAddress, 1, 1);
    ch    = *(PUCHAR)virtualAddress;
    valid = TRUE;
  } __except (EXCEPTION_EXECUTE_HANDLER) {   }
  return valid;
}

BOOLEAN ProcessAddressIsValid(VirtualAddressInfo *virtualAddressInfo) {
  BOOLEAN   addressIsValid = FALSE;
  PEPROCESS eprocess       = 0;
  ASSERT(virtualAddressInfo->ProcessId);
  if (!OpenProcessId((ULONG)virtualAddressInfo->ProcessId, &eprocess))
    return FALSE;

  KeAttachProcess(eprocess);
  addressIsValid = UserlandAddressIsValid((PVOID)virtualAddressInfo->VirtualAddress);
  KeDetachProcess();
  ObDereferenceObject(eprocess);
  return addressIsValid;
}

BOOLEAN KernellandAddressIsValid(PVOID virtualAddress) {
  BOOLEAN valid = FALSE;
  __try {
    volatile UCHAR ch;
    ch    = *(PUCHAR)virtualAddress;
    valid = TRUE;
  } __except (EXCEPTION_EXECUTE_HANDLER) {   }
  return valid;
}

BOOLEAN VirtualAddressIsValid(VirtualAddressInfo *virtualAddressInfo) {
  if (virtualAddressInfo->ProcessId)
    return ProcessAddressIsValid(virtualAddressInfo);
  else
    return KernellandAddressIsValid((PVOID)virtualAddressInfo->VirtualAddress);
}