/*++

Module Name:

    stsec.h - Windows Security functions

--*/

#ifndef __FC_STSEC_H__
#define __FC_STSEC_H__
#include <ntddk.h>
#include <ntdef.h>
#include <wdm.h>

#include "fc.h"

VOID
StSecDeinitialize(
    VOID);

VOID StSecFree(
    PVOID Buffer
);

NTSTATUS
StSecGetSecurityDescriptor(
    PCUNICODE_STRING InputPath,
    PSECURITY_DESCRIPTOR OutSecurityDescriptor,
    PWCHAR* OutChamberId,
    PULONG OutChamberType
);

NTSTATUS
StSecInitialize(
    PDRIVER_OBJECT DriverObject
);

NTSTATUS
StSecpAddChamberProfileKey(
    PWCHAR ChamberId,
    PUCHAR InstallSecretKey,
    PUCHAR DataSecretKey,
    ULONG SecretKeySize
);

VOID
StSecpCacheCleanupWorkItem(
    VOID);

VOID
StSecpCacheDeinitialize(
    VOID);

PVOID
StSecpCacheGenericTableAllocRoutine(
    PRTL_GENERIC_TABLE Table,
    CLONG ByteSize
);

RTL_GENERIC_COMPARE_RESULTS
StSecpCacheGenericTableCompareRoutine(
    PRTL_GENERIC_TABLE Table,
    PCUSTOM_FC_STSEC_CACHE_TABLE_ENTRY FirstStruct,
    PCUSTOM_FC_STSEC_CACHE_TABLE_ENTRY SecondStruct
);

VOID
StSecpCacheGenericTableFreeRoutine(
    PRTL_GENERIC_TABLE Table,
    PVOID Buffer
);

//VOID
NTSTATUS
StSecpCacheInitialize(
    PFLT_FILTER FilterHandle
);

NTSTATUS
StSecpCheckConditionalPolicy(
    PCUNICODE_STRING SecpParameterName,
    PUNICODE_STRING OutPackageFamilyName,
    PUCHAR OutIsDebugProfile
);

NTSTATUS
StSecpDeriveChamberProfileKey(
    PWCHAR ChamberId,
    ULONG ChamberType,
    PUCHAR OutputProfileKey,
    ULONG ProfileKeyLength
);

PCUSTOM_FC_STSEC_FOLDER_PROP_CACHE_LIST_ENTRY
StSecpFindFolderPropertyPolicyElement(
    PUNICODE_STRING Path
);

PCUSTOM_FC_STSEC_SEC_DESC_CACHE_LIST_ENTRY
StSecpFindSecurityDescriptorPolicyElement(
    PCUNICODE_STRING Path
);

VOID
StSecpFreeNonPaged(
    PUCHAR Buffer,
    ULONG Size
);

NTSTATUS
StSecpGetAppSid(
    PUNICODE_STRING Data,
    PWCHAR* ResultStringSid
);

NTSTATUS
StSecpGetChamberProfileKey(
    PWCHAR ChamberId,
    ULONG ChamberType,
    PUCHAR OutChamberProfileKey,
    ULONG KeySize
);

NTSTATUS
StSecpGetFolderPropertyPolicy(
    HANDLE RegistryKeyHandle
);

NTSTATUS
StSecpGetMasterKey(
    PUCHAR* OutMasterKey,
    PULONG OutMasterKeySizeInBytes
);

NTSTATUS
StSecpGetParameterValue(
    PCUNICODE_STRING ParameterName,
    PCUNICODE_STRING Value,
    PWCHAR* ResultSid
);

NTSTATUS
StSecpGetSecurityDescriptorPolicy(
    HANDLE RegistryKeyHandle
);

NTSTATUS
StSecpGetSidFromPackageFamilyName(
    PCUNICODE_STRING PackageFamilyName,
    PWCHAR* ResultSid
);

NTSTATUS
StSecpGetSidFromPackageFullName(
    PUNICODE_STRING PackgeFullName,
    PWCHAR* ResultSid
);

NTSTATUS
StSecpGetSidFromProductId(
    PCUNICODE_STRING ProductId,
    PWCHAR* ResultSid
);

NTSTATUS
StSecpGetSidFromUserName(
    PCUNICODE_STRING UserName,
    PWCHAR* ResultSid
);

NTSTATUS
StSecpGetStorageFolderStringSecurityDescriptor(
    PCUNICODE_STRING FolderPath,
    PWCHAR* OutStringSecurityDescriptor
);

NTSTATUS
StSecpInitializePolicyCache(
    VOID);

NTSTATUS
StSecpOpenMasterKeyHandle(
    HANDLE* OutMasterKeyHandle
);

NTSTATUS
StSecpPackageFamilyNameFromFullName(
    PUNICODE_STRING PackageFullName,
    PUNICODE_STRING OutPackageFamilyName
);

NTSTATUS
StSecpReadSealedKeyBlob(
    PUCHAR* OutSealedKeyBlob,
    PULONG OutSealedKeyBlobSize
);

NTSTATUS
StSecpSealKey(
    PUCHAR UnsealedKey,
    ULONG UnsealedKeySize,
    PUCHAR OutSealedKey,
    PULONG OutsealedKeySize
);

BOOLEAN
StSecpSealKeyTestHookSet(
    VOID);

NTSTATUS
StSecpUnsealKey(
    PUCHAR SealedKeyBlob,
    ULONG SealedKeyBlobSize,
    PUCHAR OutUnsealedKey,
    PULONG OutUnsealedKeySize
);

NTSTATUS
StSecpWriteSealedKeyBlob(
    PVOID SealedKeyBlob,
    ULONG KeyBlobSize
);

/* ntoskrnl.exe */
ulonglong
SeConvertSecurityDescriptorToStringSecurityDescriptor(
    longlong param_1,
    int param_2,
    int param_3,
    undefined8* param_4,
    undefined4* param_5
);

/* ntoskrnl.exe */
ulonglong
SeConvertStringSecurityDescriptorToSecurityDescriptor(
    PVOID param_1,
    undefined8 param_2,
    PVOID* param_3,
    UINT64* param_4
);

/* ntoskrnl.exe */
BOOL
SeConvertSidToStringSid (
    PSID Sid,
    LPSTR* StringSid
);

#endif /* __FC_STSEC_H__ */
