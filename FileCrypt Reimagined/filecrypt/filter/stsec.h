/*++

Module Name:

    stsec.h - Windows Security functions

--*/

#ifndef __FC_STSEC_H__
#define __FC_STSEC_H__


#pragma warning(disable: 4201)

#include "fc.h"
#include <ntddk.h>
#include <ntdef.h>
#include <wdm.h>

typedef union CUSTOM_FC_TPM_SEAL_COMMAND {
    struct {
         UINT32 _0_4_;              // part of header?
         UCHAR _4_1_;               // Another part of a header?
         UCHAR _5_1_;               // Another part of a header!
         UINT16 _6_2_;              // Some sort of response code
         UINT16 uStack_240;
         UINT16 uStack_23e;
         UINT32 uStack_23c;
         UINT32 local_238;
         UINT32 uStack_234;
         UINT32 uStack_230;
         UINT32 uStack_22c;
         CHAR local_228;
         UINT32 commandBuffer[3];
         UINT64 uStack_21b;
         UINT16 auStack_213[229];
    };
    UCHAR rawBuffer[0x200];        // 0x200 buffer
} CUSTOM_FC_TPM_SEAL_COMMAND;

typedef union CUSTOM_FC_TPM_UNSEAL_COMMAND {
    struct {
        UINT8 abCommand;
        UINT8 uStack_254;
        UINT8 uStack_253;
        // UINT8 padding_byte // Here is a padding of 1 byte
        UINT16 uStack_252;
        UINT16 uStack_250;
        UINT16 uStack_24e;
        UINT16 uStack_24c;
        UINT8 bStack_24a;
        UINT8 bStack_249;
        UINT16 uStack_248;
        UINT32 uStack_246;
        UINT16 uStack_242;
        UINT16 uStack_240;
        UINT8 local_23e;
        UINT8 sealedKeyBlob[485];
        // UINT8 padding_byte // Here is a padding of 1 byte
        // UINT8 padding_byte // Here is a padding of 1 byte
    };
    UCHAR rawBuffer[0x200];        // 0x200 buffer
} CUSTOM_FC_TPM_UNSEAL_COMMAND;

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
    PUNICODE_STRING SecpParameterValue,
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
    PCUNICODE_STRING Path
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
    PCUNICODE_STRING PackgeFullName,
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
    PCUNICODE_STRING PackageFullName,
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
    ULONG* param_5
);

///* ntoskrnl.exe */
ulonglong
SeConvertStringSecurityDescriptorToSecurityDescriptor(
    PVOID param_1,
    undefined8 param_2,
    PVOID* param_3,
    UINT64* param_4
);

///* ntoskrnl.exe */
bool
SeConvertSidToStringSid (
    PSID Sid,
    LPSTR* StringSid
);

#endif /* __FC_STSEC_H__ */