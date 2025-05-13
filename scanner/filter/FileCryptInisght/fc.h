/*++

Module Name:

    fc.h - FileCrypt

--*/

#ifndef __FC_H__
#define __FC_H__
#include <fltKernel.h>
#include <ntdef.h>
#include <windows.h>

///
/// Following defines are not hit in wdm,h despite compling to the same settings
///

#define KI_USER_SHARED_DATA 0xFFFFF78000000000UI64

//
// const is on the pointer, not the struct.
//

#define SharedUserData ((KUSER_SHARED_DATA * const)KI_USER_SHARED_DATA)

#define SharedInterruptTime (KI_USER_SHARED_DATA + 0x8)
#define SharedSystemTime (KI_USER_SHARED_DATA + 0x14)
#define SharedTickCount (KI_USER_SHARED_DATA + 0x320)

///////////////////////////////////////////////////////////////////////////
//
//  Data structures
//
///////////////////////////////////////////////////////////////////////////

/* typedefs for Ghidra types */
typedef long long undefined8;
typedef long undefined, undefined4;
typedef long long longlong;
typedef unsigned long long ulonglong;
typedef unsigned int uint;
typedef unsigned short ushort;
typedef unsigned char undefined2;

/* Holds AES-CBC encryption settings - 24 bytes in length */
typedef struct CUSTOM_FC_BCRYPT_DATA
{
    /* Initialized AES Algorithm */
    BCRYPT_ALG_HANDLE BcryptAlgHandle;
    /* AES ObjectLength */
    ULONG ObjectLength;
    /* AES BlockLength */
    ULONG BlockLength;
    /* The volume's sector size */
    ULONG EncryptionSectorSize;
    /* Used to call BCryptGenerateSymmetricKey as the pbSecret parameter */
    ULONG SecretKeySize;
} CUSTOM_FC_BCRYPT_DATA, *PCUSTOM_FC_BCRYPT_DATA;

/* Volume-wide settings - 56 bytes in size */
typedef struct _CUSTOM_FC_VOLUME_CONTEXT
{
    /* Initialized by RtlVolumeDeviceToDosName at FCInstanceSetup */
    UNICODE_STRING DeviceName;
    /* Disk sector size used for encryption alignment */
    ULONG SectorSize;
    UCHAR Padding1[4];
    /* Encryption settings for the volume */
    CUSTOM_FC_BCRYPT_DATA BcryptAlgHandle;
    /* Flag indicating if encryption is enabled */
    BYTE EncryptionEnabled;
    /* Does volume need verification */
    BYTE VerificationNeeded;
    UCHAR Padding2[6];
} CUSTOM_FC_VOLUME_CONTEXT, *PCUSTOM_FC_VOLUME_CONTEXT;

/* 20 bytes in size */
typedef struct CUSTOM_FC_BCRYPT_KEY_DATA
{
    /* Symmetric key, generated using a ChamberId */
    BCRYPT_KEY_HANDLE BcryptKeyHandle;
    /* Bugger that holds the key */
    PUCHAR KeyObject;
    /* Size of the key */
    ULONG KeyObjectSize;
} CUSTOM_FC_BCRYPT_KEY_DATA, *PCUSTOM_FC_BCRYPT_KEY_DATA;

/* File-specific settings 40 bytes in size */
typedef struct _CUSTOM_FC_STREAM_CONTEXT
{
    /* File-specific encryption key data */
    CUSTOM_FC_BCRYPT_KEY_DATA KeyData;
    UCHAR Padding1[4];
    /* Chamber identifier for this file, see FCPostCreate */
    PWCHAR ChamberId;
    /* (1=Install or 2=Data) see StSecpDeriveChamberProfileKey */
    ULONG ChamberType;
    UCHAR Padding2[4];
} CUSTOM_FC_STREAM_CONTEXT, *PCUSTOM_FC_STREAM_CONTEXT;

/* Information passed from FCPreCreate to FCPostCreate - 13 bytes in size*/
typedef struct _CUSTOM_FC_CREATE_CONTEXT
{
    /* Calculated ChamberId */
    PWCHAR ChamberId;
    /* Calculated ChamerType */
    ULONG ChamberType;
    /* Is access to the file has been modified */
    BOOLEAN IsAccessModified;
} CUSTOM_FC_CREATE_CONTEXT, *PCUSTOM_FC_CREATE_CONTEXT;

/* Used in FCPostRead as parameters for the FCDecryptWorker function - 16 bytes in size */
typedef struct _CUSTOM_FC_DECRYPT_PARAMS
{
    PFLT_CALLBACK_DATA CallbackData;
    struct CUSTOM_FC_READ_CONTEXT* CompletionContext;
} CUSTOM_FC_DECRYPT_PARAMS, *PCUSTOM_FC_DECRYPT_PARAMS;

/* 16 bytes in size */
typedef struct _CUSTOM_FC_READ_CONTEXT
{
    struct CUSTOM_FC_VOLUME_CONTEXT* VolumeContext;
    struct CUSTOM_FC_STREAM_CONTEXT* StreamContext;
} CUSTOM_FC_READ_CONTEXT, *PCUSTOM_FC_READ_CONTEXT;

/* Information passed from FCPreWrite to FCPostWrite - 25 bytes in size*/
typedef struct _CUSTOM_FC_WRITE_CONTEXT
{
    struct CUSTOM_FC_VOLUME_CONTEXT* VolumeContext;
    struct CUSTOM_FC_STREAM_CONTEXT* StreamContext;
    /* The data that being written to the disk after encryption */
    PUCHAR Ciphertext;
    /* Where Ciphertext was allocated: "x01" => NPagedLookasideList, "x02" => PoolWithTag */
    UCHAR AllocationType;
} CUSTOM_FC_WRITE_CONTEXT, *PCUSTOM_FC_WRITE_CONTEXT;

/* Cache of derived profile keys - 36 bytes in size*/
typedef struct _CUSTOM_FC_STSEC_CACHE_TABLE_ENTRY
{
    ULONG64 LastAccessTime;
    PWCHAR ChamberId;
    PUCHAR InstallKey;
    PUCHAR DataKey;
    ULONG KeySize;
} CUSTOM_FC_STSEC_CACHE_TABLE_ENTRY, *PCUSTOM_FC_STSEC_CACHE_TABLE_ENTRY;

/* Used in FCpObtainSecurityInfoCallout to obtain the
 * ChamberId and Type of the current file/directory that is being opened  - 36 bytes in size*/
typedef struct CUSTOM_FC_CHAMBER_DATA
{
    /* The path to check */
    PUNICODE_STRING InputPath;
    /* Calculated security descriptor of the path */
    PSECURITY_DESCRIPTOR SecurityDescriptor;
    /* Calculated chamber Id */
    PWCHAR ChamberId;
    /*  FolderId of CUSTOM_FC_STSEC_FOLDER_PROP_CACHE_LIST_ENTRY */
    ULONG ChamberType;
    UCHAR Padding[4];
    /* Final operation status */
    NTSTATUS Status;
} CUSTOM_FC_CHAMBER_DATA, *PCUSTOM_FC_CHAMBER_DATA;

/* Initialized on startup. Populates the StSecSecurityDescriptorCacheList global variable
 * from registry values - 48 bytes in size*/
typedef struct _CUSTOM_FC_STSEC_SEC_DESC_CACHE_LIST_ENTRY
{
    struct _CUSTOM_FC_STSEC_SEC_DESC_CACHE_LIST_ENTRY* Next;
    struct _CUSTOM_FC_STSEC_SEC_DESC_CACHE_LIST_ENTRY* Prev;
    UNICODE_STRING Path;
    PWCHAR SecurityDescriptor;
    PWCHAR DebugValue;
} CUSTOM_FC_STSEC_SEC_DESC_CACHE_LIST_ENTRY, *PCUSTOM_FC_STSEC_SEC_DESC_CACHE_LIST_ENTRY;

/* Initialized on startup. Populates the StSecFolderPropertyCacheList global variable
 * from registry values */
typedef struct _CUSTOM_FC_STSEC_FOLDER_PROP_CACHE_LIST_ENTRY
{
    struct _CUSTOM_FC_STSEC_FOLDER_PROP_CACHE_LIST_ENTRY* Next;
    struct _CUSTOM_FC_STSEC_FOLDER_PROP_CACHE_LIST_ENTRY* Prev;
    UNICODE_STRING Path;
    ULONG FolderId; /* Chamber Type */
    char Padding[4];
    PWCHAR ChamberId;
} CUSTOM_FC_STSEC_FOLDER_PROP_CACHE_LIST_ENTRY, *PCUSTOM_FC_STSEC_FOLDER_PROP_CACHE_LIST_ENTRY;

///////////////////////////////////////////////////////////////////////////
//
//  FC Functions
//
///////////////////////////////////////////////////////////////////////////

VOID
FCCleanupStreamContext(
    PCUSTOM_FC_STREAM_CONTEXT StreamContext
);

VOID
FCCleanupVolumeContext(
    PCUSTOM_FC_VOLUME_CONTEXT VolumeContext
);

VOID
FCDecryptWorker(
    PFLT_GENERIC_WORKITEM WorkItem,
    PFLT_INSTANCE Instance,
    PCUSTOM_FC_DECRYPT_PARAMS Params
);

NTSTATUS
FCFilterUnload(
    VOID);

VOID
FCFreeShadowBuffer(
    PVOID unused,
    PVOID Buffer,
    UCHAR AllocationType
);

NTSTATUS
FCInstanceQueryTeardown(
    VOID);

NTSTATUS
FCInstanceSetup(
    PCFLT_RELATED_OBJECTS FltObjects,
    FLT_INSTANCE_SETUP_FLAGS Flags,
    ULONG VolumeDeviceType,
    FLT_FILESYSTEM_TYPE VolumeFilesystemType
);

NTSTATUS
FCpAccessCheck(
    PFLT_CALLBACK_DATA Data,
    PSECURITY_DESCRIPTOR SecurityDescriptor,
    PACCESS_MASK OutGrantedAccess
);

NTSTATUS
FCpEncDecrypt(
    PCUSTOM_FC_BCRYPT_DATA BcryptAlgData,
    PCUSTOM_FC_BCRYPT_KEY_DATA KeyHandle,
    PUCHAR PbInput,
    PUCHAR PbOutput,
    int TotalBytesToDecrypt,
    PVOID Parameters,
    ULONG ZeroingOffest
);

NTSTATUS
FCpEncEncrypt(
    PCUSTOM_FC_BCRYPT_DATA CiphertextData,
    PCUSTOM_FC_BCRYPT_KEY_DATA BcryptHandle,
    PUCHAR DataToEncrypt,
    PUCHAR OutCiphertext,
    int TotalSizeToEncrypt,
    PUCHAR InitVector
);

VOID
FCpEncStreamCleanup(
    PCUSTOM_FC_BCRYPT_KEY_DATA KeyData
);

NTSTATUS
FCpEncStreamStart(
    PCUSTOM_FC_BCRYPT_DATA HAlgorithm,
    PWCHAR ChamberId,
    ULONG ChamberType,
    PCUSTOM_FC_BCRYPT_KEY_DATA OutKeyReceiver
);

VOID
FCpEncVolumeCleanup(
    BCRYPT_ALG_HANDLE* AlgHandle
);

NTSTATUS
FCpEncVolumeStart(
    PCUSTOM_FC_BCRYPT_DATA AlgHandle
);

BOOLEAN
FCpEqualChamberIds(
    PWCHAR ChamberIdA,
    PWCHAR ChamberIdB
);

VOID
FCpFreeChamberId(
    PWCHAR ChamberId
);

VOID
FCpObtainSecurityInfoCallout(
    PCUSTOM_FC_CHAMBER_DATA ChamberData
);

FLT_POSTOP_CALLBACK_STATUS
FCPostCreate(
    PFLT_CALLBACK_DATA Data,
    PCFLT_RELATED_OBJECTS FltObjects,
    PCUSTOM_FC_CREATE_CONTEXT CompletionContext,
    FLT_POST_OPERATION_FLAGS Flags
);

FLT_POSTOP_CALLBACK_STATUS
FCPostRead(
    PFLT_CALLBACK_DATA CallbackData,
    PCFLT_RELATED_OBJECTS FltObjects,
    PCUSTOM_FC_READ_CONTEXT CompletionContext,
    FLT_POST_OPERATION_FLAGS Flags
);

FLT_POSTOP_CALLBACK_STATUS
FCPostWrite(
    PFLT_CALLBACK_DATA CallbackData,
    PCFLT_RELATED_OBJECTS RelatedObjects,
    PCUSTOM_FC_WRITE_CONTEXT CompletionContext
);

FLT_PREOP_CALLBACK_STATUS
FCPreCreate(
    PFLT_CALLBACK_DATA Data,
    PCFLT_RELATED_OBJECTS FltObjects,
    PVOID* CompletionContext
);

FLT_PREOP_CALLBACK_STATUS
FCPreRead(
    PFLT_CALLBACK_DATA CallbackData,
    PCFLT_RELATED_OBJECTS FltObjects,
    PVOID* CompletionContext
);

NTSTATUS
FCpRetrieveAppPairingId(
    PCFLT_RELATED_OBJECTS FltObjects
);

FLT_PREOP_CALLBACK_STATUS
FCPreWrite(
    PFLT_CALLBACK_DATA CallbackData,
    PCFLT_RELATED_OBJECTS FltObjects,
    PVOID* CompletionContext
);

VOID
FCReadDriverParameters(
    PUNICODE_STRING PRegistryPath
);

VOID
DriverEntry(
    PDRIVER_OBJECT PDriverObject,
    PUNICODE_STRING PRegistryPath
);

///////////////////////////////////////////////////////////////////////////
//
//  Global Variables
//
///////////////////////////////////////////////////////////////////////////

/* Event Tracing */

#if !defined(MCGEN_TRACE_CONTEXT_DEF)
#define MCGEN_TRACE_CONTEXT_DEF

typedef struct _MCGEN_TRACE_CONTEXT
{
    TRACEHANDLE RegistrationHandle;
    TRACEHANDLE Logger;
    ULONGLONG MatchAnyKeyword;
    ULONGLONG MatchAllKeyword;
    ULONG Flags;
    ULONG IsEnabled;
    UCHAR Level;
    UCHAR Reserve;
    USHORT EnableBitsCount;
    PULONG EnableBitMask;
    const ULONGLONG* EnableKeyWords;
    const UCHAR* EnableLevel;
} MCGEN_TRACE_CONTEXT, *PMCGEN_TRACE_CONTEXT;
#endif

EXTERN_C __declspec(selectany) DECLSPEC_CACHEALIGN ULONG Microsoft_Windows_FileCrypt_DriverEnableBits[1];
EXTERN_C __declspec(selectany) const ULONGLONG Microsoft_Windows_FileCrypt_DriverKeywords[1] = {0x8000000000000001};
EXTERN_C __declspec(selectany) const UCHAR Microsoft_Windows_FileCrypt_DriverLevels[1] = {4};
EXTERN_C __declspec(selectany) MCGEN_TRACE_CONTEXT Microsoft_Windows_FileCrypt_DRIVER_PROVIDER_GUID_Context = {
    0, 0, 0, 0, 0, 0, 0, 0, 1, Microsoft_Windows_FileCrypt_DriverEnableBits, Microsoft_Windows_FileCrypt_DriverKeywords,
    Microsoft_Windows_FileCrypt_DriverLevels
};

EVENT_DESCRIPTOR LockUserBufferFailure;


/* Filter */

PFLT_GENERIC_WORKITEM g_WorkItem;
PVOID g_FilterObject;
PFLT_FILTER gFilterHandle;

ULONG g_WorkItemQueued; 

/* Package */

ULONG g_PackageRootLength = 0;
PWCHAR g_PackageRoot = NULL;

/* Security */

FAST_MUTEX g_StSecKeyMutex;
ULONG _g_CacheMaxSize;
ULONG _g_CacheCleanupTriggerSize;
ULONG64 g_CacheLifetime;

PCUSTOM_FC_STSEC_SEC_DESC_CACHE_LIST_ENTRY g_StSecSecurityDescriptorCacheListHead = NULL;
PCUSTOM_FC_STSEC_SEC_DESC_CACHE_LIST_ENTRY g_StSecSecurityDescriptorCacheListTail = NULL;

PCUSTOM_FC_STSEC_FOLDER_PROP_CACHE_LIST_ENTRY g_StSecFolderPropertyCacheListHead = NULL;
PCUSTOM_FC_STSEC_FOLDER_PROP_CACHE_LIST_ENTRY g_StSecFolderPropertyCacheListTail = NULL;

RTL_GENERIC_TABLE g_StSecCacheGenericTable;

BCRYPT_ALG_HANDLE g_HmacHashProvider = NULL;
BCRYPT_ALG_HANDLE g_HashProvider = NULL;
PUCHAR g_cbHashObject = NULL;
PUCHAR g_cbHashValue = NULL;
ULONG g_cbHashOutputLength = 0;
ULONG g_cbHashObjectLength = 0;

PUCHAR g_MasterKey = NULL;
BOOLEAN g_MasterKeyPersisted = FALSE;
BOOLEAN g_SkipSealKey = FALSE;

HANDLE g_DebugProfileKey = NULL;

#endif /* __FC_H__ */

///////////////////////////////////////////////////////////////////////////
//
//  Pool Tags
//
///////////////////////////////////////////////////////////////////////////

#define POOL_TAG_FCin 0x6e694346
#define POOL_TAG_FCpp 0x70704346
#define POOL_TAG_FCsb 0x62734346
#define POOL_TAG_FCvx 0x78764346
#define POOL_TAG_FCsx 0x78734346
#define POOL_TAG_FCvp 0x70764346
#define POOL_TAG_FCvi 0x69764346
#define POOL_TAG_FCnv 0x766e4346
#define POOL_TAG_FCCr 0x72434346
#define POOL_TAG_FCnf 0x666e4346
#define POOL_TAG_FCdc 0x63644346
#define POOL_TAG_STsp 0x70537453
#define POOL_TAG_AppX 0x58707041
#define POOL_TAG_StSn 0x6e537453