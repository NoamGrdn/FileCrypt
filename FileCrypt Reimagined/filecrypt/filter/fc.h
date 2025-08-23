/*++

Module Name:

    fc.h - FileCrypt

--*/

#ifndef __FC_H__
#define __FC_H__

#include <fltKernel.h>
#include <ntdef.h>
#include <ntddk.h>
#include <bcrypt.h>

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
typedef unsigned long long undefined8;
typedef unsigned int undefined4;
typedef unsigned char undefined, undefined1;
typedef long long longlong;
typedef unsigned long long ulonglong;
typedef unsigned int uint;
typedef unsigned short ushort;
typedef unsigned short undefined2;

/* Holds AES-CBC encryption settings - 24 bytes in length */
typedef struct _CUSTOM_FC_BCRYPT_DATA
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
    /* Volume device name, initialized by RtlVolumeDeviceToDosName at FCInstanceSetup */
    UNICODE_STRING DeviceName;
    /* Disk sector size used for encryption alignment  (default 0x200/512 bytes) */
    ULONG SectorSize;
    /* Encryption settings for the volume */
    CUSTOM_FC_BCRYPT_DATA BcryptAlgHandle;
    /* Flag indicating if encryption is enabled on a volume */
    BOOLEAN EncryptionEnabled;
    /* Flag indicating whether a volume requires security verification */
    BOOLEAN VerificationNeeded;
} CUSTOM_FC_VOLUME_CONTEXT, *PCUSTOM_FC_VOLUME_CONTEXT;

/* 20 bytes in size */
typedef struct _CUSTOM_FC_BCRYPT_KEY_DATA
{
    /* Symmetric key, generated using a ChamberId */
    BCRYPT_KEY_HANDLE BcryptKeyHandle;
    /* Bugger that holds the key object */
    PUCHAR KeyObject;
    /* Size of the key object buffer*/
    ULONG KeyObjectSize;
} CUSTOM_FC_BCRYPT_KEY_DATA, *PCUSTOM_FC_BCRYPT_KEY_DATA;

/* File-specific settings 40 bytes in size */
typedef struct _CUSTOM_FC_STREAM_CONTEXT
{
    /* File-specific encryption key data */
    CUSTOM_FC_BCRYPT_KEY_DATA KeyData;
    /* Chamber identifier for this file (determines encryption policy) */
    PWCHAR ChamberId;
    /* used for key derivation (1 = Install or 2 = Data) */
    ULONG ChamberType;
} CUSTOM_FC_STREAM_CONTEXT, *PCUSTOM_FC_STREAM_CONTEXT;

/* Information passed from FCPreCreate to FCPostCreate - 13 bytes in size*/
typedef struct _CUSTOM_FC_CREATE_CONTEXT
{
    /* Calculated ChamberId */
    PWCHAR ChamberId;
    /* Calculated Chamber type */
    ULONG ChamberType;
    /* Flag indicating if file access was modified during the pre-operation */
    BOOLEAN IsAccessModified;
} CUSTOM_FC_CREATE_CONTEXT, *PCUSTOM_FC_CREATE_CONTEXT;

/* 16 bytes in size */
typedef struct _CUSTOM_FC_READ_CONTEXT
{
    /* Volume encryption settings */
    PCUSTOM_FC_VOLUME_CONTEXT VolumeContext;
    /* File-specific encryption context */
    PCUSTOM_FC_STREAM_CONTEXT StreamContext;
} CUSTOM_FC_READ_CONTEXT, *PCUSTOM_FC_READ_CONTEXT;

/* Used in FCPostRead as parameters for the FCDecryptWorker function - 16 bytes in size */
typedef struct _CUSTOM_FC_DECRYPT_PARAMS
{
    /* Filter manager callback data */
    PFLT_CALLBACK_DATA CallbackData;
    /* Read completion context */
    PCUSTOM_FC_READ_CONTEXT CompletionContext;
} CUSTOM_FC_DECRYPT_PARAMS, *PCUSTOM_FC_DECRYPT_PARAMS;

/* Information passed from FCPreWrite to FCPostWrite - 25 bytes in size*/
typedef struct _CUSTOM_FC_WRITE_CONTEXT
{
    /* Volume encryption context */
    PCUSTOM_FC_VOLUME_CONTEXT VolumeContext;
    /* File encryption context */
    PCUSTOM_FC_STREAM_CONTEXT StreamContext;
    /* The data that is being written to the disk after being encrypted */
    PUCHAR Ciphertext;
    /* Memory allocation type - where Ciphertext was allocated: (0x01 = NPagedLookasideList, 0x02 = PoolWithTag) */
    UCHAR AllocationType;
} CUSTOM_FC_WRITE_CONTEXT, *PCUSTOM_FC_WRITE_CONTEXT;

/* Cache of derived profile keys. Used to avoid expensive re-derivation - 36 bytes in size*/
typedef struct _CUSTOM_FC_STSEC_CACHE_TABLE_ENTRY
{
    /* Timestamp for cache expiration management */
    ULONG64 LastAccessTime;
    /* Chamber Id - used as the cache key */
    PWCHAR ChamberId;
    /* Derived install key (ChamberType = 1) */
    PUCHAR InstallKey;
    /* Derived data key (ChamberType = 2) */
    PUCHAR DataKey;
    /* Uniform size of both keys */
    ULONG KeySize;
} CUSTOM_FC_STSEC_CACHE_TABLE_ENTRY, *PCUSTOM_FC_STSEC_CACHE_TABLE_ENTRY;

/* Used in FCpObtainSecurityInfoCallout to obtain the
 * ChamberId and Type of the current file/directory that is being opened  - 36 bytes in size*/
typedef struct CUSTOM_FC_CHAMBER_DATA
{
    /* Path to check for chamber assignment */
    PUNICODE_STRING InputPath;
    /* Calculated security descriptor of the path */
    PSECURITY_DESCRIPTOR SecurityDescriptor;
    /* Calculated chamber Id */
    PWCHAR ChamberId;
    /*  FolderId of CUSTOM_FC_STSEC_FOLDER_PROP_CACHE_LIST_ENTRY */
    ULONG ChamberType;
    /* Final operation status */
    NTSTATUS Status;
} CUSTOM_FC_CHAMBER_DATA, *PCUSTOM_FC_CHAMBER_DATA;

/* Cache entry for security descriptor policies loaded from registry - 48 bytes in size */
typedef struct _CUSTOM_FC_STSEC_SEC_DESC_CACHE_LIST_ENTRY
{
    /* Next entry in linked list */
    struct _CUSTOM_FC_STSEC_SEC_DESC_CACHE_LIST_ENTRY* Next;
    /* Previous entry in linked list */
    struct _CUSTOM_FC_STSEC_SEC_DESC_CACHE_LIST_ENTRY* Prev;
    /* egistry path pattern (may contain parameters like <PackageFamilyName>) */
    UNICODE_STRING Path;
    /* SDDL security descriptor string */
    PWCHAR SecurityDescriptor;
    /* Debug-specific security descriptor addition */
    PWCHAR DebugValue;
} CUSTOM_FC_STSEC_SEC_DESC_CACHE_LIST_ENTRY, *PCUSTOM_FC_STSEC_SEC_DESC_CACHE_LIST_ENTRY;

/* Cache entry for folder properties that determine chamber assignments */
typedef struct _CUSTOM_FC_STSEC_FOLDER_PROP_CACHE_LIST_ENTRY
{
    /* Next entry in linked list */
    struct _CUSTOM_FC_STSEC_FOLDER_PROP_CACHE_LIST_ENTRY* Next;
    /* Previous entry in linked list */
    struct _CUSTOM_FC_STSEC_FOLDER_PROP_CACHE_LIST_ENTRY* Prev;
    /* Folder path pattern */
    UNICODE_STRING Path;
    /* Chamber Type */
    ULONG FolderId;
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

NTSTATUS
FCReadDriverParameters(
    PUNICODE_STRING PRegistryPath
);

NTSTATUS
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

EXTERN_C __declspec(selectany) DECLSPEC_CACHEALIGN ULONG Microsoft_Windows_FileCryptEnableBits;
EXTERN_C __declspec(selectany) const ULONGLONG Microsoft_Windows_FileCrypt_DriverKeywords[1] = {0x8000000000000001};
EXTERN_C __declspec(selectany) const UCHAR Microsoft_Windows_FileCrypt_DriverLevels[1] = {4};
EXTERN_C __declspec(selectany) MCGEN_TRACE_CONTEXT Microsoft_Windows_FileCrypt_DRIVER_PROVIDER_GUID_Context = {
    0, 0, 0, 0, 0, 0, 0, 0, 1, &Microsoft_Windows_FileCryptEnableBits, Microsoft_Windows_FileCrypt_DriverKeywords,
    Microsoft_Windows_FileCrypt_DriverLevels
};
EXTERN_C __declspec(selectany) MCGEN_TRACE_CONTEXT* FileCryptGuid_Context = NULL;

EXTERN_C __declspec(selectany) GUID FileCryptGuidData = {
    0xDADEFA21,          // Data1
    0x806E,              // Data2
    0x4241,              // Data3
    {0x8D, 0x0E, 0xE2, '2', 0x93, 0xC7, 0x4E, 0x06}  // Data4
};

EXTERN_C __declspec(selectany) EVENT_DESCRIPTOR PreWriteFailure = {
    0xCB,                  /* Id */
    0x00,                  /* Version */
    0x10,                  /* Channel */
    0x04,                  /* Level */
    0x00,                  /* Opcode */
    0x0000,                /* Task */
    0x8000000000000004     /* Keyword */
};

EXTERN_C __declspec(selectany) EVENT_DESCRIPTOR PostReadFailure = {
    0x00C9,                    // Event ID (201)
    0x00,                      // Version 0
    0x10,                      // Channel 16
    0x04,                      // Information level
    0x00,                      // No opcode
    0x0000,                    // No task
    0x8000000000000004ULL      // Keyword bitmask
};


EXTERN_C __declspec(selectany) LPGUID FileCryptGuid = &FileCryptGuidData;


EVENT_DESCRIPTOR LockUserBufferFailure;
EVENT_DESCRIPTOR GetSystemAddressFailure;
EVENT_DESCRIPTOR GetFsZeroingOffsetFailure;
EVENT_DESCRIPTOR DecryptWorkerFailure;
EVENT_DESCRIPTOR DecryptFailure;
EVENT_DESCRIPTOR EncryptFailure;
EVENT_DESCRIPTOR GetChamberProfileEncryptionKeyFailure;
EVENT_DESCRIPTOR GenerateSymmetricKeyFailure;
EVENT_DESCRIPTOR GetSecurityDescriptorFailure;
EVENT_DESCRIPTOR PostCreateFailure;
EVENT_DESCRIPTOR PreCreateFailure;
EVENT_DESCRIPTOR GetFileNameInformationFailure;
EVENT_DESCRIPTOR ParseFileNameInformationFailure;
EVENT_DESCRIPTOR AllocationFailure;
EVENT_DESCRIPTOR ObtainSdAndChamberIdFailure;
EVENT_DESCRIPTOR ConstructFullPathFailure;
EVENT_DESCRIPTOR GetVolumeContextFailure;
EVENT_DESCRIPTOR PreReadFailure;
EVENT_DESCRIPTOR DriverEntryFailure;

/* Filter */
 
EXTERN_C __declspec(selectany) ULONG gFCFlags = 0;

#define EncryptMediaFlagBit                0x02
#define EncryptAllFlagBit                  0x04
#define FilterEmulatedExternalDriveFlagBit 0x08
#define BypassAccessChecksFlagBit          0x10
EXTERN_C __declspec(selectany) ULONG FcDebugTraceLevel = 0;

EXTERN_C __declspec(selectany) UNICODE_STRING gMusicPath = {0xe, 0x10, L"\\Music\\"};
EXTERN_C __declspec(selectany) UNICODE_STRING gPicturesPath = {0x14, 0x16, L"\\Pictures\\"};
EXTERN_C __declspec(selectany) UNICODE_STRING gVideosPath = {0x10, 0x12, L"\\Videos\\"};

EXTERN_C __declspec(selectany) UNICODE_STRING gRegistryPath = {0, 0, NULL};
EXTERN_C __declspec(selectany) PFLT_GENERIC_WORKITEM g_WorkItem;
EXTERN_C __declspec(selectany) PVOID g_FilterObject;
EXTERN_C __declspec(selectany) PFLT_FILTER gFilterHandle;

EXTERN_C __declspec(selectany) ULONG g_WorkItemQueued;

EXTERN_C __declspec(selectany) NPAGED_LOOKASIDE_LIST gPre2PostIoContextList;
EXTERN_C __declspec(selectany) NPAGED_LOOKASIDE_LIST gPre2PostCreateContextList;
EXTERN_C __declspec(selectany) NPAGED_LOOKASIDE_LIST gShadowBufferList;

/* Package */

EXTERN_C __declspec(selectany) ULONG g_PackageRootLength = 0;
EXTERN_C __declspec(selectany) PWCHAR g_PackageRoot = NULL;

/* Security */

EXTERN_C __declspec(selectany) FAST_MUTEX g_StSecKeyMutex;
EXTERN_C __declspec(selectany) ULONG _g_CacheMaxSize;
EXTERN_C __declspec(selectany) ULONG _g_CacheCleanupTriggerSize;
EXTERN_C __declspec(selectany) ULONG64 g_CacheLifetime;

EXTERN_C __declspec(selectany) PCUSTOM_FC_STSEC_SEC_DESC_CACHE_LIST_ENTRY g_StSecSecurityDescriptorCacheListHead = NULL;
EXTERN_C __declspec(selectany) PCUSTOM_FC_STSEC_SEC_DESC_CACHE_LIST_ENTRY g_StSecSecurityDescriptorCacheListTail = NULL;

EXTERN_C __declspec(selectany) PCUSTOM_FC_STSEC_FOLDER_PROP_CACHE_LIST_ENTRY g_StSecFolderPropertyCacheListHead = NULL;
EXTERN_C __declspec(selectany) PCUSTOM_FC_STSEC_FOLDER_PROP_CACHE_LIST_ENTRY g_StSecFolderPropertyCacheListTail = NULL;

EXTERN_C __declspec(selectany) RTL_GENERIC_TABLE g_StSecCacheGenericTable;

EXTERN_C __declspec(selectany) BCRYPT_ALG_HANDLE g_HmacHashProvider = NULL;
EXTERN_C __declspec(selectany) BCRYPT_ALG_HANDLE g_HashProvider = NULL;
EXTERN_C __declspec(selectany) PUCHAR g_cbHashObject = NULL;
EXTERN_C __declspec(selectany) PUCHAR g_cbHashValue = NULL;
EXTERN_C __declspec(selectany) ULONG g_cbHashOutputLength = 0;
EXTERN_C __declspec(selectany) ULONG g_cbHashObjectLength = 0;

EXTERN_C __declspec(selectany) PUCHAR g_MasterKey = NULL;
EXTERN_C __declspec(selectany) BOOLEAN g_MasterKeyPersisted = FALSE;
EXTERN_C __declspec(selectany) BOOLEAN g_SkipSealKey = FALSE;

EXTERN_C __declspec(selectany) HANDLE g_DebugProfileKey = NULL;

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


///////////////////////////////////////////////////////////////////////////
//
// other stuff
//
///////////////////////////////////////////////////////////////////////////

#define bool unsigned char
#define true 1
#define false 0
#define byte UCHAR