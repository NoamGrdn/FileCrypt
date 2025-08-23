# Documentation

## Table of Contents

### 1. Metadata
- Ghidra
- Driver

### 2. Imports
- **fltMgr.sys** - Filesystem Filter Manager
- **KSecdD.sys** - Kernel Security Support Provider Driver
- **ntoskrnl.exe** - NT Kernel & System
- **tbs.sys** - Kernel TPM API

### 3. Exports
- **entry** - DriverEntry

### 4. Select Strings of Interest

### 5. Functions
- **DriverEntry**
- **entry**
- **FC** - FileCrypt functions
- **Kappx** - Windows Apps packages helper functions
- **m** - C memory manipulation functions
- **Mc** - Logging functions
- **Rtl** - String manipulation functions
- **StSec** - Windows security
- **write_** - C style Character manipulation functions

### 6. Registered Operations

### 7. Flags

### 8. Custom Data Types
- **CUSTOM_FC_BCRYPT_DATA**
- **CUSTOM_FC_VOLUME_CONTEXT**
- **CUSTOM_FC_BCRYPT_KEY_DATA**
- **CUSTOM_FC_STREAM_CONTEXT**
- **CUSTOM_FC_CREATE_CONTEXT**
- **CUSTOM_FC_DECRYPT_PARAMS**
- **CUSTOM_FC_READ_CONTEXT**
- **CUSTOM_FC_WRITE_CONTEXT**
- **CUSTOM_FC_STSEC_CACHE_TABLE_ENTRY**
- **CUSTOM_FC_CHAMBER_DATA**
- **CUSTOM_FC_STSEC_SEC_DESC_CACHE_LIST_ENTRY**
- **CUSTOM_FC_STSEC_FOLDER_PROP_CACHE_LIST_ENTRY**

### 9. Pool Tags

### 10. Registries
- `\Registry\Machine\System\ControlSet001\Services\FileCrypt\`
- `\Registry\Machine\Software\Microsoft\SecurityManager\StorageCardProfiles\Chambers\`
- `\Registry\Machine\Software\Microsoft\StorageSec\Encrypt\`
- `\Registry\Machine\System\ControlSet001\Control\StSec\SecurityDescriptors\`
- `\Registry\Machine\System\ControlSet001\Control\StSec\\FolderProperties\`
- `\Registry\Machine\Software\Microsoft\Windows\CurrentVersion\Appx\`
- `\Registry\Machine\Software\Microsoft\Windows\CurrentVersion\Appx\PackageSidRef\`

---

# 1. Metadata

### Ghidra
All decompilation and disassembly was done in **Ghidra 10.2 PUBLIC 2022-Nov-01 1334 EDT**

### Driver
- **File name:** filecrypt.sys
- **File description:** Windows sandboxing and encryption filter
- **File version:** 10.0.26100.1150 (WinBuild.160101.0800)
- **Size:** 94208 bytes
- **Driver digital signatures**
  - Serial number: `3300000460cf42a912315f6fb3000000000460`
  - Tag: `BCCB808BCB9EF42957F660EB26709AEC85712F875225AB7AF77C79170F05A1FD`
  - Thumbprint: `bc cb 80 8b cb 9e f4 29 57 f6 60 eb 26 70 9a ec 85 71 2f 87 52 25 ab 7a f7 7c 79 17 0f 05 a1 fd`
- **File SHA256 hash** ([https://emn178.github.io/online-tools/sha256_checksum.html](https://emn178.github.io/online-tools/sha256_checksum.html)):
  `48f8408987eccdcc97b3d32c14c17fcc9e4e13ffb8be5e6c481b931be7ad5b1c`
- **Assembly information**
  - Processor: x86
  - Endian: Little
  - Address Size: 64
  - Minimum Address: 1c0000000
  - Maximum Address: 1c0016fff
  - Compiler: visualstudio

# 2. Imports

### fltMgr.sys - Filesystem Filter Manager
- FltAllocateContext
- FltAllocateGenericWorkItem
- FltCancelFileOpen
- FltClose
- FltCompletePendedPostOperation
- FltCreateFileEx
- FltFreeGenericWorkItem
- FltGetDestinationFileNameInformation
- FltGetDiskDeviceObject
- FltGetFileNameInformation
- FltGetFsZeroingOffset
- FltGetStreamContext
- FltGetVolumeContext
- FltGetVolumeName
- FltGetVolumeProperties
- FltIsDirectory
- FltLockUserBuffer
- FltParseFileNameInformation
- FltQueryVolumeInformation
- FltQueueGenericWorkItem
- FltReadFile
- FltRegisterFilter
- FltReleaseContext
- FltReleaseFileNameInformation
- FltSetCallbackDataDirty
- FltSetFsZeroingOffsetRequired
- FltSetStreamContext
- FltSetVolumeContext
- FltStartFiltering
- FltUnregisterFilter

### KSecdD.sys - Kernel Security Support Provider Driver
- BCryptCloseAlgorithmProvider
- BCryptCreateHash
- BCryptDecrypt
- BCryptDestroyHash
- BCryptDestroyKey
- BCryptDuplicateHash
- BCryptEncrypt
- BCryptFinishHash
- BCryptGenerateSymmetricKey
- BCryptGenRandom
- BCryptGetProperty
- BCryptHashData
- BCryptOpenAlgorithmProvider
- BCryptSetProperty

### ntoskrnl.exe - NT Kernel & System
- __C_specific_handler
- _wcsnicmp
- EtwRegister
- EtwUnregister
- EtwWriteTransfer
- ExAcquireFastMutex
- ExAllocateFromNPagedLookasideList
- ExAllocatePool2
- ExDeleteNPagedLookasideList
- ExFreePoolWithTag
- ExFreeToNPagedLookasideList
- ExInitializeNPagedLookasideList
- ExReleaseFastMutex
- FsRtlDissectName
- FsRtlIsMobileOS
- IoAllocateMdl
- IoCreateFileEx
- IoFreeMdl
- IoGetAttachedDeviceReference
- IoGetFileObjectGenericMapping
- IoGetLowerDeviceObject
- KeExpandKernelStackAndCalloutEx
- KeGetCurrentIrql
- KeInitializeEvent
- KeQueryTimeIncrement
- MmBuildMdlForNonPagedPool
- MmGetSystemRoutineAddress
- MmMapLockedPagesSpecifyCache
- MmMdlPageContentsState
- ObfDereferenceObject
- PsGetHostSilo
- RtlAnsiCharToUnicodeChar
- RtlAppendUnicodeStringToString
- RtlAppendUnicodeToString
- RtlCompareUnicodeString
- RtlCopyUnicodeString
- RtlCreateUnicodeString
- RtlDeleteElementGenericTable
- RtlDowncaseUnicodeString
- RtlEnumerateGenericTableWithoutSplaying
- RtlFreeUnicodeString
- RtlGetElementGenericTable
- RtlGetPersistedStateLocation
- RtlGetVersion
- RtlInitializeGenericTable
- RtlInitializeSid
- RtlInitUnicodeString
- RtlInsertElementGenericTable
- RtlLookupElementGenericTable
- RtlNumberGenericTableElements
- RtlPrefixUnicodeString
- RtlQueryRegistryValues
- RtlSubAuthoritySid
- RtlUpcaseUnicodeString
- RtlVolumeDeviceToDosName
- SeAccessCheck
- SeConvertSecurityDescriptorToStringSecurityDescriptor
- SeConvertSidToStringSid
- SeConvertStringSecurityDescriptorToSecurityDescriptor
- ZwClose
- ZwEnumerateKey
- ZwFlushKey
- ZwOpenKey
- ZwQueryKey
- ZwQuerySecurityObject
- ZwQueryValueKey
- ZwSetValueKey

### tbs.sys - Kernel TPM API
- Tbsi_Context_Create
- Tbsip_Context_Close
- Tbsip_Submit_Command

# 3. Exports
- **entry** - DriverEntry

# 4. Select Strings of Interest
- `u"\\??\\%ws\\"`
- `u"\\Music\\"`
- `u"\\Pictures\\"`
- `u"\\REGISTRY\\MACHINE\\Software\\Microsoft\\SecurityManager\\StorageCardProfiles\\Chambers"`
- `u"\\REGISTRY\\MACHINE\\Software\\Microsoft\\StorageSec\\Encrypt"`
- `u"\\Registry\\Machine\\Software\\Microsoft\\Windows\\CurrentVersion\\Appx"`
- `u"\\Registry\\Machine\\Software\\Microsoft\\Windows\\CurrentVersion\\Appx\\PackageSidRef"`
- `u"\\Registry\\Machine\\System\\ControlSet001\\Control\\StSec\\FolderProperties"`
- `u"\\Registry\\Machine\\System\\ControlSet001\\Control\\StSec\\SecurityDescriptors"`
- `u"\\System Volume Information\\WPAppSettings.dat"`
- `u"\\Videos\\"`
- `u"{0b7992da-c5e6-41e3-b24f-55419b997a15}"`
- `u"<PackageFamilyName>"`
- `u"<PackageFullName>"`
- `u"<PackageFullNameRedirected>"`
- `u"<ProductId>"`
- `u"<User>"`
- `u"AES"`
- `u"AppxPackageSidRef"`
- `u"BlockLength"`
- `u"BypassAccessChecks"`
- `u"CacheCleanupTriggerSize"`
- `u"CacheLifetime"`
- `u"CacheMaxSize"`
- `u"ChainingMode"`
- `u"ChainingModeCBC"`
- `u"ChamberId"`
- `u"D:AI(A;OICI;0x1200a9;;;BU)(A;ID;FA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;CIIOID;FA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;ID;FA;;;SY)(A;OICIIOID;FA;;;SY)(A;OICIID;0x1200a9;;;BA)(A;OICIID;0x1200a9;;;LS)(A;OICIID;0x1200a9;;;NS)"`
- `u"Data"`
- `u"Debug"`
- `u"DebugTraceLevel"`
- `u"EncryptAll"`
- `u"EncryptMedia"`
- `u"FilterEmulatedExternalDrive"`
- `u"FolderId"`
- `u"HashDigestLength"`
- `u"Install"`
- `u"MK"`
- `u"MUI"`
- `u"MusicChamber"`
- `u"NULL"`
- `u"ObjectLength"`
- `u"PackageRoot"`
- `u"PackageSid"`
- `u"PicturesChamber"`
- `u"RtlQueryRegistryValuesEx"`
- `u"SDCARD"`
- `u"SecurityDescriptor"`
- `u"SHA256"`
- `u"SkipSealKey"`
- `u"StSec"`
- `u"TargetNtPath"`
- `u"VideosChamber"`

# 5. Functions

### DriverEntry

### entry

### FC - FileCrypt functions
- FCCleanupStreamContext
- FCCleanupVolumeContext
- FCDecryptWorker
- FCFilterUnload
- FCFreeShadowBuffer
- FCInstanceQueryTeardown
- FCInstanceSetup
- FCpAccessCheck
- FCpConstructFullPath - Called from FCpPreRename (see below)
- FCpEncDecrypt
- FCpEncEncrypt
- FCpEncStreamCleanup
- FCpEncStreamStart
- FCpEncVolumeCleanup
- FCpEncVolumeStart
- FCpEqualChamberIds
- FCpFreeChamberId
- FCpObtainSecurityInfoCallout
- FCpObtainSecurityInfoWorker - Called only from FCpPreRename (see below)
- FCPostCreate
- FCPostRead
- FCPostWrite
- FCpPreRename - Unregistered callback
- FCPreCreate
- FCPreRead
- FCPreSetInformation - No calls to function
- FCpRetrieveAppPairingId
- FCPreWrite
- FCReadDriverParameters

### Kappx - Windows Apps packages helper functions
- KappxGetPackageRootPathForPackageFullName
- KappxGetPackageSidFromPackageFamilyNameInRegistry
- KappxGetSecurityDescriptorStringForPackageFullName

### m - C memory manipulation functions
- mbtowc - Fully typed
- memcpy - Has comments, no need to go further
- memset - Same as above

### Mc - Logging functions
- McGenControlCallbackV2
- McGenEventRegister_EtwRegister
- McGenEventUnregister_EtwUnregister
- McGenEventWrite_EtwWriteTransfer
- McTemplateK0d_EtwWriteTransfer
- McTemplateK0pd_EtwWriteTransfer
- McTemplateK0zd_EtwWriteTransfer
- McTemplateK0zzd_EtwWriteTransfer

### Rtl - String manipulation functions
- RtlStringCbCatNW
- RtlStringCbCatW
- RtlStringCbCopyNW
- RtlStringCbCopyW
- RtlStringCbLengthW
- RtlStringCbPrintfW
- RtlStringCchCopyW
- RtlStringCopyWorkerW
- RtlStringLengthWorkerW

### StSec - Windows security
- StSecDeinitialize
- StSecFree
- StSecGetSecurityDescriptor
- StSecInitialize
- StSecpAddChamberProfileKey
- StSecpCacheCleanupWorkItem
- StSecpCacheDeinitialize
- StSecpCacheGenericTableAllocRoutine
- StSecpCacheGenericTableCompareRoutine
- StSecpCacheGenericTableFreeRoutine
- StSecpCacheInitialize
- StSecpCheckConditionalPolicy
- StSecpDeriveChamberProfileKey
- StSecpFindFolderPropertyPolicyElement
- StSecpFindSecurityDescriptorPolicyElement
- StSecpFreeNonPaged
- StSecpGetAppSid
- StSecpGetChamberProfileKey
- StSecpGetFolderPropertyPolicy
- StSecpGetMasterKey
- StSecpGetParameterValue
- StSecpGetSecurityDescriptorPolicy
- StSecpGetSidFromPackageFamilyName
- StSecpGetSidFromPackageFullName
- StSecpGetSidFromProductId
- StSecpGetSidFromUserName
- StSecpGetStorageFolderStringSecurityDescriptor
- StSecpInitializePolicyCache
- StSecpOpenMasterKeyHandle
- StSecpPackageFamilyNameFromFullName
- StSecpReadSealedKeyBlob
- StSecpSealKey
- StSecpSealKeyTestHookSet
- StSecpUnsealKey
- StSecpWriteSealedKeyBlob

### write_ - C style Character manipulation functions
- write_char
- write_multi_char
- write_string

# 6. Registered Operations

### On a non-mobile Windows OS:
1. IRP_MJ_CREATE - No flags
2. IRP_MJ_OPERATION_END - No flags

### On a mobile Windows OS:
1. IRP_MJ_CREATE - No flags
2. IRP_MJ_READ - No flags
3. IRP_MJ_WRITE - No flags
4. IRP_MJ_OPERATION_END - No flags

# 7. Flags

The driver has flags that can be configured by editing registry values.

The driver's registry path is:
`Computer\HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\FileCrypt`

The driver searches for the following registry keys:
- **DebugTraceLevel**
- **EncryptMedia**
- **EncryptAll**
- **BypassAccessChecks**
- **FilterEmulatedExternalDrive**

The values of these keys modify two global variables:
- `FcDebugTraceLevel`
- `gFCFlags`

**DebugTraceLevel**'s value is assigned to the `FcDebugTraceLevel` global variable.

The rest of the values affect the `gFCFlags` global variable:
- **EncryptMedia** sets the first bit (`gFCFlags | 2`)
- **EncryptAll** sets the second bit (`gFCFlags | 4`)
- **FilterEmulatedExternalDrive** sets the third bit (`gFCFlags | 8`)
- **BypassAccessChecks** sets the fourth bit (`gFCFlags | 0x10`)

For more information about these flags, refer to the Registries chapter.

# 8. Custom Data Types

### CUSTOM_FC_BCRYPT_DATA

**Functions Used In:**
- FCpEncVolumeStart

```c
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
```

Initializes an instance of the struct by opening an AES algorithm provider, querying block and object lengths, and setting CBC chaining mode for volume-level encryption.

`FCpEncVolumeCleanup`

Cleans up the BCrypt algorithm handle when volume is detached by calling BCryptCloseAlgorithmProvider and setting the handle to NULL.

`FCpEncEncrypt`

Uses the previously initialized encryption settings to encrypt plaintext data in sector-sized chunks, validating block length and using the sector size for proper alignment.

`FCpEncDecrypt`

Performs decryption operations using the structure's BCrypt handle and sector size, processing data in chunks while handling security zeroing requirements.

`FCInstanceSetup`

Embeds this structure in the volume context during filter attachment, calling FCpEncVolumeStart to initialize encryption capabilities for the entire volume.

CUSTOM_FC_VOLUME_CONTEXT
```c
/* Volume-wide settings - 56 bytes in size */
typedef struct _CUSTOM_FC_VOLUME_CONTEXT
{
    /* Volume device name, initialized by RtlVolumeDeviceToDosName at FCInstanceSetup */
    UNICODE_STRING DeviceName;
    /* Disk sector size used for encryption alignment (default 0x200/512 bytes) */
    ULONG SectorSize;
    /* Encryption settings for the volume */
    CUSTOM_FC_BCRYPT_DATA BcryptAlgHandle;
    /* Flag indicating if encryption is enabled on a volume */
    BOOLEAN EncryptionEnabled;
    /* Flag indicating whether a volume requires security verification */
    BOOLEAN VerificationNeeded;
} CUSTOM_FC_VOLUME_CONTEXT, *PCUSTOM_FC_VOLUME_CONTEXT;
```

Functions Used In:

`FCInstanceSetup`

Creates and initializes the volume context during filter attachment, setting up device name, sector size, BCrypt encryption settings, and verification requirements based on OS type and volume properties.

`FCCleanupVolumeContext`

A cleanup function that frees the device name buffer and calls FCpEncVolumeCleanup to destroy encryption resources when the volume context is released.

`FCPreRead`

Retrieves the volume context to access encryption settings and stores it in the completion context for use by FCPostRead during decryption operations.

`FCPreWrite`

Gets the volume context to access sector size for encryption buffer alignment calculations and BCrypt settings for encryption operations during write processing.

`FCDecryptWorker`

Uses the volume context from the completion context to access SectorSize and BcryptAlgHandle to perform the actual decryption work in both synchronous and asynchronous scenarios.

```c
CUSTOM_FC_BCRYPT_KEY_DATA
typedef struct _CUSTOM_FC_BCRYPT_KEY_DATA
{
    /* Symmetric key, generated using a ChamberId */
    BCRYPT_KEY_HANDLE BcryptKeyHandle;
    /* Buffer that holds the key object */
    PUCHAR KeyObject;
    /* Size of the key object buffer*/
    ULONG KeyObjectSize;
} CUSTOM_FC_BCRYPT_KEY_DATA, *PCUSTOM_FC_BCRYPT_KEY_DATA;
```

Functions Used In:

`FCpEncStreamStart`

Creates the symmetric encryption key by allocating a key object buffer, deriving or retrieving the chamber profile key, and calling BCryptGenerateSymmetricKey to populate the key handle.

`FCpEncStreamCleanup`

Securely destroys the encryption key by calling BCryptDestroyKey, zeroing the key object buffer byte by byte, and freeing the allocated memory.

`FCpEncEncrypt`

Uses the BCrypt key handle from this structure to encrypt file data in sector-aligned chunks during write operations.

`FCpEncDecrypt`

Uses the BCrypt key handle to decrypt file data in sector-aligned chunks during read operations, handling security zeroing as needed.

`FCPostCreate`

Initializes this structure by calling FCpEncStreamStart with chamber information, embedding the resulting key data in the stream context for subsequent file operations.

```c
CUSTOM_FC_STREAM_CONTEXT
/* File-specific settings 40 bytes in size */
typedef struct _CUSTOM_FC_STREAM_CONTEXT
{
    /* File-specific encryption key data */
    CUSTOM_FC_BCRYPT_KEY_DATA KeyData;
    /* Chamber identifier for this file (determines encryption policy) */
    PWCHAR ChamberId;
    /* Used for key derivation (1 = Install or 2 = Data) */
    ULONG ChamberType;
} CUSTOM_FC_STREAM_CONTEXT, *PCUSTOM_FC_STREAM_CONTEXT;
```

Functions Used In:

`FCPostCreate`

Creates the stream context by allocating it, initializing the KeyData field, setting the chamber ID and type from the completion context, and calling FCpEncStreamStart to establish file-specific encryption.

`FCCleanupStreamContext`

A cleanup function that frees the chamber Id using FCpFreeChamberId and securely destroys encryption key data via FCpEncStreamCleanup.

`FCPreRead`

Retrieves the stream context to determine if the file is encrypted; if no context exists, the file is not encrypted, and no callback is needed.

`FCPreWrite`

Gets the stream context to access the file's encryption key data for encrypting write operations, storing the context reference for post-operation cleanup.

```c
CUSTOM_FC_CREATE_CONTEXT
c/* Information passed from FCPreCreate to FCPostCreate - 13 bytes in size*/
typedef struct _CUSTOM_FC_CREATE_CONTEXT
{
    /* Calculated ChamberId */
    PWCHAR ChamberId;
    /* Calculated Chamber type */
    ULONG ChamberType;
    /* Flag indicating if file access was modified during the pre-operation */
    BOOLEAN IsAccessModified;
} CUSTOM_FC_CREATE_CONTEXT, *PCUSTOM_FC_CREATE_CONTEXT;
```

Functions Used In:

`FCPreCreate`

Creates the completion context by analyzing the file path to determine the chamber Id through security policy lookups, resolving parameterized chambers to actual values, and setting access modification flags based on security check results.

`FCPostCreate`

Consumes the completion context to extract chamber information, transfers ownership of the chamber ID to stream context, and uses the chamber type for encryption setup, handling error cases by modifying access status appropriately.

```c
CUSTOM_FC_DECRYPT_PARAMS
/* Used in FCPostRead as parameters for the FCDecryptWorker function - 16 bytes in size */
typedef struct _CUSTOM_FC_DECRYPT_PARAMS
{
    /* Filter manager callback data */
    PFLT_CALLBACK_DATA CallbackData;
    /* Read completion context */
    PCUSTOM_FC_READ_CONTEXT CompletionContext;
} CUSTOM_FC_DECRYPT_PARAMS, *PCUSTOM_FC_DECRYPT_PARAMS;
```

Functions Used In:

`FCPostRead`

Creates a parameters structure when immediate decryption is not possible due to high IRQL or large read size, packaging callback data and completion context for asynchronous work item processing.

`FCDecryptWorker`

Receives parameters for both synchronous and asynchronous decryption operations, extracts I/O information and context data, performs buffer mapping and decryption operations, and handles completion and cleanup responsibilities.

```c
CUSTOM_FC_READ_CONTEXT
typedef struct _CUSTOM_FC_READ_CONTEXT
{
    /* Volume encryption settings */
    PCUSTOM_FC_VOLUME_CONTEXT VolumeContext;
    /* File-specific encryption context */
    PCUSTOM_FC_STREAM_CONTEXT StreamContext;
} CUSTOM_FC_READ_CONTEXT, *PCUSTOM_FC_READ_CONTEXT;
```

Functions Used In:

`FCPreRead`

Sets up the completion context by verifying file encryption status, getting volume and stream contexts, configuring security zeroing, and preparing for either immediate or asynchronous decryption based on system conditions.

`FCPostRead`

Consumes completion context to determine decryption strategy, either performing immediate decryption by calling FCDecryptWorker directly or queuing asynchronous work item based on IRQL and data size.

`FCDecryptWorker`

Receives the completion context containing volume and stream contexts, extracts encryption parameters and key data, performs actual decryption operations, and releases all context references upon completion.

```c
CUSTOM_FC_WRITE_CONTEXT
/* Information passed from FCPreWrite to FCPostWrite - 25 bytes in size*/
typedef struct _CUSTOM_FC_WRITE_CONTEXT
{
    /* Volume encryption context */
    PCUSTOM_FC_VOLUME_CONTEXT VolumeContext;
    /* File encryption context */
    PCUSTOM_FC_STREAM_CONTEXT StreamContext;
    /* The data that is being written to the disk after being encrypted */
    PUCHAR Ciphertext;
    /* Memory allocation type - where Ciphertext was allocated: 
       (0x01 = NPagedLookasideList, 0x02 = PoolWithTag) */
    UCHAR AllocationType;
} CUSTOM_FC_WRITE_CONTEXT, *PCUSTOM_FC_WRITE_CONTEXT;
```

Functions Used In:

`FCPreWrite`

Creates a completion context and manages encryption by allocating a ciphertext buffer (from a lookaside list or pool), creating an MDL for encrypted data, calling FCpEncEncrypt to encrypt the write data, and replacing the original buffer with the encrypted version.

`FCPostWrite`

Cleanup function that releases volume and stream context references, frees the ciphertext buffer back to the appropriate memory pool based on allocation type, and frees the completion context lookaside list entry.

```c
CUSTOM_FC_STSEC_CACHE_TABLE_ENTRY
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
```

Functions Used In:

`StSecpAddChamberProfileKey`

Adds newly derived encryption keys to the cache by creating a cache entry with the current timestamp, copying the chamber Id and key data, inserting into the generic table (g_StSecCacheGenericTable) with thread safety, and managing cache size limits.

`StSecpGetChamberProfileKey`

Retrieves cached encryption keys by a chamber ID lookup, updates access timestamp for LRU management, validates key size, and copies the appropriate key (install or data) based on the chamber type.

`StSecpCacheCleanupWorkItem`

Background cleanup worker that removes expired cache entries by enumerating the cache, checking timestamps against the lifetime threshold, securely zeroing, and freeing expired key data.

`StSecpDeriveChamberProfileKey`

Creates new cache entries when requested keys are not found by deriving both install and data keys through HMAC operations and calling StSecpAddChamberProfileKey to populate the cache.

```c
CUSTOM_FC_CHAMBER_DATA
/* Used in FCpObtainSecurityInfoCallout to obtain the
 * ChamberId and Type of the current file/directory that is being opened - 
 * 36 bytes in size*/
typedef struct CUSTOM_FC_CHAMBER_DATA
{
    /* Path to check for chamber assignment */
    PUNICODE_STRING InputPath;
    /* Calculated security descriptor of the path */
    PSECURITY_DESCRIPTOR SecurityDescriptor;
    /* Calculated chamber Id */
    PWCHAR ChamberId;
    /* FolderId of CUSTOM_FC_STSEC_FOLDER_PROP_CACHE_LIST_ENTRY */
    ULONG ChamberType;
    /* Final operation status */
    NTSTATUS Status;
} CUSTOM_FC_CHAMBER_DATA, *PCUSTOM_FC_CHAMBER_DATA;
```

Functions Used In:

`FCpObtainSecurityInfoCallout`

Processes the path to determine the chamber and security info

`FCPreCreate`

Uses to determine encryption policy for file operations

```c
CUSTOM_FC_STSEC_SEC_DESC_CACHE_LIST_ENTRY
/* Cache entry for security descriptor policies loaded from registry - 48 bytes in size */
typedef struct _CUSTOM_FC_STSEC_SEC_DESC_CACHE_LIST_ENTRY
{
    /* Next entry in linked list */
    struct _CUSTOM_FC_STSEC_SEC_DESC_CACHE_LIST_ENTRY* Next;
    /* Previous entry in linked list */
    struct _CUSTOM_FC_STSEC_SEC_DESC_CACHE_LIST_ENTRY* Prev;
    /* Registry path pattern (may contain parameters like <PackageFamilyName>) */
    UNICODE_STRING Path;
    /* SDDL security descriptor string */
    PWCHAR SecurityDescriptor;
    /* Debug-specific security descriptor addition */
    PWCHAR DebugValue;
} CUSTOM_FC_STSEC_SEC_DESC_CACHE_LIST_ENTRY,
*PCUSTOM_FC_STSEC_SEC_DESC_CACHE_LIST_ENTRY;
```

Functions Used In:

`StSecpInitializePolicyCache`

Initializes the linked list structure (g_StSecSecurityDescriptorCacheList[Head/Tail])

`StSecpGetSecurityDescriptorPolicy`

Populates cache from registry

`StSecpFindSecurityDescriptorPolicyElement`

Searches the cache for path matches

`StSecDeinitialize`

Cleanup function that traverses and frees all entries

```c
CUSTOM_FC_STSEC_FOLDER_PROP_CACHE_LIST_ENTRY
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
} CUSTOM_FC_STSEC_FOLDER_PROP_CACHE_LIST_ENTRY,
*PCUSTOM_FC_STSEC_FOLDER_PROP_CACHE_LIST_ENTRY;
```

Functions Used In:

`StSecpInitializePolicyCache`

Initializes the linked list structure (g_StSecFolderPropertyCacheList[Head/Tail])

`StSecpGetFolderPropertyPolicy`

Populates cache from registry

`StSecpFindFolderPropertyPolicyElement`

Searches the cache for matching folder paths

`StSecDeinitialize`

Cleanup function that frees all entries

# 9. Pool Tags

`0x6e694346` - "FCin"
- DriverEntry
- FCFilterUnload

`0x70704346` - "FCpp"
- DriverEntry

`0x62734346` - "FCsb" (Shadow Buffer)
- DriverEntry
- FCPreWrite
- FcFreeShadowBuffer

`0x78764346` - "FCvx" (Volume Context)
- ContextRegistration at `1c0006018`

`0x78734346` - "FCsx" (Stream Context)
- ContextRegistration at `1c0006050`

`0x70764346` - "FCvp"
- FCInstanceSetup

`0x69764346` - "FCvi"
- FCInstanceSetup

`0x766e4346` - "FCnv"
- FCInstanceSetup
- FCCleanupVolumeContext
- FCpRetrieveAppPairingId

`0x72434346` - "FCCr"
- FCpEncStreamCleanup
- FCpEncStreamStart

`0x666e4346` - "FCnf"
- FCPreCreate
- FCpConstructFullPath

`0x63644346` - "FCdc" (Decrypt)
- FCPostRead
- FCDecryptWorker

`0x70537453` - "StSp"
- StSecpGetFolderPropertyPolicy
- StSecpGetSecurityDescriptorPolicy
- StSecpReadSealedKeyBlob
- StSecpPackageFamilyNameFromFullName
- StSecpGetStorageFolderStringSecurityDescriptor
- StSecpGetMasterKey
- StSecpReadSealedKeyBlob
- FCPreCreate
- FCpPreRename
- FCpObtainSecurityInfoWorker
- FCpFreeChamberId
- StSecFree
- StSecGetSecurityDescriptor
- StSecpAddChamberProfileKey
- StSecpCacheGenericTableAllocRoutine
- StSecpGetAppSid
- StSecpReadSealedKeyBlob

`0x58707041` - "AppX"
- KappxGetPackageSidFromPackageFamilyNameInRegistry
- KappxGetSecurityDescriptorStringForPackageFullName
- KappxGetPackageRootPathForPackageFullName

`0x6e537453` - "StSn"
- StSecpDeriveChamberProfileKey
- StSecpFreeNonPaged
- StSecpAddChamberProfileKey
- StSecpGetMasterKey
- StSecpGetSidFromUserName


# 10. Registries

#### `\Registry\Machine\System\ControlSet001\Services\FileCrypt\`

<u>Used in:</u> Injected into the driver `DriverEntry` and passed to `FCReadDriverParameters`.
Stored at the `gRegistryPath` global variable.

Keys and Values:

- <b>"DebugTraceLevel":</b> Saved in global variable `FcDebugTraceLevel`. This is unused throughout the driver.
- <b>"EncryptMedia":</b> Used to decide whether to encrypt files in the media chambers (Music, Video, and Pictures) or not.
- <b>"EncryptAll"</b>: Used to decide whether to encrypt files in the general chamber (`0b7992da-c5e6-41e3-b24f-55419b997a15`).
- <b>"BypassAccessChecks":</b> Used to decide whether to do an access check when creating a file. The access check is performed with the SeAccessCheck function, and if it fails, the driver attempts to change the create disposition. If this registry is positive, any attached volume will be marked as unsecured by removing the `FILE_DEVICE_SECURE_OPEN` characteristic from it.
- <b>"FilterEmulatedExternalDrive"</b>: When the driver is attempting to attach to a volume, it is used to decide if the driver is allowed to attach to SD cards. If the registry is positive, the driver will also set the volume it is attached to be 'removable media'.

#### `\Registry\Machine\Software\Microsoft\SecurityManager\StorageCardProfiles\Chambers\`

<u>Used in:</u> `StSecpCheckConditionalPolicy`

Keys and Values:

This path contains keys that are Microsoft package family names or SIDs. The value says whether this package is to be treated as 'debug'.
The registry handle is set to the global variable `g_DebugProfileKey`.

#### `\Registry\Machine\Software\Microsoft\StorageSec\Encrypt\`

<u>uUsed at:</u> `StSecpWriteSealedKeyBlob`, `StSecpOpenMasterKeyHandle`, `StSecpSealKeyTestHookSet`

Keys and Values:

- <b>"MK":</b> This key is used in `StSecpWriteSealedKeyBlob` after obtaining the registry handle from `StSecpOpenMasterKeyHandle`. It contains the sealed master key. The master key is also saved in the g_MasterKey.
- <b>"SkipSealKey":</b> a boolean value that indicates whether the driver needs to seal and unseal using the TPM (Trusted Platform Module) or whether it can just put it right in the "MK" registry without doing so.

#### `\Registry\Machine\System\ControlSet001\Control\StSec\SecurityDescriptors\`

<u>Used in:</u> `StSecpInitializePolicyCache`, `StSecpGetSecurityDescriptorPolicy`.

Keys and Values:

The keys under this registry path are the names of packages or parameter names. `StSecpGetSecurityDescriptorPolicy` enumerates over all subkeys of this path recursively (2 recursive calls). It populates the global `g_StSecSecurityDescriptorCacheList[Head/Tail]` with the registry's data to be accessed later by StSecpGetStorageFolderStringSecurityDescriptor.

```c
\Registry\Machine\System\ControlSet001\Control\StSec\SecurityDescriptors\
├── Documents\\
│   ├── <PackageFamilyName>\\
│   │   ├── PrivateData\\
│   │   │   ├── SecurityDescriptor = "D:(A;OICI;GA;;;S-1-5-21-..."
│   │   │   └── Debug = 0
│   │   └── PublicData\\
│   │       └── SecurityDescriptor = "D:(A;OICI;GR;;;WD)..."
│   └── Public\\
│       └── SecurityDescriptor = "D:(A;OICI;GR;;;WD)..."
├── Pictures\\
│   └── SecurityDescriptor = "D:(A;OICI;GA;;;S-1-5-21-..."
├── <User>\\
│   └── PersonalFiles\\
│       └── SecurityDescriptor = "D:(A;OICI;GA;;;S-1-5-21-..."
└── System\\
    └── SecurityDescriptor = "D:(A;OICI;GR;;;SY)..."
```
*See the `CUSTOM_FC_STSEC_SEC_DESC_CACHE_LIST_ENTRY` struct.


#### `\Registry\Machine\System\ControlSet001\Control\StSec\FolderProperties\`

<u>Used in:</u> `StSecpInitializePolicyCache`, `StSecpGetFolderPropertyPolicy`.

Similar to the previous registry, the keys under this registry path are only the names of packages - no parameter names. StSecpGetFolderPropertyPolicy enumerates over all subkeys of this path recursively (single recursive call). It populates the global g_StSecFolderPropertyCacheList[Head/Tail] with the registry's data to be accessed later by `StSecGetSecurityDescriptor`.

```c
SYSTEM\ControlSet001\Control\StSec\FolderProperties\Documents\MyApp_8wekyb3d8bbwe\PrivateData
├── FolderId = 1 (DWORD)
└── ChamberId = "MyAppChamber" (String)
```

```c
#### `\Registry\Machine\System\ControlSet001\Control\StSec\FolderProperties\`
├── SomeFolder\
│   ├── SubFolder1\
│   │   ├── FolderId (DWORD)
│   │   └── ChamberId (String)
│   └── SubFolder2\
│       ├── FolderId (DWORD)
│       └── ChamberId (String)
├── AnotherFolder\
    ├── FolderId (DWORD)
    └── ChamberId (String)
```
*See the CUSTOM_FC_STSEC_FOLDER_PROP_CACHE_LIST_ENTRY struct.

#### `\Registry\Machine\Software\Microsoft\Windows\CurrentVersion\Appx\`

<u>Used in:</u> KappxGetPackageRootPathForPackageFullName.
This is a core Windows AppX/UWP registry location that contains system-wide configuration for Windows Store applications.

- <b>"PackageRoot":</b> contains the base filesystem path where all Windows Store applications are installed. Typically, this is "C:\Program Files\WindowsApps\". This value is then cached in the g_PackageRoot (and g_PackageRootLength) global variables.

#### `\Registry\Machine\Software\Microsoft\Windows\CurrentVersion\Appx\PackageSidRef\`

<u>Used in:</u> KappxGetPackageSidFromPackageFamilyNameInRegistry
This registry location is specifically for resolving Package SIDs.

```c
\Registry\Machine\Software\Microsoft\Windows\CurrentVersion\Appx\PackageSidRef\
└── {PackageFamilyName}\
    └── PackageSid (REG_SZ)
```

```c
\Registry\Machine\Software\Microsoft\Windows\CurrentVersion\Appx\PackageSidRef\
├── Microsoft.Office.Word_8wekyb3d8bbwe\
│   └── PackageSid = "S-1-15-2-1234567890-..." (String)
├── Microsoft.WindowsCalculator_8wekyb3d8bbwe\
│   └── PackageSid = "S-1-15-2-0987654321-..." (String)
└── SomeOther.App_1234567890\
    └── PackageSid = "S-1-15-2-5555555555-..." (String)
```
This is used to retrieve the security descriptor for the path passed to the pre-create callback.