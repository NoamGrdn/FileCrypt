#pragma warning(disable: 4047)
#pragma warning(disable: 4024)
#pragma warning(disable: 4133)
#pragma warning(disable: 4189)
#pragma warning(disable: 4100)
#pragma warning(disable: 4152)
#pragma warning(disable: 4022)
#pragma warning(disable: 4242)
#pragma warning(disable: 4146)
#pragma warning(disable: 4113)
#pragma warning(disable: 4244)
#pragma warning(disable: 4701)
#pragma warning(disable: 4700)
#pragma warning(disable: 4703)

#include "fc.h"

#include "mc.h"
#include "stsec.h"

VOID
FCCleanupStreamContext(
    PCUSTOM_FC_STREAM_CONTEXT StreamContext
)
{
    if (StreamContext->ChamberId != NULL)
    {
        FCpFreeChamberId(StreamContext->ChamberId);
        StreamContext->ChamberId = NULL;
    }

    FCpEncStreamCleanup(&StreamContext->KeyData);
}

VOID
FCCleanupVolumeContext(
    PCUSTOM_FC_VOLUME_CONTEXT VolumeContext
)
{
    PWCH volumeNameBuffer = (VolumeContext->DeviceName).Buffer;

    if (volumeNameBuffer != NULL)
    {
        ExFreePoolWithTag(volumeNameBuffer,POOL_TAG_FCnv);
        (VolumeContext->DeviceName).Buffer = NULL;
    }

    if (VolumeContext->EncryptionEnabled != 0)
    {
        FCpEncVolumeCleanup(&(VolumeContext->BcryptAlgHandle).BcryptAlgHandle);
        VolumeContext->EncryptionEnabled = 0;
    }
}


VOID
FCDecryptWorker(
    PFLT_GENERIC_WORKITEM WorkItem,
    PFLT_INSTANCE Instance,
    CUSTOM_FC_DECRYPT_PARAMS* Params
)
{
    NTSTATUS status;
    PVOID ppvVar4;
    PFLT_CALLBACK_DATA p_Var5;
    PVOID event;
    EVENT_DESCRIPTOR* eventDescriptor;
    PVOID eventParam = &Params->CallbackData;
    ULONG zeroingOffset = 0;
    PCUSTOM_FC_READ_CONTEXT completionContext = Params->CompletionContext;
    PFLT_CALLBACK_DATA callbackData = Params->CallbackData;
    PFLT_IO_PARAMETER_BLOCK parameterBlock = callbackData->Iopb;
    PMDL mdl = (parameterBlock->Parameters).Read.MdlAddress;
    ULONG sectorSize;

    if (mdl == NULL)
    {
        if ((callbackData->Flags & 8) == 0)
        {
            p_Var5 = callbackData;
            status = FltLockUserBuffer(callbackData);

            if (status < 0)
            {
                if ((Microsoft_Windows_FileCryptEnableBits & 1) != 0)
                {
                    McTemplateK0d_EtwWriteTransfer(p_Var5, &LockUserBufferFailure, eventParam, status);
                }
                goto FCDecryptWorker_cleanup_and_return;
            }

            mdl = (parameterBlock->Parameters).Read.MdlAddress;
            goto LAB_1c0002288;
        }
        // TODO
        ppvVar4 = (parameterBlock->Parameters).LockControl.ProcessId;
    FCDecryptWorker_decrypt:
        mdl = (PMDL)callbackData;
        status = FltGetFsZeroingOffset(callbackData, &zeroingOffset);
        if (-1 < status)
        {
            sectorSize = completionContext->VolumeContext->SectorSize;

            status = FCpEncDecrypt(
                &completionContext->VolumeContext->BcryptAlgHandle,
                &completionContext->StreamContext->KeyData,
                ppvVar4,
                ppvVar4,
                // TODO
                *(int*)&(callbackData->IoStatus).Information + -1 + sectorSize & -sectorSize,
                (parameterBlock->Parameters).CreatePipe.Parameters,
                zeroingOffset
            );

            eventParam = (PVOID*)ppvVar4;
            goto FCDecryptWorker_cleanup_and_return;
        }

        if ((Microsoft_Windows_FileCryptEnableBits & 1) == 0)
        {
            goto FCDecryptWorker_cleanup_and_return;
        }
        eventDescriptor = &GetFsZeroingOffsetFailure;
    }
    else
    {
    LAB_1c0002288:
        if ((*(byte*)((longlong)&((PFLT_CALLBACK_DATA)mdl)->Thread + 2) & 5) == 0)
        {
            eventParam = (PVOID*)0x1;

            ppvVar4 = MmMapLockedPagesSpecifyCache(
                mdl,
                '\0',
                MmCached,
                NULL,
                0,
                ExDefaultMdlProtection | 0x40000010
            );
        }
        else
        {
            ppvVar4 = (((PFLT_CALLBACK_DATA)mdl)->IoStatus).Pointer;
        }

        if ((CUSTOM_FC_DECRYPT_PARAMS*)ppvVar4 != NULL)
        {
            goto FCDecryptWorker_decrypt;
        }

        status = STATUS_INSUFFICIENT_RESOURCES;
        if ((Microsoft_Windows_FileCryptEnableBits & 1) == 0)
        {
            goto FCDecryptWorker_cleanup_and_return;
        }

        eventDescriptor = &GetSystemAddressFailure;
        status = STATUS_INSUFFICIENT_RESOURCES;
    }
    McTemplateK0d_EtwWriteTransfer(mdl, eventDescriptor, eventParam, status);
FCDecryptWorker_cleanup_and_return:
    FltReleaseContext(completionContext->VolumeContext);
    FltReleaseContext(completionContext->StreamContext);
    event = &gPre2PostIoContextList;
    ExFreeToNPagedLookasideList(&gPre2PostIoContextList, completionContext);

    if (status < 0)
    {
        (callbackData->IoStatus).Status = status;
        (callbackData->IoStatus).Information = 0;
        if ((Microsoft_Windows_FileCryptEnableBits & 2) != 0)
        {
            McTemplateK0d_EtwWriteTransfer(event, &DecryptWorkerFailure, eventParam, status);
        }
    }

    if (WorkItem != NULL)
    {
        FltCompletePendedPostOperation(callbackData);
        FltFreeGenericWorkItem(WorkItem);
        ExFreePoolWithTag(Params, POOL_TAG_FCdc);
    }
}


NTSTATUS
FCFilterUnload(
    VOID)
{
    StSecDeinitialize();
    FltUnregisterFilter(gFilterHandle);
    ExDeleteNPagedLookasideList(&gPre2PostIoContextList);
    ExDeleteNPagedLookasideList(&gPre2PostCreateContextList);
    ExDeleteNPagedLookasideList(&gShadowBufferList);

    if (gRegistryPath.Buffer != NULL)
    {
        ExFreePoolWithTag(gRegistryPath.Buffer, POOL_TAG_FCin);
    }

    McGenEventUnregister_EtwUnregister();

    return STATUS_SUCCESS;
}


VOID
FCFreeShadowBuffer(
    PVOID unused,
    PVOID Buffer,
    UCHAR AllocationType
)
{
    if (AllocationType == '\x01')
    {
        ExFreeToNPagedLookasideList(&gShadowBufferList, Buffer);
    }
    else if (AllocationType == '\x02')
    {
        ExFreePoolWithTag(Buffer,POOL_TAG_FCsb);
    }
}


NTSTATUS
FCInstanceQueryTeardown(
    VOID)
{
    return STATUS_SUCCESS;
}

/* This function contains determines which volumes the driver attaches to. */
NTSTATUS
FCInstanceSetup(
    PCFLT_RELATED_OBJECTS FltObjects,
    FLT_INSTANCE_SETUP_FLAGS Flags,
    ULONG VolumeDeviceType,
    FLT_FILESYSTEM_TYPE VolumeFilesystemType
)
{
    USHORT volumeSectorSize;
    BOOLEAN isMobileOS;
    int compResult;
    NTSTATUS status;
    NTSTATUS getDosNameStatus;
    NTSTATUS encryptVolumeStartStatus;
    PFLT_VOLUME_PROPERTIES volumeProperties = NULL;
    PFILE_FS_VOLUME_INFORMATION fsVolumeInfo = NULL;
    PDEVICE_OBJECT highestDeviceObject;
    PDEVICE_OBJECT lowerDeviceObject;
    NTSTATUS return_status = STATUS_FLT_DO_NOT_ATTACH;
    USHORT fileSystemDeviceNameLength;
    BOOLEAN doesVolumeNotSupportRemovableMedia;
    BOOLEAN isVolumeSdCard = FALSE;
    ULONG volumePropertiesLength = 0;
    PCUSTOM_FC_VOLUME_CONTEXT volumeContext = NULL;
    PDEVICE_OBJECT diskDeviceObject = NULL;
    PCUNICODE_STRING fileSystemDeviceName;
    IO_STATUS_BLOCK ioStatusBlock = {0, 0};
    PVPB vqb;
    PDEVICE_OBJECT vqb_deviceObject;

    /* Only attach to file systems */
    if (VolumeDeviceType != FILE_DEVICE_DISK_FILE_SYSTEM)
    {
        goto FCInstanceSetup_cleanup_and_return;
    }

    /* Only attach to the following filesystems: RAW, NTFS, FAT, and EXFAT */
    if (1 < VolumeFilesystemType + ~FLT_FSTYPE_RAW && VolumeFilesystemType != FLT_FSTYPE_EXFAT)
    {
        goto FCInstanceSetup_cleanup_and_return;
    }

    volumeProperties = ExAllocatePool2(0x100, 0x248, POOL_TAG_FCvp);

    if (volumeProperties == NULL)
    {
        goto FCInstanceSetup_cleanup_and_return;
    }

    status = FltGetVolumeProperties(
        FltObjects->Volume,
        volumeProperties,
        0x248,
        &volumePropertiesLength
    );

    if (status < 0)
    {
        goto FCInstanceSetup_cleanup_and_return;
    }

    /* "removable" means that the media of the device is removable.
     * For example, CD-ROM drives or card readers for flash media */
    doesVolumeNotSupportRemovableMedia = (volumeProperties->DeviceCharacteristics & FILE_REMOVABLE_MEDIA) == 0;

    /* If FilterEmulatedExternalDrive is ON check if volume is an sd card */
    if ((gFCFlags & FilterEmulatedExternalDriveFlagBit) != 0)
    {
        fsVolumeInfo = ExAllocatePool2(0x100, 0x58, POOL_TAG_FCvi);

        if (fsVolumeInfo == NULL)
        {
            goto FCInstanceSetup_cleanup_and_return;
        }

        status = FltQueryVolumeInformation(
            FltObjects->Instance,
            &ioStatusBlock,
            fsVolumeInfo,
            0x58,
            FileFsVolumeInformation
        );

        if (status < 0)
        {
            goto FCInstanceSetup_cleanup_and_return;
        }

        /* Check if the VolumeLabelLength is 6 wchars in length (12/13 byte longs).
         * If it is, then compare the VolumeLabel with the string "SDCARD" */
        if ((fsVolumeInfo->VolumeLabelLength & 0xfffffffe) == 12)
        {
            compResult = _wcsnicmp(
                fsVolumeInfo->VolumeLabel,
                L"SDCARD",
                fsVolumeInfo->VolumeLabelLength >> 1
            );
            isVolumeSdCard = compResult == 0;
        }
    }

    /* Different behavior on mobile vs desktop */
    isMobileOS = FsRtlIsMobileOS();
    if (isMobileOS == FALSE)
    {
        /* On non-mobile, if the file system has an app pairing id, or it's an sd card - continue the attachment process */
        status = FCpRetrieveAppPairingId(FltObjects);
        if (status < 0)
        {
        FCInstanceSetup_sd_card_check:
            /* On a non-mobile OS, if the app pairing id is not found, only continue if the volume is an SDCARD */
            if (!isVolumeSdCard)
            {
                goto FCInstanceSetup_cleanup_and_return;
            }
        }
    }
    else if (doesVolumeNotSupportRemovableMedia)
    {
        /* On mobile continue attachment process only on sd cards */
        goto FCInstanceSetup_sd_card_check;
    }

    volumeSectorSize = 0x200;

    status = FltAllocateContext(
        FltObjects->Filter,
        FLT_VOLUME_CONTEXT,
        0x38,
        NonPagedPoolNx,
        &volumeContext
    );

    if (-1 < status)
    {
        volumeContext->DeviceName.Length = 0;
        volumeContext->DeviceName.MaximumLength = 0;
        volumeContext->DeviceName.Buffer = NULL;
        volumeContext->SectorSize = 0;
        volumeContext->BcryptAlgHandle.ObjectLength = 0;
        volumeContext->EncryptionEnabled = 0;

        if (0x200 < volumeProperties->SectorSize)
        {
            volumeSectorSize = volumeProperties->SectorSize;
        }

        volumeContext->SectorSize = volumeSectorSize;

        status = FltGetDiskDeviceObject(FltObjects->Volume, &diskDeviceObject);

        if (-1 < status)
        {
            getDosNameStatus = RtlVolumeDeviceToDosName(diskDeviceObject, &volumeContext->DeviceName);
            if (getDosNameStatus < 0)
            {
                fileSystemDeviceName = &volumeProperties->RealDeviceName;
                fileSystemDeviceNameLength = ((UNICODE_STRING*)fileSystemDeviceName)->Length;
                if (fileSystemDeviceNameLength == 0)
                {
                    fileSystemDeviceName = (PCUNICODE_STRING)&volumeProperties->FileSystemDeviceName;
                    fileSystemDeviceNameLength = ((UNICODE_STRING*)fileSystemDeviceName)->Length;

                    if (fileSystemDeviceNameLength == 0)
                    {
                        goto FCInstanceSetup_cleanup_and_return;
                    }
                }

                volumeContext->DeviceName.Buffer = ExAllocatePool2(
                    0x40,
                    fileSystemDeviceNameLength + 2,
                    POOL_TAG_FCnv
                );

                if (volumeContext->DeviceName.Buffer == NULL)
                {
                    goto FCInstanceSetup_cleanup_and_return;
                }

                (volumeContext->DeviceName).Length = 0;
                (volumeContext->DeviceName).MaximumLength = fileSystemDeviceNameLength + 2;
                RtlCopyUnicodeString(&volumeContext->DeviceName, fileSystemDeviceName);
                RtlAppendUnicodeToString(&volumeContext->DeviceName, L":");
            }
            volumeContext->BcryptAlgHandle.BcryptAlgHandle = NULL;
            volumeContext->BcryptAlgHandle.ObjectLength = 0;
            volumeContext->BcryptAlgHandle.EncryptionSectorSize = volumeContext->SectorSize;
            volumeContext->BcryptAlgHandle.SecretKeySize = 0x10;
            volumeContext->EncryptionEnabled = 1;
            /* Initialize Bcrypt Alg Handle */
            encryptVolumeStartStatus = FCpEncVolumeStart(&volumeContext->BcryptAlgHandle);
            /* if EnvVolumeStart and SetVolumeContext both succeed
             * (that + 0x8.. & 0x8.. bit checks if the highest bit is set which with NTSTATUS always means error)
             * or SetVolumeContext returned STATUS_FLT_CONTEXT_ALREADY_DEFINED, we can continue
             */
            if (
                -1 < encryptVolumeStartStatus &&
                (
                    status = FltSetVolumeContext(
                        FltObjects->Volume,
                        FLT_SET_CONTEXT_KEEP_IF_EXISTS,
                        volumeContext,
                        NULL
                    ),
                    (status + 0x80000000U & 0x80000000) != 0 || (status == STATUS_FLT_CONTEXT_ALREADY_DEFINED)
                )
            )
            {
                vqb = diskDeviceObject->Vpb;
                isMobileOS = FsRtlIsMobileOS();
                /* Checks if we are not on mobile and the device can persist ACLS */
                if (
                    isMobileOS == FALSE &&
                    (vqb->DeviceObject->Flags & DO_SUPPORTS_PERSISTENT_ACLS) != 0
                )
                {
                    volumeContext->VerificationNeeded = FALSE;
                }
                else
                {
                    /* Always verify on mobile */
                    volumeContext->VerificationNeeded = TRUE;
                    vqb_deviceObject = vqb->DeviceObject;
                    vqb_deviceObject->Flags = vqb_deviceObject->Flags | DO_SUPPORTS_PERSISTENT_ACLS;
                }

                if (
                    (gFCFlags & FilterEmulatedExternalDriveFlagBit) != 0 &&
                    doesVolumeNotSupportRemovableMedia
                )
                {
                    highestDeviceObject = IoGetAttachedDeviceReference(diskDeviceObject);

                    while (highestDeviceObject != NULL)
                    {
                        /* Apply the FILE_REMOVABLE_MEDIA characteristic to all devices in the stack */
                        highestDeviceObject->Characteristics =
                            highestDeviceObject->Characteristics | FILE_REMOVABLE_MEDIA;
                        lowerDeviceObject = IoGetLowerDeviceObject(highestDeviceObject);
                        ObfDereferenceObject(highestDeviceObject);
                        highestDeviceObject = lowerDeviceObject;
                    }
                }

                return_status = STATUS_SUCCESS;

                /* if BypassAccessChecks is ON remove the FILE_DEVICE_SECURE_OPEN characteristic */
                if ((gFCFlags & BypassAccessChecksFlagBit) != 0)
                {
                    diskDeviceObject->Characteristics = diskDeviceObject->Characteristics & ~FILE_DEVICE_SECURE_OPEN;
                }
            }
        }
    }
FCInstanceSetup_cleanup_and_return:
    if (volumeProperties != NULL)
    {
        ExFreePoolWithTag(volumeProperties, POOL_TAG_FCvp);
    }
    if (fsVolumeInfo != NULL)
    {
        ExFreePoolWithTag(fsVolumeInfo, POOL_TAG_FCvi);
    }
    if (volumeContext != NULL)
    {
        FltReleaseContext(volumeContext);
    }
    if (diskDeviceObject != NULL)
    {
        ObfDereferenceObject(diskDeviceObject);
    }

    return return_status;
}


/* This function determines whether a file access operation should be allowed based on security
 * descriptors and requested access rights */
NTSTATUS FCpAccessCheck(
    PFLT_CALLBACK_DATA Data,
    PSECURITY_DESCRIPTOR SecurityDescriptor,
    PACCESS_MASK OutGrantedAccess
)
{
    BOOLEAN isAllowed;
    PGENERIC_MAPPING genericMapping;
    uint createDisposition;
    KPROCESSOR_MODE requestMode = Data->RequestorMode;
    ACCESS_MASK desiredAccess;
    NTSTATUS return_status = STATUS_SUCCESS;
    NTSTATUS accessStatus = STATUS_SUCCESS;
    ACCESS_MASK grantedAccess = 0;
    uint securityContextDesiredAccess;
    PACCESS_STATE accessState;
    uint createOptions;
    PFLT_IO_PARAMETER_BLOCK iopb = Data->Iopb;
    PIO_SECURITY_CONTEXT iopbSecurityContext;

    createOptions = (iopb->Parameters).Create.Options;
    iopbSecurityContext = (iopb->Parameters).Create.SecurityContext;
    /* See the Create struct (IRP_MJ_CREATE) in FLT_PARAMETERS (flt.kernel.h) */
    createDisposition = createOptions >> 0x18;
    securityContextDesiredAccess = iopbSecurityContext->DesiredAccess;
    /* Initially set desiredAccess to include FILE_READ_ATTRIBUTES (0x10000) */
    desiredAccess = securityContextDesiredAccess | 0x10000;

    /* If bit 12 of createOptions is not set (NOT FILE_DIRECTORY_FILE):
     * Use the original desired access without modification */
    if ((createOptions >> 0xc & 1) == 0)
    {
        desiredAccess = securityContextDesiredAccess;
    }
    if (createDisposition - 4 < 2)
    {
        /* If disposition is 4 (FILE_OVERWRITE) or 5 (FILE_OVERWRITE_IF):
           Add STANDARD_RIGHTS_WRITE | FILE_WRITE_DATA (0x112) */
        desiredAccess = desiredAccess | 0x112;
    }
    else if (createDisposition - 2 < 2)
    {
        /* If disposition is 2 (FILE_CREATE) or 3 (FILE_OPEN_IF):
           Add FILE_WRITE_DATA (0x2) or FILE_APPEND_DATA (0x4) depending on the least significant bit */
        desiredAccess = desiredAccess | (createOptions & 1) * 2 + 2;
    }
    else
    {
        /* If disposition is 0 (FILE_SUPERSEDE):
           Add FILE_READ_ATTRIBUTES (0x10000) */
        if (createDisposition == 0)
        {
            desiredAccess = desiredAccess | 0x10000;
        }
    }
    /* If bit 0 of IrpFlags is set (SL_FORCE_ACCESS_CHECK):
       Force the access mode to KernelMode (1) */
    if ((*(byte*)&iopb->IrpFlags & 1) != 0)
    {
        requestMode = '\x01';
    }
    /* If BypassAccessChecks is off do access check */
    if ((gFCFlags & BypassAccessChecksFlagBit) == 0)
    {
        accessState = iopbSecurityContext->AccessState;
        genericMapping = IoGetFileObjectGenericMapping();

        isAllowed = SeAccessCheck(
            SecurityDescriptor,
            &accessState->SubjectSecurityContext,
            '\0',
            desiredAccess,
            accessState->PreviouslyGrantedAccess,
            NULL,
            genericMapping,
            requestMode,
            &grantedAccess,
            &accessStatus
        );

        return_status = accessStatus;

        if (isAllowed == '\0')
        {
            if (-1 < accessStatus)
            {
                return_status = STATUS_ACCESS_DENIED;
            }
        }
        else
        {
            *OutGrantedAccess = grantedAccess;
        }
    }

    return return_status;
}


NTSTATUS
FCpEncDecrypt(
    PCUSTOM_FC_BCRYPT_DATA BcryptAlgData,
    PCUSTOM_FC_BCRYPT_KEY_DATA KeyHandle,
    PUCHAR PbInput,
    PUCHAR PbOutput,
    int TotalBytesToDecrypt,
    PVOID Parameters,
    ULONG ZeroingOffest
)
{
    NTSTATUS status = STATUS_SUCCESS;
    ulonglong chunkSize;
    BCRYPT_KEY_HANDLE keyHandle;
    // TODO
    // rename uVar1
    uint uVar1 = 0;
    ULONG pcbResult[2];
    PCUSTOM_FC_BCRYPT_KEY_DATA pKeyHandle = KeyHandle;
    PVOID pbIV;
    uint cypherTextSize;

    pcbResult[0] = 0;

    if ((BcryptAlgData->BlockLength == 0x10) && (ZeroingOffest != 0))
    {
        for (; TotalBytesToDecrypt != 0; TotalBytesToDecrypt = TotalBytesToDecrypt - cypherTextSize)
        {
            cypherTextSize = BcryptAlgData->EncryptionSectorSize;
            chunkSize = (ulonglong)cypherTextSize;
            keyHandle = pKeyHandle->BcryptKeyHandle;
            pbIV = Parameters;

            status = BCryptDecrypt(
                keyHandle,
                PbInput,
                cypherTextSize,
                NULL,
                (PUCHAR)&pbIV,
                BcryptAlgData->BlockLength,
                PbOutput,
                cypherTextSize,
                pcbResult,
                0
            );

            if (status < 0)
            {
                if ((Microsoft_Windows_FileCryptEnableBits & 1) != 0)
                {
                    McTemplateK0d_EtwWriteTransfer(keyHandle, &DecryptFailure, chunkSize, status);
                }
                break;
            }
            cypherTextSize = BcryptAlgData->EncryptionSectorSize;
            chunkSize = (ulonglong)cypherTextSize;
            uVar1 = uVar1 + cypherTextSize;

            if (ZeroingOffest < uVar1)
            {
                memset(PbOutput + ZeroingOffest, 0, uVar1 - ZeroingOffest);
                break;
            }

            Parameters = (PVOID)((longlong)Parameters + chunkSize);
            PbOutput = PbOutput + chunkSize;
            PbInput = PbInput + chunkSize;
        }
    }

    return status;
}

/* This function actually creates the ciphertext from the plaintext that is supposed to be written to the disk */
NTSTATUS
FCpEncEncrypt(
    PCUSTOM_FC_BCRYPT_DATA CiphertextData,
    PCUSTOM_FC_BCRYPT_KEY_DATA BcryptHandle,
    PUCHAR DataToEncrypt,
    PUCHAR OutCiphertext,
    int TotalSizeToEncrypt,
    PUCHAR InitVector
)
{
    NTSTATUS status;
    BCRYPT_KEY_HANDLE keyHandle;
    ulonglong eventParam;
    ULONG cyphertextsize = 0;
    PUCHAR initVector;
    ULONG sectorSize;
    uint chunkSize;


    /* Block length is 16 bytes (128 bits) */
    if (CiphertextData->BlockLength == 0x10)
    {
        for (; TotalSizeToEncrypt != 0; TotalSizeToEncrypt = TotalSizeToEncrypt - chunkSize)
        {
            sectorSize = CiphertextData->EncryptionSectorSize;
            eventParam = (ulonglong)sectorSize;
            keyHandle = BcryptHandle->BcryptKeyHandle;
            initVector = InitVector;

            status = BCryptEncrypt(
                keyHandle,
                DataToEncrypt,
                sectorSize,
                NULL,
                (PUCHAR)&initVector,
                CiphertextData->BlockLength,
                OutCiphertext,
                sectorSize,
                &cyphertextsize,
                0
            );

            if (status < 0)
            {
                if ((Microsoft_Windows_FileCryptEnableBits & 1) != 0)
                {
                    McTemplateK0d_EtwWriteTransfer(keyHandle, &EncryptFailure, eventParam, status);
                }

                break;
            }
            /* After encrypting a chunk, advances the pointers.  */
            chunkSize = CiphertextData->EncryptionSectorSize;
            DataToEncrypt = DataToEncrypt + chunkSize;
            OutCiphertext = OutCiphertext + chunkSize;
            InitVector = InitVector + chunkSize;
        }
    }

    return STATUS_SUCCESS;
}


VOID
FCpEncStreamCleanup(
    PCUSTOM_FC_BCRYPT_KEY_DATA KeyData
)
{
    ulonglong keySize;
    PUCHAR key;

    if (KeyData->BcryptKeyHandle != NULL)
    {
        BCryptDestroyKey(KeyData->BcryptKeyHandle);
        KeyData->BcryptKeyHandle = NULL;
    }
    if (KeyData->KeyObject != NULL)
    {
        key = KeyData->KeyObject;

        for (keySize = (ulonglong)KeyData->KeyObjectSize; keySize != 0; keySize = keySize - 1)
        {
            *key = '\0';
            key = key + 1;
        }

        ExFreePoolWithTag(KeyData->KeyObject, POOL_TAG_FCCr);
        KeyData->KeyObject = NULL;
    }
}


/* This function initializes a stream context for encryption or decryption operations by:
 * 
 * 1. Retrieving the appropriate chamber key
 * 2. Creating a BCrypt key handle for encryption operations
 * 3. Setting up the key receiver structure for file operations */
NTSTATUS
FCpEncStreamStart(
    PCUSTOM_FC_BCRYPT_DATA HAlgorithm,
    PWCHAR ChamberId,
    ULONG ChamberType,
    PCUSTOM_FC_BCRYPT_KEY_DATA OutKeyReceiver
)
{
    NTSTATUS return_status;
    PUCHAR chamberProfileKey;
    PWCHAR event;
    ulonglong keyCharIndex;
    EVENT_DESCRIPTOR* eventDescriptor;
    PUCHAR pbKeyObject;
    ULONG pbKeyObjectSize = HAlgorithm->ObjectLength;
    ULONG profileKeySize;

    OutKeyReceiver->KeyObjectSize = pbKeyObjectSize;

    chamberProfileKey = ExAllocatePool2(0x40, HAlgorithm->SecretKeySize, POOL_TAG_FCCr);

    if (chamberProfileKey == NULL)
    {
    FCpEncStreamStart_return_InvalidParam:
        return_status = STATUS_INSUFFICIENT_RESOURCES;
    }
    else
    {
        profileKeySize = HAlgorithm->SecretKeySize;
        event = (PWCHAR)(ulonglong)profileKeySize;

        if (ChamberId == NULL || 1 < ChamberType - 1)
        {
            return_status = STATUS_INVALID_PARAMETER;
        }
        else
        {
            event = ChamberId;
            pbKeyObject = chamberProfileKey;
            /* Try to get the chamber profile key from cache */
            return_status = StSecpGetChamberProfileKey(ChamberId, ChamberType, chamberProfileKey, profileKeySize);

            if (return_status < 0 && return_status == STATUS_OBJECT_NAME_NOT_FOUND)
            {
                pbKeyObject = chamberProfileKey;
                /* If not found in cache, derive it */
                return_status = StSecpDeriveChamberProfileKey(
                    ChamberId,
                    ChamberType,
                    chamberProfileKey,
                    profileKeySize
                );

                event = ChamberId;
            }
        }
        if (return_status < 0)
        {
            if ((Microsoft_Windows_FileCryptEnableBits & 1) == 0)
            {
                goto FCpEncStreamStart_cleanup_and_return;
            }
            eventDescriptor = &GetChamberProfileEncryptionKeyFailure;
        }
        else
        {
            pbKeyObject = ExAllocatePool2(0x40, pbKeyObjectSize, POOL_TAG_FCCr);
            OutKeyReceiver->KeyObject = pbKeyObject;

            if (pbKeyObject == NULL)
            {
                goto FCpEncStreamStart_return_InvalidParam;
            }

            /* Generate a symmetric key using the chamber profile key */
            return_status = BCryptGenerateSymmetricKey(
                HAlgorithm->BcryptAlgHandle,
                &OutKeyReceiver->BcryptKeyHandle,
                pbKeyObject,
                pbKeyObjectSize,
                chamberProfileKey,
                HAlgorithm->SecretKeySize,
                0
            );

            if ((-1 < return_status) ||
                (event = (PWCHAR)(ulonglong)Microsoft_Windows_FileCryptEnableBits,
                    (Microsoft_Windows_FileCryptEnableBits & 1) == 0))
            {
                goto FCpEncStreamStart_cleanup_and_return;
            }
            eventDescriptor = &GenerateSymmetricKeyFailure;
        }
        McTemplateK0d_EtwWriteTransfer(event, eventDescriptor, pbKeyObject, return_status);
    }
FCpEncStreamStart_cleanup_and_return:
    if (chamberProfileKey != NULL)
    {
        pbKeyObject = chamberProfileKey;
        /* Zero the key memory before freeing */
        for (keyCharIndex = (ulonglong)HAlgorithm->SecretKeySize; keyCharIndex != 0; keyCharIndex = keyCharIndex - 1)
        {
            *pbKeyObject = '\0';
            pbKeyObject = pbKeyObject + 1;
        }
        ExFreePoolWithTag(chamberProfileKey, POOL_TAG_FCCr);
    }
    if (return_status < 0)
    {
        FCpEncStreamCleanup(OutKeyReceiver);
    }

    return return_status;
}


VOID
FCpEncVolumeCleanup(
    BCRYPT_ALG_HANDLE* AlgHandle
)
{
    if (*AlgHandle != NULL)
    {
        BCryptCloseAlgorithmProvider(*AlgHandle, 0);
    }
}


NTSTATUS
FCpEncVolumeStart(
    PCUSTOM_FC_BCRYPT_DATA AlgHandle
)
{
    NTSTATUS status;
    ULONG objectLength = 0;
    ULONG pcbResult = 0;
    ULONG blockLength;

    status = BCryptOpenAlgorithmProvider(
        &AlgHandle->BcryptAlgHandle,
        L"AES",
        NULL,
        BCRYPT_PROV_DISPATCH
    );

    if (-1 < status)
    {
        goto FCpEncVolumeStart_cleanup_and_return;
    }

    status = BCryptGetProperty(
        AlgHandle->BcryptAlgHandle,
        L"BlockLength",
        (PUCHAR)&AlgHandle->BlockLength,
        4,
        &pcbResult,
        0
    );

    if (-1 < status)
    {
        blockLength = AlgHandle->BlockLength;

        if (blockLength == 0 || (blockLength & blockLength - 1) != 0)
        {
            status = STATUS_INVALID_BLOCK_LENGTH;
        }
        else
        {
            /* ObjectLength represents the memory space that is required to hold an instance of a cryptographic
             * object (hash object, cipher object) */
            status = BCryptGetProperty(
                AlgHandle->BcryptAlgHandle,
                L"ObjectLength",
                (PUCHAR)&objectLength,
                4,
                &pcbResult,
                0
            );

            if (-1 < status)
            {
                AlgHandle->ObjectLength = objectLength;
                /* 0x20 is the length of ChainingModeCBC */
                status = BCryptSetProperty(
                    AlgHandle->BcryptAlgHandle,
                    L"ChainingMode",
                    L"ChainingModeCBC",
                    0x20,
                    0
                );

                if (-1 < status)
                {
                    return STATUS_SUCCESS;
                }
            }
        }
    }
FCpEncVolumeStart_cleanup_and_return:
    FCpEncVolumeCleanup(&AlgHandle->BcryptAlgHandle);

    return status;
}


BOOLEAN
FCpEqualChamberIds(
    PWCHAR ChamberIdA,
    PWCHAR ChamberIdB
)
{
    longlong offset;
    WCHAR chamberAChar;
    WCHAR chamberBChar;

    if (ChamberIdA == NULL || ChamberIdB == NULL)
    {
        return ChamberIdA == ChamberIdB;
    }

    offset = (longlong)ChamberIdB - (longlong)ChamberIdA;

    do
    {
        chamberAChar = *ChamberIdA;
        chamberBChar = *(WCHAR*)((longlong)ChamberIdA + offset);
        if (chamberAChar != chamberBChar) break;
        ChamberIdA = ChamberIdA + 1;
    }
    while (chamberBChar != L'\0');

    return chamberAChar == chamberBChar;
}


VOID
FCpFreeChamberId(
    PWCHAR ChamberId
)
{
    BOOLEAN isEqual;

    /* gFCFlags & 6 == 0 => EncryptMedia and EncryptAll are turned off 
     * (bits 1 and 2 are 0) */
    if (
        (
            (gFCFlags & 6) == 0 ||
            (isEqual = FCpEqualChamberIds(ChamberId, L"MusicChamber"), isEqual == '\0') &&
            (isEqual = FCpEqualChamberIds(ChamberId, L"PicturesChamber"), isEqual == '\0') &&
            (isEqual = FCpEqualChamberIds(ChamberId, L"VideosChamber"), isEqual == '\0') &&
            (isEqual = FCpEqualChamberIds(ChamberId, L"{0b7992da-c5e6-41e3-b24f-55419b997a15}"), isEqual == '\0')
        ) && ChamberId != NULL
    )
    {
        ExFreePoolWithTag(ChamberId, 0x70537453);
    }
}


/* This function processes a file path and determines which encryption chamber (if any) should be
 * applied to it */
VOID
FCpObtainSecurityInfoCallout(
    PCUSTOM_FC_CHAMBER_DATA ChamberData
)
{
    BOOLEAN chamberMatch;
    NTSTATUS status;
    PWCHAR assignedChamberId;
    PSECURITY_DESCRIPTOR securityDescriptor = &ChamberData->SecurityDescriptor;
    PWCHAR* chamberId;
    PCUNICODE_STRING chamberPath = ChamberData->InputPath;

    /* reset ChamberId */
    ChamberData->ChamberId = NULL;

    if (chamberPath->Length == 0)
    {
        ChamberData->Status = 0;

        return;
    }

    chamberId = &ChamberData->ChamberId;
    status = StSecGetSecurityDescriptor(chamberPath, securityDescriptor, chamberId, &ChamberData->ChamberType);

    if (securityDescriptor == NULL && chamberId != NULL)
    {
        ExFreePoolWithTag(chamberId, POOL_TAG_STsp);
    }
    if (status < 0)
    {
        if ((Microsoft_Windows_FileCryptEnableBits & 1) != 0)
        {
            McTemplateK0d_EtwWriteTransfer(chamberPath, &GetSecurityDescriptorFailure, chamberId, status);
        }

        goto FCpObtainSecurityInfoCallout_return;
    }

    /* If StSecGetSecurityDescriptor succeeded, the current file/directory were succsessfuly resolved to
     * a ChamberId, ChamberType and we can return.
     * Otherwise, check for predetermined chambers */
    if (ChamberData->ChamberId != NULL)
    {
        goto FCpObtainSecurityInfoCallout_return;
    }

    /* If EncryptAll is ON chamberId is the global guid */
    if ((gFCFlags & EncryptAllFlagBit) != 0)
    {
        assignedChamberId = L"{0b7992da-c5e6-41e3-b24f-55419b997a15}";
        goto FCpObtainSecurityInfoCallout_assign_chamberid_and_return;
    }
    if ((gFCFlags & EncryptMediaFlagBit) == 0)
    {
        goto FCpObtainSecurityInfoCallout_return;
    }

    chamberMatch = RtlPrefixUnicodeString(&gMusicPath, chamberPath, '\x01');
    if (chamberMatch == '\0')
    {
        chamberMatch = RtlPrefixUnicodeString(&gPicturesPath, chamberPath, '\x01');
        if (chamberMatch != '\0')
        {
            assignedChamberId = L"PicturesChamber";
            goto FCpObtainSecurityInfoCallout_assign_chamberid_and_return;
        }
        chamberMatch = RtlPrefixUnicodeString(&gVideosPath, chamberPath, '\x01');
        if (chamberMatch != '\0')
        {
            assignedChamberId = L"VideosChamber";
            goto FCpObtainSecurityInfoCallout_assign_chamberid_and_return;
        }
    }
    else
    {
        assignedChamberId = L"MusicChamber";
    FCpObtainSecurityInfoCallout_assign_chamberid_and_return:
        ChamberData->ChamberId = assignedChamberId;
    }

    ChamberData->ChamberType = 1;
FCpObtainSecurityInfoCallout_return:
    ChamberData->Status = status;
}

/* FCPostCreate sets up the encryption infrastructure that will be used for all subsequent operations on the file */
FLT_POSTOP_CALLBACK_STATUS
FCPostCreate(
    PFLT_CALLBACK_DATA Data,
    PCFLT_RELATED_OBJECTS FltObjects,
    CUSTOM_FC_CREATE_CONTEXT* CompletionContext,
    FLT_POST_OPERATION_FLAGS Flags
)
{
    NTSTATUS status = STATUS_SUCCESS;
    PWCHAR chamberId = NULL;
    PFLT_INSTANCE instance;
    BOOLEAN isAccessModified = FALSE;
    BOOLEAN isDirectory = FALSE;
    ULONG chamberType = 1;
    PCUSTOM_FC_STREAM_CONTEXT streamContext = NULL;
    PCUSTOM_FC_VOLUME_CONTEXT volumeContext = NULL;
    NTSTATUS ioStatus;
    bool error = FALSE;

    /* Extract data from completion context if available */
    if (CompletionContext != NULL)
    {
        chamberId = CompletionContext->ChamberId;
        chamberType = CompletionContext->ChamberType;
        isAccessModified = CompletionContext->IsAccessModified;

        /* frees the lookaside list entry that was used to pass the CompletionContext */
        ExFreeToNPagedLookasideList(&gPre2PostCreateContextList, CompletionContext);
    }

    ioStatus = (Data->IoStatus).Status;

    /* If error has occurred, or the operation is a reparse operation, don't do anything and return some error */
    if ((ioStatus < 0) || (ioStatus == STATUS_REPARSE))
    {
        if ((ioStatus == STATUS_OBJECT_NAME_NOT_FOUND) && (isAccessModified != '\0'))
        {
            (Data->IoStatus).Status = STATUS_ACCESS_DENIED;
        }

        // TODO rename this variable
        error = true;
    }
    else
    {
        if ((Flags & 1) == FLTFL_POST_OPERATION_DRAINING)
        {
            status = FltGetStreamContext(FltObjects->Instance, FltObjects->FileObject, (PFLT_CONTEXT*)streamContext);

            if (status < 0)
            {
                if (chamberId == NULL)
                {
                    /* No chamber ID, skip encryption */
                    status = STATUS_SUCCESS;
                }
                else
                {
                    status = FltIsDirectory(FltObjects->FileObject, FltObjects->Instance, &isDirectory);

                    if (-1 < status && isDirectory == FALSE)
                    {
                        /* Retrieves the volume context which contains the AES-CBC cryptographic provider */
                        status = FltGetVolumeContext(
                            FltObjects->Filter,
                            FltObjects->Volume,
                            (PFLT_CONTEXT*)volumeContext
                        );

                        if (-1 < status)
                        {
                            status = FltAllocateContext(
                                gFilterHandle,
                                FLT_STREAM_CONTEXT,
                                0x28,
                                NonPagedPoolNx,
                                (PFLT_CONTEXT*)streamContext
                            );

                            if (-1 < status)
                            {
                                /* Reset KeyData and ChamberType */
                                streamContext->KeyData.BcryptKeyHandle = NULL;
                                streamContext->KeyData.KeyObject = NULL;
                                streamContext->KeyData.KeyObjectSize = 0;
                                streamContext->ChamberType = 0;

                                /* Set chamber info */
                                streamContext->ChamberId = chamberId;
                                streamContext->ChamberType = chamberType;
                                chamberId = NULL;

                                /* Initialize encryption - populate KeyData and ChamberType */
                                status = FCpEncStreamStart(
                                    &volumeContext->BcryptAlgHandle,
                                    streamContext->ChamberId,
                                    chamberType,
                                    &streamContext->KeyData
                                );

                                if (-1 < status)
                                {
                                    /* Register the stream context with the filter manager */
                                    status = FltSetStreamContext(
                                        FltObjects->Instance,
                                        FltObjects->FileObject,
                                        FLT_SET_CONTEXT_KEEP_IF_EXISTS,
                                        streamContext,
                                        NULL
                                    );

                                    if (status == STATUS_FLT_CONTEXT_ALREADY_DEFINED)
                                    {
                                        status = STATUS_SUCCESS;
                                    }
                                    else if (-1 < status)
                                    {
                                        /* Successfully set - release our reference */
                                        FltReleaseContext(streamContext);
                                        streamContext = NULL;
                                        chamberId = NULL;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    if (volumeContext != NULL)
    {
        FltReleaseContext(volumeContext);
        volumeContext = NULL;
    }
    if (streamContext != NULL)
    {
        FltReleaseContext(streamContext);
        streamContext = NULL;
    }
    if (chamberId != NULL)
    {
        FCpFreeChamberId(chamberId);
    }
    if ((!error) && (status < 0))
    {
        instance = FltObjects->Instance;
        FltCancelFileOpen(instance, FltObjects->FileObject);
        (Data->IoStatus).Status = status;
        (Data->IoStatus).Information = 0;
        if ((Microsoft_Windows_FileCryptEnableBits & 2) != 0)
        {
            McTemplateK0d_EtwWriteTransfer(instance, &PostCreateFailure, 0x1, status);
        }
    }

    return FLT_POSTOP_FINISHED_PROCESSING;
}

FLT_POSTOP_CALLBACK_STATUS
FCPostRead(
    PFLT_CALLBACK_DATA CallbackData,
    PCFLT_RELATED_OBJECTS FltObjects,
    PCUSTOM_FC_READ_CONTEXT CompletionContext,
    FLT_POST_OPERATION_FLAGS Flags
)
{
    KIRQL currentIrql;
    NTSTATUS ioStatus = STATUS_SUCCESS;
    PFLT_GENERIC_WORKITEM fltWorkItem = NULL;
    PCUSTOM_FC_DECRYPT_PARAMS fcDecryptParams = NULL;
    PCUSTOM_FC_DECRYPT_PARAMS contexts = CompletionContext;
    PVOID event;
    FLT_POSTOP_CALLBACK_STATUS return_status = FLT_POSTOP_FINISHED_PROCESSING;
    CUSTOM_FC_DECRYPT_PARAMS decryptParamsSetter;
    bool shouldCleanupMemory = true;

    memset(&decryptParamsSetter, 0, sizeof(decryptParamsSetter));

    /* The condition checks if:
       1. FLTFL_POST_OPERATION_DRAINING is off => Not a cleanup call (fltKernel.h)
       2. Whether the I/O operation succeeded (status >= 0)
       3. Whether any data was actually read (Information != 0) */
    if (
        (Flags & 1) == 0 &&
        -1 < CallbackData->IoStatus.Status &&
        CallbackData->IoStatus.Information != 0
    )
    {
        currentIrql = KeGetCurrentIrql();
        /* THE IOQB PARAMETERS STRUCT HERE MIGHT BE WRONG
           
           This condition checks if immediate decryption is possible:
           1. Either we're at a low IRQL (below DISPATCH_LEVEL)
           2. Or the read size is small (< 131,073 bytes) AND either:
             - An MDL (Memory Descriptor List) is available
             - The FLTFL_CALLBACK_DATA_FS_FILTER_OPERATION flag is set
           
           The FLTFL_CALLBACK_DATA_FS_FILTER_OPERATION flag is raised. The flag indicates that the operation
           is a file system filter operation */
        if (
            currentIrql < DISPATCH_LEVEL ||
            CallbackData->IoStatus.Information < 0x20001 &&
            (CallbackData->Iopb->Parameters.Others.Argument5 != NULL || (CallbackData->Flags & 8) != 0)
        )
        {
            //decryptParamsSetter = (CUSTOM_FC_DECRYPT_PARAMS)CONCAT88(CompletionContext, CallbackData);
            decryptParamsSetter.CallbackData = CallbackData;
            decryptParamsSetter.CompletionContext = CompletionContext;
            contexts = &decryptParamsSetter;
            FCDecryptWorker(NULL, FltObjects->Instance, contexts);
            shouldCleanupMemory = false;
            ioStatus = (CallbackData->IoStatus).Status;
        }
        else
        {
            /* If immediate decryption isn't possible */
            fltWorkItem = FltAllocateGenericWorkItem();
            if (fltWorkItem != NULL)
            {
                contexts = (CUSTOM_FC_DECRYPT_PARAMS*)0x63644346;
                fcDecryptParams = ExAllocatePool2(0x40, 0x10, POOL_TAG_FCdc);
                if (fcDecryptParams != NULL)
                {
                    fcDecryptParams->CallbackData = CallbackData;
                    fcDecryptParams->CompletionContext = CompletionContext;
                    event = FCDecryptWorker;
                    /* Queue the work item to call FCDecryptWorker asynchronously */
                    ioStatus = FltQueueGenericWorkItem(
                        fltWorkItem,
                        FltObjects->Instance,
                        FCDecryptWorker,
                        DelayedWorkQueue,
                        fcDecryptParams
                    );

                    contexts = (CUSTOM_FC_DECRYPT_PARAMS*)event;
                    if (-1 < ioStatus)
                    {
                        shouldCleanupMemory = false;
                        return_status = FLT_POSTOP_MORE_PROCESSING_REQUIRED;
                    }
                    goto FCPostRead_cleanup_and_return;
                }
            }

            ioStatus = STATUS_INSUFFICIENT_RESOURCES;
        }
    }
FCPostRead_cleanup_and_return:
    if (ioStatus < 0)
    {
        (CallbackData->IoStatus).Status = ioStatus;
        (CallbackData->IoStatus).Information = 0;
    }
    if (shouldCleanupMemory)
    {
        FltReleaseContext(CompletionContext->VolumeContext);
        FltReleaseContext(CompletionContext->StreamContext);
        ExFreeToNPagedLookasideList(&gPre2PostIoContextList, CompletionContext);
        if (fltWorkItem != NULL)
        {
            FltFreeGenericWorkItem(fltWorkItem);
        }
        if (fcDecryptParams != NULL)
        {
            ExFreePoolWithTag(fcDecryptParams, POOL_TAG_FCdc);
        }
        return_status = FLT_POSTOP_FINISHED_PROCESSING;
    }
    if ((ioStatus < 0) && ((Microsoft_Windows_FileCryptEnableBits & 2) != 0))
    {
        McTemplateK0d_EtwWriteTransfer(Microsoft_Windows_FileCryptEnableBits, &PostReadFailure, contexts, ioStatus);
    }

    return return_status;
}


FLT_POSTOP_CALLBACK_STATUS
FCPostWrite(
    PFLT_CALLBACK_DATA CallbackData,
    PCFLT_RELATED_OBJECTS RelatedObjects,
    PCUSTOM_FC_WRITE_CONTEXT CompletionContext
)
{
    FltReleaseContext(CompletionContext->VolumeContext);
    FltReleaseContext(CompletionContext->StreamContext);

    FCFreeShadowBuffer(
        CompletionContext->StreamContext,
        CompletionContext->Ciphertext,
        CompletionContext->AllocationType
    );

    ExFreeToNPagedLookasideList(&gPre2PostIoContextList, CompletionContext);

    return FLT_POSTOP_FINISHED_PROCESSING;
}


/* This function is the first major decision point when a file is opened or created. It decides:
 * 
 * 1. Whether the operation is allowed: Using security descriptors obtained from policies
 * 2. Which encryption context applies: Based on chamber IDs from policy or defaults
 * 3. How to pass information to post-operation: Through completion contexts
 * 
 * Uses key components:
 * 
 * 1. Security Descriptor Policies: Using StSecGetSecurityDescriptor to find matching policies
 * 2. Chamber Assignment: Determining which encryption chamber to use for the file
 */
// TODO GO OVER THIS AGAIN
FLT_PREOP_CALLBACK_STATUS
FCPreCreate(
    PFLT_CALLBACK_DATA Data,
    PCFLT_RELATED_OBJECTS FltObjects,
    PVOID* CompletionContext
)
{
    BOOLEAN fileNameEndsWithBackslash;
    BOOLEAN isMobile;
    BOOLEAN result;
    NTSTATUS kernelStackStatus;
    ULONG fileCreateOptionsHighByte;
    ULONG newCreateOptions;
    PFLT_FILE_NAME_INFORMATION fileNameInfoForLog;
    PEVENT_DESCRIPTOR eventParam1;
    PWCHAR chamberId = NULL;
    PEVENT_DESCRIPTOR errorEventDescriptor;
    BOOLEAN isAccessModified;
    PVOID eventParam3;
    FLT_PREOP_CALLBACK_STATUS return_status = FLT_PREOP_SUCCESS_WITH_CALLBACK;
    PCUSTOM_FC_CREATE_CONTEXT lookasideListEntry = NULL;
    ACCESS_MASK accessMask = 0;
    ushort totalPathLength;
    PWCHAR chamberIdStr = NULL;
    UNICODE_STRING chamberPath = {0, 0, NULL};
    PFLT_FILE_NAME_INFORMATION fileNameInfo = NULL;
    PNPAGED_LOOKASIDE_LIST securityDescriptor = NULL;
    PCUSTOM_FC_VOLUME_CONTEXT volumeContext = NULL;
    PWCHAR currentPathPosition;
    PWCHAR fullPathBuffer;
    CUSTOM_FC_CHAMBER_DATA chamberData;
    ULONG fileCreateOptions;
    PFLT_CALLBACK_DATA callbackData;
    PWCHAR fileName = NULL;
    ushort fileNameLength;
    PFILE_OBJECT fileObject;
    BOOLEAN isChamberPathSet = FALSE;
    PFLT_FILE_NAME_INFORMATION pFileNameInformation;


    chamberData.ChamberType = 0;
    chamberData.Status = FltGetVolumeContext(FltObjects->Filter, FltObjects->Volume, (PFLT_CONTEXT*)volumeContext);

    if (-1 < chamberData.Status)
    {
        fileObject = FltObjects->FileObject;
        fileNameLength = fileObject->FileName.Length;

        if (
            (Data->Iopb->Parameters.Create.Options & FILE_OPEN_BY_FILE_ID) == 0 &&
            2 < fileNameLength &&
            fileObject->FileName.Buffer[(fileNameLength >> 1) - 1] == L'\\'
        )
        {
            /* This shortens the filename length by 2 bytes (which is 1 wide character). Since the code just
             * determined that the last character was a backslash, and that the filename is not going to be an Id,
             * it removes that trailing backslash from the filename by adjusting the length field
             */
            (fileObject->FileName).Length = fileNameLength - 2;
        }

        callbackData = Data;
        chamberData.Status = FltGetFileNameInformation(
            Data,
            FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
            &fileNameInfo
        );

        if (chamberData.Status < 0)
        {
            if (volumeContext->VerificationNeeded == FALSE)
            {
                chamberData.Status = 0;
                chamberId = fileName;
            }
            else
            {
                chamberId = fileName;
                if ((Microsoft_Windows_FileCryptEnableBits & 2) != 0)
                {
                    McTemplateK0d_EtwWriteTransfer(
                        callbackData,
                        &GetFileNameInformationFailure,
                        fileNameInfo,
                        chamberData.Status
                    );
                }
            }
        }
        else
        {
            fileNameInfoForLog = fileNameInfo;
            /* Parse file name components */
            chamberData.Status = FltParseFileNameInformation(fileNameInfo);
            pFileNameInformation = fileNameInfo;
            if (chamberData.Status < 0)
            {
                chamberId = fileName;
                if ((Microsoft_Windows_FileCryptEnableBits & 1) != 0)
                {
                    McTemplateK0d_EtwWriteTransfer(
                        fileNameInfoForLog,
                        &ParseFileNameInformationFailure,
                        fileNameInfo,
                        chamberData.Status
                    );
                }
            }
            else
            {
                if ((fileNameInfo->ParentDir).Buffer == NULL)
                {
                    return_status = FLT_PREOP_SUCCESS_NO_CALLBACK;
                    lookasideListEntry = NULL;

                    goto FCPreCreate_cleanup;
                }

                currentPathPosition = NULL;
                fileNameEndsWithBackslash = TRUE;
                fileNameLength = (fileNameInfo->FinalComponent).Length;
                totalPathLength = fileNameLength + 2 + (fileNameInfo->ParentDir).Length;

                if (
                    fileNameLength != 0 &&
                    fileNameInfo->FinalComponent.Buffer[(ulonglong)(fileNameLength >> 1) - 1] != L'\\'
                )
                {
                    totalPathLength = totalPathLength + 2;
                    fileNameEndsWithBackslash = FALSE;
                }

                fileNameLength = totalPathLength;

                /* Construct full path for security checks */
                fullPathBuffer = ExAllocatePool2(0x100, totalPathLength, POOL_TAG_FCnf);

                if (fullPathBuffer == NULL)
                {
                    chamberData.Status = STATUS_INSUFFICIENT_RESOURCES;
                    if ((Microsoft_Windows_FileCryptEnableBits & 1) != 0)
                    {
                        errorEventDescriptor = &ConstructFullPathFailure;
                        chamberData.Status = STATUS_INSUFFICIENT_RESOURCES;
                    FCPreCreate_log_before_return:
                        McTemplateK0d_EtwWriteTransfer(0x100, errorEventDescriptor, POOL_TAG_FCnf,
                                                       chamberData.Status);
                    }
                }
                else
                {
                    // chamberPath = (UNICODE_STRING)CONCAT88(fullPathBuffer, chamberPath._0_8_);
                    // chamberPath._4_12_ =
                    //     SUB1612((undefined [16])chamberPath >> 0x20, 0) &
                    //     SUB1612((undefined [16])0xffffffffffffffff >> 0x10, 0);
                    // chamberPath = (UNICODE_STRING)(ZEXT1416(CONCAT122(chamberPath._4_12_, fileNameLength)) << 0x10);
                    chamberPath.Length = fileNameLength;
                    chamberPath.MaximumLength = fileNameLength;
                    chamberPath.Buffer = fullPathBuffer;

                    currentPathPosition = fullPathBuffer;

                    memcpy(
                        fullPathBuffer,
                        (pFileNameInformation->ParentDir).Buffer,
                        pFileNameInformation->ParentDir.Length
                    );

                    fileName = fullPathBuffer + ((pFileNameInformation->ParentDir).Length >> 1);
                    currentPathPosition = fileName;

                    memcpy(
                        fileName,
                        (pFileNameInformation->FinalComponent).Buffer,
                        pFileNameInformation->FinalComponent.Length
                    );

                    currentPathPosition = fileName + ((pFileNameInformation->FinalComponent).Length >> 1);

                    if (!fileNameEndsWithBackslash)
                    {
                        *currentPathPosition = L'\\';
                        currentPathPosition = currentPathPosition + 1;
                    }

                    chamberData.Status = STATUS_SUCCESS;
                    *currentPathPosition = L'\0';
                    isChamberPathSet = TRUE;

                    // chamberPath = (UNICODE_STRING)CONCAT142(chamberPath._2_14_, fileNameLength - 2);
                    // chamberData._16_16_ = ZEXT816(0);
                    // chamberData._0_16_ = ZEXT816(&chamberPath);
                    chamberPath.Length = fileNameLength - 2;
                    chamberData.ChamberId = NULL;
                    chamberData.ChamberType = 0;
                    chamberData.InputPath = &chamberPath;
                    chamberData.SecurityDescriptor = NULL;

                    kernelStackStatus = KeExpandKernelStackAndCalloutEx(
                        FCpObtainSecurityInfoCallout,
                        &chamberData,
                        0x3000,
                        0,
                        0
                    );

                    /* If KeExpandKernelStackAndCalloutEx does not succeed, try do find the chamber and the security
                     * descriptor here now */
                    if (kernelStackStatus < 0)
                    {
                        fullPathBuffer = NULL;
                        chamberIdStr = NULL;
                        chamberId = NULL;
                        if (chamberPath.Length != 0)
                        {
                            /* Get security descriptor and chamber ID for this path */
                            chamberData.Status = StSecGetSecurityDescriptor(
                                &chamberPath,
                                securityDescriptor,
                                &chamberIdStr,
                                &accessMask
                            );
                            chamberId = chamberIdStr;
                            chamberData.ChamberType = accessMask;

                            /* If no chamber ID explicitly found, check for default chambers */
                            if ((chamberData.Status < 0) || (chamberIdStr != NULL))
                            {
                                if ((chamberData.Status < 0) && ((Microsoft_Windows_FileCryptEnableBits & 1) != 0))
                                {
                                    McTemplateK0d_EtwWriteTransfer(&chamberPath, &GetSecurityDescriptorFailure,
                                                                   &chamberIdStr, chamberData.Status);

                                    chamberData.ChamberType = accessMask;
                                }
                            }
                            else
                            {
                                if ((gFCFlags & EncryptAllFlagBit) == 0)
                                {
                                    if ((gFCFlags & EncryptMediaFlagBit) != 0)
                                    {
                                        /* Check if path is in Music/Pictures/Videos special folders */
                                        result = RtlPrefixUnicodeString(&gMusicPath, &chamberPath, '\x01');

                                        /* Not Music chamber */
                                        if (result == '\0')
                                        {
                                            result = RtlPrefixUnicodeString(&gPicturesPath, &chamberPath, '\x01');

                                            /* If Not Pictures chamber */
                                            if (result == '\0')
                                            {
                                                result = RtlPrefixUnicodeString(&gVideosPath, &chamberPath, '\x01');
                                                chamberIdStr = L"VideosChamber";

                                                /* Not Videos chamber */
                                                if (result == '\0')
                                                {
                                                    chamberIdStr = chamberId;
                                                }
                                            }
                                            else
                                            {
                                                chamberIdStr = L"PicturesChamber";
                                            }
                                        }
                                        else
                                        {
                                            chamberIdStr = L"MusicChamber";
                                        }
                                        chamberData.ChamberType = 1;
                                        accessMask = 1;
                                        chamberId = chamberIdStr;
                                    }
                                }
                                else
                                {
                                    /* If EncryptAll is ON, use global chamber */
                                    chamberIdStr = L"{0b7992da-c5e6-41e3-b24f-55419b997a15}";
                                    chamberData.ChamberType = 1;
                                    accessMask = 1;
                                    chamberId = L"{0b7992da-c5e6-41e3-b24f-55419b997a15}";
                                }
                            }
                        }
                    }
                    else
                    {
                        /* If KeExpandKernelStackAndCalloutEx succeeds */
                        securityDescriptor = chamberData.SecurityDescriptor;
                        chamberIdStr = chamberData.ChamberId;
                        accessMask = chamberData.ChamberType;
                        chamberId = chamberData.ChamberId;
                    }
                    if (-1 < chamberData.Status)
                    {
                        chamberData.Status = STATUS_SUCCESS;
                        if (volumeContext->VerificationNeeded == FALSE)
                        {
                        FCPreCreate_access_not_modified:
                            isAccessModified = FALSE;
                        }
                        else
                        {
                            callbackData = Data;
                            eventParam1 = securityDescriptor;
                            chamberData.Status = FCpAccessCheck(Data, securityDescriptor, &accessMask);

                            if (-1 < chamberData.Status)
                            {
                                goto FCPreCreate_access_not_modified;
                            }

                            /* If access denied, adjust access or block operation */
                            if (chamberData.Status == STATUS_ACCESS_DENIED)
                            {
                                eventParam1 = fileCreateOptions;
                                eventParam3 = (PVOID)(ulonglong)(fileCreateOptions & 0xffffff);

                                fileCreateOptions = (Data->Iopb->Parameters).Create.Options;
                                fileCreateOptionsHighByte = fileCreateOptions >> 0x18;
                                callbackData = fileCreateOptionsHighByte;

                                /* Check if we can adjust the operation to make it succeed */
                                if ((fileCreateOptionsHighByte - 3 & 0xfffffffd) != 0)
                                {
                                    if ((fileCreateOptionsHighByte == 2) && ((fileCreateOptions & 1) != 0))
                                    {
                                        /* Object Name already exists */
                                        chamberData.Status = STATUS_OBJECT_NAME_COLLISION;
                                        goto FCPreCreate_return_no_post_op;
                                    }
                                    goto FCPreCreate_access_not_modified_2;
                                }
                                newCreateOptions = FILE_OVERWRITE;
                                if (fileCreateOptionsHighByte != 5)
                                {
                                    newCreateOptions = FILE_OPEN;
                                }
                                /* Setting the high 8 bits which contain the CreateOptions flags
                                   See fltKernel.h _FLT_PARAMETERS */
                                (Data->Iopb->Parameters).Create.Options =
                                    newCreateOptions << 0x18 | fileCreateOptions & 0xffffff;

                                eventParam3 = &accessMask;
                                eventParam1 = securityDescriptor;

                                /* Try access check again with modified options */
                                chamberData.Status = FCpAccessCheck(Data, securityDescriptor, &accessMask);

                                if (chamberData.Status != 0)
                                {
                                    goto FCPreCreate_access_not_modified_2;
                                }

                                isAccessModified = '\x01';
                                /* Mark the data as modified
                                   
                                   This section (above) did the following:
                                   1. Perform an access check using the security descriptor
                                   2. If access is denied, it tries to modify the operation (changing create disposition) to make it
                                   succeed
                                   3. If the modified operation is allowed, it marks the callback data as modified
                                   4. Otherwise, it denies the operation */
                                FltSetCallbackDataDirty(Data);
                            }
                            else
                            {
                            FCPreCreate_access_not_modified_2:
                                isAccessModified = '\0';
                            }
                            if (chamberData.Status < 0)
                            {
                                if ((Microsoft_Windows_FileCryptEnableBits & 2) != 0)
                                {
                                    McTemplateK0zd_EtwWriteTransfer(
                                        Data, eventParam1, eventParam3, chamberPath.Buffer, chamberData.Status);
                                }
                                goto FCPreCreate_return_no_post_op;
                            }
                        }
                        isMobile = FsRtlIsMobileOS();
                        if (isMobile == '\0')
                        {
                            /* For desktop OS, just set privileged mode flag SPECIAL_ENCRYPTED_OPEN on AccessState's flags */
                            if (chamberData.ChamberType - 1 < 2)
                            {
                                eventParam3 = ((Data->Iopb->Parameters).Create.SecurityContext)->AccessState;
                                (((Data->Iopb->Parameters).Create.SecurityContext)->AccessState->Flags) =
                                    (((Data->Iopb->Parameters).Create.SecurityContext)->AccessState->Flags) |
                                    SPECIAL_ENCRYPTED_OPEN;
                            }
                            if (chamberId != NULL)
                            {
                                /* Free chamber ID and return without completion context */
                                FCpFreeChamberId(chamberId);
                                chamberIdStr = NULL;
                                *CompletionContext = NULL;
                                return_status = FLT_PREOP_SUCCESS_WITH_CALLBACK;
                                chamberId = NULL;
                                goto FCPreCreate_cleanup;
                            }
                        }
                        else if (chamberId != NULL)
                        {
                            /* For mobile OS, create a completion context to pass to post-operation */
                            eventParam1 = &gPre2PostCreateContextList;

                            lookasideListEntry = ExAllocateFromNPagedLookasideList(&gPre2PostCreateContextList);

                            if (lookasideListEntry == NULL)
                            {
                                chamberData.Status = STATUS_BAD_INITIAL_STACK;
                                if ((Microsoft_Windows_FileCryptEnableBits & 1) != 0)
                                {
                                    McTemplateK0d_EtwWriteTransfer(
                                        eventParam1, &AllocationFailure, eventParam3, 0xc000009a);
                                }

                                return_status = FLT_PREOP_SUCCESS_WITH_CALLBACK;
                                goto FCPreCreate_cleanup;
                            }
                            lookasideListEntry->ChamberId = chamberId;
                            lookasideListEntry->ChamberType = chamberData.ChamberType;
                            lookasideListEntry->IsAccessModified = isAccessModified;
                        }
                        *CompletionContext = lookasideListEntry;
                        goto FCPreCreate_cleanup;
                    }
                    isChamberPathSet = TRUE;
                    if ((Microsoft_Windows_FileCryptEnableBits & 1) != 0)
                    {
                        errorEventDescriptor = &ObtainSdAndChamberIdFailure;
                        isChamberPathSet = TRUE;

                        goto FCPreCreate_log_before_return;
                    }
                }
            }
        }
    }
FCPreCreate_return_no_post_op:
    /* Only way to get here is with a goto after some sort of failure.
     * The return status will be changed later to FLT_PREOP_COMPLETE.
     */
    return_status = FLT_PREOP_SUCCESS_WITH_CALLBACK;
    lookasideListEntry = NULL;
FCPreCreate_cleanup:
    if (volumeContext != NULL)
    {
        FltReleaseContext(volumeContext);
    }
    if (fileNameInfo != NULL)
    {
        FltReleaseFileNameInformation(fileNameInfo);
    }
    if (isChamberPathSet)
    {
        ExFreePoolWithTag(chamberPath.Buffer, POOL_TAG_FCnf);
        //chamberPath = (UNICODE_STRING)((undefined [16])chamberPath & (undefined [16])0xffffffff00000000);
        chamberPath.Length = 0;
        chamberPath.MaximumLength = 0;
    }
    eventParam1 = securityDescriptor;
    if (securityDescriptor != NULL)
    {
        ExFreePoolWithTag(securityDescriptor, POOL_TAG_STsp);
    }
    if (chamberData.Status < 0)
    {
        if (chamberId != NULL)
        {
            FCpFreeChamberId(chamberId);
            eventParam1 = chamberId;
        }
        if (lookasideListEntry != NULL)
        {
            eventParam1 = &gPre2PostCreateContextList;
            ExFreeToNPagedLookasideList(&gPre2PostCreateContextList, lookasideListEntry);
        }
        /* Returning FLT_PREOP_COMPLETE must be accompanied by an IoStatus set */
        (Data->IoStatus).Status = chamberData.Status;
        (Data->IoStatus).Information = 0;
        /* When this routine returns FLT_PREOP_COMPLETE, FltMgr won't send the I/O operation to any
           minifilter drivers below the caller in the driver stack or to the file system. In this case,
           FltMgr only calls the post-operation callback routines of the minifilter drivers above the caller
           in the driver stack. */
        return_status = FLT_PREOP_COMPLETE;

        if ((Microsoft_Windows_FileCryptEnableBits & 2) != 0)
        {
            McTemplateK0d_EtwWriteTransfer(eventParam1, &PreCreateFailure, eventParam3, chamberData.Status);
        }
    }

    return return_status;
}


/* This function:
 * 
 * 1. Determins if the file being read is encrypted
 * 2. Sets up the necessary context for decryption
 * 3. Decides whether a post-operation callback is needed
 */
FLT_PREOP_CALLBACK_STATUS
FCPreRead(
    PFLT_CALLBACK_DATA CallbackData,
    PCFLT_RELATED_OBJECTS FltObjects,
    PVOID* CompletionContext
)
{
    NTSTATUS status;
    PCUSTOM_FC_READ_CONTEXT lookasideListEntry = NULL;
    PVOID eventParam = NULL;
    FLT_PREOP_CALLBACK_STATUS return_status;
    PFLT_CONTEXT* contextSetter;
    PCUSTOM_FC_VOLUME_CONTEXT volumeContext = NULL;
    PCUSTOM_FC_STREAM_CONTEXT streamContext = NULL;
    ULONG readLength = (CallbackData->Iopb->Parameters).Read.Length;

    status = FltGetStreamContext(FltObjects->Instance, FltObjects->FileObject, streamContext);

    /* The condition checks if either the FltGetStreamContext has failed, 
     * minifilters should be skipped (FO_BYPASS_IO_ENABLED), or that the length is zero */
    if (
        status < 0 ||
        (FltObjects->FileObject != NULL && (FltObjects->FileObject->Flags & FO_BYPASS_IO_ENABLED) != 0 || readLength == 0)
    )
    {
        return_status = FLT_PREOP_SUCCESS_NO_CALLBACK;
        goto FCPreRead_cleanup_and_return;
    }

    status = FltGetVolumeContext(FltObjects->Filter, FltObjects->Volume, volumeContext);

    if (status < 0)
    {
        if ((Microsoft_Windows_FileCryptEnableBits & 1) != 0)
        {
            McTemplateK0d_EtwWriteTransfer(FltObjects->Filter, &GetVolumeContextFailure, volumeContext, status);
        }
    }
    else
    {
        /* To prepare for the actual decryption that will occur in the post-read operation, setup the contexts: */
        lookasideListEntry = ExAllocateFromNPagedLookasideList(&gPre2PostIoContextList);

        if (lookasideListEntry == NULL)
        {
            status = STATUS_INSUFFICIENT_RESOURCES;
            return_status = FLT_PREOP_COMPLETE;

            if ((Microsoft_Windows_FileCryptEnableBits & 1) != 0)
            {
                McTemplateK0d_EtwWriteTransfer(
                    &gPre2PostIoContextList, &AllocationFailure, contextSetter, STATUS_INSUFFICIENT_RESOURCES);
            }
            goto FCPreRead_cleanup_and_return;
        }
        eventParam = CallbackData;
        /* Sets up zeroing offset, this is important for security, as it ensures that sensitive data buffers
           are properly zeroed out after use to prevent data leakage */
        status = FltSetFsZeroingOffsetRequired(CallbackData);
        if (-1 < status)
        {
            eventParam = CallbackData;

            FltSetCallbackDataDirty(CallbackData);

            lookasideListEntry->VolumeContext = volumeContext;
            lookasideListEntry->StreamContext = streamContext;
            *CompletionContext = lookasideListEntry;

            return_status = FLT_PREOP_SUCCESS_WITH_CALLBACK;

            goto FCPreRead_cleanup_and_return;
        }
    }
    return_status = FLT_PREOP_COMPLETE;
FCPreRead_cleanup_and_return:
    if (return_status != FLT_PREOP_SUCCESS_WITH_CALLBACK)
    {
        if (lookasideListEntry != NULL)
        {
            ExFreeToNPagedLookasideList(&gPre2PostIoContextList, lookasideListEntry);
        }
        if (volumeContext != NULL)
        {
            FltReleaseContext(volumeContext);
        }
        eventParam = streamContext;
        if (streamContext != NULL)
        {
            FltReleaseContext(streamContext);
        }
    }

    if (return_status == FLT_PREOP_COMPLETE)
    {
        (CallbackData->IoStatus).Status = status;
        (CallbackData->IoStatus).Information = 0;
    }

    if ((status < 0) && ((Microsoft_Windows_FileCryptEnableBits & 2) != 0))
    {
        McTemplateK0d_EtwWriteTransfer(eventParam, &PreReadFailure, contextSetter, status);
    }

    return return_status;
}


/* This function checks for the existence of a special marker file on a volume to determine if the
 * volume has been "paired" with a Windows application */
NTSTATUS
FCpRetrieveAppPairingId(
    PCFLT_RELATED_OBJECTS FltObjects
)
{
    NTSTATUS strAppendStatus;
    NTSTATUS status;
    ULONG volumeNameLength = 0;
    UNICODE_STRING volumeName = {0, 0, NULL};
    PFILE_OBJECT fileObject = NULL;
    HANDLE fileHandle = NULL;
    LARGE_INTEGER byteOffset;
    byteOffset.QuadPart = 0;
    OBJECT_ATTRIBUTES objectAttributes;
    IO_STATUS_BLOCK ioStatusBlock = {0, 0};
    PVOID fileBuffer;
    bool fileInUse = false;

    status = FltGetVolumeName(FltObjects->Volume, NULL, &volumeNameLength);

    if (status == STATUS_BUFFER_TOO_SMALL)
    {
        volumeNameLength = volumeNameLength + 0x5c;
        volumeName.Buffer = ExAllocatePool2(0x100, volumeNameLength, POOL_TAG_FCnv);

        if (volumeName.Buffer != NULL)
        {
            // volumeName._0_4_ = CONCAT22((undefined2)volumeNameLength, volumeName.Length);
            // volumeName._0_8_ = volumeName._0_8_ & 0xffffffff00000000 | (ulonglong)volumeName._0_4_;
            volumeName.MaximumLength = volumeNameLength;

            status = FltGetVolumeName(FltObjects->Volume, &volumeName,NULL);

            if ((-1 < status) &&
                (strAppendStatus =
                    RtlAppendUnicodeToString(&volumeName, L"\\System Volume Information\\WPAppSettings.dat"),
                    -1 < strAppendStatus))
            {
                // objectAttributes._0_16_ = CONCAT124(objectAttributes._4_12_, 0x30);
                // objectAttributes._0_16_ = objectAttributes._0_16_ & (undefined [16])0xffffffffffffffff;
                // objectAttributes._32_16_ = ZEXT816(0);
                InitializeObjectAttributes(
                    &objectAttributes,
                    NULL,
                    0,
                    NULL,
                    NULL
                )

                status = FltCreateFileEx(
                    FltObjects->Filter,
                    FltObjects->Instance,
                    &fileHandle,
                    &fileObject,
                    FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES | FILE_READ_EA | FILE_READ_DATA | FILE_LIST_DIRECTORY,
                    &objectAttributes,
                    &ioStatusBlock,
                    NULL,
                    0,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    1,
                    FILE_NON_DIRECTORY_FILE,
                    NULL,
                    0,
                    0
                );

                if (-1 < status)
                {
                    /* If the file exists, it reads a small amount of data (20 bytes) */
                    status = FltReadFile(
                        FltObjects->Instance,
                        fileObject,
                        &byteOffset,
                        0x14,
                        &fileBuffer,
                        0,
                        NULL,
                        NULL,
                        NULL
                    );

                    fileInUse = true;
                }
            }
        }
    }

    if (volumeName.Buffer != NULL)
    {
        ExFreePoolWithTag(volumeName.Buffer, POOL_TAG_FCnv);
        volumeName.Buffer = NULL;
    }
    if (fileObject != NULL)
    {
        ObfDereferenceObject(fileObject);
        fileObject = NULL;
    }
    if (fileInUse)
    {
        FltClose(fileHandle);
    }

    return status;
}

FLT_PREOP_CALLBACK_STATUS
FCPreWrite(
    PFLT_CALLBACK_DATA CallbackData,
    PCFLT_RELATED_OBJECTS FltObjects,
    PVOID* CompletionContext
)
{
    UCHAR allocationType;
    NTSTATUS ioStatus;
    PUCHAR ciphertext = NULL;
    PMDL mdl = NULL;
    PVOID setter;
    PCUSTOM_FC_WRITE_CONTEXT lookasideEntry = NULL;
    PNPAGED_LOOKASIDE_LIST shadowBufferPtr;
    NPAGED_LOOKASIDE_LIST* generalPtr;
    EVENT_DESCRIPTOR* eventDescriptor;
    uint totalSizeToEncrypt;
    FLT_PREOP_CALLBACK_STATUS return_status = FLT_PREOP_SUCCESS_NO_CALLBACK;
    UCHAR allocationTypeCopy = '\0';
    PCUSTOM_FC_VOLUME_CONTEXT volumeContext = NULL;
    PCUSTOM_FC_STREAM_CONTEXT streamContext = NULL;
    PFLT_IO_PARAMETER_BLOCK ioqb = CallbackData->Iopb;
    ULONG writeLength = (ioqb->Parameters).Write.Length;
    PUCHAR plaintext;

    /* This function intercepts write operations before they reach the disk.
     * It performs encryption on the fly without application awareness.
     * It replaces the original write buffer with an encrypted version, making the File System write
     * encrypted data to disk.
     */

    setter = &streamContext;
    generalPtr = (NPAGED_LOOKASIDE_LIST*)FltObjects->Instance;
    ioStatus = FltGetStreamContext((PFLT_INSTANCE)generalPtr, FltObjects->FileObject, setter);
    
    /* The function exits early if:
     * Stream context retrieval failed (file isn't encrypted)
     * The FO_BYPASS_IO_ENABLED flag is set (skip minifilters)
     * The write length is zero (nothing to encrypt)
     */
    if (ioStatus < 0 || FltObjects->FileObject != NULL && (FltObjects->FileObject->Flags & FO_BYPASS_IO_ENABLED) != 0)
    {
        return_status = FLT_PREOP_SUCCESS_NO_CALLBACK;
        goto FCPreWrite_cleanup_and_return;
    }
    
    if (writeLength == 0)
    {
        goto FCPreWrite_cleanup_and_return;
    }

    setter = &volumeContext;
    generalPtr = (NPAGED_LOOKASIDE_LIST*)FltObjects->Filter;
    ioStatus = FltGetVolumeContext((PFLT_FILTER)generalPtr, FltObjects->Volume, setter);

    if (ioStatus < 0)
    {
        if ((Microsoft_Windows_FileCryptEnableBits & 1) != 0)
        {
            McTemplateK0d_EtwWriteTransfer(generalPtr, &GetVolumeContextFailure, setter, ioStatus);
        }
        return_status = FLT_PREOP_COMPLETE;
        goto FCPreWrite_cleanup_and_return;
    }
    /* This calculation rounds up the write size to a multiple of the sector size, which is necessary
     * for block cipher encryption */
    totalSizeToEncrypt = (writeLength - 1) + volumeContext->SectorSize & -volumeContext->SectorSize;
    if (totalSizeToEncrypt < 0x10001)
    {
        /* For small writes (< 64KB), allocate from lookaside list */
        shadowBufferPtr = &gShadowBufferList;
        ciphertext = ExAllocateFromNPagedLookasideList(&gShadowBufferList);
        allocationType = '\x01';
        generalPtr = shadowBufferPtr;
    }
    else
    {
        /* For large writes, allocate from pool */
        generalPtr = (NPAGED_LOOKASIDE_LIST*)0x40;
        setter = (CUSTOM_FC_VOLUME_CONTEXT**)0x62734346;
        ciphertext = ExAllocatePool2(0x40, totalSizeToEncrypt, POOL_TAG_FCsb);
        allocationType = '\x02';
    }
    if (ciphertext == NULL)
    {
    FCPreWrite_set_allocation_failure_status:
        ioStatus = STATUS_INSUFFICIENT_RESOURCES;
        return_status = FLT_PREOP_COMPLETE;
        if ((Microsoft_Windows_FileCryptEnableBits & 1) == 0)
        {
            goto FCPreWrite_cleanup_and_return;
        }
        eventDescriptor = &AllocationFailure;
    }
    else
    {
        setter = NULL;
        generalPtr = ciphertext;
        /* this is a call to IoAllocateMdl
           
           When the driver intercepts a write operation, it needs to replace the original plaintext data
           with encrypted data. The original data might be described by an MDL (if present) or direct
           buffer. By creating a new MDL for the encrypted buffer, the driver can redirect the I/O operation
           to use the encrypted data instead. */
        // mdl = (PMDL)(*(code*)0xa8fc)(ciphertext, totalSizeToEncrypt, 0, 0, 0);
        mdl = IoAllocateMdl(ciphertext, totalSizeToEncrypt, 0, 0, 0);
        allocationTypeCopy = allocationType;

        if (mdl == NULL)
        {
            goto FCPreWrite_set_allocation_failure_status;
        }

        /* This is a call to MmBuildMdlForNonPagedPool */
        //(*(code*)0xa8c8)(mdl);
        MmBuildMdlForNonPagedPool(mdl);
        /* This is a call to MmProbeAndLockPages */
        //(*(code*)0xa996)(mdl, 1);
        MmMdlPageContentsState(mdl, 1);
        generalPtr = (NPAGED_LOOKASIDE_LIST*)(ioqb->Parameters).Others.Argument5;

        if (generalPtr == NULL)
        {
            plaintext = (PUCHAR)(ioqb->Parameters).Write.MdlAddress;
        FCPreWrite_encrypt:
            setter = plaintext;
            ioStatus = FCpEncEncrypt(
                &volumeContext->BcryptAlgHandle,
                &streamContext->KeyData,
                plaintext,
                ciphertext,
                totalSizeToEncrypt,
                ioqb->Parameters.Write.WriteBuffer
            );
            generalPtr = &gPre2PostIoContextList;
            lookasideEntry = ExAllocateFromNPagedLookasideList(&gPre2PostIoContextList);

            if (lookasideEntry != NULL)
            {
                /* Replace original write buffer with encrypted buffer */
                (ioqb->Parameters).Write.MdlAddress = ciphertext;
                (ioqb->Parameters).Others.Argument5 = mdl;
                generalPtr = (NPAGED_LOOKASIDE_LIST*)CallbackData;
                /* Mark callback data as modified */
                FltSetCallbackDataDirty(CallbackData);
                /*  Set up completion context */
                lookasideEntry->Ciphertext = ciphertext;
                lookasideEntry->AllocationType = allocationType;
                lookasideEntry->VolumeContext = volumeContext;
                lookasideEntry->StreamContext = streamContext;
                *CompletionContext = lookasideEntry;
                return_status = FLT_PREOP_SUCCESS_WITH_CALLBACK;
                goto FCPreWrite_cleanup_and_return;
            }
            goto FCPreWrite_set_allocation_failure_status;
        }
        if (((PMDL)generalPtr)->MdlFlags & (MDL_MAPPED_TO_SYSTEM_VA | MDL_SOURCE_IS_NONPAGED_POOL) == 0)
        {
            /* Map MDL to get virtual address */
            setter = MmMapLockedPagesSpecifyCache(
                (PMDLX)generalPtr,
                '\0',
                MmCached,
                NULL,
                0,
                ExDefaultMdlProtection | 0x40000010
            );
        }
        else
        {
            setter = *(PVOID*)&(((PFLT_CALLBACK_DATA)generalPtr)->IoStatus).Status;
        }
        plaintext = (PUCHAR)setter;
        if ((CUSTOM_FC_VOLUME_CONTEXT**)setter != NULL)
        {
            goto FCPreWrite_encrypt;
        }
        ioStatus = STATUS_INSUFFICIENT_RESOURCES;
        return_status = FLT_PREOP_COMPLETE;
        if ((Microsoft_Windows_FileCryptEnableBits & 1) == 0)
        {
            goto FCPreWrite_cleanup_and_return;
        }
        eventDescriptor = &GetSystemAddressFailure;
    }
    return_status = FLT_PREOP_COMPLETE;
    ioStatus = STATUS_INSUFFICIENT_RESOURCES;
    McTemplateK0d_EtwWriteTransfer(generalPtr, eventDescriptor, setter, 0xc000009a);
FCPreWrite_cleanup_and_return:
    if (return_status != FLT_PREOP_SUCCESS_WITH_CALLBACK)
    {
        if ((PFLT_CALLBACK_DATA)ciphertext != NULL)
        {
            setter = (PVOID)((ulonglong)setter & 0xffffffffffffff00 | (ulonglong)allocationTypeCopy);
            FCFreeShadowBuffer(generalPtr, ciphertext, allocationTypeCopy);
        }
        if (mdl != NULL)
        {
            IoFreeMdl(mdl);
        }
        if (volumeContext != NULL)
        {
            FltReleaseContext(volumeContext);
        }
        if (streamContext != NULL)
        {
            FltReleaseContext(streamContext);
        }
        if (lookasideEntry != NULL)
        {
            ExFreeToNPagedLookasideList(&gPre2PostIoContextList, lookasideEntry);
        }
    }
    if (return_status == FLT_PREOP_COMPLETE)
    {
        (CallbackData->IoStatus).Status = ioStatus;
        (CallbackData->IoStatus).Information = 0;
        if ((Microsoft_Windows_FileCryptEnableBits & 2) != 0)
        {
            McTemplateK0d_EtwWriteTransfer(Microsoft_Windows_FileCryptEnableBits, &PreWriteFailure, setter,
                                           ioStatus);
        }
    }
    return return_status;
}


/* WARNING: Could not reconcile some variable overlaps */

NTSTATUS
FCReadDriverParameters(
    PUNICODE_STRING PRegistryPath
)
{
    NTSTATUS status;
    ULONG resultLength = 0;
    HANDLE keyHandle = NULL;
    UNICODE_STRING registryValueName = {0, 0, NULL};
    OBJECT_ATTRIBUTES ObjectAttributes;
    KEY_VALUE_PARTIAL_INFORMATION keyValueInfo;

    // ObjectAttributes._0_16_ = CONCAT124(SUB1612(ZEXT816(0) >> 0x20, 0), 0x30);
    // ObjectAttributes._0_16_ = ObjectAttributes._0_16_ & (undefined [16])0xffffffffffffffff;
    // ObjectAttributes._16_16_ = ZEXT1216(CONCAT48(0x240, PRegistryPath));
    // ObjectAttributes._32_16_ = ZEXT816(0);
    InitializeObjectAttributes(
        &ObjectAttributes,
        PRegistryPath,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
        NULL,
        NULL
    )

    status = ZwOpenKey(&keyHandle, 0x20019, &ObjectAttributes);

    if (-1 < status)
    {
        /* If debug */
        if (FcDebugTraceLevel == 0)
        {
            RtlInitUnicodeString(&registryValueName, L"DebugTraceLevel");
            status = ZwQueryValueKey(
                keyHandle,
                &registryValueName,
                KeyValuePartialInformation,
                &keyValueInfo,
                0x14,
                &resultLength
            );

            if (-1 < status)
            {
                /* The 4-byte value in the Data field (4 offest from the 12th byte) is a DWORD that contains the
                 * actual registry value */

                FcDebugTraceLevel = keyValueInfo.Data[0];
            }
        }
        RtlInitUnicodeString(&registryValueName, L"EncryptMedia");
        status = ZwQueryValueKey(
            keyHandle,
            &registryValueName,
            KeyValuePartialInformation,
            &keyValueInfo,
            0x14,
            &resultLength
        );

        if (-1 < status)
        {
            if (keyValueInfo.Data[0] == 0)
            {
                gFCFlags = gFCFlags & 0xfffffffd;
            }
            else
            {
                gFCFlags = gFCFlags | EncryptMediaFlagBit;
            }
        }
        RtlInitUnicodeString(&registryValueName, L"EncryptAll");
        status = ZwQueryValueKey(
            keyHandle,
            &registryValueName,
            KeyValuePartialInformation,
            &keyValueInfo,
            0x14
            , &resultLength
        );

        if (-1 < status)
        {
            if (keyValueInfo.Data[0] == 0)
            {
                gFCFlags = gFCFlags & 0xfffffffb;
            }
            else
            {
                gFCFlags = gFCFlags | EncryptAllFlagBit;
            }
        }
        RtlInitUnicodeString(&registryValueName, L"BypassAccessChecks");
        status = ZwQueryValueKey(
            keyHandle,
            &registryValueName,
            KeyValuePartialInformation,
            &keyValueInfo,
            0x14,
            &resultLength
        );

        if (-1 < status)
        {
            if (keyValueInfo.Data[0] == 0)
            {
                gFCFlags = gFCFlags & 0xffffffef;
            }
            else
            {
                gFCFlags = gFCFlags | BypassAccessChecksFlagBit;
            }
        }
        RtlInitUnicodeString(&registryValueName, L"FilterEmulatedExternalDrive");
        status = ZwQueryValueKey(
            keyHandle,
            &registryValueName,
            KeyValuePartialInformation,
            &keyValueInfo,
            0x14,
            &resultLength
        );

        if (-1 < status)
        {
            if (keyValueInfo.Data[0] == 0)
            {
                gFCFlags = gFCFlags & 0xfffffff7;
            }
            else
            {
                gFCFlags = gFCFlags | FilterEmulatedExternalDriveFlagBit;
            }
        }
    }

    if (keyHandle != NULL)
    {
        ZwClose(keyHandle);
    }

    return status;
}


const FLT_OPERATION_REGISTRATION Callbacks[] = {
    {
        IRP_MJ_CREATE,
        0,
        FCPreCreate,
        FCPostCreate
    },
    {
        IRP_MJ_OPERATION_END,
        0,
        NULL,
        NULL
    }
};

const FLT_OPERATION_REGISTRATION CallbacksMobile[] = {
    {
        IRP_MJ_CREATE,
        0,
        FCPreCreate,
        FCPostCreate
    },
    {
        IRP_MJ_READ,
        0,
        FCPreRead,
        FCPostRead
    },
    {
        IRP_MJ_WRITE,
        0,
        FCPreWrite,
        FCPostWrite
    },
    {
        IRP_MJ_OPERATION_END,
        0,
        NULL,
        NULL
    }
};

const FLT_CONTEXT_REGISTRATION ContextRegistration[] = {
    {
        FLT_VOLUME_CONTEXT,
        0,
        FCCleanupVolumeContext,
        sizeof(CUSTOM_FC_VOLUME_CONTEXT),
        POOL_TAG_FCvx,
        NULL,
        NULL,
        NULL
    },
    {
        FLT_STREAM_CONTEXT,
        0,
        FCCleanupStreamContext,
        sizeof(CUSTOM_FC_STREAM_CONTEXT),
        POOL_TAG_FCsx,
        NULL,
        NULL,
        NULL
    },
    {
        FLT_CONTEXT_END,
        0,
        NULL,
        0,
        0,
        NULL,
        NULL,
        NULL
    }
};

FLT_REGISTRATION FilterRegistration = {
    sizeof(FLT_REGISTRATION),
    FLT_REGISTRATION_VERSION,
    0,
    ContextRegistration,
    Callbacks,
    FCFilterUnload,
    FCInstanceSetup,
    FCInstanceQueryTeardown,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL
};

NTSTATUS
DriverEntry(
    PDRIVER_OBJECT PDriverObject,
    PUNICODE_STRING PRegistryPath
)
{
    BOOLEAN isMobileOS;
    NTSTATUS osVersionStatus;
    NTSTATUS status;
    PVOID event1;
    USHORT regPathLengthPlus2;
    PVOID event2;
    ULONG flags;
    OSVERSIONINFOW lpVersionInfo;
    bool cleanupLists = false;
    bool driverInitialized = false;
    bool driverRegistered = false;
    bool listsInitialized = false;

    event2 = (PVOID)0x110;

    memset(&lpVersionInfo.dwMajorVersion, 0, 0x110);
    lpVersionInfo.dwOSVersionInfoSize = 0x114;

    osVersionStatus = RtlGetVersion(&lpVersionInfo);

    /* Check if OS is later than Windows 7 (Win7 => 6.1, Win8 => 6.2, Win8.1 => 6.3, Win10 => 10) */
    if (-1 < osVersionStatus &&
        (
            6 < lpVersionInfo.dwMajorVersion || // Later than Windows 7
            lpVersionInfo.dwMajorVersion == 6 && 1 < lpVersionInfo.dwMinorVersion // Windows 7 or 8
        )
    )
    {
        ExDefaultNonPagedPoolType = NonPagedPoolNx;
        ExDefaultMdlProtection = MdlMappingNoExecute;
    }

    /* Registers the driver for Event Tracing (ETW) */
    McGenEventRegister_EtwRegister();
    event1 = PRegistryPath;

    /* Registry Path is: Computer\HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\FileCrypt */
    status = FCReadDriverParameters(PRegistryPath);
    listsInitialized = false;

    if (status < 0)
    {
    DriverEntry_cleanup:
        cleanupLists = listsInitialized;
        if (-1 < status)
        {
            goto DriverEntry_return;
        }
    }
    else
    {
        event1 = (PVOID)0x40;
        event2 = (undefined8*)0x6e694346;

        regPathLengthPlus2 = PRegistryPath->Length + 2;
        gRegistryPath.Buffer = ExAllocatePool2(0x40, regPathLengthPlus2, POOL_TAG_FCin);

        if (gRegistryPath.Buffer != NULL)
        {
            gRegistryPath.MaximumLength = regPathLengthPlus2;
            RtlCopyUnicodeString(&gRegistryPath, PRegistryPath);

            flags = ExDefaultNonPagedPoolType | NonPagedPoolNx;
            gRegistryPath.Buffer[PRegistryPath->Length >> 1] = L'\0';

            /* gPre2PostIoContextList is used to pass encryption data between the the pre and post operations of
             * Read and Write */
            ExInitializeNPagedLookasideList(
                &gPre2PostIoContextList,
                NULL,
                NULL,
                flags,
                0x20,
                POOL_TAG_FCpp,
                0
            );

            /* gPre2PostCreateContextList is used to pass a CompletionContext between the Pre and Post
               operations of the Create callback */
            ExInitializeNPagedLookasideList(
                &gPre2PostCreateContextList,
                NULL,
                NULL,
                ExDefaultNonPagedPoolType | NonPagedPoolNx,
                0x10,
                POOL_TAG_FCpp,
                0
            );

            listsInitialized = true;
            ExInitializeNPagedLookasideList(
                &gShadowBufferList,
                NULL,
                NULL,
                ExDefaultNonPagedPoolType | NonPagedPoolNx,
                0x10000,
                POOL_TAG_FCsb,
                0
            );

            isMobileOS = FsRtlIsMobileOS();
            if (isMobileOS == TRUE)
            {
                /* Swap the normal callbacks with ones specific for mobile */
                FilterRegistration.OperationRegistration = CallbacksMobile;
            }

            event2 = &gFilterHandle;
            status = FltRegisterFilter(PDriverObject, &FilterRegistration, &gFilterHandle);
            event1 = PDriverObject;

            if (-1 < status)
            {
                status = StSecInitialize(PDriverObject);

                event1 = PDriverObject;
                driverRegistered = true;
                if (-1 < status)
                {
                    event1 = gFilterHandle;
                    status = FltStartFiltering(gFilterHandle);
                    driverInitialized = true;
                    driverRegistered = true;
                }
            }

            goto DriverEntry_cleanup;
        }

        status = STATUS_INSUFFICIENT_RESOURCES;
    }
    if ((Microsoft_Windows_FileCryptEnableBits & 1) != 0)
    {
        McTemplateK0d_EtwWriteTransfer(event1, &DriverEntryFailure, event2, status);
    }
    if (cleanupLists)
    {
        ExDeleteNPagedLookasideList(&gPre2PostIoContextList);
        ExDeleteNPagedLookasideList(&gPre2PostCreateContextList);
        ExDeleteNPagedLookasideList(&gShadowBufferList);
    }
    if (gRegistryPath.Buffer != NULL)
    {
        ExFreePoolWithTag(gRegistryPath.Buffer,POOL_TAG_FCin);
    }
    if (driverInitialized)
    {
        StSecDeinitialize();
    }
    if (driverRegistered)
    {
        FltUnregisterFilter(gFilterHandle);
    }

DriverEntry_return:
    return STATUS_SUCCESS;
}
