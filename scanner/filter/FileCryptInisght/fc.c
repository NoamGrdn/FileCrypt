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
    PVOID nullPtr = NULL;
    PFLT_VOLUME_PROPERTIES fltObjectVolProps = NULL;
    PFILE_FS_VOLUME_INFORMATION fsVolumeInfo = NULL;
    PDEVICE_OBJECT highestDeviceObject;
    PDEVICE_OBJECT LowerDeviceObject;
    NTSTATUS return_status = STATUS_FLT_DO_NOT_ATTACH;
    USHORT fileSystemDeviceNameLength;
    bool isNotRemovableMedia;
    bool isVolumeSdCard = false;
    ULONG fltObjectVolPropsLength = 0;
    PCUSTOM_FC_VOLUME_CONTEXT volumeContext = NULL;
    PDEVICE_OBJECT diskDeviceObject = NULL;
    PCUNICODE_STRING fileSystemDeviceName;
    IO_STATUS_BLOCK ioStatusBlock = {0, 0};
    PVPB vqb;
    PDEVICE_OBJECT vqb_deviceObject;

    status = FltGetVolumeProperties(
        FltObjects->Volume,
        fltObjectVolProps,
        0x248,
        &fltObjectVolPropsLength
    );

    if (status < 0)
    {
        goto FCInstanceSetup_cleanup_and_return;
    }

    fltObjectVolProps = ExAllocatePool2(0x100, 0x248, POOL_TAG_FCvp);

    if (fltObjectVolProps == NULL)
    {
        goto FCInstanceSetup_cleanup_and_return;
    }

    /* Only attach to file systems,
     * Only attach to standard filesystems (RAW, NTFS, FAT and EXFAT) */
    if (
        VolumeDeviceType != FILE_DEVICE_DISK_FILE_SYSTEM ||
        1 < VolumeFilesystemType + ~FLT_FSTYPE_RAW && VolumeFilesystemType != FLT_FSTYPE_EXFAT
    )
    {
        goto FCInstanceSetup_cleanup_and_return;
    }

    /* fltKernel.h: DeviceCharacteristics bit 1 => FILE_REMOVABLE_MEDIA */
    isNotRemovableMedia = (fltObjectVolProps->DeviceCharacteristics & 1) == 0;
    fsVolumeInfo = (PFILE_FS_VOLUME_INFORMATION)nullPtr;

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

        /* Check if the VolumeLabelLength is 6,
         * if it is than compare VolumeLabel with the string "SDCARD" */
        if ((fsVolumeInfo->VolumeLabelLength & 0xfffffffe) == 0xc)
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
        status = FCpRetrieveAppPairingId(FltObjects);
        if (status < 0)
        {
        joined_r0x0001c0011463:
            /* On mobile: only attach to removable media (SD cards) */
            if (!isVolumeSdCard)
            {
                goto FCInstanceSetup_cleanup_and_return;
            }
        }
    }
    else if (isNotRemovableMedia)
    {
        goto joined_r0x0001c0011463;
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

        if (0x200 < fltObjectVolProps->SectorSize)
        {
            volumeSectorSize = fltObjectVolProps->SectorSize;
        }

        volumeContext->SectorSize = volumeSectorSize;

        status = FltGetDiskDeviceObject(FltObjects->Volume, &diskDeviceObject);

        if (-1 < status)
        {
            getDosNameStatus = RtlVolumeDeviceToDosName(diskDeviceObject, &volumeContext->DeviceName);
            if (getDosNameStatus < 0)
            {
                fileSystemDeviceName = &fltObjectVolProps->RealDeviceName;
                fileSystemDeviceNameLength = ((UNICODE_STRING*)fileSystemDeviceName)->Length;
                if (fileSystemDeviceNameLength == 0)
                {
                    fileSystemDeviceName = (PCUNICODE_STRING)&fltObjectVolProps->FileSystemDeviceName;
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
            /* if EnvVolumeStart and SetVolumeContext both succeed (that + 0x8.. & 0x8.. bit
                fuckery checks if the highest bit is set which with NTSTATUS always means error) or
               SetVolumeContext returned STATUS_FLT_CONTEXT_ALREADY_DEFINED (-0x3fe3fffe == 0xC01C0002L)
               
               => if (encryption setup went aight and set the volume / volume was already there) */
            if (
                (-1 < encryptVolumeStartStatus) &&
                (
                    (status = FltSetVolumeContext(
                            FltObjects->Volume,
                            FLT_SET_CONTEXT_KEEP_IF_EXISTS,
                            volumeContext,
                            NULL
                        ),
                        (status + 0x80000000U & 0x80000000) != 0 || (status == -0x3fe3fffe))
                )
            )
            {
                vqb = diskDeviceObject->Vpb;
                isMobileOS = FsRtlIsMobileOS();
                /* Checks if we are not on mobile and the device can persist ACLS */
                if ((isMobileOS == FALSE) && ((vqb->DeviceObject->Flags & DO_SUPPORTS_PERSISTENT_ACLS) != 0))
                {
                    volumeContext->VerificationNeeded = 0;
                }
                else
                {
                    /* Always verify on mobile */
                    volumeContext->VerificationNeeded = 1;
                    vqb_deviceObject = vqb->DeviceObject;
                    vqb_deviceObject->Flags = vqb_deviceObject->Flags | DO_SUPPORTS_PERSISTENT_ACLS;
                }
                if (((gFCFlags & FilterEmulatedExternalDriveFlagBit) != 0) && (isNotRemovableMedia))
                {
                    highestDeviceObject = IoGetAttachedDeviceReference(diskDeviceObject);

                    while (highestDeviceObject != NULL)
                    {
                        /* Apply the FILE_REMOVABLE_MEDIA characteristic to all devices in the stack
                           (fltKernel.h: _FLT_VOLUME_PROPERTIES DeviceCharacteristics) */
                        highestDeviceObject->Characteristics = highestDeviceObject->Characteristics |
                            FILE_REMOVABLE_MEDIA;
                        LowerDeviceObject = IoGetLowerDeviceObject(highestDeviceObject);
                        ObfDereferenceObject(highestDeviceObject);
                        highestDeviceObject = LowerDeviceObject;
                    }
                }

                return_status = STATUS_SUCCESS;

                /* if BypassAccessChecks is ON remove the FILE_DEVICE_SECURE_OPEN characteristic
                   (fltKernel.h: _FLT_VOLUME_PROPERTIES DeviceCharacteristics) */
                if ((gFCFlags & BypassAccessChecksFlagBit) != 0)
                {
                    diskDeviceObject->Characteristics = diskDeviceObject->Characteristics & 0xfffffeff;
                }
            }
        }
    }
FCInstanceSetup_cleanup_and_return:
    if (fltObjectVolProps != NULL)
    {
        ExFreePoolWithTag(fltObjectVolProps, POOL_TAG_FCvp);
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


// TODO
NTSTATUS
FCpEncDecrypt(
    CUSTOM_FC_BCRYPT_DATA* BcryptAlgData,
    CUSTOM_FC_BCRYPT_KEY_DATA* KeyHandle,
    PUCHAR PbInput,
    PUCHAR PbOutput,
    int TotalBytesToDecrypt,
    PVOID Parameters,
    ULONG ZeroingOffest
)
{
    NTSTATUS status;
    NTSTATUS extraout_EAX;
    ulonglong chunkSize;
    BCRYPT_KEY_HANDLE keyHandle;
    uint uVar1;
    ULONG pcbResult[2];
    CUSTOM_FC_BCRYPT_KEY_DATA* pKeyHandle;
    PUCHAR local_68;
    PVOID pbIV;
    PVOID local_58;
    uint cypherTextSize;

    uVar1 = 0;
    pcbResult[0] = 0;
    pKeyHandle = KeyHandle;
    local_68 = PbOutput;
    if ((BcryptAlgData->BlockLength == 0x10) && (ZeroingOffest != 0))
    {
        for (; TotalBytesToDecrypt != 0; TotalBytesToDecrypt = TotalBytesToDecrypt - cypherTextSize)
        {
            cypherTextSize = BcryptAlgData->EncryptionSectorSize;
            chunkSize = (ulonglong)cypherTextSize;
            keyHandle = pKeyHandle->BcryptKeyHandle;
            pbIV = Parameters;
            local_58 = Parameters;
            status = BCryptDecrypt(keyHandle, PbInput, cypherTextSize,NULL, (PUCHAR)&pbIV, BcryptAlgData->BlockLength,
                                   PbOutput,
                                   cypherTextSize, pcbResult, 0);
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
                memset(local_68 + ZeroingOffest, 0, (ulonglong)(uVar1 - ZeroingOffest));
                break;
            }
            Parameters = (PVOID)((longlong)Parameters + chunkSize);
            PbOutput = PbOutput + chunkSize;
            PbInput = PbInput + chunkSize;
        }
    }

    return extraout_EAX;
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

    status = BCryptOpenAlgorithmProvider(&AlgHandle->BcryptAlgHandle, L"AES",NULL, BCRYPT_PROV_DISPATCH);

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
    BOOLEAN isChamber;
    NTSTATUS status;
    PWCHAR chamberId;
    PUNICODE_STRING chamberPathRef;
    PSECURITY_DESCRIPTOR securityDescriptor;
    PWCHAR* chamerIdRef;
    PUNICODE_STRING local_res8 = NULL;
    PCUNICODE_STRING chamberPath = ChamberData->InputPath;
    PSECURITY_DESCRIPTOR* securityDescriptorRef = &ChamberData->SecurityDescriptor;

    /* reset ChamberId */
    ChamberData->ChamberId = NULL;

    securityDescriptor = &local_res8;

    if (securityDescriptorRef != NULL)
    {
        securityDescriptor = securityDescriptorRef;
    }
    if (chamberPath->Length == 0)
    {
        ChamberData->Status = 0;
        return;
    }

    chamerIdRef = &ChamberData->ChamberId;
    chamberPathRef = chamberPath;
    status = StSecGetSecurityDescriptor(chamberPath, securityDescriptor, chamerIdRef, &ChamberData->ChamberType);
    if (securityDescriptorRef == NULL && (chamberPathRef = local_res8, local_res8 != NULL))
    {
        ExFreePoolWithTag(local_res8, POOL_TAG_STsp);
    }
    if (status < 0)
    {
        if ((Microsoft_Windows_FileCryptEnableBits & 1) != 0)
        {
            McTemplateK0d_EtwWriteTransfer(chamberPathRef, &GetSecurityDescriptorFailure, chamerIdRef, status);
        }
        goto FCpObtainSecurityInfoCallout_return;
    }

    /* If StSecGetSecurityDescriptor succeeded, the current file/directory were succsessfuly resolved to
       a ChamberId, ChamberType and we can return.
       Otherwise, check for predetermined chambers */
    if (ChamberData->ChamberId != NULL)
    {
        goto FCpObtainSecurityInfoCallout_return;
    }

    /* if EncryptAll is ON chamberId is the global guid */
    if ((gFCFlags & EncryptAllFlagBit) != 0)
    {
        chamberId = L"{0b7992da-c5e6-41e3-b24f-55419b997a15}";
        goto FCpObtainSecurityInfoCallout_assign_chamberid_and_return;
    }
    if ((gFCFlags & EncryptMediaFlagBit) == 0)
    {
        goto FCpObtainSecurityInfoCallout_return;
    }

    isChamber = RtlPrefixUnicodeString(&gMusicPath, chamberPath, '\x01');
    if (isChamber == '\0')
    {
        isChamber = RtlPrefixUnicodeString(&gPicturesPath, chamberPath, '\x01');
        if (isChamber != '\0')
        {
            chamberId = L"PicturesChamber";
            goto FCpObtainSecurityInfoCallout_assign_chamberid_and_return;
        }
        isChamber = RtlPrefixUnicodeString(&gVideosPath, chamberPath, '\x01');
        if (isChamber != '\0')
        {
            chamberId = L"VideosChamber";
            goto FCpObtainSecurityInfoCallout_assign_chamberid_and_return;
        }
    }
    else
    {
        chamberId = L"MusicChamber";
    FCpObtainSecurityInfoCallout_assign_chamberid_and_return:
        ChamberData->ChamberId = chamberId;
    }

    ChamberData->ChamberType = 1;
FCpObtainSecurityInfoCallout_return:
    ChamberData->Status = status;
}