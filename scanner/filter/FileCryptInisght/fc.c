#include "fc.h"

#include "mc.h"

VOID
FCCleanupStreamContext (
    PCUSTOM_FC_STREAM_CONTEXT StreamContext
    )
{
    if (StreamContext->ChamberId != NULL) {
        FCpFreeChamberId(StreamContext->ChamberId);
        StreamContext->ChamberId = NULL;
    }
    
    FCpEncStreamCleanup(&StreamContext->KeyData);
}

VOID
FCCleanupVolumeContext (
    PCUSTOM_FC_VOLUME_CONTEXT VolumeContext
    )
{
    PWCH volumeNameBuffer = (VolumeContext->DeviceName).Buffer;
    
    if (volumeNameBuffer != NULL) {
        ExFreePoolWithTag(volumeNameBuffer,0x766e4346);
        (VolumeContext->DeviceName).Buffer = NULL;
    }
    
    if (VolumeContext->EncryptionEnabled != 0) {
        FCpEncVolumeCleanup(&(VolumeContext->BcryptAlgHandle).BcryptAlgHandle);
        VolumeContext->EncryptionEnabled = 0;
    }
}