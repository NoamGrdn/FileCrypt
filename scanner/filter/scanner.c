/*++

Copyright (c) 1999-2002  Microsoft Corporation

Module Name:

    scanner.c

Abstract:

    This is the main module of the scanner filter.

    This filter scans the data in a file before allowing an open to proceed.  This is similar
    to what virus checkers do.

Environment:

    Kernel mode

--*/

#include <fltKernel.h>
#include <dontuse.h>
#include <suppress.h>
#include "scanuk.h"
#include "scanner.h"

#pragma prefast(disable:__WARNING_ENCODE_MEMBER_FUNCTION_POINTER, "Not valid for kernel mode drivers")

#define SCANNER_REG_TAG       'Rncs'
#define SCANNER_STRING_TAG    'Sncs'

//
//  Structure that contains all the global data structures
//  used throughout the scanner.
//

SCANNER_DATA ScannerData;

//
//  This is a static list of file name extensions files we are interested in scanning
//

PUNICODE_STRING ScannedExtensions;
ULONG ScannedExtensionCount;

//
//  The default extension to scan if not configured in the registry
//

UNICODE_STRING ScannedExtensionDefault = RTL_CONSTANT_STRING( L"doc" );

//
//  Function prototypes
//

typedef
NTSTATUS
(*PFN_IoOpenDriverRegistryKey) (
    PDRIVER_OBJECT     DriverObject,
    DRIVER_REGKEY_TYPE RegKeyType,
    ACCESS_MASK        DesiredAccess,
    ULONG              Flags,
    PHANDLE            DriverRegKey
    );

PFN_IoOpenDriverRegistryKey
ScannerGetIoOpenDriverRegistryKey (
    VOID
    );

NTSTATUS
ScannerOpenServiceParametersKey (
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING ServiceRegistryPath,
    _Out_ PHANDLE ServiceParametersKey
    );

NTSTATUS
ScannerInitializeScannedExtensions(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    );

VOID
ScannerFreeExtensions(
    );

NTSTATUS
ScannerAllocateUnicodeString (
    _Inout_ PUNICODE_STRING String
    );

VOID
ScannerFreeUnicodeString (
    _Inout_ PUNICODE_STRING String
    );

NTSTATUS
ScannerPortConnect (
    _In_ PFLT_PORT ClientPort,
    _In_opt_ PVOID ServerPortCookie,
    _In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
    _In_ ULONG SizeOfContext,
    _Outptr_result_maybenull_ PVOID *ConnectionCookie
    );

VOID
ScannerPortDisconnect (
    _In_opt_ PVOID ConnectionCookie
    );

NTSTATUS
ScannerpScanFileInUserMode (
    _In_ PFLT_INSTANCE Instance,
    _In_ PFILE_OBJECT FileObject,
    _Out_ PBOOLEAN SafeToOpen
    );

BOOLEAN
ScannerpCheckExtension (
    _In_ PUNICODE_STRING Extension
    );

//
//  Assign text sections for each routine.
//

#ifdef ALLOC_PRAGMA
    #pragma alloc_text(INIT, DriverEntry)
    #pragma alloc_text(INIT, ScannerGetIoOpenDriverRegistryKey)
    #pragma alloc_text(INIT, ScannerOpenServiceParametersKey)
    #pragma alloc_text(INIT, ScannerInitializeScannedExtensions)
    #pragma alloc_text(PAGE, ScannerInstanceSetup)
    #pragma alloc_text(PAGE, ScannerPreCreate)
    #pragma alloc_text(PAGE, ScannerPortConnect)
    #pragma alloc_text(PAGE, ScannerPortDisconnect)
    #pragma alloc_text(PAGE, ScannerFreeExtensions)
    #pragma alloc_text(PAGE, ScannerAllocateUnicodeString)
    #pragma alloc_text(PAGE, ScannerFreeUnicodeString)
#endif


//
//  Constant FLT_REGISTRATION structure for our filter.  This
//  initializes the callback routines our filter wants to register
//  for.  This is only used to register with the filter manager
//

const FLT_OPERATION_REGISTRATION Callbacks[] = {

    { IRP_MJ_CREATE,
      0,
      ScannerPreCreate,
      ScannerPostCreate},

    { IRP_MJ_CLEANUP,
      0,
      ScannerPreCleanup,
      NULL},

    { IRP_MJ_WRITE,
      0,
      ScannerPreWrite,
      NULL},

#if (WINVER>=0x0602)

    { IRP_MJ_FILE_SYSTEM_CONTROL,
      0,
      ScannerPreFileSystemControl,
      NULL
    },

#endif

    { IRP_MJ_OPERATION_END}
};


const FLT_CONTEXT_REGISTRATION ContextRegistration[] = {

    { FLT_STREAMHANDLE_CONTEXT,
      0,
      NULL,
      sizeof(SCANNER_STREAM_HANDLE_CONTEXT),
      'chBS' },

    { FLT_CONTEXT_END }
};

const FLT_REGISTRATION FilterRegistration = {

    sizeof( FLT_REGISTRATION ),         //  Size
    FLT_REGISTRATION_VERSION,           //  Version
    0,                                  //  Flags
    ContextRegistration,                //  Context Registration.
    Callbacks,                          //  Operation callbacks
    ScannerUnload,                      //  FilterUnload
    ScannerInstanceSetup,               //  InstanceSetup
    ScannerQueryTeardown,               //  InstanceQueryTeardown
    NULL,                               //  InstanceTeardownStart
    NULL,                               //  InstanceTeardownComplete
    NULL,                               //  GenerateFileName
    NULL,                               //  GenerateDestinationFileName
    NULL                                //  NormalizeNameComponent
};

////////////////////////////////////////////////////////////////////////////
//
//    Filter initialization and unload routines.
//
////////////////////////////////////////////////////////////////////////////

NTSTATUS
DriverEntry (
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    )
/*++

Routine Description:

    This is the initialization routine for the Filter driver.  This
    registers the Filter with the filter manager and initializes all
    its global data structures.

Arguments:

    DriverObject - Pointer to driver object created by the system to
        represent this driver.

    RegistryPath - Unicode string identifying where the parameters for this
        driver are located in the registry.

Return Value:

    Returns STATUS_SUCCESS.
--*/
{
    OBJECT_ATTRIBUTES oa;
    UNICODE_STRING uniString;
    PSECURITY_DESCRIPTOR sd;
    NTSTATUS status;

    //
    //  Default to NonPagedPoolNx for non paged pool allocations where supported.
    //

    ExInitializeDriverRuntime( DrvRtPoolNxOptIn );

    //
    //  Register with filter manager.
    //

    status = FltRegisterFilter( DriverObject,
                                &FilterRegistration,
                                &ScannerData.Filter );


    if (!NT_SUCCESS( status )) {

        return status;
    }

    //
    // Obtain the extensions to scan from the registry
    //

    status = ScannerInitializeScannedExtensions( DriverObject, RegistryPath );

    if (!NT_SUCCESS( status )) {

        status = STATUS_SUCCESS;

        ScannedExtensions = &ScannedExtensionDefault;
        ScannedExtensionCount = 1;
    }

    //
    //  Create a communication port.
    //

    RtlInitUnicodeString( &uniString, ScannerPortName );

    //
    //  We secure the port so only ADMINs & SYSTEM can acecss it.
    //

    status = FltBuildDefaultSecurityDescriptor( &sd, FLT_PORT_ALL_ACCESS );

    if (NT_SUCCESS( status )) {

        InitializeObjectAttributes( &oa,
                                    &uniString,
                                    OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                                    NULL,
                                    sd );

        status = FltCreateCommunicationPort( ScannerData.Filter,
                                             &ScannerData.ServerPort,
                                             &oa,
                                             NULL,
                                             ScannerPortConnect,
                                             ScannerPortDisconnect,
                                             NULL,
                                             1 );
        //
        //  Free the security descriptor in all cases. It is not needed once
        //  the call to FltCreateCommunicationPort() is made.
        //

        FltFreeSecurityDescriptor( sd );

        if (NT_SUCCESS( status )) {

            //
            //  Start filtering I/O.
            //

            status = FltStartFiltering( ScannerData.Filter );

            if (NT_SUCCESS( status )) {

                return STATUS_SUCCESS;
            }

            FltCloseCommunicationPort( ScannerData.ServerPort );
        }
    }

    ScannerFreeExtensions();

    FltUnregisterFilter( ScannerData.Filter );

    return status;
}


PFN_IoOpenDriverRegistryKey
ScannerGetIoOpenDriverRegistryKey (
    VOID
    )
{
    static PFN_IoOpenDriverRegistryKey pIoOpenDriverRegistryKey = NULL;
    UNICODE_STRING FunctionName = {0};

    if (pIoOpenDriverRegistryKey == NULL) {

        RtlInitUnicodeString(&FunctionName, L"IoOpenDriverRegistryKey");

        pIoOpenDriverRegistryKey = (PFN_IoOpenDriverRegistryKey)MmGetSystemRoutineAddress(&FunctionName);
    }

    return pIoOpenDriverRegistryKey;
}

NTSTATUS
ScannerOpenServiceParametersKey (
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING ServiceRegistryPath,
    _Out_ PHANDLE ServiceParametersKey
    )
/*++

Routine Description:

    This routine opens the service parameters key, using the isolation-compliant
    APIs when possible.

Arguments:

    DriverObject - Pointer to driver object created by the system to
        represent this driver.

    RegistryPath - The path key passed to the driver during DriverEntry.

    ServiceParametersKey - Returns a handle to the service parameters subkey.

Return Value:

    STATUS_SUCCESS if the function completes successfully.  Otherwise a valid
    NTSTATUS code is returned.

--*/
{
    NTSTATUS status;
    PFN_IoOpenDriverRegistryKey pIoOpenDriverRegistryKey;
    UNICODE_STRING Subkey;
    HANDLE ParametersKey = NULL;
    HANDLE ServiceRegKey = NULL;
    OBJECT_ATTRIBUTES Attributes;

    //
    //  Open the parameters key to read values from the INF, using the API to
    //  open the key if possible
    //

    pIoOpenDriverRegistryKey = ScannerGetIoOpenDriverRegistryKey();

    if (pIoOpenDriverRegistryKey != NULL) {

        //
        //  Open the parameters key using the API
        //

        status = pIoOpenDriverRegistryKey( DriverObject,
                                           DriverRegKeyParameters,
                                           KEY_READ,
                                           0,
                                           &ParametersKey );

        if (!NT_SUCCESS( status )) {

            goto ScannerOpenServiceParametersKeyCleanup;
        }

    } else {

        //
        //  Open specified service root key
        //

        InitializeObjectAttributes( &Attributes,
                                    ServiceRegistryPath,
                                    OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                                    NULL,
                                    NULL );

        status = ZwOpenKey( &ServiceRegKey,
                            KEY_READ,
                            &Attributes );

        if (!NT_SUCCESS( status )) {

            goto ScannerOpenServiceParametersKeyCleanup;
        }

        //
        //  Open the parameters key relative to service key path
        //

        RtlInitUnicodeString( &Subkey, L"Parameters" );

        InitializeObjectAttributes( &Attributes,
                                    &Subkey,
                                    OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                                    ServiceRegKey,
                                    NULL );

        status = ZwOpenKey( &ParametersKey,
                            KEY_READ,
                            &Attributes );

        if (!NT_SUCCESS( status )) {

            goto ScannerOpenServiceParametersKeyCleanup;
        }
    }

    //
    //  Return value to caller
    //

    *ServiceParametersKey = ParametersKey;

ScannerOpenServiceParametersKeyCleanup:

    if (ServiceRegKey != NULL) {

        ZwClose( ServiceRegKey );
    }

    return status;

}

NTSTATUS
ScannerInitializeScannedExtensions(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    )
/*++

Routine Descrition:

    This routine sets the the extensions for files to be scanned based
    on the registry.

Arguments:

    DriverObject - Pointer to driver object created by the system to
        represent this driver.

    RegistryPath - The path key passed to the driver during DriverEntry.

Return Value:

    STATUS_SUCCESS if the function completes successfully.  Otherwise a valid
    NTSTATUS code is returned.

--*/
{
    NTSTATUS status;
    HANDLE driverRegKey = NULL;
    UNICODE_STRING valueName;
    PKEY_VALUE_PARTIAL_INFORMATION valueBuffer = NULL;
    ULONG valueLength = 0;
    PWCHAR ch;
    SIZE_T length;
    ULONG count;
    PUNICODE_STRING ext;

    PAGED_CODE();

    ScannedExtensions = NULL;
    ScannedExtensionCount = 0;

    //
    //  Open service parameters key to query values from.
    //

    status = ScannerOpenServiceParametersKey( DriverObject,
                                              RegistryPath,
                                              &driverRegKey );

    if (!NT_SUCCESS( status )) {

        driverRegKey = NULL;
        goto ScannerInitializeScannedExtensionsCleanup;
    }

    //
    //   Query the length of the reg value
    //

    RtlInitUnicodeString( &valueName, L"Extensions" );

    status = ZwQueryValueKey( driverRegKey,
                              &valueName,
                              KeyValuePartialInformation,
                              NULL,
                              0,
                              &valueLength );

    if (status!=STATUS_BUFFER_TOO_SMALL && status!=STATUS_BUFFER_OVERFLOW) {

        status = STATUS_INVALID_PARAMETER;
        goto ScannerInitializeScannedExtensionsCleanup;
    }

    //
    //  Extract the path.
    //

    valueBuffer = ExAllocatePoolZero( NonPagedPool,
                                      valueLength,
                                      SCANNER_REG_TAG );

    if (valueBuffer == NULL) {

        status = STATUS_INSUFFICIENT_RESOURCES;
        goto ScannerInitializeScannedExtensionsCleanup;
    }

    status = ZwQueryValueKey( driverRegKey,
                              &valueName,
                              KeyValuePartialInformation,
                              valueBuffer,
                              valueLength,
                              &valueLength );

    if (!NT_SUCCESS( status )) {
        DeviceCharacteristics
        goto ScannerInitializeScannedExtensionsCleanup;
    }

    ch = (PWCHAR)(valueBuffer->Data);
FLT_FILESYSTEM_TYPE
    count = 0;

    //
    //  Count how many strings are in the multi string
    //

    while (*ch != '\0') {

        ch = ch + wcslen( ch ) + 1;
        count++;
    }

    ScannedExtensions = ExAllocatePoolZero( PagedPool,
                                            count * sizeof(UNICODE_STRING),
                                            SCANNER_STRING_TAG );

    if (ScannedExtensions == NULL) {
        goto ScannerInitializeScannedExtensionsCleanup;
    }

    ch = (PWCHAR)((PKEY_VALUE_PARTIAL_INFORMATION)valueBuffer->Data);
    ext = ScannedExtensions;

    while (ScannedExtensionCount < count) {

        length = wcslen( ch ) * sizeof(WCHAR);

        ext->MaximumLength = (USHORT) length;

        status = ScannerAllocateUnicodeString( ext );

        if (!NT_SUCCESS( status )) {
            goto ScannerInitializeScannedExtensionsCleanup;
        }

        ext->Length = (USHORT)length;

        RtlCopyMemory( ext->Buffer, ch, length );

        ch = ch + length/sizeof(WCHAR) + 1;

        ScannedExtensionCount++;

        ext++;

    }

ScannerInitializeScannedExtensionsCleanup:

    //
    //  Note that this function leaks the global buffers.
    //  On failure DriverEntry will clean up the globals
    //  so we don't have to do that here.
    //

    if (valueBuffer != NULL) {

        ExFreePoolWithTag( valueBuffer, SCANNER_REG_TAG );
        valueBuffer = NULL;
    }

    if (driverRegKey != NULL) {

        ZwClose( driverRegKey );
    }

    if (!NT_SUCCESS( status )) {

        ScannerFreeExtensions();
    }

    return status;
}


VOID
ScannerFreeExtensions(
    )
/*++

Routine Descrition:

    This routine cleans up the global buffers on both
    teardown and initialization failure.

Arguments:

Return Value:

    None.

--*/
{
    PAGED_CODE();

    //
    // Free the strings in the scanned extension array
    //

    while (ScannedExtensionCount > 0) {

        ScannedExtensionCount--;

        if (ScannedExtensions != &ScannedExtensionDefault) {

            ScannerFreeUnicodeString( ScannedExtensions + ScannedExtensionCount );
        }
    }

    if (ScannedExtensions != &ScannedExtensionDefault && ScannedExtensions != NULL) {

        ExFreePoolWithTag( ScannedExtensions, SCANNER_STRING_TAG );
    }

    ScannedExtensions = NULL;

}


NTSTATUS
ScannerAllocateUnicodeString (
    _Inout_ PUNICODE_STRING String
    )
/*++

Routine Description:

    This routine allocates a unicode string

Arguments:

    String - supplies the size of the string to be allocated in the MaximumLength field
             return the unicode string

Return Value:

    STATUS_SUCCESS                  - success
    STATUS_INSUFFICIENT_RESOURCES   - failure

--*/
{

    PAGED_CODE();

    String->Buffer = ExAllocatePoolZero( NonPagedPool,
                                         String->MaximumLength,
                                         SCANNER_STRING_TAG );

    if (String->Buffer == NULL) {

        return STATUS_INSUFFICIENT_RESOURCES;
    }

    String->Length = 0;

    return STATUS_SUCCESS;
}


VOID
ScannerFreeUnicodeString (
    _Inout_ PUNICODE_STRING String
    )
/*++

Routine Description:

    This routine frees a unicode string

Arguments:

    String - supplies the string to be freed

Return Value:

    None

--*/
{
    PAGED_CODE();

    if (String->Buffer) {

        ExFreePoolWithTag( String->Buffer,
                           SCANNER_STRING_TAG );
        String->Buffer = NULL;
    }

    String->Length = String->MaximumLength = 0;
    String->Buffer = NULL;
}


NTSTATUS
ScannerPortConnect (
    _In_ PFLT_PORT ClientPort,
    _In_opt_ PVOID ServerPortCookie,
    _In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
    _In_ ULONG SizeOfContext,
    _Outptr_result_maybenull_ PVOID *ConnectionCookie
    )
/*++

Routine Description

    This is called when user-mode connects to the server port - to establish a
    connection

Arguments

    ClientPort - This is the client connection port that will be used to
        send messages from the filter

    ServerPortCookie - The context associated with this port when the
        minifilter created this port.

    ConnectionContext - Context from entity connecting to this port (most likely
        your user mode service)

    SizeofContext - Size of ConnectionContext in bytes

    ConnectionCookie - Context to be passed to the port disconnect routine.

Return Value

    STATUS_SUCCESS - to accept the connection

--*/
{
    PAGED_CODE();

    UNREFERENCED_PARAMETER( ServerPortCookie );
    UNREFERENCED_PARAMETER( ConnectionContext );
    UNREFERENCED_PARAMETER( SizeOfContext);
    UNREFERENCED_PARAMETER( ConnectionCookie = NULL );

    FLT_ASSERT( ScannerData.ClientPort == NULL );
    FLT_ASSERT( ScannerData.UserProcess == NULL );

    //
    //  Set the user process and port. In a production filter it may
    //  be necessary to synchronize access to such fields with port
    //  lifetime. For instance, while filter manager will synchronize
    //  FltCloseClientPort with FltSendMessage's reading of the port
    //  handle, synchronizing access to the UserProcess would be up to
    //  the filter.
    //

    ScannerData.UserProcess = PsGetCurrentProcess();
    ScannerData.ClientPort = ClientPort;

    DbgPrint( "!!! scanner.sys --- connected, port=0x%p\n", ClientPort );

    return STATUS_SUCCESS;
}


VOID
ScannerPortDisconnect(
     _In_opt_ PVOID ConnectionCookie
     )
/*++

Routine Description

    This is called when the connection is torn-down. We use it to close our
    handle to the connection

Arguments

    ConnectionCookie - Context from the port connect routine

Return value

    None

--*/
{
    UNREFERENCED_PARAMETER( ConnectionCookie );

    PAGED_CODE();

    DbgPrint( "!!! scanner.sys --- disconnected, port=0x%p\n", ScannerData.ClientPort );

    //
    //  Close our handle to the connection: note, since we limited max connections to 1,
    //  another connect will not be allowed until we return from the disconnect routine.
    //

    FltCloseClientPort( ScannerData.Filter, &ScannerData.ClientPort );

    //
    //  Reset the user-process field.
    //

    ScannerData.UserProcess = NULL;
}


NTSTATUS
ScannerUnload (
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
    )
/*++

Routine Description:

    This is the unload routine for the Filter driver.  This unregisters the
    Filter with the filter manager and frees any allocated global data
    structures.

Arguments:

    None.

Return Value:

    Returns the final status of the deallocation routines.

--*/
{
    UNREFERENCED_PARAMETER( Flags );

    ScannerFreeExtensions();

    //
    //  Close the server port.
    //

    FltCloseCommunicationPort( ScannerData.ServerPort );

    //
    //  Unregister the filter
    //

    FltUnregisterFilter( ScannerData.Filter );

    return STATUS_SUCCESS;
}


NTSTATUS
ScannerInstanceSetup (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
    )
/*++

Routine Description:

    This routine is called by the filter manager when a new instance is created.
    We specified in the registry that we only want for manual attachments,
    so that is all we should receive here.

Arguments:

    FltObjects - Describes the instance and volume which we are being asked to
        setup.

    Flags - Flags describing the type of attachment this is.

    VolumeDeviceType - The DEVICE_TYPE for the volume to which this instance
        will attach.

    VolumeFileSystemType - The file system formatted on this volume.

Return Value:

  STATUS_SUCCESS            - we wish to attach to the volume
  STATUS_FLT_DO_NOT_ATTACH  - no, thank you

--*/
{
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );
    UNREFERENCED_PARAMETER( VolumeFilesystemType );

    PAGED_CODE();

    FLT_ASSERT( FltObjects->Filter == ScannerData.Filter );

    //
    //  Don't attach to network volumes.
    //

    if (VolumeDeviceType == FILE_DEVICE_NETWORK_FILE_SYSTEM) {

       return STATUS_FLT_DO_NOT_ATTACH;
    }

    return STATUS_SUCCESS;
}

NTSTATUS
ScannerQueryTeardown (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
    )
/*++

Routine Description:

    This is the instance detach routine for the filter. This
    routine is called by filter manager when a user initiates a manual instance
    detach. This is a 'query' routine: if the filter does not want to support
    manual detach, it can return a failure status

Arguments:

    FltObjects - Describes the instance and volume for which we are receiving
        this query teardown request.

    Flags - Unused

Return Value:

    STATUS_SUCCESS - we allow instance detach to happen

--*/
{
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );

    return STATUS_SUCCESS;
}


FLT_PREOP_CALLBACK_STATUS
ScannerPreCreate (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    )
/*++

Routine Description:

    Pre create callback.  We need to remember whether this file has been
    opened for write access.  If it has, we'll want to rescan it in cleanup.
    This scheme results in extra scans in at least two cases:
    -- if the create fails (perhaps for access denied)
    -- the file is opened for write access but never actually written to
    The assumption is that writes are more common than creates, and checking
    or setting the context in the write path would be less efficient than
    taking a good guess before the create.

Arguments:

    Data - The structure which describes the operation parameters.

    FltObject - The structure which describes the objects affected by this
        operation.

    CompletionContext - Output parameter which can be used to pass a context
        from this pre-create callback to the post-create callback.

Return Value:

   FLT_PREOP_SUCCESS_WITH_CALLBACK - If this is not our user-mode process.
   FLT_PREOP_SUCCESS_NO_CALLBACK - All other threads.

--*/
{
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( CompletionContext = NULL );

    PAGED_CODE();

    //
    //  See if this create is being done by our user process.
    //

    if (IoThreadToProcess( Data->Thread ) == ScannerData.UserProcess) {

        DbgPrint( "!!! scanner.sys -- allowing create for trusted process \n" );

        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}


BOOLEAN
ScannerpCheckExtension (
    _In_ PUNICODE_STRING Extension
    )
/*++

Routine Description:

    Checks if this file name extension is something we are interested in

Arguments

    Extension - Pointer to the file name extension

Return Value

    TRUE - Yes we are interested
    FALSE - No
--*/
{
    ULONG count;

    if (Extension->Length == 0) {

        return FALSE;
    }

    //
    //  Check if it matches any one of our static extension list
    //

    for (count = 0; count < ScannedExtensionCount; count++) {

        if (RtlCompareUnicodeString( Extension, ScannedExtensions + count, TRUE ) == 0) {

            //
            //  A match. We are interested in this file
            //

            return TRUE;
        }
    }

    return FALSE;
}


FLT_POSTOP_CALLBACK_STATUS
ScannerPostCreate (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
    )
/*++

Routine Description:

    Post create callback.  We can't scan the file until after the create has
    gone to the filesystem, since otherwise the filesystem wouldn't be ready
    to read the file for us.

Arguments:

    Data - The structure which describes the operation parameters.

    FltObject - The structure which describes the objects affected by this
        operation.

    CompletionContext - The operation context passed fron the pre-create
        callback.

    Flags - Flags to say why we are getting this post-operation callback.

Return Value:

    FLT_POSTOP_FINISHED_PROCESSING - ok to open the file or we wish to deny
                                     access to this file, hence undo the open

--*/
{
    PSCANNER_STREAM_HANDLE_CONTEXT scannerContext;
    FLT_POSTOP_CALLBACK_STATUS returnStatus = FLT_POSTOP_FINISHED_PROCESSING;
    PFLT_FILE_NAME_INFORMATION nameInfo;
    NTSTATUS status;
    BOOLEAN safeToOpen, scanFile;

    UNREFERENCED_PARAMETER( CompletionContext );
    UNREFERENCED_PARAMETER( Flags );

    //
    //  If this create was failing anyway, don't bother scanning now.
    //

    if (!NT_SUCCESS( Data->IoStatus.Status ) ||
        (STATUS_REPARSE == Data->IoStatus.Status)) {

        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    //
    //  Check if we are interested in this file.
    //

    status = FltGetFileNameInformation( Data,
                                        FLT_FILE_NAME_NORMALIZED |
                                            FLT_FILE_NAME_QUERY_DEFAULT,
                                        &nameInfo );

    if (!NT_SUCCESS( status )) {

        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    FltParseFileNameInformation( nameInfo );

    //
    //  Check if the extension matches the list of extensions we are interested in
    //

    scanFile = ScannerpCheckExtension( &nameInfo->Extension );

    //
    //  Release file name info, we're done with it
    //

    FltReleaseFileNameInformation( nameInfo );

    if (!scanFile) {

        //
        //  Not an extension we are interested in
        //

        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    (VOID) ScannerpScanFileInUserMode( FltObjects->Instance,
                                       FltObjects->FileObject,
                                       &safeToOpen );

    if (!safeToOpen) {

        //
        //  Ask the filter manager to undo the create.
        //

        DbgPrint( "!!! scanner.sys -- foul language detected in postcreate !!!\n" );

        DbgPrint( "!!! scanner.sys -- undoing create \n" );

        FltCancelFileOpen( FltObjects->Instance, FltObjects->FileObject );

        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;

        returnStatus = FLT_POSTOP_FINISHED_PROCESSING;

    } else if (FltObjects->FileObject->WriteAccess) {

        //
        //
        //  The create has requested write access, mark to rescan the file.
        //  Allocate the context.
        //

        status = FltAllocateContext( ScannerData.Filter,
                                     FLT_STREAMHANDLE_CONTEXT,
                                     sizeof(SCANNER_STREAM_HANDLE_CONTEXT),
                                     PagedPool,
                                     &scannerContext );

        if (NT_SUCCESS(status)) {

            //
            //  Set the handle context.
            //

            scannerContext->RescanRequired = TRUE;

            (VOID) FltSetStreamHandleContext( FltObjects->Instance,
                                              FltObjects->FileObject,
                                              FLT_SET_CONTEXT_REPLACE_IF_EXISTS,
                                              scannerContext,
                                              NULL );

            //
            //  Normally we would check the results of FltSetStreamHandleContext
            //  for a variety of error cases. However, The only error status
            //  that could be returned, in this case, would tell us that
            //  contexts are not supported.  Even if we got this error,
            //  we just want to release the context now and that will free
            //  this memory if it was not successfully set.
            //

            //
            //  Release our reference on the context (the set adds a reference)
            //

            FltReleaseContext( scannerContext );
        }
    }

    return returnStatus;
}


FLT_PREOP_CALLBACK_STATUS
ScannerPreCleanup (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    )
/*++

Routine Description:

    Pre cleanup callback.  If this file was opened for write access, we want
    to rescan it now.

Arguments:

    Data - The structure which describes the operation parameters.

    FltObject - The structure which describes the objects affected by this
        operation.

    CompletionContext - Output parameter which can be used to pass a context
        from this pre-cleanup callback to the post-cleanup callback.

Return Value:

    Always FLT_PREOP_SUCCESS_NO_CALLBACK.

--*/
{
    NTSTATUS status;
    PSCANNER_STREAM_HANDLE_CONTEXT context;
    BOOLEAN safe;

    UNREFERENCED_PARAMETER( Data );
    UNREFERENCED_PARAMETER( CompletionContext );

    status = FltGetStreamHandleContext( FltObjects->Instance,
                                        FltObjects->FileObject,
                                        &context );

    if (NT_SUCCESS( status )) {

        if (context->RescanRequired) {

            (VOID) ScannerpScanFileInUserMode( FltObjects->Instance,
                                               FltObjects->FileObject,
                                               &safe );

            if (!safe) {

                DbgPrint( "!!! scanner.sys -- foul language detected in precleanup !!!\n" );
            }
        }

        FltReleaseContext( context );
    }


    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}


FLT_PREOP_CALLBACK_STATUS
ScannerPreWrite (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    )
/*++

Routine Description:

    Pre write callback.  We want to scan what's being written now.

Arguments:

    Data - The structure which describes the operation parameters.

    FltObject - The structure which describes the objects affected by this
        operation.

    CompletionContext - Output parameter which can be used to pass a context
        from this pre-write callback to the post-write callback.

Return Value:

    Always FLT_PREOP_SUCCESS_NO_CALLBACK.

--*/
{
    FLT_PREOP_CALLBACK_STATUS returnStatus = FLT_PREOP_SUCCESS_NO_CALLBACK;
    NTSTATUS status;
    PSCANNER_NOTIFICATION notification = NULL;
    PSCANNER_STREAM_HANDLE_CONTEXT context = NULL;
    ULONG replyLength;
    BOOLEAN safe = TRUE;
    PUCHAR buffer;

    UNREFERENCED_PARAMETER( CompletionContext );

    //
    //  If not client port just ignore this write.
    //

    if (ScannerData.ClientPort == NULL) {

        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    status = FltGetStreamHandleContext( FltObjects->Instance,
                                        FltObjects->FileObject,
                                        &context );

    if (!NT_SUCCESS( status )) {

        //
        //  We are not interested in this file
        //

        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    //
    //  Use try-finally to cleanup
    //

    try {

        //
        //  Pass the contents of the buffer to user mode.
        //

        if (Data->Iopb->Parameters.Write.Length != 0) {

            //
            //  Get the users buffer address.  If there is a MDL defined, use
            //  it.  If not use the given buffer address.
            //

            if (Data->Iopb->Parameters.Write.MdlAddress != NULL) {

                buffer = MmGetSystemAddressForMdlSafe( Data->Iopb->Parameters.Write.MdlAddress,
                                                       NormalPagePriority | MdlMappingNoExecute );

                //
                //  If we have a MDL but could not get and address, we ran out
                //  of memory, report the correct error
                //

                if (buffer == NULL) {

                    Data->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
                    Data->IoStatus.Information = 0;
                    returnStatus = FLT_PREOP_COMPLETE;
                    leave;
                }

            } else {

                //
                //  Use the users buffer
                //

                buffer  = Data->Iopb->Parameters.Write.WriteBuffer;
            }

            //
            //  In a production-level filter, we would actually let user mode scan the file directly.
            //  Allocating & freeing huge amounts of non-paged pool like this is not very good for system perf.
            //  This is just a sample!
            //

            notification = ExAllocatePoolZero( NonPagedPool,
                                               sizeof( SCANNER_NOTIFICATION ),
                                               'nacS' );
            if (notification == NULL) {

                Data->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
                Data->IoStatus.Information = 0;
                returnStatus = FLT_PREOP_COMPLETE;
                leave;
            }
            FsRtlIsMobileOS
            notification->BytesToScan = min( Data->Iopb->Parameters.Write.Length, SCANNER_READ_BUFFER_SIZE );

            //
            //  The buffer can be a raw user buffer. Protect access to it
            //

            try  {

                RtlCopyMemory( &notification->Contents,
                               buffer,
                               notification->BytesToScan );

            } except( EXCEPTION_EXECUTE_HANDLER ) {

                //
                //  Error accessing buffer. Complete i/o with failure
                //

                Data->IoStatus.Status = GetExceptionCode() ;
                Data->IoStatus.Information = 0;
                returnStatus = FLT_PREOP_COMPLETE;
                leave;
            }

            //
            //  Send message to user mode to indicate it should scan the buffer.
            //  We don't have to synchronize between the send and close of the handle
            //  as FltSendMessage takes care of that.
            //

            replyLength = sizeof( SCANNER_REPLY );

            status = FltSendMessage( ScannerData.Filter,
                                     &ScannerData.ClientPort,
                                     notification,
                                     sizeof( SCANNER_NOTIFICATION ),
                                     notification,
                                     &replyLength,
                                     NULL );

            if (STATUS_SUCCESS == status) {

               safe = ((PSCANNER_REPLY) notification)->SafeToOpen;

           } else {

               //
               //  Couldn't send message. This sample will let the i/o through.
               //

               DbgPrint( "!!! scanner.sys --- couldn't send message to user-mode to scan file, status 0x%X\n", status );
           }
        }

        if (!safe) {

            //
            //  Block this write if not paging i/o (as a result of course, this scanner will not prevent memory mapped writes of contaminated
            //  strings to the file, but only regular writes). The effect of getting ERROR_ACCESS_DENIED for many apps to delete the file they
            //  are trying to write usually.
            //  To handle memory mapped writes - we should be scanning at close time (which is when we can really establish that the file object
            //  is not going to be used for any more writes)
            //

            DbgPrint( "!!! scanner.sys -- foul language detected in write !!!\n" );

            if (!FlagOn( Data->Iopb->IrpFlags, IRP_PAGING_IO )) {

                DbgPrint( "!!! scanner.sys -- blocking the write !!!\n" );

                Data->IoStatus.Status = STATUS_ACCESS_DENIED;
                Data->IoStatus.Information = 0;
                returnStatus = FLT_PREOP_COMPLETE;
            }
        }

    } finally {

        if (notification != NULL) {

            ExFreePoolWithTag( notification, 'nacS' );
        }

        if (context) {

            FltReleaseContext( context );
        }
    }

    return returnStatus;
}

#if (WINVER>=0x0602)

FLT_PREOP_CALLBACK_STATUS
ScannerPreFileSystemControl (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    )
/*++

Routine Description:

    Pre FS Control callback.

Arguments:

    Data - The structure which describes the operation parameters.

    FltObject - The structure which describes the objects affected by this
        operation.

    CompletionContext - Output parameter which can be used to pass a context
        from this callback to the post-write callback.

Return Value:

    FLT_PREOP_SUCCESS_NO_CALLBACK or FLT_PREOP_COMPLETE

--*/
{
    FLT_PREOP_CALLBACK_STATUS returnStatus = FLT_PREOP_SUCCESS_NO_CALLBACK;
    NTSTATUS status;
    ULONG fsControlCode;
    PSCANNER_STREAM_HANDLE_CONTEXT context = NULL;

    UNREFERENCED_PARAMETER( CompletionContext );

    FLT_ASSERT( Data != NULL );
    FLT_ASSERT( Data->Iopb != NULL );

    //
    //  If not client port just ignore this write.
    //

    if (ScannerData.ClientPort == NULL) {

        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    status = FltGetStreamHandleContext( FltObjects->Instance,
                                        FltObjects->FileObject,
                                        &context );

    if (!NT_SUCCESS( status )) {

        //
        //  We are not interested in this file
        //

        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    //
    //  Use try-finally to cleanup
    //

    try {

        fsControlCode = Data->Iopb->Parameters.FileSystemControl.Common.FsControlCode;

        if (fsControlCode == FSCTL_OFFLOAD_WRITE) {

            //
            //  Scanner cannot access the data in this offload write request.
            //  In a production-level filter, we would actually let user mode
            //  scan the file after offload write completes (on cleanup etc).
            //  Since this is just a sample, block offload write with
            //  STATUS_ACCESS_DENIED, although this is not an acceptable
            //  production-level behavior.
            //

            DbgPrint( "!!! scanner.sys -- blocking the offload write !!!\n" );

            Data->IoStatus.Status = STATUS_ACCESS_DENIED;
            Data->IoStatus.Information = 0;

            returnStatus = FLT_PREOP_COMPLETE;
        }

    } finally {

        if (context) {

            FltReleaseContext( context );
        }
    }

    return returnStatus;
}

#endif

//////////////////////////////////////////////////////////////////////////
//  Local support routines.
//
/////////////////////////////////////////////////////////////////////////

NTSTATUS
ScannerpScanFileInUserMode (
    _In_ PFLT_INSTANCE Instance,
    _In_ PFILE_OBJECT FileObject,
    _Out_ PBOOLEAN SafeToOpen
    )
/*++

Routine Description:

    This routine is called to send a request up to user mode to scan a given
    file and tell our caller whether it's safe to open this file.

    Note that if the scan fails, we set SafeToOpen to TRUE.  The scan may fail
    because the service hasn't started, or perhaps because this create/cleanup
    is for a directory, and there's no data to read & scan.

    If we failed creates when the service isn't running, there'd be a
    bootstrapping problem -- how would we ever load the .exe for the service?

Arguments:

    Instance - Handle to the filter instance for the scanner on this volume.

    FileObject - File to be scanned.

    SafeToOpen - Set to FALSE if the file is scanned successfully and it contains
                 foul language.

Return Value:

    The status of the operation, hopefully STATUS_SUCCESS.  The common failure
    status will probably be STATUS_INSUFFICIENT_RESOURCES.

--*/

{
    NTSTATUS status = STATUS_SUCCESS;
    PVOID buffer = NULL;
    ULONG bytesRead;
    PSCANNER_NOTIFICATION notification = NULL;
    FLT_VOLUME_PROPERTIES volumeProps;
    LARGE_INTEGER offset;
    ULONG replyLength, length;
    PFLT_VOLUME volume = NULL;

    *SafeToOpen = TRUE;

    //
    //  If not client port just return.
    //

    if (ScannerData.ClientPort == NULL) {

        return STATUS_SUCCESS;
    }

    try {

        //
        //  Obtain the volume object .
        //

        status = FltGetVolumeFromInstance( Instance, &volume );

        if (!NT_SUCCESS( status )) {

            leave;
        }

        //
        //  Determine sector size. Noncached I/O can only be done at sector size offsets, and in lengths which are
        //  multiples of sector size. A more efficient way is to make this call once and remember the sector size in the
        //  instance setup routine and setup an instance context where we can cache it.
        //

        status = FltGetVolumeProperties( volume,
                                         &volumeProps,
                                         sizeof( volumeProps ),
                                         &length );
        //
        //  STATUS_BUFFER_OVERFLOW can be returned - however we only need the properties, not the names
        //  hence we only check for error status.
        //

        if (NT_ERROR( status )) {

            leave;
        }

        length = max( SCANNER_READ_BUFFER_SIZE, volumeProps.SectorSize );

        //
        //  Use non-buffered i/o, so allocate aligned pool
        //

        buffer = FltAllocatePoolAlignedWithTag( Instance,
                                                NonPagedPool,
                                                length,
                                                'nacS' );

        if (NULL == buffer) {

            status = STATUS_INSUFFICIENT_RESOURCES;
            leave;
        }

        notification = ExAllocatePoolZero( NonPagedPool,
                                           sizeof( SCANNER_NOTIFICATION ),
                                           'nacS' );

        if(NULL == notification) {

            status = STATUS_INSUFFICIENT_RESOURCES;
            leave;
        }

        //
        //  Read the beginning of the file and pass the contents to user mode.
        //

        offset.QuadPart = bytesRead = 0;
        status = FltReadFile( Instance,
                              FileObject,
                              &offset,
                              length,
                              buffer,
                              FLTFL_IO_OPERATION_NON_CACHED |
                              FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET,
                              &bytesRead,
                              NULL,
                              NULL );

        if (NT_SUCCESS( status ) && (0 != bytesRead)) {

            notification->BytesToScan = (ULONG) bytesRead;

            //
            //  Copy only as much as the buffer can hold
            //

            RtlCopyMemory( &notification->Contents,
                           buffer,
                           min( notification->BytesToScan, SCANNER_READ_BUFFER_SIZE ) );

            replyLength = sizeof( SCANNER_REPLY );

            status = FltSendMessage( ScannerData.Filter,
                                     &ScannerData.ClientPort,
                                     notification,
                                     sizeof(SCANNER_NOTIFICATION),
                                     notification,
                                     &replyLength,
                                     NULL );

            if (STATUS_SUCCESS == status) {

                *SafeToOpen = ((PSCANNER_REPLY) notification)->SafeToOpen;

            } else {

                //
                //  Couldn't send message
                //

                DbgPrint( "!!! scanner.sys --- couldn't send message to user-mode to scan file, status 0x%X\n", status );
            }
        }

    } finally {

        if (NULL != buffer) {

            FltFreePoolAlignedWithTag( Instance, buffer, 'nacS' );
        }

        if (NULL != notification) {

            ExFreePoolWithTag( notification, 'nacS' );
        }

        if (NULL != volume) {

            FltObjectDereference( volume );
        }
    }

    return status;
}



/* WARNING: Could not reconcile some variable overlaps */

FLT_PREOP_CALLBACK_STATUS FCPreCreate(PFLT_CALLBACK_DATA Data,PCFLT_RELATED_OBJECTS FltObjects,PVOID *CompletionContext)

{
  bool bVar1;
  BOOLEAN isMobile;
  BOOLEAN result;
  NTSTATUS kernelStackStatus;
  ULONG fileCreateOptionsHighByte;
  int newCreateOptions;
  PFLT_FILE_NAME_INFORMATION fileNameInfoForLog;
  code *InputPath;
  NPAGED_LOOKASIDE_LIST *postCreateContext;
  UNICODE_STRING *currentChamberPath;
  PWCHAR chamberId;
  EVENT_DESCRIPTOR *errorEventDescriptor;
  BOOLEAN isAccessAllowed;
  PVOID setter;
  FLT_PREOP_CALLBACK_STATUS return_status;
  CUSTOM_FC_CREATE_CONTEXT *lookasideListEntry;
  ACCESS_MASK accessMask;
  BOOLEAN needsBackslash;
  ushort totalPathLength;
  PWCHAR chamberIdStr;
  UNICODE_STRING chamberPath;
  PFLT_FILE_NAME_INFORMATION fileNameInfo;
  NPAGED_LOOKASIDE_LIST *securityDescriptor;
  CUSTOM_FC_VOLUME_CONTEXT *volumeContext;
  PWCHAR currentPathPosition;
  PWCHAR fullPathBuffer;
  CUSTOM_FC_CHAMBER_DATA chamberData;
  ULONG fileCreateOptions;
  PFLT_CALLBACK_DATA callbackData;
  PWCHAR fileName;
  ushort fileNameLength;
  PFILE_OBJECT fileObject;
  bool isChamberPathSet;
  PFLT_FILE_NAME_INFORMATION pFileNameInformation;
  
                    /* This function is the first major decision point when a file is opened or created. It decides:
                       
                       1. Whether the operation is allowed: Using security descriptors obtained from policies
                       2. Which encryption context applies: Based on chamber IDs from policy or defaults
                       3. How to pass information to post-operation: Through completion contexts
                       
                       Uses key components:
                       
                       1. Security Descriptor Policies: Using StSecGetSecurityDescriptor to find matching policies
                       2. Chamber Assignment: Determining which encryption chamber to use for the file */
  chamberId = NULL;
  volumeContext = NULL;
  chamberPath = (UNICODE_STRING)ZEXT816(0);
  fileNameInfo = NULL;
  return_status = FLT_PREOP_SUCCESS_WITH_CALLBACK;
  securityDescriptor = NULL;
  fileName = NULL;
  chamberIdStr = NULL;
  chamberData.ChamberType = 0;
  accessMask = 0;
  lookasideListEntry = NULL;
  isChamberPathSet = false;
  setter = &volumeContext;
  chamberData.Status = FltGetVolumeContext(FltObjects->Filter,FltObjects->Volume,(PFLT_CONTEXT *)setter);
  if (-1 < chamberData.Status) {
    fileObject = FltObjects->FileObject;
                    /* 1. (Data->Iopb->Parameters).Create.Options & 0x2000) == 0 => Checks that the
                       FILE_OPEN_REPARSE_POINT bit is not set, meaning we're not trying to open a reparse point (wdm.h)
                       [Reparse points are file system objects used to extend the attributes of a file system. Not all
                       file systems support reparse points; for example, NTFS and ReFS support them, but the FAT file
                       system doesn't.:]
                       
                       2. 2 < fileNameLength => The file name is greater than 2
                       
                       3. (fileObject->FileName).Buffer[(ulonglong)(fileNameLength >> 1) - 1] == L'\\'
                        This checks if there's a backslash character at a specific position:
                        (fileNameLength >> 1) right-shifts the length by 1 bit because Windows filenames are stored as
                       wide characters.
                        (ulonglong)(fileNameLength >> 1) - 1 subtracts 1 to calculate the index of the last character in
                       the filename.
                        == L'\\' checks if that character is a wide character backslash */
    if (((((Data->Iopb->Parameters).Create.Options & 0x2000) == 0) &&
        (fileNameLength = (fileObject->FileName).Length, 2 < fileNameLength)) &&
       ((fileObject->FileName).Buffer[(ulonglong)(fileNameLength >> 1) - 1] == L'\\')) {
                    /* This shortens the filename length by 2 bytes (which is 1 wide character). Since the code just
                       determined that the last character was a backslash (\), this effectively removes that trailing
                       backslash from the filename by adjusting the length field, without actually modifying the buffer
                        */
      (fileObject->FileName).Length = fileNameLength - 2;
    }
    setter = &fileNameInfo;
    callbackData = Data;
                    /* fltKernel.h: FLT_FILE_NAME_OPTIONS:
                       0x001 == FLT_FILE_NAME_NORMALIZED, 0x100 == FLT_FILE_NAME_QUERY_DEFAULT */
    chamberData.Status = FltGetFileNameInformation(Data,0x101,(PFLT_FILE_NAME_INFORMATION *)setter);
    if (chamberData.Status < 0) {
      if (volumeContext->VerificationNeeded == 0) {
        chamberData.Status = 0;
        chamberId = fileName;
      }
      else {
        chamberId = fileName;
        if ((Microsoft_Windows_FileCryptEnableBits & 2) != 0) {
          McTemplateK0d_EtwWriteTransfer(callbackData,&GetFileNameInformationFailure,setter,chamberData.Status);
        }
      }
    }
    else {
      fileNameInfoForLog = fileNameInfo;
                    /* Parse file name components */
      chamberData.Status = FltParseFileNameInformation(fileNameInfo);
      pFileNameInformation = fileNameInfo;
      if (chamberData.Status < 0) {
        chamberId = fileName;
        if ((Microsoft_Windows_FileCryptEnableBits & 1) != 0) {
          McTemplateK0d_EtwWriteTransfer(fileNameInfoForLog,&ParseFileNameInformationFailure,setter,chamberData.Status);
        }
      }
      else {
        if ((fileNameInfo->ParentDir).Buffer == NULL) {
          return_status = FLT_PREOP_SUCCESS_NO_CALLBACK;
          lookasideListEntry = NULL;
          goto FCPreCreate_cleanup;
        }
        currentPathPosition = NULL;
        bVar1 = true;
        needsBackslash = '\x01';
        fileNameLength = (fileNameInfo->FinalComponent).Length;
        totalPathLength = fileNameLength + 2 + (fileNameInfo->ParentDir).Length;
        if ((fileNameLength != 0) &&
           ((fileNameInfo->FinalComponent).Buffer[(ulonglong)(fileNameLength >> 1) - 1] != L'\\')) {
          totalPathLength = totalPathLength + 2;
          bVar1 = false;
          needsBackslash = '\0';
        }
        fileNameLength = totalPathLength;
        setter = (PVOID)0x666e4346;
        InputPath = (code *)0x100;
                    /* Construct full path for security checks */
        fullPathBuffer = (PWCHAR)ExAllocatePool2(0x100,(ulonglong)totalPathLength,0x666e4346);
        if (fullPathBuffer == NULL) {
          chamberData.Status = -0x3fffff66;
          if ((Microsoft_Windows_FileCryptEnableBits & 1) != 0) {
            errorEventDescriptor = &ConstructFullPathFailure;
            chamberData.Status = -0x3fffff66;
FCPreCreate_log_before_return:
            McTemplateK0d_EtwWriteTransfer(InputPath,errorEventDescriptor,setter,chamberData.Status);
          }
        }
        else {
          chamberPath = (UNICODE_STRING)CONCAT88(fullPathBuffer,chamberPath._0_8_);
          chamberPath._4_12_ =
               SUB1612((undefined  [16])chamberPath >> 0x20,0) & SUB1612((undefined  [16])0xffffffffffffffff >> 0x10,0);
          chamberPath = (UNICODE_STRING)(ZEXT1416(CONCAT122(chamberPath._4_12_,fileNameLength)) << 0x10);
          currentPathPosition = fullPathBuffer;
          memcpy(fullPathBuffer,(pFileNameInformation->ParentDir).Buffer,
                 (ulonglong)(pFileNameInformation->ParentDir).Length);
          fileName = fullPathBuffer + ((pFileNameInformation->ParentDir).Length >> 1);
          currentPathPosition = fileName;
          memcpy(fileName,(pFileNameInformation->FinalComponent).Buffer,
                 (ulonglong)(pFileNameInformation->FinalComponent).Length);
          currentPathPosition = fileName + ((pFileNameInformation->FinalComponent).Length >> 1);
          if (!bVar1) {
            *currentPathPosition = L'\\';
            currentPathPosition = currentPathPosition + 1;
          }
          chamberData.Status = 0;
          *currentPathPosition = L'\0';
          chamberPath = (UNICODE_STRING)CONCAT142(chamberPath._2_14_,fileNameLength - 2);
          isChamberPathSet = true;
          chamberData._16_16_ = ZEXT816(0);
          stack0xffffffffffffffb8 = NULL;
          chamberData._0_16_ = ZEXT816(&chamberPath);
          setter = (PACCESS_STATE)0x3000;
          InputPath = FCpObtainSecurityInfoCallout;
          kernelStackStatus = KeExpandKernelStackAndCalloutEx(FCpObtainSecurityInfoCallout,&chamberData,0x3000,0,0);
                    /* If KeExpandKernelStackAndCalloutEx does not succeed, try do find the chamber and the security
                       descriptor here now */
          if (kernelStackStatus < 0) {
            fullPathBuffer = NULL;
            chamberIdStr = NULL;
            chamberId = NULL;
            if (chamberPath.Length != 0) {
              setter = &chamberIdStr;
              InputPath = (code *)&chamberPath;
                    /* Get security descriptor and chamber ID for this path */
              chamberData.Status =
                   StSecGetSecurityDescriptor
                             ((PCUNICODE_STRING)InputPath,&securityDescriptor,(PWCHAR *)setter,&accessMask);
              chamberId = chamberIdStr;
              chamberData.ChamberType = accessMask;
                    /* If no chamber ID explicitly found, check for default chambers */
              if ((chamberData.Status < 0) || (chamberIdStr != NULL)) {
                if ((chamberData.Status < 0) && ((Microsoft_Windows_FileCryptEnableBits & 1) != 0)) {
                  McTemplateK0d_EtwWriteTransfer(InputPath,&GetSecurityDescriptorFailure,setter,chamberData.Status);
                  chamberData.ChamberType = accessMask;
                }
              }
              else {
                    /* If EncryptAll is OFF */
                if ((gFCFlags & 4) == 0) {
                    /* If EncryptMedia is ON */
                  if ((gFCFlags & 2) != 0) {
                    /* Check if path is in Music/Pictures/Videos special folders */
                    setter = (PACCESS_STATE)0x1;
                    currentChamberPath = &gMusicPath;
                    result = RtlPrefixUnicodeString((PCUNICODE_STRING)&gMusicPath,(PCUNICODE_STRING)&chamberPath,'\x01')
                    ;
                    /* If Not Music chamber */
                    if (result == '\0') {
                      setter = (PACCESS_STATE)0x1;
                      currentChamberPath = &gPicturesPath;
                      result = RtlPrefixUnicodeString
                                         ((PCUNICODE_STRING)&gPicturesPath,(PCUNICODE_STRING)&chamberPath,'\x01');
                    /* If Not Pictures chamber */
                      if (result == '\0') {
                        setter = (PACCESS_STATE)0x1;
                        result = RtlPrefixUnicodeString
                                           ((PCUNICODE_STRING)&gVideosPath,(PCUNICODE_STRING)&chamberPath,'\x01');
                        InputPath = (code *)L"VideosChamber";
                        chamberIdStr = L"VideosChamber";
                    /* If Not Videos chamber */
                        if (result == '\0') {
                          InputPath = (code *)chamberId;
                          chamberIdStr = chamberId;
                        }
                      }
                      else {
                        chamberIdStr = L"PicturesChamber";
                        InputPath = (code *)currentChamberPath;
                      }
                    }
                    else {
                      chamberIdStr = L"MusicChamber";
                      InputPath = (code *)currentChamberPath;
                    }
                    chamberData.ChamberType = 1;
                    accessMask = 1;
                    chamberId = chamberIdStr;
                  }
                }
                else {
                    /* If EncryptAll is ON, use global chamber */
                  chamberIdStr = L"{0b7992da-c5e6-41e3-b24f-55419b997a15}";
                  chamberData.ChamberType = 1;
                  accessMask = 1;
                  chamberId = L"{0b7992da-c5e6-41e3-b24f-55419b997a15}";
                }
              }
            }
          }
          else {
                    /* If KeExpandKernelStackAndCalloutEx succeeds: */
            securityDescriptor = (NPAGED_LOOKASIDE_LIST *)chamberData.SecurityDescriptor;
            chamberIdStr = chamberData.ChamberId;
            accessMask = chamberData.ChamberType;
            chamberId = chamberData.ChamberId;
          }
          if (-1 < chamberData.Status) {
            chamberData.Status = 0;
            if (volumeContext->VerificationNeeded != 0) {
                setter = &accessMask;
                callbackData = Data;
                postCreateContext = securityDescriptor;
                chamberData.Status = FCpAccessCheck(Data,securityDescriptor,(PACCESS_MASK)setter);
                if (-1 < chamberData.Status) goto FCPreCreate_access_denied;
                /* If access denied, adjust access or block operation */
                if (chamberData.Status == -0x3fffffde) {
                    fileCreateOptions = (Data->Iopb->Parameters).Create.Options;
                    postCreateContext = (NPAGED_LOOKASIDE_LIST *)(ulonglong)fileCreateOptions;
                    setter = (PVOID)(ulonglong)(fileCreateOptions & 0xffffff);
                    fileCreateOptionsHighByte = fileCreateOptions >> 0x18;
                    callbackData = (PFLT_CALLBACK_DATA)(ulonglong)fileCreateOptionsHighByte;
                    /* Check if we can adjust the operation to make it succeed */
                    if ((fileCreateOptionsHighByte - 3 & 0xfffffffd) != 0) {
                        if ((fileCreateOptionsHighByte == 2) && ((fileCreateOptions & 1) != 0)) {
                            /* STATUS_OBJECT_NAME_COLLISION - Object Name already exists */
                            chamberData.Status = -0x3fffffcb;
                            goto FCPreCreate_return;
                        }
                        goto FCPreCreate_access_denied2;
                    }
                    /* 4 = FILE_OVERWRITE */
                    newCreateOptions = 4;
                    /* 1 = FILE_OPEN */
                    if (fileCreateOptionsHighByte != 5) {
                        newCreateOptions = 1;
                    }
                    /* Setting the high 8 bits which contain the CreateOptions flags
                       See fltKernel.h _FLT_PARAMETERS */
                    (Data->Iopb->Parameters).Create.Options = newCreateOptions << 0x18 | fileCreateOptions & 0xffffff;
                    setter = &accessMask;
                    callbackData = Data;
                    postCreateContext = securityDescriptor;
                    /* Try access check again with modified options */
                    chamberData.Status = FCpAccessCheck(Data,securityDescriptor,(PACCESS_MASK)setter);
                    if (chamberData.Status != 0) goto FCPreCreate_access_denied2;
                    isAccessAllowed = '\x01';
                    callbackData = Data;
                    /* Mark the data as modified
                       
                       This section (above) did the following:
                       1. Perform an access check using the security descriptor
                       2. If access is denied, it tries to modify the operation (changing create disposition) to make it
                       succeed
                       3. If the modified operation is allowed, it marks the callback data as modified
                       4. Otherwise, it denies the operation */
                    FltSetCallbackDataDirty(Data);
                }
                else {
                FCPreCreate_access_denied2:
                    isAccessAllowed = '\0';
                }
                if (chamberData.Status < 0) {
                    if ((Microsoft_Windows_FileCryptEnableBits & 2) != 0) {
                        McTemplateK0zd_EtwWriteTransfer
                            (callbackData,postCreateContext,setter,chamberPath.Buffer,(char)chamberData.Status);
                    }
                    goto FCPreCreate_return;
                }
            }
            else {
            FCPreCreate_access_denied:
                isAccessAllowed = '\0';
            }
            isMobile = FsRtlIsMobileOS();
            if (isMobile == '\0') {
                    /* For desktop OS, just set privileged mode flag SPECIAL_ENCRYPTED_OPEN on AccessState's flags */
              if (chamberData.ChamberType - 1 < 2) {
                setter = ((Data->Iopb->Parameters).Create.SecurityContext)->AccessState;
                *(ULONG *)((longlong)setter + 0xc) = *(ULONG *)((longlong)setter + 0xc) | 0x40000;
              }
              if (chamberId != NULL) {
                    /* Free chamber ID and return without completion context */
                FCpFreeChamberId(chamberId);
                chamberIdStr = NULL;
                *CompletionContext = NULL;
                return_status = FLT_PREOP_SUCCESS_WITH_CALLBACK;
                chamberId = NULL;
                goto FCPreCreate_cleanup;
              }
            }
            else if (chamberId != NULL) {
                    /* For mobile OS, create a completion context to pass to post-operation */
              postCreateContext = &gPre2PostCreateContextList;
              lookasideListEntry =
                   (CUSTOM_FC_CREATE_CONTEXT *)
                   ExAllocateFromNPagedLookasideList((PNPAGED_LOOKASIDE_LIST)&gPre2PostCreateContextList);
              if (lookasideListEntry == NULL) {
                    /* ntstatus.h STATUS_BAD_INITIAL_STACK (see the function return at the end) */
                chamberData.Status = -0x3fffff66;
                if ((Microsoft_Windows_FileCryptEnableBits & 1) != 0) {
                  McTemplateK0d_EtwWriteTransfer(postCreateContext,&AllocationFailure,setter,0xc000009a);
                }
                return_status = FLT_PREOP_SUCCESS_WITH_CALLBACK;
                goto FCPreCreate_cleanup;
              }
              lookasideListEntry->ChamberId = chamberId;
              lookasideListEntry->ChamberType = chamberData.ChamberType;
              lookasideListEntry->IsAccessAllowed = isAccessAllowed;
            }
            *CompletionContext = lookasideListEntry;
            goto FCPreCreate_cleanup;
          }
          isChamberPathSet = true;
          if ((Microsoft_Windows_FileCryptEnableBits & 1) != 0) {
            errorEventDescriptor = &ObtainSdAndChamberIdFailure;
            isChamberPathSet = true;
            goto FCPreCreate_log_before_return;
          }
        }
      }
    }
  }
FCPreCreate_return:
  return_status = FLT_PREOP_SUCCESS_WITH_CALLBACK;
  lookasideListEntry = NULL;
FCPreCreate_cleanup:
  if (volumeContext != NULL) {
    FltReleaseContext(volumeContext);
  }
  if (fileNameInfo != NULL) {
    FltReleaseFileNameInformation(fileNameInfo);
  }
  if (isChamberPathSet) {
    ExFreePoolWithTag(chamberPath.Buffer,0x666e4346);
    chamberPath = (UNICODE_STRING)((undefined  [16])chamberPath & (undefined  [16])0xffffffff00000000);
  }
  postCreateContext = securityDescriptor;
  if (securityDescriptor != NULL) {
    ExFreePoolWithTag(securityDescriptor,0x70537453);
  }
  if (chamberData.Status < 0) {
    if (chamberId != NULL) {
      FCpFreeChamberId(chamberId);
      postCreateContext = (NPAGED_LOOKASIDE_LIST *)chamberId;
    }
    if (lookasideListEntry != NULL) {
      postCreateContext = &gPre2PostCreateContextList;
      ExFreeToNPagedLookasideList((PNPAGED_LOOKASIDE_LIST)&gPre2PostCreateContextList,lookasideListEntry);
    }
                    /* Returning FLT_PREOP_COMPLETE must be accompanied with an IoStatus set */
    (Data->IoStatus).field0_0x0.Status = chamberData.Status;
    (Data->IoStatus).Information = 0;
                    /* When this routine returns FLT_PREOP_COMPLETE, FltMgr won't send the I/O operation to any
                       minifilter drivers below the caller in the driver stack or to the file system. In this case,
                       FltMgr only calls the post-operation callback routines of the minifilter drivers above the caller
                       in the driver stack. */
    return_status = FLT_PREOP_COMPLETE;
    if ((Microsoft_Windows_FileCryptEnableBits & 2) != 0) {
      McTemplateK0d_EtwWriteTransfer(postCreateContext,&PreCreateFailure,setter,chamberData.Status);
    }
  }
  return return_status;
}