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

#include "kappx.h"
#include "fc.h"
#include <ntstrsafe.h>
#include "stsec.h"


/* This function is tasked with locating where Windows Store applications are physically installed on the filesystem. */
NTSTATUS
KappxGetPackageRootPathForPackageFullName(
    PCUNICODE_STRING PackageFullName,
    PWCHAR* PackageRootPath
)
{
    NTSTATUS return_status;
    NTSTATUS registryStatus;
    PWCHAR packagePathBuffer;
    ULONG pathBufferSize;
    ULONG resultLength = 0;
    HANDLE keyHandle = NULL;
    UNICODE_STRING registryPath = {
        0x80,
        0x82,
        L"\\Registry\\Machine\\Software\\Microsoft\\Windows\\CurrentVersion\\Appx"
    };
    UNICODE_STRING valueName = {
        0x16,
        0x18,
        L"PackageRoot"
    };
    OBJECT_ATTRIBUTES objectAttributes;
    KEY_VALUE_FULL_INFORMATION keyValueInfo;

    if (PackageFullName->Length == 0)
    {
        goto KappxGetPackageRootPathForPackageFullName_return;
    }

    /* If the global package root (g_PackageRoot) hasn't been initialized yet */
    if (g_PackageRoot == NULL)
    {
        /* Open the registry key containing Windows app package information and
           query the "PackageRoot" value from the key */
        InitializeObjectAttributes(
            &objectAttributes,
            &registryPath,
            OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
            NULL,
            NULL
        )

        registryStatus = ZwOpenKey(&keyHandle, 0x2000000, &objectAttributes);
        packagePathBuffer = NULL;

        if (
            (
                ((-1 < registryStatus) &&
                    (registryStatus = ZwQueryValueKey(
                        keyHandle,
                        &valueName,
                        KeyValueFullInformation,
                        &keyValueInfo,
                        0x210,
                        &resultLength), -1 < registryStatus)
                ) &&
                (keyValueInfo.Type == 1)
            ) &&
            (
                (3 < keyValueInfo.DataLength &&
                    (*(short*)((longlong)keyValueInfo.Name +
                        (ulonglong)keyValueInfo.DataOffset + (ulonglong)keyValueInfo.DataLength + -0x16) == 0))
            )
        )
        {
            /* If successful, process the value and stores it in global variables */
            g_PackageRootLength = keyValueInfo.DataLength + 10;
            /* Format and store the path with prefix
               
               The "\\??\\" prefix is significant - it's a Windows NT object manager namespace prefix that
               allows accessing filesystem paths */
            return_status = RtlStringCbPrintfW(
                (PWCHAR)&g_PackageRoot,
                0x104,
                L"\\??\\%ws\\",
                (longlong)keyValueInfo.Name + ((ulonglong)keyValueInfo.DataOffset - 0x14)
            );

            if (-1 < return_status)
            {
                goto KappxGetPackageRootPathForPackageFullName_construct_path;
            }

            g_PackageRootLength = 0;
            g_PackageRoot = NULL;
        }
    }
    else
    {
    KappxGetPackageRootPathForPackageFullName_construct_path:
        pathBufferSize = (ULONG)PackageFullName->Length;
        pathBufferSize = pathBufferSize + g_PackageRootLength + 2;
        packagePathBuffer = ExAllocatePool2(0x100, pathBufferSize, POOL_TAG_AppX);
        /* Combine the root path with the package name */

        if (((packagePathBuffer != NULL) &&
                (return_status = RtlStringCbCopyW(
                    packagePathBuffer,
                    (ulonglong)pathBufferSize,
                    (PWCHAR)&g_PackageRoot
                ), -1 < return_status)) &&
            (return_status = RtlStringCbCatNW(
                packagePathBuffer,
                pathBufferSize,
                PackageFullName->Buffer,
                PackageFullName->Length
            ), -1 < return_status)
        )
        {
            /* End result example:
             * "\\??\C:\Program
             * Files\WindowsApps\Microsoft.Office.Word_16.0.14228.20216_x64_en-us_8wekyb3d8bbwe\" */
            *PackageRootPath = packagePathBuffer;
            packagePathBuffer = NULL;
        }
    }

    if (keyHandle != NULL)
    {
        ZwClose(keyHandle);
    }

    if (packagePathBuffer != NULL)
    {
        ExFreePoolWithTag(packagePathBuffer, 0);
    }

KappxGetPackageRootPathForPackageFullName_return:
    return return_status;
}


/* This function extracts a Security Identifier (SID) for a Windows Store app from the registry,
 * using its package family name. It retrieves the SID associated with a package family name by
 * querying the Windows registry. This SID represents the security principal of the app. */
NTSTATUS
KappxGetPackageSidFromPackageFamilyNameInRegistry(
    PCUNICODE_STRING PackageFamilyName,
    PWCHAR* OutSid
)
{
    NTSTATUS return_status;
    PWCHAR targetRegistryPath;
    NTSTATUS status1;
    NTSTATUS status2;
    NTSTATUS status3;
    NTSTATUS status4;
    NTSTATUS status5;
    PVOID fullPathBuffer;
    KEY_VALUE_FULL_INFORMATION* valueInfoBuffer = NULL;
    NTSTATUS status6;
    PWCHAR sidStringBuffer;
    uint regValueLengthPlus2;
    PWCHAR currentCharPos;
    longlong lVar1;
    ushort pathLength;
    NTSTATUS status7;
    KEY_VALUE_FULL_INFORMATION* pKVar2 = NULL;
    KEY_VALUE_FULL_INFORMATION* pKVar3 = NULL;
    ULONG bufferLength = 0;
    PHANDLE regKeyHandle = NULL;
    UNICODE_STRING fullPathString;
    UNICODE_STRING pathString = {0, 0, NULL};
    UNICODE_STRING packageSidValueName = {
        0x14,
        0x18,
        L"PackageSid"
    };
    OBJECT_ATTRIBUTES objectAttributes;
    short registryPathLength;

    /* The registry path this function accesses has a structure like:
     * \Registry\Machine\Software\Microsoft\Windows\CurrentVersion\Appx\PackageSidRef\{PackageFamilyName}
     * This key contains a value named "PackageSid" that stores the string representation of the app's
     * Security Identifier.
     * By retrieving the SID, the driver can identify the security principal associated with a Windows
     * Store app*/

    sidStringBuffer = (PWCHAR)valueInfoBuffer;

    if (PackageFamilyName->Length == 0)
    {
        return_status = STATUS_OBJECT_NAME_NOT_FOUND;
    }
    else
    {
        targetRegistryPath = (PWCHAR)ExAllocatePool2(0x100, 0x20a, POOL_TAG_AppX);

        if (targetRegistryPath == NULL)
        {
            return_status = STATUS_NO_MEMORY;
            valueInfoBuffer = pKVar2;
            sidStringBuffer = (PWCHAR)pKVar3;
        }
        else
        {
            /* Get the registry path for app package SID references */
            return_status = RtlGetPersistedStateLocation(
                L"AppxPackageSidRef",
                L"TargetNtPath",
                L"\\Registry\\Machine\\Software\\Microsoft\\Windows\\CurrentVersion\\Appx\\PackageSidRef",
                0,
                targetRegistryPath,
                0x20a,
                &bufferLength
            );

            if (-1 < return_status)
            {
                lVar1 = 0x7fff;
                currentCharPos = targetRegistryPath;
                do
                {
                    if (*currentCharPos == L'\0')
                    {
                        /* Path is valid, now append the package family name */
                        registryPathLength = (0x7fff - (short)lVar1) * 2;

                        // pathString = (UNICODE_STRING)CONCAT88(targetRegistryPath, pathString._0_8_);
                        pathString.Buffer = targetRegistryPath;

                        RtlInitUnicodeString(&fullPathString,NULL);
                        /* Calculate full path length (registry path + package family name + null terminator) */
                        pathLength = pathString.Length + 2 + PackageFamilyName->Length;
                        fullPathBuffer = ExAllocatePool2(0x100, (ulonglong)pathLength, POOL_TAG_AppX);

                        //fullPathString = CONCAT88(fullPathBuffer, fullPathString);
                        fullPathString.Buffer = fullPathBuffer;

                        if (fullPathBuffer == NULL)
                        {
                            return_status = STATUS_NO_MEMORY;
                            valueInfoBuffer = pKVar2;
                            sidStringBuffer = (PWCHAR)pKVar3;
                        }
                        else
                        {
                            memset(fullPathBuffer, 0, pathLength);
                            //fullPathString = ZEXT1416(CONCAT122(stack0xffffffffffffff6c, pathLength)) << 0x10;
                            fullPathString.Length = pathLength;
                            fullPathString.MaximumLength = pathLength;

                            status1 = RtlAppendUnicodeStringToString(&fullPathString, &pathString);
                            return_status = status1;

                            if (((-1 < status1) &&
                                    (status2 = RtlAppendUnicodeStringToString
                                        (&fullPathString, PackageFamilyName),
                                        valueInfoBuffer = pKVar2, sidStringBuffer = (PWCHAR)pKVar3, return_status =
                                        status2, -1 < status2)) &&
                                (status3 = RtlAppendUnicodeToString(&fullPathString, L""),
                                    return_status = status3,
                                    -1 < status3))
                            {
                                // objectAttributes._0_16_ = CONCAT124(objectAttributes._4_12_, 0x30);
                                // objectAttributes._0_16_ = objectAttributes._0_16_ & (undefined [16])0xffffffffffffffff;
                                // objectAttributes._32_16_ = ZEXT816(0);
                                InitializeObjectAttributes(
                                    &objectAttributes,
                                    &fullPathString,
                                    OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                                    0,
                                    NULL
                                )

                                status4 = ZwOpenKey(&regKeyHandle, 0x2000000, &objectAttributes);
                                return_status = status4;
                                /* Query the "PackageSid" value */
                                if ((-1 < status4) &&
                                    (status5 = ZwQueryValueKey(regKeyHandle, (PUNICODE_STRING)&packageSidValueName,
                                                               KeyValueFullInformation
                                                               ,NULL, 0, &bufferLength), return_status = status5,
                                        status5 == STATUS_BUFFER_TOO_SMALL))
                                {
                                    valueInfoBuffer =
                                        (KEY_VALUE_FULL_INFORMATION*)ExAllocatePool2(
                                            0x100, (ulonglong)bufferLength, POOL_TAG_AppX);
                                    if (valueInfoBuffer == NULL)
                                    {
                                        return_status = STATUS_NO_MEMORY;
                                    }
                                    else
                                    {
                                        /* Get the value info */
                                        status6 = ZwQueryValueKey(regKeyHandle, (PUNICODE_STRING)&packageSidValueName,
                                                                  KeyValueFullInformation
                                                                  , valueInfoBuffer, bufferLength, &bufferLength);
                                        return_status = status6;
                                        if (-1 < status6)
                                        {
                                            /* Validate the value data */
                                            if (((valueInfoBuffer->Type == 1) &&
                                                    (regValueLengthPlus2 = valueInfoBuffer->DataLength, 3 <
                                                        regValueLengthPlus2)) ||
                                                (regValueLengthPlus2 = valueInfoBuffer->DataLength,
                                                    *(short*)((longlong)valueInfoBuffer->Name +
                                                        (ulonglong)regValueLengthPlus2 + (ulonglong)valueInfoBuffer->
                                                        DataOffset + -0x16) != 0
                                                ))
                                            {
                                                sidStringBuffer = (PWCHAR)ExAllocatePool2(
                                                    0x100, (ulonglong)regValueLengthPlus2 + 2, POOL_TAG_AppX);
                                                if (sidStringBuffer == NULL)
                                                {
                                                    return_status = STATUS_NO_MEMORY;
                                                }
                                                else
                                                {
                                                    return_status =
                                                        RtlStringCbCopyNW(
                                                            sidStringBuffer, (ulonglong)valueInfoBuffer->DataLength + 2,
                                                            (PWCHAR)((longlong)valueInfoBuffer->Name +
                                                                ((ulonglong)valueInfoBuffer->DataOffset - 0x14)),
                                                            (ulonglong)valueInfoBuffer->DataLength);
                                                    if (-1 < return_status)
                                                    {
                                                        *OutSid = sidStringBuffer;
                                                        sidStringBuffer = (PWCHAR)NULL;
                                                    }
                                                }
                                            }
                                            else
                                            {
                                                return_status = STATUS_BAD_DATA;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        goto KappxGetPackageSidFromPackageFamilyNameInRegistry_cleanup_and_return;
                    }
                    currentCharPos = currentCharPos + 1;
                    lVar1 = lVar1 + -1;
                }
                while (lVar1 != 0);
                status7 = STATUS_INVALID_PARAMETER;
                valueInfoBuffer = pKVar2;
                sidStringBuffer = (PWCHAR)pKVar3;
                return_status = status7;
            }
        }
    KappxGetPackageSidFromPackageFamilyNameInRegistry_cleanup_and_return:
        if (regKeyHandle != NULL)
        {
            ZwClose(regKeyHandle);
        }
        if (targetRegistryPath != NULL)
        {
            ExFreePoolWithTag(targetRegistryPath, POOL_TAG_AppX);
        }
    }

    if (fullPathString.Buffer != NULL)
    {
        ExFreePoolWithTag(fullPathString.Buffer, 0);
    }
    if (sidStringBuffer != NULL)
    {
        ExFreePoolWithTag(sidStringBuffer, 0);
    }
    if (valueInfoBuffer != NULL)
    {
        ExFreePoolWithTag(valueInfoBuffer, 0);
    }

    return return_status;
}


/* Obtains a security descriptor string for a Windows Store app (UWP application) based on its package full name.
 * It enables the driver to apply different security policies to different Windows Store app. */
NTSTATUS
KappxGetSecurityDescriptorStringForPackageFullName(
    PCUNICODE_STRING PackageFullName,
    PWCHAR* SecurityDescriptorString
)
{
    NTSTATUS intermediateStatus;
    NTSTATUS return_status;
    PSECURITY_DESCRIPTOR binarySecurityDescriptor = NULL;
    PWCHAR defaultSecDescBuffer;
    longlong stringCopyCount;
    PWCHAR destStringPos = NULL;
    PWCHAR stringBuffer = NULL;
    bool stringCopySuccess;
    ULONG secObjectLenght = 0;
    ULONG secDescStringLength = 0;
    HANDLE secObjectHandle = NULL;
    PWCHAR* packageRootPath = NULL;
    OBJECT_ATTRIBUTES objectAttributes;
    UNICODE_STRING packagePathString = {0, 0, NULL};
    IO_DRIVER_CREATE_CONTEXT driverCreateContext;
    IO_STATUS_BLOCK ioStatusBlock = {0, 0};
    PWCHAR* packagePathPointer;
    WCHAR stringSecurityDescriptor;

    /* determine the filesystem path where the package is installed */
    intermediateStatus = KappxGetPackageRootPathForPackageFullName(PackageFullName, (PWCHAR*)&packageRootPath);
    packagePathPointer = packageRootPath;
    defaultSecDescBuffer = (PWCHAR)binarySecurityDescriptor;

    if (-1 < intermediateStatus)
    {
        RtlInitUnicodeString(&packagePathString, (PCWSTR)packageRootPath);

        // objectAttributes._0_16_ = CONCAT124(objectAttributes._4_12_, 0x30);
        // objectAttributes._0_16_ = objectAttributes._0_16_ & (undefined [16])0xffffffffffffffff;
        // objectAttributes._32_16_ = ZEXT816(0);
        InitializeObjectAttributes(
            &objectAttributes,
            &packagePathString,
            OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
            NULL,
            NULL
        )

        // driverCreateContext._0_16_ = CONCAT142(driverCreateContext._2_14_, 0x28);
        driverCreateContext.Size = 0x28;
        driverCreateContext.SiloContext = PsGetHostSilo();

        /* open the package's directory */
        intermediateStatus = IoCreateFileEx(
            &secObjectHandle,
            0x20000,
            &objectAttributes,
            &ioStatusBlock,
            0,
            0,
            7,
            1,
            0x200009,
            0,
            0,
            0,
            0,
            0,
            &driverCreateContext
        );

        if (intermediateStatus == STATUS_OBJECT_NAME_NOT_FOUND)
        {
            defaultSecDescBuffer = (PWCHAR)ExAllocatePool2(0x100, 0x23a, POOL_TAG_AppX);
            binarySecurityDescriptor = destStringPos;

            if (defaultSecDescBuffer == NULL)
            {
                intermediateStatus = STATUS_NO_MEMORY;
            }
            else
            {
                /* If the package directory can't be opened (STATUS_OBJECT_NAME_NOT_FOUND), provide a default
                 * security descriptor */
                stringCopyCount = 0x11d;
                destStringPos = defaultSecDescBuffer;
                do
                {
                    /* This is an SDDL (Security Descriptor Definition Language) string that defines:
                       - Owner: App integrity level (AI)
                       - Discretionary ACL (D:) with multiple ACEs (Access Control Entries)
                       - Various permissions for different security identifiers (SIDs) */
                    if ((stringCopyCount == -0x7ffffee1) ||
                        (
                            stringSecurityDescriptor =
                            *(WCHAR*)(((longlong)
                                    L"D:AI(A;OICI;0x1200a9;;;BU)(A;ID;FA;;;S-1-5-80-956008885-3418522649-1831038044-185329263 1-2271478464)(A;CIIOID;FA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-227147846 4)(A;ID;FA;;;SY)(A;OICIIOID;FA;;;SY)(A;OICIID;0x1200a9;;;BA)(A;OICIID;0x1200a9;;;LS)(A;OI CIID;0x1200a9;;;NS)"
                                    - (longlong)defaultSecDescBuffer)
                                + (longlong)destStringPos
                            ),
                            stringSecurityDescriptor == L'\0'
                        )
                    )
                    {
                        break;
                    }

                    *destStringPos = stringSecurityDescriptor;
                    destStringPos = destStringPos + 1;
                    stringCopyCount = stringCopyCount + -1;
                }
                while (stringCopyCount != 0);

                stringCopySuccess = stringCopyCount != 0;
                stringBuffer = destStringPos + -1;
                if (stringCopySuccess)
                {
                    stringBuffer = destStringPos;
                }

                intermediateStatus = STATUS_BUFFER_OVERFLOW;
                if (stringCopySuccess)
                {
                    intermediateStatus = STATUS_SUCCESS;
                }

                *stringBuffer = L'\0';
                if (stringCopySuccess)
                {
                    *SecurityDescriptorString = defaultSecDescBuffer;
                    defaultSecDescBuffer = NULL;
                }
            }
        }
        else
        {
            defaultSecDescBuffer = stringBuffer;
            /* If IoCreateFileEx was successful */
            if (-1 < intermediateStatus)
            {
                return_status = ZwQuerySecurityObject(
                    secObjectHandle,
                    0xc,
                    NULL,
                    0,
                    &secObjectLenght
                );
                intermediateStatus = return_status;

                if (return_status == STATUS_BUFFER_TOO_SMALL)
                {
                    binarySecurityDescriptor = ExAllocatePool2(0x100, secObjectLenght, POOL_TAG_AppX);

                    if (binarySecurityDescriptor == NULL)
                    {
                        intermediateStatus = STATUS_NO_MEMORY;
                    }
                    else
                    {
                        intermediateStatus =
                            ZwQuerySecurityObject(secObjectHandle, 0xc, binarySecurityDescriptor, secObjectLenght,
                                                  &secObjectLenght);
                        if (-1 < intermediateStatus)
                        {
                            intermediateStatus = SeConvertSecurityDescriptorToStringSecurityDescriptor(
                                binarySecurityDescriptor,
                                1,
                                0xc,
                                SecurityDescriptorString,
                                &secDescStringLength
                            );
                        }
                    }
                }
            }
        }
    }
    if (secObjectHandle != NULL)
    {
        ZwClose(secObjectHandle);
    }
    if (packagePathPointer != NULL)
    {
        ExFreePoolWithTag(packagePathPointer, 0);
    }
    if ((PWCHAR)binarySecurityDescriptor != NULL)
    {
        ExFreePoolWithTag(binarySecurityDescriptor, 0);
    }
    if (defaultSecDescBuffer != NULL)
    {
        ExFreePoolWithTag(defaultSecDescBuffer, 0);
    }
    return intermediateStatus;
}
