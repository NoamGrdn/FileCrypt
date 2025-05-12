#include "stsec.h"
#include <wdm.h>
#include <bcrypt.h>

#include "rtlString.h"

VOID
StSecDeinitialize(
    VOID)
{
    PCUSTOM_FC_STSEC_FOLDER_PROP_CACHE_LIST_ENTRY folderPropcacheEntry;
    PCUSTOM_FC_STSEC_FOLDER_PROP_CACHE_LIST_ENTRY folderPropcacheEntryPrev;
    UNICODE_STRING* path;
    PCUSTOM_FC_STSEC_SEC_DESC_CACHE_LIST_ENTRY secDescCacheEntry;
    PCUSTOM_FC_STSEC_SEC_DESC_CACHE_LIST_ENTRY secDescCachePrevEntry;

    StSecpCacheDeinitialize();
    if (g_HmacHashProvider != NULL)
    {
        BCryptCloseAlgorithmProvider(g_HmacHashProvider, 0);
        g_HmacHashProvider = NULL;
    }
    while (
        secDescCacheEntry = g_StSecSecurityDescriptorCacheListHead,
        g_StSecSecurityDescriptorCacheListHead != g_StSecSecurityDescriptorCacheListHead)
    {
        if (
            (g_StSecSecurityDescriptorCacheListHead->Prev != g_StSecSecurityDescriptorCacheListHead) ||
            (
                secDescCachePrevEntry = g_StSecSecurityDescriptorCacheListHead->Next,
                secDescCachePrevEntry->Prev != g_StSecSecurityDescriptorCacheListHead
            )
        )
        {
            goto StSecDeinitialize_cleanup_and_return;
        }

        path = &g_StSecSecurityDescriptorCacheListHead->Path;
        g_StSecSecurityDescriptorCacheListHead = secDescCachePrevEntry;
        secDescCachePrevEntry->Prev = g_StSecSecurityDescriptorCacheListHead;

        RtlFreeUnicodeString(path);
        StSecFree(secDescCacheEntry->SecurityDescriptor);
        StSecFree(secDescCacheEntry->DebugValue);
        StSecFree(secDescCacheEntry);
    }
    while (
        folderPropcacheEntry = g_StSecFolderPropertyCacheListHead,
        g_StSecFolderPropertyCacheListHead != g_StSecFolderPropertyCacheListHead
    )
    {
        if ((g_StSecFolderPropertyCacheListHead->Prev != g_StSecFolderPropertyCacheListHead) ||
            (folderPropcacheEntryPrev = g_StSecFolderPropertyCacheListHead->Next,
                folderPropcacheEntryPrev->Prev != g_StSecFolderPropertyCacheListHead))
        {
            goto StSecDeinitialize_cleanup_and_return;
        }

        path = &g_StSecFolderPropertyCacheListHead->Path;
        g_StSecFolderPropertyCacheListHead = folderPropcacheEntryPrev;
        folderPropcacheEntryPrev->Prev = g_StSecFolderPropertyCacheListHead;

        RtlFreeUnicodeString(path);
        StSecFree(folderPropcacheEntry->ChamberId);
        StSecFree(folderPropcacheEntry);
    }

StSecDeinitialize_cleanup_and_return:
    if (g_HashProvider != NULL)
    {
        BCryptCloseAlgorithmProvider(g_HashProvider, 0);
        g_HashProvider = NULL;
    }
    if (g_DebugProfileKey != NULL)
    {
        ZwClose(g_DebugProfileKey);
    }
}


VOID
StSecFree(
    PVOID Buffer
)
{
    if (Buffer != NULL)
    {
        ExFreePoolWithTag(Buffer,POOL_TAG_STsp);
    }
}


/* This function represents the culmination of the driver's path-based security model:
 * Security Descriptor Lookup:
 * It calls StSecpGetStorageFolderStringSecurityDescriptor which in turn uses
 * StSecpFindSecurityDescriptorPolicyElement to find and process the matching security policy
 *
 * Folder Property Lookup:
 * It calls StSecpFindFolderPropertyPolicyElement directly to determine encryption behaviors
 *
 * Parameter Resolution:
 * For parameterized chamber IDs, it uses similar path-matching logic to what we've seen in the
 * policy lookup functions
 * It resolves parameters based on their type, with special handling for package names
 *
 * Encryption Context Determination:
 * Through the chamber ID and type, it identifies the specific encryption context to use */
NTSTATUS
StSecGetSecurityDescriptor(
    PCUNICODE_STRING InputPath,
    PSECURITY_DESCRIPTOR OutSecurityDescriptor,
    PWCHAR* OutChamberId,
    PULONG OutChamberType
)
{
    NTSTATUS return_status;
    int status;
    CUSTOM_FC_STSEC_FOLDER_PROP_CACHE_LIST_ENTRY* policyElement;
    PWCHAR stringBuffer;
    longlong stringLength;
    PWCHAR chamberId = NULL;
    PWCHAR securityDescString = NULL;
    UNICODE_STRING paramName;
    UNICODE_STRING componentName;
    UNICODE_STRING policyComponent;
    UNICODE_STRING remainingPath;
    UNICODE_STRING pathSuffix;
    PWCHAR chamberIdStr = NULL;
    longlong stringSegmentLength;
    UNICODE_STRING tempString;

    chamberId = chamberIdStr;

    if (
        InputPath == NULL ||
        InputPath->Buffer == NULL ||
        OutSecurityDescriptor == NULL ||
        OutChamberId == NULL ||
        OutChamberType == NULL
    )
    {
    StSecGetSecurityDescriptor_invalid_parameter:
        return_status = STATUS_INVALID_PARAMETER;
        goto StSecGetSecurityDescriptor_cleanup_and_return;
    }

    /* Get a security descriptor string that matches the input path */
    return_status = StSecpGetStorageFolderStringSecurityDescriptor(InputPath, &securityDescString);
    chamberId = securityDescString;

    /* converts the string-form security descriptor into a binary security descriptor that can be used
     * for access checks. The 1 parameter indicates this is SDDL format. */
    if ((return_status < 0) ||
        (return_status = SeConvertStringSecurityDescriptorToSecurityDescriptor(
            securityDescString,
            1,
            OutSecurityDescriptor,
            0
        ), return_status < 0))
    {
        goto StSecGetSecurityDescriptor_cleanup_and_return;
    }

    securityDescString = (PWCHAR)((ulonglong)securityDescString & 0xffffffff00000000);
    // componentName = (UNICODE_STRING)ZEXT816(0);
    // pathSuffix = (UNICODE_STRING)ZEXT816(0);
    // policyComponent = (UNICODE_STRING)ZEXT816(0);
    // remainingPath = (UNICODE_STRING)ZEXT816(0);
    componentName.Length = 0;
    componentName.MaximumLength = 0;
    componentName.Buffer = 0;
    pathSuffix.Length = 0;
    pathSuffix.MaximumLength = 0;
    pathSuffix.Buffer = 0;
    policyComponent.Length = 0;
    policyComponent.MaximumLength = 0;
    policyComponent.Buffer = 0;
    remainingPath.Length = 0;
    remainingPath.MaximumLength = 0;
    remainingPath.Buffer = 0;

    policyElement = StSecpFindFolderPropertyPolicyElement(InputPath);
    paramName.Buffer = NULL;
    tempString = paramName;

    if (policyElement == NULL)
    {
        goto StSecGetSecurityDescriptor_set_output_params;
    }

    chamberIdStr = policyElement->ChamberId;
    securityDescString = (PWCHAR)((ulonglong)securityDescString & 0xffffffff00000000 | (ulonglong)policyElement->
        FolderId);

    if (chamberIdStr == NULL)
    {
        goto StSecGetSecurityDescriptor_invalid_parameter;
    }

    stringLength = 0x7fffffff;
    stringBuffer = chamberIdStr;
    do
    {
        if (*stringBuffer == L'\0')
        {
            break;
        }
        stringBuffer = stringBuffer + 1;
        stringLength = stringLength + -1;
    }
    while (stringLength != 0);

    return_status = STATUS_INVALID_PARAMETER;

    if (stringLength == 0)
    {
        //paramName = (UNICODE_STRING)(ZEXT816(paramName.Buffer) << 0x40);
        paramName.Length = 0;
        paramName.MaximumLength = 0;
        goto StSecGetSecurityDescriptor_cleanup_and_return;
    }

    stringSegmentLength = -stringLength;

    //paramName = (UNICODE_STRING)CONCAT88(paramName.Buffer, stringSegmentLength + 0x7fffffff);
    USHORT calculatedLength = stringSegmentLength + 0x7fffffff;
    paramName.Length = calculatedLength;
    paramName.MaximumLength = calculatedLength;

    stringLength = 0x7fffffff - stringLength;

    /* Check if this is a parameterized chamber ID (enclosed in <>) */
    if ((*chamberIdStr == L'<') &&
        (stringLength = stringSegmentLength + 0x7fffffff, chamberIdStr[stringSegmentLength + 0x7ffffffe] == L'>'))
    {
        /* For parameterized chamber IDs, perform path-based parameter resolution */
        paramName = policyElement->Path;
        FsRtlDissectName(paramName, &policyComponent, &remainingPath);
        paramName = *InputPath;
        FsRtlDissectName(paramName, &componentName, &pathSuffix);
        tempString = paramName;
        paramName = remainingPath;
        while (remainingPath = paramName, policyComponent.Buffer != NULL)
        {
            FsRtlDissectName(paramName, &policyComponent, &remainingPath);
            paramName = pathSuffix;
            FsRtlDissectName(paramName, &componentName, &pathSuffix);
            tempString = paramName;
            paramName = remainingPath;
        }
        //componentName.Buffer = SUB168((undefined [16])componentName >> 0x40, 0);
        // NOOP?
        paramName.Buffer = NULL;

        /* handles different parameter types */
        if (componentName.Buffer != NULL)
        {
            paramName = tempString;
            status = _wcsicmp(policyElement->ChamberId, L"<PackageFamilyName>");
            if ((status == 0) || (status = _wcsicmp(policyElement->ChamberId, L"<ProductId>"), status == 0))
            {
                /* Handle PackageFamilyName or ProductId parameter */
                paramName.Buffer = ExAllocatePool2(0x100, (ulonglong)componentName.Length + 2, 0x70537453);
                if (paramName.Buffer == NULL)
                {
                    return_status = STATUS_NO_MEMORY;
                    goto StSecGetSecurityDescriptor_cleanup_and_return;
                }
                return_status =
                    RtlStringCbCopyNW(paramName.Buffer, (ulonglong)componentName.Length + 2, componentName.Buffer,
                                      (ulonglong)componentName.Length);
                goto joined_r0x0001c000f657;
            }
            /* Handle PackageFullName parameter */
            status = _wcsicmp(policyElement->ChamberId, L"<PackageFullName>");
            if (status != 0)
            {
                return_status = -0x3fffffff;
                goto StSecGetSecurityDescriptor_cleanup_and_return;
            }
            //paramName = (UNICODE_STRING)ZEXT816(0);
            paramName.Length = 0;
            paramName.MaximumLength = 0;
            paramName.Buffer = NULL;

            return_status = StSecpPackageFamilyNameFromFullName(&componentName, &paramName);
            if (return_status < 0) goto StSecGetSecurityDescriptor_cleanup_and_return;
            tempString = paramName;
            /* - For <PackageFamilyName> and <ProductId>, it uses the path component directly
               - For <PackageFullName>, it calls StSecpPackageFamilyNameFromFullName to extract the family */
        }
    }
    else
    {
        paramName.Buffer = ExAllocatePool2(0x100, stringLength * 2 + 2, POOL_TAG_STsp);
        if (paramName.Buffer == NULL)
        {
            return_status = STATUS_NO_MEMORY;
            goto StSecGetSecurityDescriptor_cleanup_and_return;
        }
        return_status = RtlStringCchCopyW(paramName.Buffer, stringSegmentLength + 0x80000000, policyElement->ChamberId);
    joined_r0x0001c000f657:
        tempString = paramName;
        if (return_status < 0)
        {
            ExFreePoolWithTag(paramName.Buffer, POOL_TAG_STsp);
            goto StSecGetSecurityDescriptor_cleanup_and_return;
        }
    }
StSecGetSecurityDescriptor_set_output_params:
    paramName = tempString;
    return_status = 0;
    *OutChamberType = (ULONG)securityDescString;
    *OutChamberId = paramName.Buffer;
StSecGetSecurityDescriptor_cleanup_and_return:
    if (chamberId != NULL)
    {
        ExFreePoolWithTag(chamberId, POOL_TAG_STsp);
    }

    return return_status;
}


NTSTATUS StSecInitialize(PDRIVER_OBJECT DriverObject)

{
    NTSTATUS return_status;
    ULONG pcbResult[7];
    PFLT_FILTER filterHandle;

    filterHandle = gFilterHandle;
    // pcbResult._0_8_ = (ulonglong)DriverObject & 0xffffffff00000000;
    pcbResult[2] = 0;

    return_status = BCryptOpenAlgorithmProvider(
        &g_HashProvider,
        L"SHA256",
        NULL,
        0
    );

    if ((g_HashProvider == NULL) && (return_status < 0))
    {
        return return_status;
    }

    return_status = BCryptGetProperty(
        g_HashProvider,
        L"ObjectLength",
        g_cbHashObject,
        4,
        pcbResult,
        0
    );

    if ((-1 < return_status) &&
        (
            return_status = BCryptGetProperty(
                g_HashProvider,
                L"HashDigestLength",
                g_cbHashValue,
                4,
                pcbResult,
                0
            ), -1 < return_status
        )
    )
    {
        if ((g_HmacHashProvider == NULL) &&
            (
                return_status = BCryptOpenAlgorithmProvider(
                    &g_HmacHashProvider,
                    L"SHA256",
                    NULL,
                    8
                ), return_status < 0
            )
        )
        {
            return return_status;
        }

        return_status = BCryptGetProperty(
            g_HmacHashProvider,
            L"HashDigestLength",
            g_cbHashOutputLength,
            4,
            pcbResult + 2,
            0
        );

        if (((-1 < return_status) &&
                (
                    return_status = BCryptGetProperty(
                        g_HmacHashProvider,
                        L"ObjectLength",
                        g_cbHashObjectLength,
                        4,
                        pcbResult + 2,
                        0
                    ), -1 < return_status)) &&
            (
                return_status = StSecpCacheInitialize(filterHandle), -1 < return_status
            )
        )
        {
            return_status = StSecpInitializePolicyCache();
        }
    }
    return return_status;
}


/* This function stores newly derived encryption keys in a memory cache to avoid expensive
 * re-derivation from the master key for subsequent operations */
NTSTATUS
StSecpAddChamberProfileKey(
    PWCHAR ChamberId,
    PUCHAR InstallSecretKey,
    PUCHAR DataSecretKey,
    ULONG SecretKeySize
)
{
    NTSTATUS strCountStatus;
    NTSTATUS return_status;
    PWCHAR chamberIdCopy;
    PUCHAR installKeyCopy = NULL;
    PUCHAR dataKeyCopy = NULL;
    PCUSTOM_FC_STSEC_CACHE_TABLE_ENTRY cacheInsertEntryPointer;
    ULONG numberOfCacheEntries;
    PCUSTOM_FC_STSEC_CACHE_TABLE_ENTRY oldestCacheEntry;
    SIZE_T chamberIdBufferSize;
    ulonglong keyLength = SecretKeySize;
    BOOLEAN wasNewEntryInserted = FALSE;
    LONGLONG chamberIdStringLength = 0;
    CUSTOM_FC_STSEC_CACHE_TABLE_ENTRY newCacheEntry;
    ULONG64 currentSystemTime;
    PWCHAR oldestCacheEntryChamberId;

    strCountStatus = RtlStringCbLengthW(ChamberId, InstallSecretKey, &chamberIdStringLength);

    if (strCountStatus < 0)
    {
        return strCountStatus;
    }

    /* space for null terminator */
    chamberIdBufferSize = chamberIdStringLength + 2;
    chamberIdStringLength = chamberIdBufferSize;
    chamberIdCopy = (PWCHAR)ExAllocatePool2(0x100, chamberIdBufferSize, POOL_TAG_STsp);

    if (chamberIdCopy == NULL)
    {
        return STATUS_NO_MEMORY;
    }
    return_status = RtlStringCbCopyW(chamberIdCopy, chamberIdBufferSize, ChamberId);

    if (-1 < return_status)
    {
        installKeyCopy = ExAllocatePool2(0x40, keyLength, POOL_TAG_StSn);
        if (installKeyCopy != NULL)
        {
            /* Allocate non-paged memory for copies of both the Install and Data key */
            memcpy(installKeyCopy, InstallSecretKey, keyLength);
            dataKeyCopy = ExAllocatePool2(0x40, keyLength, POOL_TAG_StSn);

            if (dataKeyCopy != NULL)
            {
                memcpy(dataKeyCopy, DataSecretKey, keyLength);
                currentSystemTime = SharedTickCount;

                /* Prepare new cache entry */
                // newCacheEntry._0_16_ = CONCAT88(chamberIdCopy, newCacheEntry.LastAccessTime);
                // newCacheEntry._16_16_ = CONCAT88(dataKeyCopy, installKeyCopy);
                newCacheEntry.LastAccessTime = currentSystemTime;
                newCacheEntry.ChamberId = chamberIdCopy;
                newCacheEntry.InstallKey = installKeyCopy;
                newCacheEntry.DataKey = dataKeyCopy;
                newCacheEntry.KeySize = SecretKeySize;

                //stack0xffffffffffffffb8 = stack0xffffffffffffffb8 & 0xffffffff00000000 | (ulonglong)SecretKeySize;
                ExAcquireFastMutex(&g_StSecKeyMutex);

                cacheInsertEntryPointer = RtlInsertElementGenericTable(
                    &g_StSecCacheGenericTable,
                    &newCacheEntry,
                    0x28,
                    &wasNewEntryInserted
                );

                if (cacheInsertEntryPointer == NULL)
                {
                    return_status = STATUS_UNSUCCESSFUL;
                }
                else
                {
                    if (wasNewEntryInserted != '\0')
                    {
                        chamberIdCopy = NULL;
                        installKeyCopy = NULL;
                        dataKeyCopy = NULL;
                    }
                    /* Update timestamp for the entry */
                    cacheInsertEntryPointer->LastAccessTime = currentSystemTime;
                }

                numberOfCacheEntries = RtlNumberGenericTableElements(&g_StSecCacheGenericTable);
                /* If cache exceeds maximum size, remove oldest entry */
                if (_g_CacheMaxSize < numberOfCacheEntries)
                {
                    oldestCacheEntry = RtlGetElementGenericTable(&g_StSecCacheGenericTable, 0);
                    oldestCacheEntryChamberId = oldestCacheEntry->ChamberId;

                    /* Free memory for oldest entry */
                    StSecpFreeNonPaged(oldestCacheEntry->InstallKey, oldestCacheEntry->KeySize);
                    StSecpFreeNonPaged(oldestCacheEntry->DataKey, oldestCacheEntry->KeySize);

                    /* Remove entry from table */
                    RtlDeleteElementGenericTable(&g_StSecCacheGenericTable, oldestCacheEntry);
                    StSecFree(oldestCacheEntryChamberId);
                }
                ExReleaseFastMutex(&g_StSecKeyMutex);

                /* If cache exceeds cleanup trigger size, queue background cleanup */
                if ((_g_CacheCleanupTriggerSize < numberOfCacheEntries) && (/*LOCK(), */g_WorkItemQueued == 0))
                {
                    g_WorkItemQueued = 1;
                    return_status = FltQueueGenericWorkItem(
                        g_WorkItem,
                        g_FilterObject,
                        StSecpCacheCleanupWorkItem,
                        DelayedWorkQueue,
                        NULL
                    );
                }

                if (chamberIdCopy == NULL)
                {
                    goto StSecpAddChamberProfileKey_cleanup_and_return;
                }

                goto StSecpAddChamberProfileKey_free_chamberId;
            }
        }

        return_status = STATUS_NO_MEMORY;
    }
StSecpAddChamberProfileKey_free_chamberId:
    StSecFree(chamberIdCopy);
StSecpAddChamberProfileKey_cleanup_and_return:
    if (installKeyCopy != NULL)
    {
        StSecpFreeNonPaged(installKeyCopy, SecretKeySize);
    }
    if (dataKeyCopy != NULL)
    {
        StSecpFreeNonPaged(dataKeyCopy, SecretKeySize);
    }
    return return_status;
}


VOID
StSecpCacheCleanupWorkItem(
    VOID)
{
    ULONG systemTimeIncrement = KeQueryTimeIncrement();
    ULONG64 cacheLifetimeInUnits = g_CacheLifetime;
    PCUSTOM_FC_STSEC_CACHE_TABLE_ENTRY currentCacheEntry;
    PVOID enumerationRestartKey = NULL;
    PWCHAR currentChamberId;
    longlong currentTimestamp = SharedTickCount;

    ExAcquireFastMutex(&g_StSecKeyMutex);

    while (true)
    {
        currentCacheEntry = RtlEnumerateGenericTableWithoutSplaying(
            &g_StSecCacheGenericTable,
            &enumerationRestartKey
        );

        if (currentCacheEntry == NULL)
        {
            break;
        }

        /* Check if entry has expired
         *  cacheLifetimeInUnits * 10000000 => converts the cache lifetime to 100-nanosecond units
         *  (Windows time format) */
        if ((
                (cacheLifetimeInUnits * 10000000) / systemTimeIncrement) <
            (currentTimestamp - currentCacheEntry->LastAccessTime)
        )
        {
            currentChamberId = currentCacheEntry->ChamberId;
            StSecpFreeNonPaged(currentCacheEntry->InstallKey, currentCacheEntry->KeySize);
            StSecpFreeNonPaged(currentCacheEntry->DataKey, currentCacheEntry->KeySize);
            RtlDeleteElementGenericTable(&g_StSecCacheGenericTable, currentCacheEntry);
            StSecFree(currentChamberId);
            enumerationRestartKey = NULL;
        }
    }
    ExReleaseFastMutex(&g_StSecKeyMutex);
}


VOID
StSecpCacheDeinitialize(
    VOID)
{
    PCUSTOM_FC_STSEC_CACHE_TABLE_ENTRY currentCacheEntry;
    PVOID enumerationRestartKey = NULL;
    PWCHAR currentChamberId;

    if (g_WorkItem != NULL)
    {
        FltFreeGenericWorkItem(g_WorkItem);
        g_WorkItem = NULL;
    }

    if (g_FilterObject != NULL)
    {
        g_FilterObject = NULL;
    }

    ExAcquireFastMutex(&g_StSecKeyMutex);

    while (true)
    {
        currentCacheEntry = RtlEnumerateGenericTableWithoutSplaying(
            &g_StSecCacheGenericTable,
            &enumerationRestartKey
        );

        if (currentCacheEntry == NULL)
        {
            break;
        }

        currentChamberId = currentCacheEntry->ChamberId;
        StSecpFreeNonPaged(currentCacheEntry->InstallKey, currentCacheEntry->KeySize);
        StSecpFreeNonPaged(currentCacheEntry->DataKey, currentCacheEntry->KeySize);
        RtlDeleteElementGenericTable(&g_StSecCacheGenericTable, currentCacheEntry);
        StSecFree(currentChamberId);
        enumerationRestartKey = NULL;
    }
    ExReleaseFastMutex(&g_StSecKeyMutex);
    if (g_MasterKey != NULL)
    {
        StSecpFreeNonPaged(g_MasterKey, 0x80);
        g_MasterKey = NULL;
    }
}


PVOID
StSecpCacheGenericTableAllocRoutine(
    PRTL_GENERIC_TABLE Table,
    CLONG ByteSize
)
{
    return ExAllocatePool2(0x100, ByteSize,POOL_TAG_STsp);
}


RTL_GENERIC_COMPARE_RESULTS
StSecpCacheGenericTableCompareRoutine(
    PRTL_GENERIC_TABLE Table,
    PCUSTOM_FC_STSEC_CACHE_TABLE_ENTRY FirstStruct,
    PCUSTOM_FC_STSEC_CACHE_TABLE_ENTRY SecondStruct
)
{
    int fieldsCmpResult;
    RTL_GENERIC_COMPARE_RESULTS result;

    /* Two entries are the equal if they have the same ChamberId */
    fieldsCmpResult = _wcsicmp(FirstStruct->ChamberId, SecondStruct->ChamberId);
    result = GenericLessThan;

    if (-1 < fieldsCmpResult)
    {
        result = (fieldsCmpResult < 1) + GenericGreaterThan;
    }

    return result;
}


VOID
StSecpCacheGenericTableFreeRoutine(
    PRTL_GENERIC_TABLE Table,
    PVOID Buffer
)
{
    StSecFree(Buffer);
}


NTSTATUS
StSecpCacheInitialize(
    PFLT_FILTER FilterHandle
)
{
    NTSTATUS return_status = STATUS_SUCCESS;
    PVOID rtlQueryRegistryValuesExRoutine;
    UNICODE_STRING registryQueryRoutineName = {0, 0, NULL};
    RTL_QUERY_REGISTRY_TABLE queryRegTable = {
        NULL,
        0x120,
        L"CacheLifetime",
        &g_CacheLifetime,
        0x4000000,
        NULL,
        4
    };
    PFLT_FILTER filter = g_FilterObject;

    if (FilterHandle != NULL)
    {
        g_StSecKeyMutex.Owner = NULL;
        g_StSecKeyMutex.Count = 1;
        g_StSecKeyMutex.Contention = 0;
        /* Synchronization mechanisms for cache access */
        KeInitializeEvent(&g_StSecKeyMutex.Event, SynchronizationEvent, '\0');
        RtlInitUnicodeString(&registryQueryRoutineName, L"RtlQueryRegistryValuesEx");

        rtlQueryRegistryValuesExRoutine = MmGetSystemRoutineAddress(&registryQueryRoutineName);

        if (rtlQueryRegistryValuesExRoutine == NULL)
        {
            //rtlQueryRegistryValuesExRoutine = RtlQueryRegistryValues_exref;
            rtlQueryRegistryValuesExRoutine = RtlQueryRegistryValues;
        }

        /* Read configuration from the registry under the key HKLM\SYSTEM\StSec */
        return_status = rtlQueryRegistryValuesExRoutine(2, L"StSec", &queryRegTable);

        if (((return_status + 0x80000000U & 0x80000000) != 0) || (filter = g_FilterObject, return_status == -
            0x3fffffcc))
        {
            /* Initializes a generic table data structure that will store the cache entries */
            RtlInitializeGenericTable(
                &g_StSecCacheGenericTable,
                StSecpCacheGenericTableCompareRoutine,
                StSecpCacheGenericTableAllocRoutine,
                StSecpCacheGenericTableFreeRoutine,
                NULL
            );

            /* Allocates a work item, likely for background cache maintenance or cleanup tasks. */
            g_WorkItem = FltAllocateGenericWorkItem();
            filter = FilterHandle;

            if (g_WorkItem == NULL)
            {
                filter = g_FilterObject;
            }
        }
    }

    g_FilterObject = filter;

    return return_status;
}


/* This function is designed to check if the package name exists as a value under the debug profiles
 * registry key, regardless of the original parameter type that provided that package name.
 * The "conditional" aspect refers towhether it is in debug mode or not. */
NTSTATUS
StSecpCheckConditionalPolicy(
    PCUNICODE_STRING SecpParameterName,
    PUNICODE_STRING OutPackageFamilyName,
    PUCHAR OutIsDebugProfile
)
{
    LONG compResult;
    NTSTATUS status = STATUS_SUCCESS;
    bool isDebugProfileKeyNull;
    ULONG resultLength = 0;
    HANDLE keyHandle = NULL;
    UNICODE_STRING packageFamilyName = {0x26, 0x28, L"<PackageFamilyName>"};
    UNICODE_STRING productId = {0x16, 0x18, L"<ProductId>"};
    UNICODE_STRING packageFullName = {0x22, 0x24, L"<PackageFullName>"};
    UNICODE_STRING packgeFamilyName = {0, 0, NULL};
    OBJECT_ATTRIBUTES objectAttributes;
    UNICODE_STRING chambersRegPath = {0, 0, NULL};
    KEY_VALUE_PARTIAL_INFORMATION keyValueInfo;

    /* Handle PackageFamilyName or ProductId */
    compResult = RtlCompareUnicodeString(SecpParameterName, &packageFamilyName, '\x01');
    if (
        (compResult == 0) ||
        (
            compResult = RtlCompareUnicodeString(SecpParameterName, &productId, '\x01'),
            compResult == 0
        )
    )
    {
    StSecpCheckConditionalPolicy_handle_PackageFamilyName_or_ProductId:
        if (g_DebugProfileKey == NULL)
        {
            RtlInitUnicodeString(
                &chambersRegPath,
                L"\\REGISTRY\\MACHINE\\Software\\Microsoft\\SecurityManager\\StorageCardProfiles\\Chambers"
            );

            // objectProperties._0_16_ =
            //     CONCAT124(SUB1612(objectProperties._0_16_ >> 0x20, 0) &
            //         SUB1612((undefined [16])0xffffffffffffffff >> 0x20, 0), 0x30);
            // objectProperties._32_16_ = ZEXT816(0);
            InitializeObjectAttributes(
                &objectAttributes,
                &chambersRegPath,
                OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                NULL,
                NULL
            )

            status = ZwOpenKey(&keyHandle, 0x80000000, &objectAttributes);
            if (-1 < status)
            {
                //LOCK();
                isDebugProfileKeyNull = g_DebugProfileKey == NULL;
                g_DebugProfileKey =
                    (HANDLE)(
                        (ulonglong)g_DebugProfileKey ^
                        (ulonglong)isDebugProfileKeyNull *
                        ((ulonglong)g_DebugProfileKey ^ (ulonglong)keyHandle)
                    );

                if (!isDebugProfileKeyNull)
                {
                    ZwClose(keyHandle);
                }

                goto StSecpCheckConditionalPolicy_try_set_debug_profile_key;
            }
        }
        else
        {
        StSecpCheckConditionalPolicy_try_set_debug_profile_key:
            status = ZwQueryValueKey(
                g_DebugProfileKey,
                OutPackageFamilyName,
                KeyValuePartialInformation,
                &keyValueInfo,
                0x10,
                &resultLength
            );

            if (-1 < status)
            {
                // *OutIsDebugProfile = keyValueInfo._12_4_ != 0;
                *OutIsDebugProfile = keyValueInfo.Data[0] != 0;

                goto StSecpCheckConditionalPolicy_cleanup_and_return;
            }
        }

        /* If the key is found - debug profile key has a value, return */
        if (status != STATUS_OBJECT_NAME_NOT_FOUND)
        {
            goto StSecpCheckConditionalPolicy_cleanup_and_return;
        }
    }
    else
    {
        /* Handle PackageFullName */
        compResult = RtlCompareUnicodeString(SecpParameterName, &packageFullName, '\x01');
        if (compResult == 0)
        {
            status = StSecpPackageFamilyNameFromFullName(OutPackageFamilyName, &packgeFamilyName);
            if (status < 0) goto StSecpCheckConditionalPolicy_cleanup_and_return;
            OutPackageFamilyName = &packgeFamilyName;
            goto StSecpCheckConditionalPolicy_handle_PackageFamilyName_or_ProductId;
        }
    }

    *OutIsDebugProfile = '\0';

StSecpCheckConditionalPolicy_cleanup_and_return:
    StSecFree(packgeFamilyName.Buffer);

    return status;
}


/* This function creates cryptographic keys for encryption chambers when they're not found in the
 * key cache, using a deterministic derivation process
 *
 *  1. Hierarchical Key Structure: A single master key is used to derive multiple chamber-specific
 *  keys, creating a secure key hierarchy.
 *  2. HMAC-Based Key Derivation: The use of HMAC for key derivation follows cryptographic best
 *  practices for deriving keys from a master key.
 *  3. Chamber Isolation: Each chamber gets unique keys derived from its identifier, maintaining
 *  cryptographic separation between chambers.
 *  4. Dual Key System: Each chamber has two related but distinct keys:
 *  
 *  "Install" key: Likely used for initial file encryption or metadata
 *  "Data" key: Likely used for ongoing file content encryption
 *  
 *  Performance Optimization: By caching the derived keys, the driver avoids expensive re-derivation for each operation.
 */
NTSTATUS
StSecpDeriveChamberProfileKey(
    PWCHAR ChamberId,
    ULONG ChamberType,
    PUCHAR OutputProfileKey,
    ULONG ProfileKeyLength
)
{
    NTSTATUS return_status;
    PUCHAR pbMasterKeyHashObject;
    PUCHAR pbHashObject = NULL;
    PUCHAR firstHashOutput;
    PUCHAR secondHashOutput;
    BCRYPT_HASH_HANDLE* phMasterKeyHash;
    PUCHAR pUVar1 = NULL;
    PUCHAR pUVar2 = NULL;
    PWCHAR pbChamberIdInput;
    ULONG masterKeySize = 0;
    BCRYPT_HASH_HANDLE ChamberIdHashHandle = NULL;
    BCRYPT_HASH_HANDLE dupChamberIdHashHandle;
    PUCHAR masterKey = NULL;
    longlong chamberIdLength = 0;
    PUCHAR relevantFinalKey = NULL;


    /* Check if the desired key length exceeds the hash output length. */
    if (g_cbHashOutputLength < ProfileKeyLength)
    {
        return STATUS_INVALID_PARAMETER;
    }
    return_status = StSecpGetMasterKey(&masterKey, &masterKeySize);
    firstHashOutput = pbHashObject;
    secondHashOutput = pbHashObject;
    pbMasterKeyHashObject = pbHashObject;

    if (return_status < 0)
    {
        goto StSecpDeriveChamberProfileKey_return_and_cleanup;
    }

    pbMasterKeyHashObject = ExAllocatePool2(0x40, (ulonglong)g_cbHashObjectLength, POOL_TAG_StSn);

    if (pbMasterKeyHashObject != NULL)
    {
        phMasterKeyHash = &ChamberIdHashHandle;
        /* This key derivation is based on HMAC (Hash-based Message Authentication Code), which is a
           standard approach for deriving keys. The master key serves as the HMAC key. */
        return_status = BCryptCreateHash(
            g_HmacHashProvider,
            phMasterKeyHash,
            pbMasterKeyHashObject,
            g_cbHashObjectLength,
            masterKey,
            masterKeySize,
            0
        );
        firstHashOutput = pUVar1;
        secondHashOutput = pUVar2;
        pbHashObject = relevantFinalKey;

        if (return_status < 0)
        {
            goto StSecpDeriveChamberProfileKey_return_and_cleanup;
        }

        pbChamberIdInput = ChamberId;
        return_status = RtlStringCbLengthW(ChamberId, phMasterKeyHash, &chamberIdLength);

        if (return_status < 0)
        {
            goto StSecpDeriveChamberProfileKey_return_and_cleanup;
        }

        /* Hash the chamber ID to make the derivation chamber-specific.
           The function uses the chamber ID as input to the HMAC function, ensuring that each chamber gets a
           unique key derived from the master key */
        return_status = BCryptHashData(
            ChamberIdHashHandle,
            (PUCHAR)pbChamberIdInput,
            chamberIdLength,
            0
        );

        if (return_status < 0)
        {
            goto StSecpDeriveChamberProfileKey_return_and_cleanup;
        }

        pbHashObject = ExAllocatePool2(0x40, (ulonglong)g_cbHashObjectLength, POOL_TAG_StSn);
        if (pbHashObject != NULL)
        {
            /* Create a duplicate of the hash state for generating the second key */
            return_status = BCryptDuplicateHash(
                ChamberIdHashHandle,
                &dupChamberIdHashHandle,
                pbHashObject,
                g_cbHashObjectLength,
                0
            );

            if (return_status < 0)
            {
                goto StSecpDeriveChamberProfileKey_return_and_cleanup;
            }

            /* Add "Install" to the first hash to derive the Install key */
            return_status = BCryptHashData(ChamberIdHashHandle, L"Install", 0xe, 0);

            if (return_status < 0)
            {
                goto StSecpDeriveChamberProfileKey_return_and_cleanup;
            }

            firstHashOutput = ExAllocatePool2(0x40, (ulonglong)g_cbHashOutputLength, POOL_TAG_StSn);
            if (firstHashOutput != NULL)
            {
                /* Finalize first hash to get Install key */
                return_status = BCryptFinishHash(ChamberIdHashHandle, firstHashOutput, g_cbHashOutputLength, 0);

                if (return_status < 0)
                {
                    goto StSecpDeriveChamberProfileKey_return_and_cleanup;
                }

                /* Add "Data" to the second hash to derive the Data key */
                return_status = BCryptHashData(dupChamberIdHashHandle, L"Data", 8, 0);

                if (return_status < 0)
                {
                    goto StSecpDeriveChamberProfileKey_return_and_cleanup;
                }

                secondHashOutput = ExAllocatePool2(0x40, (ulonglong)g_cbHashOutputLength, POOL_TAG_StSn);
                if (secondHashOutput != NULL)
                {
                    /* Finalize second hash to get Data key */
                    return_status = BCryptFinishHash(
                        dupChamberIdHashHandle,
                        secondHashOutput,
                        g_cbHashOutputLength,
                        0
                    );

                    /* Add both keys to the chamber key cache */
                    /* Select the appropriate key based on chamber type */
                    if ((
                            (-1 < return_status) &&
                            (return_status = StSecpAddChamberProfileKey(
                                ChamberId,
                                firstHashOutput,
                                secondHashOutput,
                                ProfileKeyLength
                            ), -1 < return_status)
                        ) &&
                        (
                            (relevantFinalKey = firstHashOutput, ChamberType == 1 ||
                                (relevantFinalKey = secondHashOutput, ChamberType == 2))
                        )
                    )
                    {
                        memcpy(OutputProfileKey, relevantFinalKey, ProfileKeyLength);
                    }

                    goto StSecpDeriveChamberProfileKey_return_and_cleanup;
                }
            }
        }
    }

    return_status = -STATUS_NO_MEMORY;
StSecpDeriveChamberProfileKey_return_and_cleanup:
    if (ChamberIdHashHandle != NULL)
    {
        BCryptDestroyHash(ChamberIdHashHandle);
    }
    if (dupChamberIdHashHandle != NULL)
    {
        BCryptDestroyHash(dupChamberIdHashHandle);
    }
    if (pbMasterKeyHashObject != NULL)
    {
        StSecpFreeNonPaged(pbMasterKeyHashObject, g_cbHashObjectLength);
    }
    if (pbHashObject != NULL)
    {
        StSecpFreeNonPaged(pbHashObject, g_cbHashObjectLength);
    }
    if (firstHashOutput != NULL)
    {
        StSecpFreeNonPaged(firstHashOutput, g_cbHashOutputLength);
    }
    if (secondHashOutput != NULL)
    {
        StSecpFreeNonPaged(secondHashOutput, g_cbHashOutputLength);
    }

    return return_status;
}

/* This function searches through the folder property cache to find an entry with a path that
 * matches the input path. Unlike the security descriptor lookup, this function performs simpler
 * path matching without parameter substitution.
 * 
 * 1. Chamber Assignment: By looking up folder properties, the driver determines which encryption
 * "chamber" (key context) to use for files in a particular folder.
 * 2. Path-Based Configuration: It enables administrators to configure different encryption
 * behaviors for different folders through registry settings.
 * 3. Policy Enforcement: Together with the security descriptor lookup, it forms the policy
 * enforcement mechanism of the driver.
 */
PCUSTOM_FC_STSEC_FOLDER_PROP_CACHE_LIST_ENTRY
StSecpFindFolderPropertyPolicyElement(
    PUNICODE_STRING Path
)
{
    int compResult = -1;
    UNICODE_STRING cacheEntrySegment;
    UNICODE_STRING inputPathSegment = {0, 0, NULL};
    UNICODE_STRING remainingInputPath = {0, 0, NULL};
    UNICODE_STRING remainingCachePath = {0, 0, NULL};
    UNICODE_STRING currentPath;
    PCUSTOM_FC_STSEC_FOLDER_PROP_CACHE_LIST_ENTRY currentEntry = g_StSecFolderPropertyCacheListHead;

    do
    {
        if (currentEntry == g_StSecFolderPropertyCacheListHead)
        {
            return NULL;
        }

        // currentPath._0_4_ = *(undefined4*)Path;
        // currentPath._4_4_ = *(undefined4*)&Path->field_0x4;
        // currentPath.Buffer._0_4_ = *(undefined4*)&Path->Buffer;
        // currentPath.Buffer._4_4_ = *(undefined4*)((longlong)&Path->Buffer + 4);
        currentPath.Buffer = Path->Buffer;
        currentPath.Length = Path->Length;
        currentPath.MaximumLength = Path->MaximumLength;
        FsRtlDissectName(currentPath, &inputPathSegment, &remainingInputPath);
        // currentPath._0_4_ = *(undefined4*)&currentEntry->Path;
        // currentPath._4_4_ = *(undefined4*)&(currentEntry->Path).field_0x4;
        // currentPath.Buffer._0_4_ = *(undefined4*)&(currentEntry->Path).Buffer;
        // currentPath.Buffer._4_4_ = *(undefined4*)((longlong)&(currentEntry->Path).Buffer + 4);
        currentPath.Buffer = currentEntry->Path.Buffer;
        currentPath.Length = currentEntry->Path.Length;
        currentPath.MaximumLength = currentEntry->Path.MaximumLength;
        FsRtlDissectName(currentPath, &cacheEntrySegment, &remainingCachePath);

        while ((
            //cacheEntrySegment.Buffer = SUB168((undefined [16])cacheEntrySegment >> 0x40, 0),
            inputPathSegment.Buffer != NULL && cacheEntrySegment.Buffer != NULL
        ))
        {
            if (cacheEntrySegment.Length == 0)
            {
                compResult = 0;
            }
            else
            {
                compResult = RtlCompareUnicodeString(
                    &inputPathSegment,
                    &cacheEntrySegment,
                    '\x01'
                );

                if (compResult != 0)
                {
                    goto StSecpFindFolderPropertyPolicyElement_next_element;
                }
            }
            // currentPath._0_4_ = remainingInputPath._0_4_;
            // currentPath._4_4_ = remainingInputPath._4_4_;
            // currentPath.Buffer._0_4_ = remainingInputPath.Buffer._0_4_;
            // currentPath.Buffer._4_4_ = remainingInputPath.Buffer._4_4_;
            currentPath.Buffer = remainingInputPath.Buffer;
            currentPath.Length = remainingInputPath.Length;
            currentPath.MaximumLength = remainingInputPath.MaximumLength;
            FsRtlDissectName(currentPath, &inputPathSegment, &remainingInputPath);
            // currentPath._0_4_ = remainingCachePath._0_4_;
            // currentPath._4_4_ = remainingCachePath._4_4_;
            // currentPath.Buffer._0_4_ = remainingCachePath.Buffer._0_4_;
            // currentPath.Buffer._4_4_ = remainingCachePath.Buffer._4_4_;
            currentPath.Buffer = remainingCachePath.Buffer;
            currentPath.Length = remainingCachePath.Length;
            currentPath.MaximumLength = remainingCachePath.MaximumLength;
            FsRtlDissectName(currentPath, &cacheEntrySegment, &remainingCachePath);
        }
        if (compResult == 0)
        {
            /* If input path has more segments - this is a match */
            if (inputPathSegment.Buffer != NULL)
            {
                return currentEntry;
            }
            /* If both paths fully consumed - this is a match */
            if (cacheEntrySegment.Buffer == NULL)
            {
                return currentEntry;
            }
            /* Cache entry has more segments - not a match */
            compResult = -1;
        }
    StSecpFindFolderPropertyPolicyElement_next_element:
        currentEntry = currentEntry->Next;
    }
    while (true);
}

/* searches through the security descriptor cache to find an entry whose path pattern matches the input path */
PCUSTOM_FC_STSEC_SEC_DESC_CACHE_LIST_ENTRY
StSecpFindSecurityDescriptorPolicyElement(
    PCUNICODE_STRING Path
)
{
    int compResult = -1;
    /* ce = cache entry */
    UNICODE_STRING cEFirstFolder = {0, 0, NULL};
    UNICODE_STRING firstFolder = {0, 0, NULL};
    UNICODE_STRING remainingPath = {0, 0, NULL};
    UNICODE_STRING cERemainingPath = {0, 0, NULL};
    UNICODE_STRING currentPath;
    CUSTOM_FC_STSEC_SEC_DESC_CACHE_LIST_ENTRY* cacheListHead = g_StSecSecurityDescriptorCacheListHead;

    do
    {
        if (cacheListHead == g_StSecSecurityDescriptorCacheListHead)
        {
            return NULL;
        }

        // currentPath._0_4_ = *(undefined4*)Path;
        // currentPath._4_4_ = *(undefined4*)&Path->field_0x4;
        // currentPath.Buffer._0_4_ = *(undefined4*)&Path->Buffer;
        // currentPath.Buffer._4_4_ = *(undefined4*)((longlong)&Path->Buffer + 4);
        currentPath.Buffer = Path->Buffer;
        currentPath.Length = Path->Length;
        currentPath.MaximumLength = Path->MaximumLength;
        FsRtlDissectName(currentPath, &firstFolder, &remainingPath);
        // currentPath._0_4_ = *(undefined4*)&cacheListHead->Path;
        // currentPath._4_4_ = *(undefined4*)&(cacheListHead->Path).field_0x4;
        // currentPath.Buffer._0_4_ = *(undefined4*)&(cacheListHead->Path).Buffer;
        // currentPath.Buffer._4_4_ = *(undefined4*)((longlong)&(cacheListHead->Path).Buffer + 4);
        currentPath.Buffer = cacheListHead->Path.Buffer;
        currentPath.Length = cacheListHead->Path.Length;
        currentPath.MaximumLength = cacheListHead->Path.MaximumLength;
        FsRtlDissectName(currentPath, &cEFirstFolder, &cERemainingPath);

        while ((
            //cEFirstFolder.Buffer = SUB168((undefined [16])cEFirstFolder >> 0x40, 0),
            firstFolder.Buffer != NULL && cEFirstFolder.Buffer != NULL
        ))
        {
            if (cEFirstFolder.Length == 0)
            {
            StSecpFindSecurityDescriptorPolicyElement_match_found:
                compResult = 0;
            }
            else
            {
                compResult = RtlCompareUnicodeString(&firstFolder, &cEFirstFolder, '\x01');
                if (compResult != 0)
                {
                    /* If not an exact match, check if it's a parameter segment */
                    if ((*cEFirstFolder.Buffer == L'<') &&
                        (cEFirstFolder.Buffer[(ulonglong)(cEFirstFolder.Length >> 1) - 1] == L'>'))
                    {
                        goto StSecpFindSecurityDescriptorPolicyElement_match_found;
                    }

                    goto StSecpFindSecurityDescriptorPolicyElement_next_element;
                }
            }
            // currentPath._0_4_ = remainingPath._0_4_;
            // currentPath._4_4_ = remainingPath._4_4_;
            // currentPath.Buffer._0_4_ = remainingPath.Buffer._0_4_;
            // currentPath.Buffer._4_4_ = remainingPath.Buffer._4_4_;
            firstFolder.Buffer = remainingPath.Buffer;
            firstFolder.Length = remainingPath.Length;
            firstFolder.MaximumLength = remainingPath.MaximumLength;
            FsRtlDissectName(currentPath, &firstFolder, &remainingPath);
            // currentPath._0_4_ = cERemainingPath._0_4_;
            // currentPath._4_4_ = cERemainingPath._4_4_;
            // currentPath.Buffer._0_4_ = cERemainingPath.Buffer._0_4_;
            // currentPath.Buffer._4_4_ = cERemainingPath.Buffer._4_4_;
            currentPath.Buffer = cERemainingPath.Buffer;
            currentPath.Length = cERemainingPath.Length;
            currentPath.MaximumLength = cERemainingPath.MaximumLength;
            FsRtlDissectName(currentPath, &cEFirstFolder, &cERemainingPath);
        }
        if (compResult == 0)
        {
            /* If input path has more segments - this is a match */
            if (firstFolder.Buffer != NULL)
            {
                return cacheListHead;
            }
            /* If both paths fully consumed - this is a match */
            if (cEFirstFolder.Buffer == NULL)
            {
                return cacheListHead;
            }

            /* Cache entry has more segments - not a match */
            compResult = -1;
        }
    StSecpFindSecurityDescriptorPolicyElement_next_element:
        cacheListHead = cacheListHead->Next;
        /* Consider these example paths stored in the cache:
           
           1. 
           \Registry\Machine\System\ControlSet001\Control\StSec\SecurityDescriptors\Documents\<PackageFamily Name>\PrivateData
           2. \Registry\Machine\System\ControlSet001\Control\StSec\SecurityDescriptors\Pictures
           
           If the driver processes a file with path:
           \Documents\Microsoft.Office.Word_8wekyb3d8bbwe\PrivateData\report.docx
           The first entry would match because:
           
           - Documents matches exactly
           - <PackageFamilyName> is a parameter that matches Microsoft.Office.Word_8wekyb3d8bbwe
           - PrivateData matches exactly
           - The extra report.docx segment in the input path is allowed by the match determination rule */
    }
    while (true);
}


VOID
StSecpFreeNonPaged(
    PUCHAR Buffer,
    ULONG Size
)
{
    ulonglong index;
    PUCHAR currentByte;

    if (Buffer != NULL)
    {
        currentByte = Buffer;
        for (index = (ulonglong)Size; index != 0; index = index - 1)
        {
            *currentByte = '\0';
            currentByte = currentByte + 1;
        }

        ExFreePoolWithTag(Buffer,POOL_TAG_StSn);
    }
}


/* Generates a Security Identifier (SID) from an input string - ProductId or PackageFamilyName.
 * Uses cryptographic hashing to ensure that the same input always produces the same SID. */
VOID
StSecpGetAppSid(
    PUNICODE_STRING Data,
    PWCHAR* ResultStringSid
)
{
    NTSTATUS hashStatus;
    NTSTATUS sidStatus;
    PUCHAR pbHashObject;
    PULONG sidSubauthority;
    byte subAuthorityIndex;
    ULONG* hashOutputBuffer = NULL;
    ULONG* hashValueIterator;
    BCRYPT_HASH_HANDLE hashHandle = NULL;
    /* Set up a custom SID authority (0x00 00 00 00 0F 00) */
    //identifierAuthority.Value._4_2_ = 0xf00;
    //identifierAuthority.Value._0_4_ = 0;
    SID_IDENTIFIER_AUTHORITY identifierAuthority = {
        0, 0, 0, 0, 0x0F, 0
    };
    PSID sid = NULL;
    ULONG subAuthorityCounter;
    ULONG hashValue;

    /* The function calls in this if do the following:
     * 1. Create a hash object
     * 2. Feed the input data into it (ProductId or PackageFamilyName)
     * 3. Finalize the hash
     * 4. Initialize a SID with 8 subauthorities under our custom authority ('\b' is 8 in character
     * form)
     */
    pbHashObject = ExAllocatePool2(0x100, (ulonglong)g_cbHashObject,POOL_TAG_STsp);
    hashOutputBuffer = ExAllocatePool2(0x100, (ulonglong)g_cbHashValue,POOL_TAG_STsp);

    if (pbHashObject != NULL && hashOutputBuffer != NULL &&
        (hashStatus = BCryptCreateHash(
            g_HashProvider,
            &hashHandle,
            pbHashObject,
            g_cbHashObject,
            NULL,
            0,
            0
        ), -1 < hashStatus) &&
        (hashStatus = BCryptHashData(
            hashHandle,
            (PUCHAR)Data->Buffer,
            Data->Length,
            0
        ), -1 < hashStatus) &&
        (hashStatus = BCryptFinishHash(
            hashHandle,
            (PUCHAR)hashOutputBuffer,
            g_cbHashValue,
            0
        ), -1 < hashStatus) &&
        (sidStatus = RtlInitializeSid(
                &sid,
                &identifierAuthority,
                '\b'
            ), -1 < sidStatus
        )
    )
    {
        sidSubauthority = RtlSubAuthoritySid(&sid, 0);
        /* Set the first subauthority to 2 (likely a type identifier) */
        subAuthorityCounter = 1;
        /* Use hash output to populate remaining 7 subauthorities */
        *sidSubauthority = 2;
        hashValueIterator = hashOutputBuffer;

        do
        {
            sidSubauthority = RtlSubAuthoritySid(&sid, subAuthorityCounter);
            hashValue = *hashValueIterator;
            hashValueIterator = hashValueIterator + 1;
            subAuthorityIndex = (char)subAuthorityCounter + 1;
            subAuthorityCounter = (ULONG)subAuthorityIndex;
            *sidSubauthority = hashValue;
        }
        while (subAuthorityIndex < 8);
        /* The output SID always has the form:
         * S-1-15-2-[hash1]-[hash2]-[hash3]-[hash4]-[hash5]-[hash6]-[hash7]
         * Where 15 is the hex value 0xF (the custom authority) and 2 is the first subauthority.
         * 
         * Convert the binary SID to a string representation that can be used in security descriptors
         */
        SeConvertSidToStringSid(&sid, ResultStringSid);
    }
    if (hashHandle != NULL)
    {
        BCryptDestroyHash(hashHandle);
    }
    if (pbHashObject != NULL)
    {
        ExFreePoolWithTag(pbHashObject,POOL_TAG_STsp);
    }
    if (hashOutputBuffer != NULL)
    {
        ExFreePoolWithTag(hashOutputBuffer,POOL_TAG_STsp);
    }
}


NTSTATUS
StSecpGetChamberProfileKey(
    PWCHAR ChamberId,
    ULONG ChamberType,
    PUCHAR OutChamberProfileKey,
    ULONG KeySize
)
{
    NTSTATUS return_status = STATUS_SUCCESS;
    PUCHAR keySource;
    //currentTime = _DAT_fffff78000000320;
    ULONG64 currentTime = SharedTickCount;
    PCUSTOM_FC_STSEC_CACHE_TABLE_ENTRY cacheEntry;
    // lookupEntry.LastAccessTime = 0;
    // lookupEntry._16_16_ = ZEXT816(0);
    // stack0xffffffffffffffd8 = 0;
    // lookupEntry.ChamberId = ChamberId;
    CUSTOM_FC_STSEC_CACHE_TABLE_ENTRY lookupEntry = {
        0,
        ChamberId,
        NULL,
        NULL,
        0
    };
    /* See KI_USER_SHARED_DATA in wdm.h
     *  
     * #define KI_USER_SHARED_DATA 0xFFFFF78000000000UI64
     * #define SharedTickCount (KI_USER_SHARED_DATA + 0x320)
     * #define KeQueryTickCount(CurrentCount)                                      \
     *      *((PULONG64)(CurrentCount)) = *((volatile ULONG64 *)(SharedTickCount)) */

    ExAcquireFastMutex(&g_StSecKeyMutex);
    cacheEntry = RtlLookupElementGenericTable(&g_StSecCacheGenericTable, &lookupEntry);

    /* If found, update the last access time */
    if (cacheEntry != NULL)
    {
        cacheEntry->LastAccessTime = currentTime;
    }
    ExReleaseFastMutex(&g_StSecKeyMutex);

    if (cacheEntry == NULL)
    {
        return_status = STATUS_OBJECT_NAME_NOT_FOUND;
    }
    else if (KeySize == cacheEntry->KeySize)
    {
        /* Choose the appropriate key based on chamber type */
        if (ChamberType == 1)
        {
            keySource = cacheEntry->InstallKey;
        }
        else
        {
            if (ChamberType != 2)
            {
                return 0;
            }
            keySource = cacheEntry->DataKey;
        }
        memcpy(OutChamberProfileKey, keySource, KeySize);
    }
    else
    {
        return_status = STATUS_INVALID_PARAMETER;
    }

    return return_status;
}

/* Reads from the registry and populates the StSecFolderPropertyCacheList with new entries */
NTSTATUS
StSecpGetFolderPropertyPolicy(
    HANDLE RegistryKeyHandle
)
{
    code* pcVar1;
    BOOLEAN createStrSuccess;
    NTSTATUS registryStatus;
    NTSTATUS status;
    NTSTATUS return_status;
    ulonglong uVar2;
    KEY_VALUE_PARTIAL_INFORMATION* chamberIdKeyInfo;
    PWCHAR chamberIdData;
    KEY_NAME_INFORMATION* keyNameInformation = NULL;
    PCUSTOM_FC_STSEC_FOLDER_PROP_CACHE_LIST_ENTRY newCacheEntry;
    PCUSTOM_FC_STSEC_FOLDER_PROP_CACHE_LIST_ENTRY cacheHead;
    undefined* puVar3;
    undefined* puVar4;
    undefined* puVar5;
    undefined* puVar6;
    KEY_VALUE_PARTIAL_INFORMATION* pKVar7 = NULL;
    KEY_VALUE_PARTIAL_INFORMATION* pKVar8 = NULL;
    ULONG subkeyIndex = 0;
    undefined auStackY_328[8];
    undefined auStackY_320[24];
    ULONG regResultLength = 0;
    UNICODE_STRING path = {0, 0, NULL};
    HANDLE innerKeyHandle;
    UNICODE_STRING keyValueName = {0x10, 0x12, L"FolderId"};
    OBJECT_ATTRIBUTES objectAttributes;
    KEY_VALUE_PARTIAL_INFORMATION keyValueInfo = {0, 0, 0};
    KEY_NAME_INFORMATION keyNameInfo = {0, {0}};
    KEY_BASIC_INFORMATION keyEnumerationInfo;

    /* The registry path of the handle is:
     * L"\\Registry\\Machine\\System\\ControlSet001\\Control\\StSec\\FolderProperties"
     * 
     * Reads from the registry and populates the StSecFolderPropertyCacheList with new entries
     */

    while (true)
    {
        innerKeyHandle = NULL;
        registryStatus = ZwEnumerateKey(
            RegistryKeyHandle,
            subkeyIndex,
            KeyBasicInformation,
            &keyEnumerationInfo,
            0x222,
            &regResultLength
        );

        if (registryStatus < 0)
        {
            break;
        }

        // objectAttributes._16_16_ = CONCAT124(objectAttributes._20_12_, 0x30);
        // objectAttributes._0_16_ = CONCAT88(keyEnumerationInfo.Name, objectAttributes._0_8_);
        // objectAttributes._16_16_ = CONCAT88(RegistryKeyHandle, objectAttributes.ObjectName);
        InitializeObjectAttributes(
            &objectAttributes,
            &keyEnumerationInfo.Name,
            0x30,
            RegistryKeyHandle,
            NULL
        )

        registryStatus = ZwOpenKey(
            &innerKeyHandle,
            0x20019,
            &objectAttributes
        );

        status = StSecpGetFolderPropertyPolicy(innerKeyHandle);

        if (registryStatus < 0 || status < 0)
        {
            goto StSecpGetFolderPropertyPolicy_free_cache_entry_string;
        }

        ZwClose(innerKeyHandle);
        subkeyIndex = subkeyIndex + 1;
    }
    //subkeyIndex = (KEY_VALUE_PARTIAL_INFORMATION*)keyNameInformation;
    chamberIdData = (PWCHAR)keyNameInformation;
    chamberIdKeyInfo = (KEY_VALUE_PARTIAL_INFORMATION*)keyNameInformation;

    if (registryStatus == STATUS_NO_MORE_ENTRIES)
    {
        /* Key value is FolderId */
        registryStatus = ZwQueryValueKey(
            RegistryKeyHandle,
            &keyValueName,
            KeyValuePartialInformation,
            &keyValueInfo,
            0x10,
            &regResultLength
        );

        //subkeyIndex = pKVar7;
        chamberIdData = (PWCHAR)pKVar8;
        chamberIdKeyInfo = NULL;
        if (registryStatus < 0)
        {
            if (registryStatus != STATUS_OBJECT_NAME_NOT_FOUND)
            {
                goto StSecpGetFolderPropertyPolicy_cleanup_and_return;
            }
        }
        else
        {
            /* If the FolderId (data) is exactly 4 bytes long: */
            if (keyValueInfo.DataLength == 4)
            {
                RtlInitUnicodeString(&keyValueName, L"ChamberId");
                /* Key value name is ChamberId, try to query with a 16 byte buffer */
                registryStatus = ZwQueryValueKey(
                    RegistryKeyHandle,
                    &keyValueName,
                    KeyValuePartialInformation,
                    &keyValueInfo,
                    0x10,
                    &regResultLength
                );

                if (registryStatus < 0)
                {
                    /* A 16 byte buffer is too small, allocate memory and try again */
                    if (registryStatus != STATUS_BUFFER_OVERFLOW)
                    {
                        goto StSecpGetFolderPropertyPolicy_cleanup_and_return;
                    }

                    chamberIdKeyInfo = ExAllocatePool2(0x100, regResultLength, 0x70537453);
                    if (chamberIdKeyInfo == NULL)
                    {
                        goto StSecpGetFolderPropertyPolicy_free_cache_entry_string;
                    }

                    /* Query ChamberId again */
                    registryStatus =
                        ZwQueryValueKey(
                            RegistryKeyHandle,
                            &keyValueName,
                            KeyValuePartialInformation,
                            chamberIdKeyInfo,
                            regResultLength,
                            &regResultLength
                        );

                    if (registryStatus < 0)
                    {
                        goto StSecpGetFolderPropertyPolicy_cleanup_and_return;
                    }

                    chamberIdData = ExAllocatePool2(0x100, chamberIdKeyInfo->DataLength, POOL_TAG_STsp);

                    if (chamberIdData != NULL)
                    {
                        status = RtlStringCbCopyW(
                            chamberIdData,
                            chamberIdKeyInfo->DataLength,
                            chamberIdKeyInfo->Data
                        );

                        if (status < 0)
                        {
                            goto StSecpGetFolderPropertyPolicy_cleanup_and_return;
                        }

                        registryStatus = ZwQueryKey(
                            RegistryKeyHandle,
                            KeyNameInformation,
                            &keyNameInfo,
                            8,
                            &regResultLength
                        );

                        if (registryStatus < 0)
                        {
                            if (registryStatus != STATUS_BUFFER_OVERFLOW)
                            {
                                goto StSecpGetFolderPropertyPolicy_cleanup_and_return;
                            }

                            keyNameInformation = ExAllocatePool2(
                                0x100,
                                (ulonglong)regResultLength + 4,
                                0x70537453
                            );

                            if (keyNameInformation != NULL)
                            {
                                registryStatus = ZwQueryKey(
                                    RegistryKeyHandle,
                                    KeyNameInformation,
                                    keyNameInformation,
                                    regResultLength,
                                    &regResultLength
                                );

                                //subkeyIndex = (KEY_VALUE_PARTIAL_INFORMATION*)keyNameInformation;
                                if (registryStatus < 0)
                                {
                                    goto StSecpGetFolderPropertyPolicy_cleanup_and_return;
                                }

                                keyNameInformation->Name[keyNameInformation->NameLength >> 1] = L'\\';
                                keyNameInformation->Name[(ulonglong)(keyNameInformation->NameLength >> 1) + 1] = L'\0';
                                
                                //createStrSuccess = RtlCreateUnicodeString(&path, &keyNameInformation[0x11].field_0x6);
                                createStrSuccess = RtlCreateUnicodeString(&path, keyNameInformation->Name);
                                
                                newCacheEntry = ExAllocatePool2(0x100, 0x30, POOL_TAG_STsp);

                                if (createStrSuccess != '\0' && newCacheEntry != NULL)
                                {
                                    newCacheEntry->FolderId = (uint)keyValueInfo.Data[0];
                                    cacheHead = g_StSecFolderPropertyCacheListHead;
                                    newCacheEntry->ChamberId = chamberIdData;
                                    // *(undefined4*)&newCacheEntry->Path = path._0_4_;
                                    // *(undefined4*)&(newCacheEntry->Path).field_0x4 = path._4_4_;
                                    // *(undefined4*)&(newCacheEntry->Path).Buffer = path.Buffer._0_4_;
                                    // *(undefined4*)((longlong)&(newCacheEntry->Path).Buffer + 4) = path.Buffer._4_4_;
                                    newCacheEntry->Path.Buffer = path.Buffer;
                                    newCacheEntry->Path.Length = path.Length;
                                    newCacheEntry->Path.MaximumLength = path.MaximumLength;

                                    if (g_StSecFolderPropertyCacheListTail->Next != g_StSecFolderPropertyCacheListHead)
                                    {
                                        cacheHead = (CUSTOM_FC_STSEC_FOLDER_PROP_CACHE_LIST_ENTRY*)0x3;
                                        pcVar1 = (code*)swi(0x29);
                                        newCacheEntry = (CUSTOM_FC_STSEC_FOLDER_PROP_CACHE_LIST_ENTRY*)(*pcVar1)();
                                        puVar3 = auStackY_320;
                                    }
                                    
                                    newCacheEntry->Next = cacheHead;
                                    newCacheEntry->Prev = g_StSecFolderPropertyCacheListTail;
                                    gfasdfStSecFolderPropertyCacheListTail->Next = newCacheEntry;
                                    *(undefined8*)(puVar3 + 0x40) = 0;
                                    puVar4 = puVar3;
                                    g_StSecFolderPropertyCacheListTail = newCacheEntry;
                                    goto LAB_1c0012538;
                                }
                            }
                        }
                        RtlFreeUnicodeString(&path);
                        //subkeyIndex = (KEY_VALUE_PARTIAL_INFORMATION*)keyNameInformation;
                        goto StSecpGetFolderPropertyPolicy_free_chamberid_data;
                    }
                LAB_1c0012538:
                    *(undefined8*)(puVar4 + -8) = 0x1c0012544;
                    RtlFreeUnicodeString((PUNICODE_STRING)(puVar4 + 0x38));
                    puVar5 = puVar4;
                    goto StSecpGetFolderPropertyPolicy_free_registry_key_info;
                }
            }
        }
    StSecpGetFolderPropertyPolicy_free_cache_entry_string:
        RtlFreeUnicodeString(&path);
    }
    else
    {
    StSecpGetFolderPropertyPolicy_cleanup_and_return:
        RtlFreeUnicodeString(&path);
        //keyNameInformation = (KEY_NAME_INFORMATION*)subkeyIndex;
        if ((KEY_VALUE_PARTIAL_INFORMATION*)chamberIdData != NULL)
        {
        StSecpGetFolderPropertyPolicy_free_chamberid_data:
            ExFreePoolWithTag(chamberIdData, POOL_TAG_STsp);
            //keyNameInformation = (KEY_NAME_INFORMATION*)subkeyIndex;
        }
        puVar6 = auStackY_328;
        if (chamberIdKeyInfo != NULL)
        {
        StSecpGetFolderPropertyPolicy_free_registry_key_info:
            *(undefined8*)(puVar5 + -8) = 0x1c0012599;
            ExFreePoolWithTag(chamberIdKeyInfo, POOL_TAG_STsp);
            puVar6 = puVar5;
        }
        if ((KEY_VALUE_PARTIAL_INFORMATION*)keyNameInformation != NULL)
        {
            *(undefined8*)(puVar6 + -8) = 0x1c00125b2;
            ExFreePoolWithTag(keyNameInformation, POOL_TAG_STsp);
        }
    }
    
    if (*(HANDLE*)(puVar6 + 0x48) != NULL)
    {
        *(undefined8*)(puVar6 + -8) = 0x1c00125c8;
        ZwClose(*(HANDLE*)(puVar6 + 0x48));
    }
    *(undefined8*)(puVar6 + -8) = 0x1c00125de;

    return return_status;
}
