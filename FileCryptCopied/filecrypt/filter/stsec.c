#include "stsec.h"
#include <intrin.h>
#include <wdm.h>
#include <tbs.h>
#include <bcrypt.h>

#include "kappx.h"
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
                paramName.Buffer = ExAllocatePool2(0x100, (ulonglong)componentName.Length + 2, POOL_TAG_STsp);
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
                if ((_g_CacheCleanupTriggerSize < numberOfCacheEntries) && (/* TODO LOCK(), */g_WorkItemQueued == 0))
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
    //PVOID rtlQueryRegistryValuesExRoutine;
    NTSTATUS (*rtlQueryRegistryValuesExRoutine)(int, short*, RTL_QUERY_REGISTRY_TABLE*);
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


/* This function checks whether the provided parameter is contained in a specific registry that decides whether
 * this value is a debug profile. The "conditional" aspect refers to whether it is in debug mode or not. */
NTSTATUS
StSecpCheckConditionalPolicy(
    PCUNICODE_STRING SecpParameterName,
    PUNICODE_STRING SecpParameterValue,
    PUCHAR OutIsDebugProfile
)
{
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
    if (
        RtlCompareUnicodeString(SecpParameterName, &packageFamilyName, '\x01') == 0 ||
        RtlCompareUnicodeString(SecpParameterName, &productId, '\x01') == 0
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
                // TODO
                // LOCK();

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
                SecpParameterValue,
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
    /* Handle PackageFullName */
    else if (RtlCompareUnicodeString(SecpParameterName, &packageFullName, '\x01') == 0)
    {
        status = StSecpPackageFamilyNameFromFullName(SecpParameterValue, &packgeFamilyName);
        if (status < 0)
        {
            goto StSecpCheckConditionalPolicy_cleanup_and_return;
        }

        SecpParameterValue = &packgeFamilyName;
        goto StSecpCheckConditionalPolicy_handle_PackageFamilyName_or_ProductId;
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
NTSTATUS
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

    return STATUS_SUCCESS;
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
    BOOLEAN createStrSuccess;
    NTSTATUS registryStatus;
    NTSTATUS status;
    NTSTATUS return_status;
    //ulonglong uVar2;
    KEY_VALUE_PARTIAL_INFORMATION* chamberIdKeyInfo;
    PWCHAR chamberIdData;
    KEY_NAME_INFORMATION* keyNameInformation = NULL;
    PCUSTOM_FC_STSEC_FOLDER_PROP_CACHE_LIST_ENTRY newCacheEntry;
    PCUSTOM_FC_STSEC_FOLDER_PROP_CACHE_LIST_ENTRY cacheHead;
    //undefined* puVar3;
    //undefined* puVar4;
    //undefined* puVar5;
    //undefined* puVar6;
    //KEY_VALUE_PARTIAL_INFORMATION* pKVar7 = NULL;
    ULONG subkeyIndex = 0;
    //undefined auStackY_328[8];
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
    //chamberIdData = (PWCHAR)keyNameInformation;
    //chamberIdKeyInfo = (KEY_VALUE_PARTIAL_INFORMATION*)keyNameInformation;

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
        chamberIdData = NULL;
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

                    chamberIdKeyInfo = ExAllocatePool2(0x100, regResultLength, POOL_TAG_STsp);
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
                                POOL_TAG_STsp
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
                                        /* INT 0x29 is an interupt for __fastfail, error code 0x3 is FAST_FAIL_CORRUPT_LIST_ENTRY */
                                        // cacheHead = (CUSTOM_FC_STSEC_FOLDER_PROP_CACHE_LIST_ENTRY*)0x3;
                                        // pcVar1 = (code*)swi(0x29);
                                        __fastfail(0x3);
                                        // newCacheEntry = (CUSTOM_FC_STSEC_FOLDER_PROP_CACHE_LIST_ENTRY*)(*pcVar1)();
                                        // puVar3 = auStackY_320;
                                    }

                                    newCacheEntry->Next = cacheHead;
                                    newCacheEntry->Prev = g_StSecFolderPropertyCacheListTail;
                                    g_StSecFolderPropertyCacheListTail->Next = newCacheEntry;
                                    //*(undefined8*)(puVar3 + 0x40) = 0;
                                    //puVar4 = puVar3;
                                    g_StSecFolderPropertyCacheListTail = newCacheEntry;
                                    goto StSecpGetFolderPropertyPolicy_free_keyValueName;
                                }
                            }
                        }
                        RtlFreeUnicodeString(&path);
                        //subkeyIndex = (KEY_VALUE_PARTIAL_INFORMATION*)keyNameInformation;
                        goto StSecpGetFolderPropertyPolicy_free_chamberid_data;
                    }
                StSecpGetFolderPropertyPolicy_free_keyValueName:
                    //*(undefined8*)(puVar4 + -8) = 0x1c0012544;
                    //RtlFreeUnicodeString((PUNICODE_STRING)(puVar4 + 0x38));
                    RtlFreeUnicodeString(&keyValueName);
                    //puVar5 = puVar4;
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
        //puVar6 = auStackY_328;
        if (chamberIdKeyInfo != NULL)
        {
        StSecpGetFolderPropertyPolicy_free_registry_key_info:
            //*(undefined8*)(puVar5 + -8) = 0x1c0012599;
            ExFreePoolWithTag(chamberIdKeyInfo, POOL_TAG_STsp);
            //puVar6 = puVar5;
        }
        if ((KEY_VALUE_PARTIAL_INFORMATION*)keyNameInformation != NULL)
        {
            //*(undefined8*)(puVar6 + -8) = 0x1c00125b2;
            ExFreePoolWithTag(keyNameInformation, POOL_TAG_STsp);
        }
    }

    // if (*(HANDLE*)(puVar6 + 0x48) != NULL)
    // {
    //     *(undefined8*)(puVar6 + -8) = 0x1c00125c8;
    //     ZwClose(*(HANDLE*)(puVar6 + 0x48));
    // }
    // *(undefined8*)(puVar6 + -8) = 0x1c00125de;
    if (RegistryKeyHandle != NULL)
    {
        ZwClose(RegistryKeyHandle);
    }

    return return_status;
}


NTSTATUS
StSecpGetMasterKey(
    PUCHAR* OutMasterKey,
    PULONG OutMasterKeySizeInBytes
)
{
    NTSTATUS return_status;
    NTSTATUS sealKeyStatus;
    PUCHAR unsealedMasterKey = NULL;
    PUCHAR* sealedKeyBuffer;
    PUCHAR* unsealedKey = OutMasterKey;
    PUCHAR UnsealedKey;
    ULONG keySizeInBytes;
    bool isMasterKeyNull;
    ULONG sealedKeyBlobSize = 0;
    ULONG unsealedMasterKeySizeInBytes = 0x80;
    PUCHAR* sealedKeyBlob = NULL;

    /* Check if master key is already available in memory */
    if (g_MasterKey == NULL)
    {
        /* 1024-bit buffer - 128 byte key */
        unsealedMasterKey = ExAllocatePool2(0x40, 0x80, POOL_TAG_StSn);
        if (unsealedMasterKey == NULL)
        {
            return STATUS_NO_MEMORY;
        }

        return_status = StSecpReadSealedKeyBlob((PUCHAR*)&sealedKeyBlob, &sealedKeyBlobSize);
        sealedKeyBuffer = sealedKeyBlob;
        if (return_status < 0)
        {
            /* 0x80 = 128 */
            keySizeInBytes = 0x80;

            /* We have failed to read sealed key - check if it's because the key doesn't exist */
            if (return_status == STATUS_OBJECT_NAME_NOT_FOUND)
            {
                return_status = BCryptGenRandom(NULL, unsealedMasterKey, 0x80, 2);
                sealedKeyBuffer = sealedKeyBlob;

                if (-1 < return_status)
                {
                    goto StSecpGetMasterKey_store_masterkey;
                }
            }
        }
        else
        {
            /* Successfully read sealed key - now unseal it via TPM */
            return_status = StSecpUnsealKey(
                (PUCHAR)sealedKeyBlob,
                sealedKeyBlobSize,
                unsealedMasterKey,
                &unsealedMasterKeySizeInBytes
            );

            keySizeInBytes = unsealedMasterKeySizeInBytes;

            if (-1 < return_status)
            {
                g_MasterKeyPersisted = '\x01';
            StSecpGetMasterKey_store_masterkey:
                // TODO LOCK();
                isMasterKeyNull = g_MasterKey == NULL;
                g_MasterKey = (PUCHAR)(
                    (ulonglong)g_MasterKey ^
                    (ulonglong)isMasterKeyNull *
                    ((ulonglong)g_MasterKey ^ (ulonglong)unsealedMasterKey)
                );

                unsealedKey = (PUCHAR*)-(ulonglong)((ulonglong)!isMasterKeyNull * (longlong)g_MasterKey != 0);
                unsealedMasterKey = (PUCHAR)((ulonglong)unsealedMasterKey & (ulonglong)unsealedKey);

                goto LAB_1c000dbf3;
            }
        }
    }
    else
    {
    LAB_1c000dbf3:
        sealedKeyBuffer = sealedKeyBlob;
        keySizeInBytes = unsealedMasterKeySizeInBytes;
        /* Key not yet persisted - need to save it */
        if (g_MasterKeyPersisted == '\0')
        {
            /* Seal the key using TPM */
            sealKeyStatus = StSecpSealKey(
                (PUCHAR)unsealedKey,
                unsealedMasterKeySizeInBytes,
                (PUCHAR)sealedKeyBlob,
                &sealedKeyBlobSize
            );

            if (sealKeyStatus == STATUS_BUFFER_TOO_SMALL)
            {
                UnsealedKey = (PUCHAR)0x100;
                sealedKeyBuffer = ExAllocatePool2(0x100, sealedKeyBlobSize, POOL_TAG_STsp);

                if (sealedKeyBuffer == NULL)
                {
                    return_status = STATUS_NO_MEMORY;
                }
                else
                {
                    /* Seal the key with larger buffer */
                    return_status = StSecpSealKey(
                        UnsealedKey,
                        keySizeInBytes,
                        (PUCHAR)sealedKeyBuffer,
                        &sealedKeyBlobSize
                    );

                    /* Write the sealed key to registry */
                    if (-1 < return_status)
                    {
                        return_status = StSecpWriteSealedKeyBlob(sealedKeyBuffer, sealedKeyBlobSize);
                        if (-1 < return_status)
                        {
                            g_MasterKeyPersisted = '\x01';
                            goto StSecpGetMasterKey_assign_masterkey;
                        }
                    }
                }
            }
            else
            {
                return_status = STATUS_UNSUCCESSFUL;
            }
        }
        else
        {
        StSecpGetMasterKey_assign_masterkey:
            return_status = STATUS_SUCCESS;
            *OutMasterKey = g_MasterKey;
            *OutMasterKeySizeInBytes = keySizeInBytes;
        }
        if (unsealedMasterKey == NULL)
        {
            goto StSecpGetMasterKey_cleanup_and_return;
        }
    }
    StSecpFreeNonPaged(unsealedMasterKey, keySizeInBytes);
StSecpGetMasterKey_cleanup_and_return:
    if (sealedKeyBuffer != NULL)
    {
        StSecFree(sealedKeyBuffer);
    }
    return return_status;
}

/* This function handles the conversion of different types of identifiers into Security Identifiers
 * (SIDs), which are then used for access control decisions */
NTSTATUS
StSecpGetParameterValue(
    PCUNICODE_STRING ParameterName,
    PCUNICODE_STRING Value,
    PWCHAR* ResultSid
)
{
    LONG cmpResult;
    NTSTATUS status;
    PWCHAR result = NULL;
    UNICODE_STRING user = {0x0c, 0xe0, L"<User>"};
    UNICODE_STRING packageFamilyName = {0x26, 0x28, L"<PackageFamilyName>"};
    UNICODE_STRING packageFullNameRedirected = {0x36, 0x38, L"<PackageFullNameRedirected>"};
    UNICODE_STRING packageFullName = {0x22, 0x24, L"<PackageFullName>"};
    UNICODE_STRING productId = {0x16, 0x18, L"<ProductId>"};

    cmpResult = RtlCompareUnicodeString(ParameterName, &user, '\x01');

    /* 0 means the string are equal */
    if (cmpResult == 0)
    {
        /* Convert a username to a SID.
           Example example: JohnDoe */
        status = StSecpGetSidFromUserName(Value, &result);
    }
    else
    {
        cmpResult = RtlCompareUnicodeString(ParameterName, &packageFamilyName, '\x01');
        if (cmpResult == 0)
        {
            /* Convert a Windows Store app family name to a SID.
             * Example PackageFamilyName: PublisherName.AppName_PublisherID */
            status = StSecpGetSidFromPackageFamilyName(Value, &result);
        }
        else
        {
            cmpResult = RtlCompareUnicodeString(ParameterName, &packageFullNameRedirected, '\x01');
            if (cmpResult == 0)
            {
                /* Get a security descriptor for a redirected package.
                 * This refers to app packages that have been redirected or virtualized.
                 * Example: Microsoft.WindowsCalculator_11.2307.4.0_x64__8wekyb3d8bbwe\PrivateVirtualization */
                status = KappxGetSecurityDescriptorStringForPackageFullName(Value, &result);
            }
            else
            {
                cmpResult = RtlCompareUnicodeString(ParameterName, &packageFullName, '\x01');
                if (cmpResult == 0)
                {
                    /* Convert a complete app package name to a SID.
                     * Example PackageFullName: Microsoft.WindowsCalculator_11.2307.4.0_x64__8wekyb3d8bbwe */
                    status = StSecpGetSidFromPackageFullName(Value, &result);
                }
                else
                {
                    cmpResult = RtlCompareUnicodeString(ParameterName, &productId, '\x01');
                    if (cmpResult != 0)
                    {
                        status = STATUS_UNSUCCESSFUL;
                        goto StSecpGetParameterValue_cleanup_and_return;
                    }
                    /* Convert a product ID to a SID.
                     * Example ProductId:
                     *  - {CF8E2E00-F4B3-11E3-AC10-0800200C9A66}
                     *  - 9WZDNCRFJ364 (Microsoft Store product ID) */
                    status = StSecpGetSidFromProductId(Value, &result);
                }
            }
        }
    }
    if (-1 < status)
    {
        *ResultSid = result;
        return STATUS_SUCCESS;
    }
StSecpGetParameterValue_cleanup_and_return:
    if (result != NULL)
    {
        ExFreePoolWithTag(result, 0);
    }

    return status;
}


/* Reads from the registry and populates the StSecSecurityDescriptorCacheList with new entries */
NTSTATUS
StSecpGetSecurityDescriptorPolicy(
    HANDLE RegistryKeyHandle
)
{
    // code* pcVar1;
    // PWCHAR pWVar2;
    BOOLEAN createSuccess;
    NTSTATUS status;
    PWCHAR parameterKeyName;
    NTSTATUS status1;
    KEY_VALUE_PARTIAL_INFORMATION* keyValuePartialInfo2;
    PWCHAR securityDescriptor;
    PWCHAR debugValue;
    NTSTATUS return_status;
    KEY_NAME_INFORMATION* keyNameInfo2;
    PCUSTOM_FC_STSEC_SEC_DESC_CACHE_LIST_ENTRY newCacheEntry;
    // PVOID pKVar4 = NULL;
    PCUSTOM_FC_STSEC_SEC_DESC_CACHE_LIST_ENTRY cacheListHead;
    // undefined* puVar3;
    // undefined* stackPtr;
    // PVOID pKVar7 = NULL;
    // PVOID pKVar8 = NULL;
    // PVOID pKVar9 = NULL;
    // PVOID pKVar11 = NULL;
    // undefined auStackY_328[8];
    // undefined auStackY_320[24];
    ULONG keyInfoLength = 0;
    UNICODE_STRING pathString = {0, 0, NULL};
    HANDLE registryKeyHandle = NULL;
    ULONG subkeyIndex = 0;
    UNICODE_STRING keyBasicInfoName = {0, 0, NULL};
    UNICODE_STRING registryValueName = {0x24, 0x26, L"SecurityDescriptor"};
    OBJECT_ATTRIBUTES objectAttributes;
    KEY_NAME_INFORMATION keyNameInfo;
    KEY_VALUE_PARTIAL_INFORMATION keyValuePartialInfo = {0, 0, 0, {0}};
    KEY_BASIC_INFORMATION keyBasicInfo;

    /* The registry path of the handle is:
     * L"\\Registry\\Machine\\System\\ControlSet001\\Control\\StSec\\SecurityDescriptors"
     */

    // puVar3 = auStackY_328;
    // stackPtr = auStackY_328;
    // keyNameInfo = (KEY_NAME_INFORMATION)0x0;
    // objectAttributes._0_16_ = ZEXT816(0);
    // objectAttributes._16_16_ = ZEXT816(0);
    // parameterKeyName = (PWCHAR)pKVar4;

    while (status = ZwEnumerateKey(
        RegistryKeyHandle,
        subkeyIndex,
        KeyBasicInformation,
        &keyBasicInfo,
        0x222,
        &keyInfoLength
    ), -1 < status)
    {
        //keyBasicInfoName = (UNICODE_STRING)CONCAT88(keyBasicInfo.Name, keyBasicInfoName._0_8_);
        keyBasicInfoName.Buffer = keyBasicInfo.Name;

        /* Process special subkeys that start with < and end with > */
        if ((keyBasicInfo.Name[0] == L'<') &&
            (keyBasicInfo.Name[(ulonglong)((ushort)keyBasicInfo.NameLength >> 1) - 1] == L'>'))
        {
            if (parameterKeyName == NULL)
            {
                /* Special handling for parameter keys (<PackageFamilyName>, etc.) */
                parameterKeyName = ExAllocatePool2(
                    0x100,
                    (ulonglong)(ushort)keyBasicInfo.NameLength + 2,
                    POOL_TAG_STsp
                );

                if (parameterKeyName == NULL)
                {
                    RtlFreeUnicodeString(&pathString);
                    goto StSecpGetSecurityDescriptorPolicy_free_handle;
                }
                status1 = RtlStringCbCopyNW(
                    parameterKeyName,
                    (ulonglong)keyBasicInfoName.Length + 2,
                    keyBasicInfoName.Buffer,
                    keyBasicInfoName.Length
                );

                if (-1 < status1)
                {
                    goto StSecpGetSecurityDescriptorPolicy_next_subkey;
                }
            }

            RtlFreeUnicodeString(&pathString);
            // stackPtr = auStackY_328;
            goto StSecpGetSecurityDescriptorPolicy_free_keyName;
        }
        // objectAttributes._0_16_ = CONCAT124(objectAttributes._4_12_, 0x30);
        // objectAttributes._0_16_ = CONCAT88(RegistryKeyHandle, objectAttributes._0_8_);
        // objectAttributes._16_12_ = CONCAT48(0x240, &keyBasicInfoName);
        // objectAttributes._32_16_ = ZEXT816(0);
        InitializeObjectAttributes(
            &objectAttributes,
            &keyBasicInfoName,
            0x30,
            RegistryKeyHandle,
            NULL
        )

        status = ZwOpenKey(
            &registryKeyHandle,
            0x20019,
            &objectAttributes
        );

        if ((status < 0) || (status1 = StSecpGetSecurityDescriptorPolicy(registryKeyHandle), status1 < 0))
        {
            goto StSecpGetSecurityDescriptorPolicy_cleanup_and_return;
        }

        ZwClose(registryKeyHandle);
        registryKeyHandle = NULL;
    StSecpGetSecurityDescriptorPolicy_next_subkey:
        subkeyIndex = subkeyIndex + 1;
    }

    // keyValuePartialInfo2 = (KEY_VALUE_PARTIAL_INFORMATION*)pKVar4;
    // securityDescriptor = (PWCHAR)pKVar4;
    // debugValue = (PWCHAR)pKVar4;
    // keyNameInfo2 = (KEY_NAME_INFORMATION*)pKVar4;
    if (status != STATUS_NO_MORE_ENTRIES)
    {
        goto LAB_1c0011eac;
    }

    // keyValuePartialInfo2 = (KEY_VALUE_PARTIAL_INFORMATION*)pKVar7;
    // securityDescriptor = (PWCHAR)pKVar8;
    // debugValue = (PWCHAR)pKVar9;
    // keyNameInfo2 = (KEY_NAME_INFORMATION*)pKVar11;
    if (parameterKeyName != NULL)
    {
        RtlInitUnicodeString(&keyBasicInfoName, parameterKeyName);
        // objectAttributes._0_16_ = CONCAT124(objectAttributes._4_12_, 0x30);
        // objectAttributes._0_16_ = CONCAT88(RegistryKeyHandle, objectAttributes._0_8_);
        // objectAttributes._16_12_ = CONCAT48(0x240, &keyBasicInfoName);
        // objectAttributes._32_16_ = ZEXT816(0);
        InitializeObjectAttributes(
            &objectAttributes,
            &keyBasicInfoName,
            0x30,
            RegistryKeyHandle,
            NULL
        )

        status = ZwOpenKey(&registryKeyHandle, 0x20019, &objectAttributes);

        if ((status < 0) || (status1 = StSecpGetSecurityDescriptorPolicy(registryKeyHandle), status1 < 0))
        {
            goto LAB_1c0011eac;
        }
    }
    status = ZwQueryValueKey(
        RegistryKeyHandle,
        &registryValueName,
        KeyValuePartialInformation,
        &keyValuePartialInfo,
        0x10,
        &keyInfoLength
    );

    if (status < 0)
    {
        if (status == STATUS_BUFFER_OVERFLOW)
        {
            keyValuePartialInfo2 = ExAllocatePool2(0x100, keyInfoLength, POOL_TAG_STsp);
            if (keyValuePartialInfo2 != NULL)
            {
                status = ZwQueryValueKey(
                    RegistryKeyHandle,
                    &registryValueName,
                    KeyValuePartialInformation,
                    keyValuePartialInfo2,
                    keyInfoLength,
                    &keyInfoLength
                );

                if (status < 0)
                {
                LAB_1c0011eac:
                    RtlFreeUnicodeString(&pathString);
                    if (securityDescriptor != NULL)
                    {
                    LAB_1c0011ec2:
                        ExFreePoolWithTag(securityDescriptor, POOL_TAG_STsp);
                    }
                    // puVar3 = auStackY_328;
                    if (debugValue != NULL)
                    {
                        ExFreePoolWithTag(debugValue, POOL_TAG_STsp);
                        // puVar3 = auStackY_328;
                    }
                LAB_1c0011eef:
                    // stackPtr = puVar3;
                    // pKVar4 = keyNameInfo2;
                    if (keyValuePartialInfo2 != NULL)
                    {
                        goto LAB_1c0011ef4;
                    }
                }
                else
                {
                    securityDescriptor = ExAllocatePool2(
                        0x100,
                        keyValuePartialInfo2->DataLength,
                        POOL_TAG_STsp
                    );

                    if (securityDescriptor != NULL)
                    {
                        status1 = RtlStringCbCopyW(
                            securityDescriptor,
                            keyValuePartialInfo2->DataLength,
                            keyValuePartialInfo2->Data
                        );

                        if (status1 < 0)
                        {
                            goto LAB_1c0011eac;
                        }

                        RtlInitUnicodeString(&registryValueName, L"Debug");

                        status = ZwQueryValueKey(
                            RegistryKeyHandle,
                            &registryValueName,
                            KeyValuePartialInformation,
                            &keyValuePartialInfo,
                            0x10,
                            &keyInfoLength
                        );

                        // debugValue = (PWCHAR)pKVar4;
                        // keyNameInfo2 = (KEY_NAME_INFORMATION*)pKVar4;
                        if (-1 < status)
                        {
                        LAB_1c0011dd3:
                            RtlFreeUnicodeString(&pathString);
                            goto LAB_1c0011ec2;
                        }

                        if (status == STATUS_BUFFER_OVERFLOW)
                        {
                            ExFreePoolWithTag(keyValuePartialInfo2, POOL_TAG_STsp);
                            keyValuePartialInfo2 = ExAllocatePool2(0x100, keyInfoLength, POOL_TAG_STsp);

                            //keyNameInfo2 = (KEY_NAME_INFORMATION*)pKVar11;
                            if (keyValuePartialInfo2 != NULL)
                            {
                                status = ZwQueryValueKey(
                                    RegistryKeyHandle,
                                    &registryValueName,
                                    KeyValuePartialInformation,
                                    keyValuePartialInfo2,
                                    keyInfoLength,
                                    &keyInfoLength
                                );

                                // debugValue = (PWCHAR)pKVar9;
                                if (-1 < status)
                                {
                                    debugValue = ExAllocatePool2(
                                        0x100,
                                        keyValuePartialInfo2->DataLength,
                                        POOL_TAG_STsp
                                    );

                                    if (debugValue == NULL)
                                    {
                                        goto LAB_1c0011dd3;
                                    }

                                    status1 = RtlStringCbCopyW(
                                        debugValue,
                                        keyValuePartialInfo2->DataLength,
                                        keyValuePartialInfo2->Data
                                    );
                                    // pWVar2 = debugValue;

                                    if (-1 < status1)
                                    {
                                        goto LAB_1c0011f8e;
                                    }
                                }
                                goto LAB_1c0011eac;
                            }
                            goto LAB_1c0011dd3;
                        }

                        // debugValue = (PWCHAR)pKVar9;
                        // pWVar2 = (PWCHAR)pKVar4;
                        // keyNameInfo2 = (KEY_NAME_INFORMATION*)pKVar11;
                        if (status != STATUS_OBJECT_NAME_NOT_FOUND)
                        {
                            goto LAB_1c0011eac;
                        }

                    LAB_1c0011f8e:
                        //debugValue = pWVar2;

                        status = ZwQueryKey(
                            RegistryKeyHandle,
                            KeyNameInformation,
                            &keyNameInfo,
                            8,
                            &keyInfoLength
                        );

                        //keyNameInfo2 = (KEY_NAME_INFORMATION*)pKVar4;

                        if (-1 < status)
                        {
                            goto LAB_1c0011dd3;
                        }
                        //keyNameInfo2 = (KEY_NAME_INFORMATION*)pKVar11;
                        if (status != STATUS_BUFFER_OVERFLOW)
                        {
                            goto LAB_1c0011eac;
                        }

                        keyNameInfo2 = ExAllocatePool2(
                            0x100,
                            (ulonglong)keyInfoLength + 4,
                            POOL_TAG_STsp
                        );

                        if (keyNameInfo2 == NULL)
                        {
                            goto LAB_1c0011dd3;
                        }

                        status = ZwQueryKey(
                            RegistryKeyHandle,
                            KeyNameInformation,
                            keyNameInfo2,
                            keyInfoLength,
                            &keyInfoLength
                        );

                        if (status < 0)
                        {
                            goto LAB_1c0011eac;
                        }

                        keyNameInfo2->Name[keyNameInfo2->NameLength >> 1] = L'\\';
                        keyNameInfo2->Name[(ulonglong)(keyNameInfo2->NameLength >> 1) + 1] = L'\0';
                        createSuccess = RtlCreateUnicodeString(&pathString, keyNameInfo2[0x12].Name);

                        if ((createSuccess == '\0') ||
                            (newCacheEntry = ExAllocatePool2(
                                    0x100,
                                    0x30,
                                    POOL_TAG_STsp
                                ),
                                newCacheEntry == NULL))
                        {
                            goto LAB_1c0011dd3;
                        }

                        newCacheEntry->SecurityDescriptor = securityDescriptor;
                        cacheListHead = g_StSecSecurityDescriptorCacheListHead;

                        newCacheEntry->DebugValue = debugValue;
                        // *(undefined4*)&newCacheEntry->Path = pathString._0_4_;
                        // *(undefined4*)&(newCacheEntry->Path).field_0x4 = pathString._4_4_;
                        // *(undefined4*)&(newCacheEntry->Path).Buffer = pathString.Buffer._0_4_;
                        // *(undefined4*)((longlong)&(newCacheEntry->Path).Buffer + 4) = pathString.Buffer._4_4_;
                        newCacheEntry->Path.Length = pathString.Length;
                        newCacheEntry->Path.MaximumLength = pathString.MaximumLength;
                        newCacheEntry->Path.Buffer = pathString.Buffer;

                        if (g_StSecSecurityDescriptorCacheListTail->Next != g_StSecSecurityDescriptorCacheListHead)
                        {
                            // cacheListHead = (CUSTOM_FC_STSEC_SEC_DESC_CACHE_LIST_ENTRY*)0x3;
                            // pcVar1 = (code*)swi(0x29);
                            __fastfail(0x3);
                            // newCacheEntry = (CUSTOM_FC_STSEC_SEC_DESC_CACHE_LIST_ENTRY*)(*pcVar1)();
                            // puVar3 = auStackY_320;
                        }

                        newCacheEntry->Next = cacheListHead;
                        newCacheEntry->Prev = g_StSecSecurityDescriptorCacheListTail;
                        g_StSecSecurityDescriptorCacheListTail->Next = newCacheEntry;
                        // *(undefined8*)(puVar3 + 0x40) = 0;
                        // *(undefined8*)(puVar3 + -8) = 0x1c00120e8;
                        g_StSecSecurityDescriptorCacheListTail = newCacheEntry;
                        //RtlFreeUnicodeString((PUNICODE_STRING)(puVar3 + 0x38));
                        RtlFreeUnicodeString(&registryValueName);
                        goto LAB_1c0011eef;
                    }
                    RtlFreeUnicodeString(&pathString);
                    //puVar3 = auStackY_328;
                LAB_1c0011ef4:
                    //*(undefined8*)(puVar3 + -8) = 0x1c0011f03;
                    ExFreePoolWithTag(keyValuePartialInfo2, POOL_TAG_STsp);
                    //stackPtr = puVar3;
                }
                //if ((KEY_NAME_INFORMATION*)pKVar4 != NULL)
                if (newCacheEntry != NULL)
                {
                    //*(undefined8*)(stackPtr + -8) = 0x1c0011f1c;
                    ExFreePoolWithTag(newCacheEntry, POOL_TAG_STsp);
                }
                goto StSecpGetSecurityDescriptorPolicy_try_free_keyName;
            }
        }
        else if (status != STATUS_OBJECT_NAME_NOT_FOUND)
        {
            goto LAB_1c0011eac;
        }
    }
StSecpGetSecurityDescriptorPolicy_cleanup_and_return:
    RtlFreeUnicodeString(&pathString);
    //stackPtr = auStackY_328;
StSecpGetSecurityDescriptorPolicy_try_free_keyName:
    if (parameterKeyName != NULL)
    {
    StSecpGetSecurityDescriptorPolicy_free_keyName:
        //*(undefined8*)(stackPtr + -8) = 0x1c0011f35;
        ExFreePoolWithTag(parameterKeyName, POOL_TAG_STsp);
    }
StSecpGetSecurityDescriptorPolicy_free_handle:
    // if (*(HANDLE*)(stackPtr + 0x48) != NULL)
    // {
    //     *(undefined8*)(stackPtr + -8) = 0x1c0011f4b;
    //     ZwClose(*(HANDLE*)(stackPtr + 0x48));
    // }
    // *(undefined8*)(stackPtr + -8) = 0x1c0011f61;
    if (RegistryKeyHandle != NULL)
    {
        ZwClose(RegistryKeyHandle);
    }

    return return_status;
}


NTSTATUS
StSecpGetSidFromPackageFamilyName(
    PCUNICODE_STRING PackageFamilyName,
    PWCHAR* ResultSid
)
{
    NTSTATUS return_status;
    UNICODE_STRING lowerCasePackageFamilyName = {0, 0, NULL};

    /* Attempt to look up the PackageFamilyName in the registry */
    return_status = KappxGetPackageSidFromPackageFamilyNameInRegistry(PackageFamilyName, ResultSid);

    /* If the registry lookup fails with STATUS_OBJECT_NAME_NOT_FOUND, Convert the package family name
       to lowercase and derive a SID algorithmically */
    if (return_status == STATUS_OBJECT_NAME_NOT_FOUND)
    {
        return_status = RtlDowncaseUnicodeString(&lowerCasePackageFamilyName, PackageFamilyName, '\x01');

        if (-1 < return_status)
        {
            return_status = StSecpGetAppSid(&lowerCasePackageFamilyName, ResultSid);
        }
    }

    RtlFreeUnicodeString(&lowerCasePackageFamilyName);

    return return_status;
}


NTSTATUS
StSecpGetSidFromPackageFullName(
    PUNICODE_STRING PackgeFullName,
    PWCHAR* ResultSid
)
{
    NTSTATUS return_status;
    UNICODE_STRING packgeFamilyName = {0, 0, NULL};

    /* Extract family name from full name */
    return_status = StSecpPackageFamilyNameFromFullName(PackgeFullName, &packgeFamilyName);

    if (-1 < return_status)
    {
        /* Try registry lookup for SID and fall back to StSecpGetAppSid for algorithmic generation if needed */
        return_status = StSecpGetSidFromPackageFamilyName(&packgeFamilyName, ResultSid);
    }

    StSecFree(packgeFamilyName.Buffer);

    return return_status;
}


NTSTATUS
StSecpGetSidFromProductId(
    PCUNICODE_STRING ProductId,
    PWCHAR* ResultSid
)
{
    NTSTATUS return_status;
    UNICODE_STRING upcaseProduceId = {0, 0, NULL};

    return_status = RtlUpcaseUnicodeString(&upcaseProduceId, ProductId, '\x01');

    if (-1 < return_status)
    {
        return_status = StSecpGetAppSid(&upcaseProduceId, ResultSid);
    }

    RtlFreeUnicodeString(&upcaseProduceId);

    return return_status;
}


NTSTATUS StSecpGetSidFromUserName(PCUNICODE_STRING UserName, PWCHAR* ResultSid)

{
    NTSTATUS return_status;
    PWCHAR sid;
    SIZE_T sidSize = UserName->Length + 2;
    undefined8 unused = 0x6e537453;

    /* This function doesn't actually convert the username to a SID as its name suggests. Instead, it
       simply copies the UserName into the ResultSid */
    sid = ExAllocatePool2(0x40, sidSize, POOL_TAG_StSn);

    if (sid == NULL)
    {
        return_status = STATUS_NO_MEMORY;
    }
    else
    {
        if (sidSize >> 1 == 0)
        {
            return_status = STATUS_INVALID_PARAMETER;
        }
        else
        {
            return_status = RtlStringCopyWorkerW(
                sid, sidSize >> 1,
                unused,
                UserName->Buffer,
                UserName->Length >> 1
            );

            if (-1 < return_status)
            {
                *ResultSid = sid;

                return return_status;
            }
        }
        ExFreePoolWithTag(sid, 0);
    }

    return return_status;
}


/* Retrieves and processes a security descriptor string for a given folder path. When the driver
   needs to make security decisions about file access, this function:
   - Finds the matching security policy template from the cache
   - Processes any parameters in the template (like <PackageFamilyName>)
   - Substitutes those parameters with actual values
   - Constructs the final security descriptor string */
NTSTATUS
StSecpGetStorageFolderStringSecurityDescriptor(
    PCUNICODE_STRING FolderPath,
    PWCHAR* OutStringSecurityDescriptor
)
{
    WCHAR WVar1;
    longlong lVar2;
    UCHAR UVar3;
    NTSTATUS return_status;
    CUSTOM_FC_STSEC_SEC_DESC_CACHE_LIST_ENTRY* policyElement;
    PWCHAR* ppWVar4;
    longlong stringLength;
    PWCHAR currentChar;
    PUNICODE_STRING firstName;
    ulonglong halfOutputLength = 0;
    ulonglong temp;
    ulonglong totalOutputLength;
    PWCHAR** parametersValues;
    uint parameterCount;
    ulonglong maxStringLength;
    PWCHAR outputBuffer = NULL;
    UCHAR isDebugProfile = FALSE;
    longlong parameterLength = 0;
    UNICODE_STRING parameterName = {0, 0, NULL};
    UNICODE_STRING sid = {0, 0, NULL};
    PWCHAR* parameters = NULL;
    UNICODE_STRING pathSegment = {0, 0, NULL};
    UNICODE_STRING remainingPath = {0, 0, NULL};
    UNICODE_STRING policyPath;
    PWCHAR securityDescriptor;

    policyElement = StSecpFindSecurityDescriptorPolicyElement(FolderPath);
    if (policyElement == NULL)
    {
        return STATUS_OBJECT_NAME_NOT_FOUND;
    }

    securityDescriptor = policyElement->SecurityDescriptor;
    if (securityDescriptor == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    /* Calculate string length */
    stringLength = 0x7fffffff;
    do
    {
        if (*securityDescriptor == L'\0')
        {
            break;
        }

        securityDescriptor = securityDescriptor + 1;
        stringLength = stringLength + -1;
    }
    while (stringLength != 0);

    temp = STATUS_INVALID_PARAMETER;
    if (stringLength != 0)
    {
        temp = halfOutputLength;
    }
    if (stringLength == 0)
    {
        return temp;
    }
    if (stringLength == 0)
    {
        return temp;
    }

    // policyPath._0_4_ = *(undefined4*)&policyElement->Path;
    // policyPath._4_4_ = *(undefined4*)&(policyElement->Path).field_0x4;
    // policyPath.Buffer._0_4_ = *(undefined4*)&(policyElement->Path).Buffer;
    // policyPath.Buffer._4_4_ = *(undefined4*)((longlong)&(policyElement->Path).Buffer + 4);
    policyPath.Length = policyElement->Path.Length;
    policyPath.MaximumLength = policyElement->Path.MaximumLength;
    policyPath.Buffer = policyElement->Path.Buffer;

    totalOutputLength = (0x7fffffff - stringLength) * 2 + 2;
    /* FsRtlDissectName seperates parts of a path, for example:
     * for Path = "Folder\SubFolder\file.txt" =>
     * FirstName = "Folder"
     * RemainingName = "\SubFolder\file.txt"
     */
    FsRtlDissectName(policyPath, &parameterName, &pathSegment);
    // policyPath._0_4_ = *(undefined4*)FolderPath;
    // policyPath._4_4_ = *(undefined4*)&FolderPath->field_0x4;
    // policyPath.Buffer._0_4_ = *(undefined4*)&FolderPath->Buffer;
    // policyPath.Buffer._4_4_ = *(undefined4*)((longlong)&FolderPath->Buffer + 4);
    policyPath.Length = FolderPath->Length;
    policyPath.MaximumLength = FolderPath->MaximumLength;
    policyPath.Buffer = FolderPath->Buffer;

    maxStringLength = halfOutputLength;
    while (true)
    {
        return_status = (NTSTATUS)temp;
        firstName = &sid;
        /* Process each segment pair */
        FsRtlDissectName(policyPath, firstName, &remainingPath);
        UVar3 = isDebugProfile;
        parameterCount = (uint)maxStringLength;

        if (parameterName.Buffer == NULL)
        {
            break;
        }
        if ((*parameterName.Buffer == L'<') &&
            (parameterName.Buffer[(ulonglong)(parameterName.Length >> 1) - 1] == L'>'))
        {
            if ((sid.Buffer == NULL) || (parameterCount == 2))
            {
                return_status = STATUS_UNSUCCESSFUL;
                goto StSecpGetStorageFolderStringSecurityDescriptor_cleanup_and_return;
            }

            return_status = StSecpGetParameterValue(
                &parameterName,
                &sid,
                (PWCHAR*)(&parameters + maxStringLength)
            );

            if (return_status < 0)
            {
                goto StSecpGetStorageFolderStringSecurityDescriptor_cleanup_and_return;
            }

            ppWVar4 = (&parameters)[maxStringLength];

            if (ppWVar4 == NULL)
            {
                return_status = STATUS_INVALID_PARAMETER;
                goto StSecpGetStorageFolderStringSecurityDescriptor_cleanup_and_return;
            }

            stringLength = 0x7fffffff;
            do
            {
                if (*(WCHAR*)ppWVar4 == L'\0') break;
                ppWVar4 = (PWCHAR*)((longlong)ppWVar4 + 2);
                stringLength = stringLength + -1;
            }
            while (stringLength != 0);

            temp = STATUS_INVALID_PARAMETER;

            if (stringLength != 0)
            {
                temp = halfOutputLength;
            }
            return_status = (NTSTATUS)temp;
            if ((stringLength == 0) || (lVar2 = (0x7fffffff - stringLength) * 2, stringLength == 0))
            {
                goto StSecpGetStorageFolderStringSecurityDescriptor_cleanup_and_return;
            }

            totalOutputLength = totalOutputLength + lVar2;
            maxStringLength = (ulonglong)(parameterCount + 1);
            parameterLength = lVar2;
        }
        parameterCount = (uint)maxStringLength;

        if (policyElement->DebugValue != NULL)
        {
            return_status = StSecpCheckConditionalPolicy(&parameterName, &sid, &isDebugProfile);
            temp = (ulonglong)(uint)return_status;

            if (return_status < 0)
            {
                goto StSecpGetStorageFolderStringSecurityDescriptor_cleanup_and_return;
            }
        }
        // policyPath._0_4_ = pathSegment._0_4_;
        // policyPath._4_4_ = pathSegment._4_4_;
        // policyPath.Buffer._0_4_ = pathSegment.Buffer._0_4_;
        // policyPath.Buffer._4_4_ = pathSegment.Buffer._4_4_;
        policyPath.Length = pathSegment.Length;
        policyPath.MaximumLength = pathSegment.Length;
        policyPath.Buffer = pathSegment.Buffer;
        FsRtlDissectName(policyPath, &parameterName, &pathSegment);
        // policyPath._0_4_ = remainingPath._0_4_;
        // policyPath._4_4_ = remainingPath._4_4_;
        // policyPath.Buffer._0_4_ = remainingPath.Buffer._0_4_;
        // policyPath.Buffer._4_4_ = remainingPath.Buffer._4_4_;
        policyPath.Length = remainingPath.Length;
        policyPath.MaximumLength = remainingPath.MaximumLength;
        policyPath.Buffer = remainingPath.Buffer;
    }
    if (isDebugProfile != '\0')
    {
        return_status = RtlStringCbLengthW(policyElement->DebugValue, firstName, &parameterLength);

        if (return_status < 0)
        {
            goto StSecpGetStorageFolderStringSecurityDescriptor_cleanup_and_return;
        }
        totalOutputLength = totalOutputLength + parameterLength;
    }
    outputBuffer = ExAllocatePool2(0x100, totalOutputLength, POOL_TAG_STsp);
    if (outputBuffer == NULL)
    {
        return_status = STATUS_NO_MEMORY;
    }
    else
    {
        if (parameterCount == 0)
        {
            securityDescriptor = policyElement->SecurityDescriptor;
            halfOutputLength = totalOutputLength >> 1;

            if (halfOutputLength - 1 < 0x7fffffff)
            {
                stringLength = 0x7ffffffe - halfOutputLength;
                currentChar = outputBuffer;

                do
                {
                    if ((stringLength + halfOutputLength == 0) ||
                        (WVar1 = *(WCHAR*)(((longlong)securityDescriptor - (longlong)outputBuffer) + (longlong)
                                currentChar),
                            WVar1 == L'\0'))
                        break;
                    *currentChar = WVar1;
                    currentChar = currentChar + 1;
                    halfOutputLength = halfOutputLength - 1;
                }
                while (halfOutputLength != 0);

                securityDescriptor = currentChar + -1;

                if (halfOutputLength != 0)
                {
                    securityDescriptor = currentChar;
                }

                return_status = STATUS_BUFFER_OVERFLOW;

                if (halfOutputLength != 0)
                {
                    return_status = STATUS_SUCCESS;
                }

                *securityDescriptor = L'\0';
            }
            else
            {
                return_status = STATUS_INVALID_PARAMETER;
                if (halfOutputLength != 0)
                {
                    *outputBuffer = L'\0';
                }
            }
        }
        else if (parameterCount == 1)
        {
            return_status = RtlStringCbPrintfW(
                outputBuffer,
                totalOutputLength,
                policyElement->SecurityDescriptor,
                parameters
            );
        }
        else if (parameterCount == 2)
        {
            return_status = RtlStringCbPrintfW(
                outputBuffer,
                totalOutputLength,
                policyElement->SecurityDescriptor,
                parameters
            );
        }
        if (
            (-1 < return_status) &&
            (
                (UVar3 == '\0' ||
                    (return_status = RtlStringCbCatW(
                        outputBuffer,
                        totalOutputLength,
                        policyElement->DebugValue
                    ), -1 < return_status))
            )
        )
        {
            *OutStringSecurityDescriptor = outputBuffer;
            outputBuffer = NULL;
        }
    }
StSecpGetStorageFolderStringSecurityDescriptor_cleanup_and_return:
    if (parameterCount != 0)
    {
        parametersValues = &parameters;
        halfOutputLength = (ulonglong)parameterCount;
        do
        {
            if (*parametersValues != NULL)
            {
                ExFreePoolWithTag(*parametersValues, 0);
            }
            parametersValues = parametersValues + 1;
            halfOutputLength = halfOutputLength - 1;
        }
        while (halfOutputLength != 0);
    }

    if (outputBuffer != NULL)
    {
        ExFreePoolWithTag(outputBuffer, POOL_TAG_STsp);
    }

    return return_status;
}


/* Two-Tier Policy Structure:
* The driver maintains separate caches for:
* 
*  Security Descriptors: Likely control access permissions and encryption requirements for specific
* files or directories
* 
*  Folder Properties: Likely define special handling for specific folders, possibly related to the
* "chamber" we see in the driver's callbacks
* 
 */
NTSTATUS
StSecpInitializePolicyCache(
    VOID)
{
    NTSTATUS return_status;
    HANDLE registryKeyHandle = NULL;
    UNICODE_STRING secDescRegistryPath = {
        0x90,
        0x92,
        L"\\Registry\\Machine\\System\\ControlSet001\\Control\\StSec\\SecurityDescriptors"
    };
    OBJECT_ATTRIBUTES objectAttributes;


    /* Circular linked list */
    g_StSecSecurityDescriptorCacheListTail = g_StSecSecurityDescriptorCacheListHead;
    g_StSecSecurityDescriptorCacheListHead = g_StSecSecurityDescriptorCacheListHead;

    // objectAttributes.ObjectName = &secDescRegistryPath;
    // objectAttributes._0_8_ = 0x30;
    // objectAttributes._24_8_ = 0x240;
    // objectAttributes.RootDirectory = NULL;
    // objectAttributes._32_16_ = ZEXT816(0);
    InitializeObjectAttributes(
        &objectAttributes,
        &secDescRegistryPath,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
        NULL,
        NULL
    )

    return_status = ZwOpenKey(&registryKeyHandle, 0x20019, &objectAttributes);

    if (-1 < return_status)
    {
        /* Read security descriptor policies from the registry and populate the SecurityDescriptorCacheList */
        return_status = StSecpGetSecurityDescriptorPolicy(registryKeyHandle);
        if (-1 < return_status)
        {
            ZwClose(registryKeyHandle);

            RtlInitUnicodeString(
                &secDescRegistryPath,
                L"\\Registry\\Machine\\System\\ControlSet001\\Control\\StSec\\FolderProperties"
            );

            registryKeyHandle = NULL;
            /* Circular linked list */
            g_StSecFolderPropertyCacheListTail = g_StSecFolderPropertyCacheListHead;
            g_StSecFolderPropertyCacheListHead = g_StSecFolderPropertyCacheListHead;

            // objectAttributes.ObjectName = &secDescRegistryPath;
            // objectAttributes._0_8_ = CONCAT44(objectAttributes._4_4_, 0x30);
            // objectAttributes.RootDirectory = NULL;
            // objectAttributes._24_8_ = CONCAT44(objectAttributes._28_4_, 0x240);
            // objectAttributes._32_16_ = ZEXT816(0);
            InitializeObjectAttributes(
                &objectAttributes,
                &secDescRegistryPath,
                OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                NULL,
                NULL
            )

            return_status = ZwOpenKey(&registryKeyHandle, 0x20019, &objectAttributes);

            if (return_status < 0)
            {
                if (return_status == STATUS_OBJECT_NAME_NOT_FOUND)
                {
                    return_status = 0;
                }
            }
            else
            {
                return_status = StSecpGetFolderPropertyPolicy(registryKeyHandle);
            }
        }
    }
    if (registryKeyHandle != NULL)
    {
        ZwClose(registryKeyHandle);
    }

    return return_status;
}


NTSTATUS
StSecpOpenMasterKeyHandle(
    HANDLE* OutMasterKeyHandle
)
{
    NTSTATUS return_status;
    HANDLE keyHandle = NULL;
    UNICODE_STRING registryPath = {0, 0, NULL};
    OBJECT_ATTRIBUTES objectAttributes;

    // objectAttributes._28_4_ = 0;
    // objectAttributes._4_4_ = 0;
    RtlInitUnicodeString(&registryPath, L"\\REGISTRY\\MACHINE\\Software\\Microsoft\\StorageSec\\Encrypt");
    // objectAttributes.RootDirectory = NULL;
    // objectAttributes.ObjectName = &registryPath;
    // objectAttributes.Length = 0x30;
    // objectAttributes.Attributes = 0x240;
    // objectAttributes._32_16_ = ZEXT816(0);
    InitializeObjectAttributes(
        &objectAttributes,
        &registryPath,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
        NULL,
        NULL
    );

    return_status = ZwOpenKey(&keyHandle, 0xf003f, &objectAttributes);

    if (-1 < return_status)
    {
        *OutMasterKeyHandle = keyHandle;
        keyHandle = NULL;
    }

    if (keyHandle != NULL)
    {
        ZwClose(keyHandle);
    }

    return return_status;
}


NTSTATUS
StSecpPackageFamilyNameFromFullName(
    PUNICODE_STRING PackageFullName,
    PUNICODE_STRING OutPackageFamilyName
)
{
    PWCH packageFamilyName;
    ulonglong uVar1;
    PWCH currentChar;
    NTSTATUS return_status = STATUS_SUCCESS;
    uint halfNameLength = PackageFullName->Length >> 1;
    uint nameIndex = 0;
    uint uVar2 = 0;
    int underscoreCount = 0;
    USHORT packageFamiltyNameLength;

    /* Windows Package Name Format
     * Windows Store apps use a specific naming format:
     * 
     * - Full Package Name: PublisherName.AppName_Version_Architecture_ResourceID_PublisherID
     * - Package Family Name: PublisherName.AppName_PublisherID
     * 
     * For example, given a full package name like:
     *   Microsoft.Office.Word_16.0.14228.20216_x64_en-us_8wekyb3d8bbwe
     * The package family name would be:
     *   Microsoft.Office.Word_8wekyb3d8bbwe
     */

    packageFamilyName = ExAllocatePool2(0x100, 0x82, POOL_TAG_STsp);

    if (packageFamilyName == NULL)
    {
        return STATUS_NO_MEMORY;
    }
    /* The loop copies characters until the first underscore */
    for (; (nameIndex < halfNameLength && (PackageFullName->Buffer[nameIndex] != L'_')); nameIndex = nameIndex + 1)
    {
        if (0x3f < uVar2)
        {
            goto StSecpPackageFamilyNameFromFullName_return_error;
        }

        uVar1 = (ulonglong)uVar2;
        uVar2 = uVar2 + 1;
        packageFamilyName[uVar1] = PackageFullName->Buffer[nameIndex];
    }
    if (nameIndex == halfNameLength)
    {
    StSecpPackageFamilyNameFromFullName_return_error:
        return_status = STATUS_BAD_DATA;

        StSecFree(packageFamilyName);
    }
    else
    {
        if (nameIndex < halfNameLength)
        {
            currentChar = PackageFullName->Buffer + nameIndex;
            do
            {
                /* This is searching for the 4th underscore in the string.
                 * The 4th underscore precedes the PublisherID, which is the final component of the package family
                 * name.
                 */
                if ((*currentChar == L'_') && (underscoreCount = underscoreCount + 1, underscoreCount == 4)) break;
                nameIndex = nameIndex + 1;
                currentChar = currentChar + 1;
            }
            while (nameIndex < halfNameLength);
            if (nameIndex == halfNameLength) goto StSecpPackageFamilyNameFromFullName_return_error;
        }
        /* After finding the 4th underscore, this loop copies all remaining characters to the output buffer */
        for (; nameIndex < halfNameLength; nameIndex = nameIndex + 1)
        {
            if (0x3f < uVar2)
            {
                goto StSecpPackageFamilyNameFromFullName_return_error;
            }
            uVar1 = (ulonglong)uVar2;
            uVar2 = uVar2 + 1;
            packageFamilyName[uVar1] = PackageFullName->Buffer[nameIndex];
        }
        packageFamiltyNameLength = (short)uVar2 * 2;
        packageFamilyName[uVar2] = L'\0';

        OutPackageFamilyName->Length = packageFamiltyNameLength;
        OutPackageFamilyName->MaximumLength = packageFamiltyNameLength + 2;
        OutPackageFamilyName->Buffer = packageFamilyName;
    }

    return return_status;
}


/* This function reads an encrypted key blob from secure storage (the registry) and returns both the
 * blob itself and its size to the caller */
NTSTATUS
StSecpReadSealedKeyBlob(
    PUCHAR* OutSealedKeyBlob,
    PULONG OutSealedKeyBlobSize
)
{
    NTSTATUS return_status;
    KEY_VALUE_PARTIAL_INFORMATION* keyValueInfo = NULL;
    PUCHAR sealedMasterKeyBlob;
    ULONG length = 0;
    HANDLE masterKeyHandle = NULL;
    UNICODE_STRING masterKeyValueName = {0, 0, NULL};
    ULONG sealedMasterKeyBlobSize;

    return_status = StSecpOpenMasterKeyHandle(&masterKeyHandle);

    if (-1 < return_status)
    {
        RtlInitUnicodeString(&masterKeyValueName, L"MK");

        return_status = ZwQueryValueKey(
            masterKeyHandle,
            &masterKeyValueName,
            KeyValuePartialInformation,
            NULL,
            length,
            length
        );

        if (return_status == STATUS_BUFFER_OVERFLOW || return_status == STATUS_BUFFER_TOO_SMALL)
        {
            keyValueInfo = ExAllocatePool2(0x100, length, POOL_TAG_STsp);

            if (keyValueInfo != NULL)
            {
                return_status =
                    ZwQueryValueKey(
                        masterKeyHandle,
                        &masterKeyValueName,
                        KeyValuePartialInformation,
                        keyValueInfo,
                        length,
                        &length
                    );

                if (return_status < 0)
                {
                    goto StSecpReadSealedKeyBlob_cleanup_and_return;
                }

                sealedMasterKeyBlobSize = keyValueInfo->DataLength;
                sealedMasterKeyBlob = ExAllocatePool2(
                    0x100,
                    sealedMasterKeyBlobSize,
                    POOL_TAG_STsp
                );

                if (sealedMasterKeyBlob != NULL)
                {
                    memcpy(sealedMasterKeyBlob, keyValueInfo->Data, sealedMasterKeyBlobSize);
                    *OutSealedKeyBlobSize = sealedMasterKeyBlobSize;
                    *OutSealedKeyBlob = sealedMasterKeyBlob;
                    goto StSecpReadSealedKeyBlob_cleanup_and_return;
                }
            }

            return_status = STATUS_NO_MEMORY;
        }
    }
StSecpReadSealedKeyBlob_cleanup_and_return:
    if (masterKeyHandle != NULL)
    {
        ZwClose(masterKeyHandle);
    }

    if (keyValueInfo != NULL)
    {
        StSecFree(keyValueInfo);
    }

    /* 1. Registry-Based Key Storage: The master key is stored in the registry rather than in a file or
       TPM, suggesting a balance between security and accessibility.
       2. Sealed Key Format: The key is stored in a "sealed" format.
       3. Fixed Storage Location: The key is stored at a fixed registry path, making it easily
       accessible to the driver but potentially to other privileged processes as well. */
    return return_status;
}

/* This function takes a raw (unprotected) master key and transforms it into a sealed key blob that
 * can only be unsealed by the specific TPM that created it */
NTSTATUS
StSecpSealKey(
    PUCHAR UnsealedKey,
    ULONG UnsealedKeySize,
    PUCHAR OutSealedKey,
    PULONG OutsealedKeySize
)
{
    BOOLEAN skipSealKey;
    int contextCreateResult;
    TBS_RESULT tpmCommandResult;
    NTSTATUS return_status;
    //undefined7 extraout_var;
    void* masterKey;
    ulonglong unsealedKeySize;
    UINT32 cbCommand;
    undefined auStackY_2c8[32];
    UINT32 pcbResult;
    TBS_HCONTEXT tbsHContext;
    TBS_CONTEXT_PARAMS2 contextParams2;
    /*PCBYTE abCommand;
    undefined2 uStack_240;
    undefined2 uStack_23e;
    undefined4 uStack_23c;
    undefined4 local_238;
    undefined4 uStack_234;
    undefined4 uStack_230;
    uint uStack_22c;
    char local_228;
    undefined4 commandBuffer[3];
    undefined8 uStack_21b;
    undefined2 auStack_213[229];*/
    CUSTOM_FC_TPM_SEAL_COMMAND abCommand;


    masterKey = g_MasterKey;
    unsealedKeySize = (ulonglong)UnsealedKeySize;
    contextParams2.version = 2;
    contextParams2.asUINT32 = 4;
    tbsHContext = NULL;
    memset(&abCommand, 0, 0x200);
    pcbResult = 0x200;
    cbCommand = UnsealedKeySize + 0x37;
    skipSealKey = StSecpSealKeyTestHookSet();
    if ((int)skipSealKey == 0)
    {
        if ((0x80 < UnsealedKeySize) ||
            (contextCreateResult = Tbsi_Context_Create(&contextParams2, &tbsHContext), contextCreateResult != 0))
            goto StSecpSealKey_cleanup_and_return;
        abCommand._6_2_ = 0;
        abCommand.uStack_240 = 0x5301;
        abCommand.uStack_23e = 0x81;
        /* Set up TPM command for sealing */
        abCommand.uStack_23c = 0x100;
        abCommand.local_238 = 0x400900;
        abCommand.uStack_234 = 0x900;
        /* onstruct command header */
        //abCommand._0_4_ = CONCAT13((char)(cbCommand >> 0x10), CONCAT12((char)(cbCommand >> 0x18), 0x280));
        abCommand._0_4_ = ((cbCommand >> 0x10) & 0xFF) << 24 | ((cbCommand >> 0x18) & 0xFF) << 8 | 0x0280;
        abCommand._4_1_ = (undefined)(cbCommand >> 8);
        /* Set up key data parameters */
        //abCommand.uStack_230 = CONCAT13((char)(UnsealedKeySize + 4 >> 8), 1);
        abCommand.uStack_230 = ((UnsealedKeySize + 4 >> 8) & 0xFF) << 24 | 1;
        abCommand.local_228 = (char)UnsealedKeySize;
        abCommand.uStack_22c = (uint)(byte)(abCommand.local_228 + 4) | (UnsealedKeySize >> 8) << 0x18;
        abCommand._5_1_ = (undefined)cbCommand;
        /* Copy the actual master key into the command buffer */
        memcpy(abCommand.commandBuffer, masterKey, unsealedKeySize);
        /* Additional TPM parameters after the key */
        *(undefined4*)((longlong)abCommand.commandBuffer + unsealedKeySize) = 0x8000e00;
        *(undefined4*)((longlong)abCommand.commandBuffer + unsealedKeySize + 4) = 0xb00;
        *(undefined4*)((longlong)abCommand.commandBuffer + unsealedKeySize + 8) = 0x5204;
        *(undefined8*)((longlong)&abCommand.uStack_21b + unsealedKeySize) = 0x1000;
        *(undefined2*)((longlong)abCommand.auStack_213 + unsealedKeySize) = 0;

        /* Submit command to TPM */
        tpmCommandResult = Tbsip_Submit_Command(
            tbsHContext,
            0,
            200,
            (PCBYTE)&abCommand,
            cbCommand,
            (PBYTE)&abCommand,
            &pcbResult
        );

        if ((tpmCommandResult != 0) || (int)(((abCommand.uStack_240 << 16) & 0xFFFF) | (abCommand._6_2_ & 0xFFFF)) != 0)
            goto
                StSecpSealKey_cleanup_and_return;
        /* Calculate location and size of sealed blob in the response */
        contextCreateResult = (abCommand.uStack_23c >> 0x18) + 2 + (abCommand.uStack_23c >> 0x10 & 0xff) * 0x100;
        UnsealedKeySize =
            (uint)*(byte*)((longlong)&abCommand + (ulonglong)(contextCreateResult + 0xe)) * 0x100 + 2 +
            (uint)*(byte*)((longlong)&abCommand + (ulonglong)(contextCreateResult + 0xf)) + contextCreateResult;
        if ((OutSealedKey != NULL) && (UnsealedKeySize <= *OutsealedKeySize))
        {
            /* Copy sealed blob to output buffer if size permits */
            unsealedKeySize = (ulonglong)UnsealedKeySize;
            masterKey = (void*)((longlong)&abCommand.uStack_23c + 2);
            goto StSecpSealKey_set_sealedKey;
        }
    }
    else if ((OutSealedKey != NULL) && (UnsealedKeySize <= *OutsealedKeySize))
    {
    StSecpSealKey_set_sealedKey:
        memcpy(OutSealedKey, masterKey, unsealedKeySize);
    }
    *OutsealedKeySize = UnsealedKeySize;
StSecpSealKey_cleanup_and_return:
    if (tbsHContext != NULL)
    {
        Tbsip_Context_Close(tbsHContext);
    }
    return return_status;
}


/* This function checks if a special registry key is set that would allow the driver to bypass the
 * normal cryptographic protection of the master key */
BOOLEAN
StSecpSealKeyTestHookSet(
    VOID)
{
    NTSTATUS status;
    //PVOID rtlQueryRegistryValuesExRoutinePtr;
    NTSTATUS (*rtlQueryRegistryValuesExRoutinePtr)(int, short*, RTL_QUERY_REGISTRY_TABLE*, int, int);
    UNICODE_STRING rtlQueryRegistryValuesExRoutineName = {0, 0, NULL};
    RTL_QUERY_REGISTRY_TABLE queryTable = {
        NULL,
        0x120,
        L"SkipSealKey",
        &g_SkipSealKey,
        0x4000000,
        NULL,
        4
    };

    RtlInitUnicodeString(&rtlQueryRegistryValuesExRoutineName, L"RtlQueryRegistryValuesEx");

    rtlQueryRegistryValuesExRoutinePtr = MmGetSystemRoutineAddress(&rtlQueryRegistryValuesExRoutineName);

    if (rtlQueryRegistryValuesExRoutinePtr == NULL)
    {
        // rtlQueryRegistryValuesExRoutinePtr = RtlQueryRegistryValues_exref;
        rtlQueryRegistryValuesExRoutinePtr = RtlQueryRegistryValues;
    }

    status = rtlQueryRegistryValuesExRoutinePtr(
        0,
        L"\\REGISTRY\\MACHINE\\Software\\Microsoft\\StorageSec\\Encrypt",
        &queryTable,
        0,
        0
    );

    if (status < 0)
    {
        g_SkipSealKey = 0;
    }

    return g_SkipSealKey != 0;
}

/* This function is responsible for "unsealing" (decrypting) the master key that was previously
 * protected using the Trusted Platform Module's (TPM) capabilities. */
NTSTATUS StSecpUnsealKey(
    PUCHAR SealedKeyBlob,
    ULONG SealedKeyBlobSize,
    PUCHAR OutUnsealedKey,
    PULONG OutUnsealedKeySize
)

{
    BOOLEAN skipSealKey;
    TBS_RESULT contextCreateResult;
    TBS_RESULT tpmCommandResult;
    NTSTATUS return_status;
    //undefined7 extraout_var;
    UINT32 cbCommand;
    undefined auStackY_2d8[32];
    UINT32 local_298;
    undefined4 local_290;
    undefined4 uStack_28c;
    undefined2 uStack_288;
    undefined2 uStack_286;
    undefined2 uStack_284;
    undefined2 uStack_282;
    undefined2 uStack_280;
    undefined4 uStack_27e;
    undefined2 uStack_27a;
    undefined2 uStack_278;
    TBS_HCONTEXT tbsHContext;
    TBS_CONTEXT_PARAMS2 contextParams2;
    BYTE abCommand;
    undefined uStack_254;
    undefined uStack_253;
    undefined2 uStack_252;
    undefined2 uStack_250;
    undefined2 uStack_24e;
    undefined2 uStack_24c;
    byte bStack_24a;
    byte bStack_249;
    undefined2 uStack_248;
    undefined4 uStack_246;
    undefined2 uStack_242;
    undefined2 uStack_240;
    undefined local_23e;
    undefined sealedKeyBlob[485];
    ulonglong sec_cookie_xor;

    local_290 = 0x280;
    uStack_28c = 0x1b00;
    uStack_288 = 0x5e01;
    uStack_282 = 0;
    uStack_280 = 0x900;
    uStack_27e = 0x9000040;
    uStack_27a = 0;
    uStack_278 = 1;
    /* Becuase version = 2 the type must be tdTBS_CONTEXT_PARAMS*2* */
    contextParams2.version = 2;
    contextParams2.asUINT32 = 4;
    tbsHContext = NULL;
    memset(&abCommand, 0, 0x200);
    local_298 = 0x200;
    cbCommand = SealedKeyBlobSize + 0x1b;
    skipSealKey = StSecpSealKeyTestHookSet();
    if ((int)skipSealKey == 0)
    {
        if ((0x1e5 < SealedKeyBlobSize) ||
            (contextCreateResult = Tbsi_Context_Create(&contextParams2, &tbsHContext), contextCreateResult != 0))
            goto StSecpUnsealKey_cleanup_and_return;
        /* Setup TPM unseal command */
        uStack_252 = 0;
        uStack_250 = 0x5701;
        //abCommand = CONCAT13((char)(cbCommand >> 0x10), CONCAT12((char)(cbCommand >> 0x18), 0x280));
        abCommand = (0x280 & 0xFF) | ((0x280 & 0xFF00) << 8) | ((cbCommand & 0xFF000000) >> 8) | ((cbCommand &
            0x00FF0000) << 8);
        uStack_254 = (undefined)(cbCommand >> 8);
        uStack_24e = 0x81;
        uStack_24c = 0x100;
        bStack_24a = 0;
        bStack_249 = 0;
        uStack_248 = 0x900;
        uStack_246 = 0x9000040;
        uStack_242 = 0;
        uStack_240 = 1;
        local_23e = 0;
        uStack_253 = (undefined)cbCommand;
        memcpy(sealedKeyBlob, SealedKeyBlob, (ulonglong)SealedKeyBlobSize);
        /* Submits the command to the TPM for processing */
        tpmCommandResult = Tbsip_Submit_Command(tbsHContext, 0, 200, &abCommand, cbCommand, &abCommand, &local_298);
        if ((tpmCommandResult != 0) || ((((UINT32)uStack_252 << 16) | (UINT32)uStack_250)) != 0)
            goto
                StSecpUnsealKey_cleanup_and_return;
        /* Setup second TPM command */
        uStack_286 = uStack_24e;
        uStack_284 = uStack_24c;
        uStack_240 = uStack_278;
        local_298 = 0x200;
        abCommand = local_290;
        uStack_254 = (undefined)uStack_28c;
        uStack_253 = (undefined)((uint)uStack_28c >> 8);
        uStack_252 = (undefined2)((uint)uStack_28c >> 0x10);
        uStack_250 = uStack_288;
        bStack_24a = (byte)uStack_282;
        bStack_249 = (byte)((ushort)uStack_282 >> 8);
        uStack_248 = uStack_280;
        uStack_246 = uStack_27e;
        uStack_242 = uStack_27a;
        local_23e = 0;
        /* Submit second TPM command */
        tpmCommandResult = Tbsip_Submit_Command(tbsHContext, 0, 200, &abCommand, 0x1b, &abCommand, &local_298);
        if (tpmCommandResult != 0) goto StSecpUnsealKey_cleanup_and_return;
        /* Extract unsealed key size and data */
        SealedKeyBlobSize = (uint)bStack_24a * 0x100 + (uint)bStack_249;
        if ((OutUnsealedKey != NULL) && (SealedKeyBlobSize <= *OutUnsealedKeySize))
        {
            /* Copy unsealed key to output buffer if size permits */
            memcpy(OutUnsealedKey, &uStack_248, (ulonglong)SealedKeyBlobSize);
        }
    }
    else if ((OutUnsealedKey != NULL) && (SealedKeyBlobSize <= *OutUnsealedKeySize))
    {
        /* skipSealKey == true then return the unsealed key */
        memcpy(OutUnsealedKey, SealedKeyBlob, (ulonglong)SealedKeyBlobSize);
    }
    *OutUnsealedKeySize = SealedKeyBlobSize;
StSecpUnsealKey_cleanup_and_return:
    if (tbsHContext != NULL)
    {
        Tbsip_Context_Close(tbsHContext);
    }

    return return_status;
}


NTSTATUS StSecpWriteSealedKeyBlob(
    PVOID SealedKeyBlob,
    ULONG KeyBlobSize
)
{
    NTSTATUS return_status;
    HANDLE* masterKeyHandle = NULL;
    UNICODE_STRING mkValueName = {0, 0, NULL};

    return_status = StSecpOpenMasterKeyHandle(&masterKeyHandle);

    if (-1 < return_status)
    {
        RtlInitUnicodeString(&mkValueName, L"MK");

        return_status = ZwSetValueKey(
            masterKeyHandle,
            &mkValueName,
            0,
            3,
            SealedKeyBlob,
            KeyBlobSize
        );

        if (-1 < return_status)
        {
            return_status = ZwFlushKey(masterKeyHandle);
        }
    }
    if (masterKeyHandle != NULL)
    {
        ZwClose(masterKeyHandle);
    }

    return return_status;
}
