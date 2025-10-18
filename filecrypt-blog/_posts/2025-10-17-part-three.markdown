---
layout: post
title:  "Part 3 - IRP_MJ_CREATE"
author: Ron Gladish, Noam Gordon, Eran Yeruhamie
date:   2025-10-17 15:40:08 +0300
tags: [reverse-engineering, windows, drivers, security, encryption, filecrypt, encryption-driver, minifilter, minifilter-drivers, encryption-drivers, windows-security, FsRtlIsMobileOS, IRP_MJ_CREATE, pre-create, post-create, windows-security-descriptors, chambers, SID]
---

[← Go back to part 2][part-two-link]

[Go to the FCPreCreate callback](#fcprecreate)

[Go to the FCPostCreate callback](#fcpostcreate)

Every kernel-mode driver must handle `IRP_MJ_CREATE` requests in a `DRIVER_DISPATCH` callback function. This is why the callback must be registered on both mobile and non-mobile systems. This callback is triggered by different user operations that can all be equated to:
- Creating a file (or directory)
- Opening a file (or directory)
Although registered on both, the functionality of this callback differs significantly depending on whether it is running on a mobile or a non-mobile system.

When `FltMgr` receives the I/O operation, it calls the minifilter _preoperation_ callback routines in the order of driver’s [altitude][altitudes-for-minifilter-drivers] from highest to lowest. `FltMgr` then forwards the I/O request to the next-lower driver for further processing.
When `FltMgr` receives the I/O request for _completion_, it calls each minifilter driver's _postoperation_ callback routines in reverse order, from lowest to highest altitude.

# FCPreCreate

In our PreCreate routine, the driver first retrieves the volume context that it had set up earlier during the instance setup. If this fails, the callback returns `FLT_PREOP_COMPLETE`. In this case, the filter manager won't send the I/O operation to any minifilter driver below the caller in the driver stack, or to the file system. The filter manager only calls the post-operation callback routines of the minifilter drivers above the caller in the driver stack.
The next step the driver takes is to retrieve and parse the file’s name, after which we have the `fullPathBuffer` and fileNameLength variables. At this point, we are introduced to the concept of _**chambers**_:

[`FcPreCreate`][fc-pre-create-code]

```c
UNICODE_STRING chamberPath = {0, 0, NULL};
CUSTOM_FC_CHAMBER_DATA chamberData;

...

chamberPath.Length = fileNameLength - 2;
chamberPath.MaximumLength = fileNameLength;
chamberPath.Buffer = fullPathBuffer;

...

chamberData.ChamberId = NULL;
chamberData.ChamberType = 0;
chamberData.InputPath = &chamberPath;
chamberData.SecurityDescriptor = NULL;
```

The majority of the code going forward will reference this term and concept; therefore, for now, a brief explanation of what chambers are: Chambers are essentially groupings of files based on their location, purpose, or security requirements. Each chamber has its own unique encryption keys, derived from a _master key_. This provides cryptographic isolation between different types of content. As we will soon see, a chamber can be a folder, a specific Windows App, or anything else. In the code above, we see that initially, the chamber’s path is set to the file we just accessed. After initializing the path of the chamber, the driver retrieves the type of the chamber and its security descriptor for access checks. The _chamber type_ determines the encryption key that will be used for encrypting and decrypting the specific chamber. This all is accomplished in two ways, whereas the other, being the fallback to the first:

[`FcPreCreate`][fc-pre-create-code]

```c
UNICODE_STRING chamberPath = {0, 0, NULL};
CUSTOM_FC_CHAMBER_DATA chamberData;
PWCHAR chamberIdStr = NULL;
UNICODE_STRING chamberPath = {0, 0, NULL};
PFLT_FILE_NAME_INFORMATION fileNameInfo = NULL;
PNPAGED_LOOKASIDE_LIST securityDescriptor = NULL;
ACCESS_MASK accessMask = 0;

...

kernelStackStatus = KeExpandKernelStackAndCalloutEx(
   FCpObtainSecurityInfoCallout,
   &chamberData,
   0x3000,
   0,
   0
);

if (kernelStackStatus < 0)
{
...
    chamberData.Status = StSecGetSecurityDescriptor(
        &chamberPath,
        securityDescriptor,
        &chamberIdStr,
        &accessMask
    );
}
/* Do mostly the same thing FCpObtainSecurityInfoCallout does, but inline right here*/
...
```

In the preferable way, the driver calls `FCpObtainSecurityInfoCallout` via `KeExpandKernelStackAndCalloutEx`. The `KeExpandKernelStackAndCalloutEx` routine is a safety mechanism designed to overcome the fundamental limitations of fixed-size kernel stacks. This routine provides guaranteed stack space for kernel operations that might otherwise trigger a stack overflow. The driver first attempts to call `FCpObtainSecurityInfoCallout` (which internally calls <span class="mark">`StSecGetSecurityDescriptor`</span>) with an expanded stack to ensure there is sufficient space for the complex security descriptor processing that occurs in <span class="mark">`StSecGetSecurityDescriptor`</span>. If stack expansion fails, the driver falls back to calling <span class="mark">`StSecGetSecurityDescriptor`</span> directly with the current (limited) stack. <span class="mark">`StSecGetSecurityDescriptor`</span> is where we begin to go into the security mechanisms of the driver.

If the stack expansion doesn't fail, `FCpObtainSecurityInfoCallout` is called with the safety of an expanded kernel stack. It takes a file path and determines which encryption chamber it belongs to, as well as the security policies that should govern access to it.

`FCpObtainSecurityInfoCallout` immediately delegates the heavy lifting to <span class="mark">`StSecGetSecurityDescriptor`</span>.

[`FCpObtainSecurityInfoCallout`][fcp-obtain-security-info-callout-code]

```c
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

   ChamberData->ChamberId = NULL;

   if (chamberPath->Length == 0)
   {
       ChamberData->Status = 0;

       return;
   }

   chamberId = &ChamberData->ChamberId;
   status = StSecGetSecurityDescriptor(chamberPath, securityDescriptor,  chamberId, &ChamberData->ChamberType);
...
```

This is where FileCrypt's path-to-chamber mapping occurs. <span class="mark">`StSecGetSecurityDescriptor`</span> searches through cached security descriptor policies that were loaded from the registry during driver initialization. It looks for patterns that match the current file path.

Before we continue, a short explanation of Windows Security Descriptors:
Windows Security Descriptors form the foundation of access control throughout the Windows operating system. They are binary data structures that define who can access objects and what actions they can perform on them. Security Descriptors contain four core components (Owner SID, Group SID, DACL, and SACL) that work together to provide access control and auditing capabilities. Security Descriptors work with any securable Windows object, including files and directories (NTFS only), registry keys, processes and threads, mutexes, and other synchronization objects, as well as Active Directory objects.

<span class="mark">`StSecGetSecurityDescriptor`</span> is the entry point to complex security logic, it calls numerous functions that extend several levels deep. Before getting into its code, here is a quick summary of what we are about to see:

It first calls `StSecpGetStorageFolderStringSecurityDescriptor` to get a string-format security descriptor that matches the input path. `StSecpGetStorageFolderStringSecurityDescriptor`:
- Searches through a cached list of security descriptor policies (One of the caches set up by `StSecInitialize`, which `DriverEntry` called)
- Finds a policy element whose path pattern matches the input path
- Processes any parameter substitutions in the security descriptor template (like `<PackageFamilyName>`)
- Returns a fully resolved security descriptor string

<span class="mark">`StSecGetSecurityDescriptor`</span> then converts the security descriptor string to binary by calling the `SeConvertStringSecurityDescriptorToSecurityDescriptor` function.

It then calls `StSecpFindFolderPropertyPolicyElement`, which searches through another cache (folder property cache) to find additional metadata for the path:
- Returns a policy element containing ChamberId and FolderId
- Uses path pattern matching similar to the security descriptor lookup

After this, <span class="mark">`StSecGetSecurityDescriptor`</span> handles two types of chamber IDs:

1. Static Chamber IDs: Direct string values that are simply copied to the output
2. Parameterized Chamber IDs: Enclosed in `<>` brackets, these require resolution:
   - `<PackageFamilyName>` or `<ProductId>`: Uses the path component directly
   - `<PackageFullName>`: Calls `StSecpPackageFamilyNameFromFullName` to extract the family name

And at the end, `StSecpPackageFamilyNameFromFullName` is called to parse Windows Store app package names:

- Full name format: `PublisherName.AppName_Version_Architecture_ResourceID_PublisherID`
- Extracts: `PublisherName.AppName_PublisherID` (the family name)

So that was a mouthful. Let's see this mess play out in the code:

[`StSecGetSecurityDescriptor`][st-sec-get-security-descriptor-code]

```c
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
   PCUSTOM_FC_STSEC_FOLDER_PROP_CACHE_LIST_ENTRY policyElement;
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

   return_status = StSecpGetStorageFolderStringSecurityDescriptor(InputPath, &securityDescString);
...
```
`StSecpGetStorageFolderStringSecurityDescriptor` transforms template security descriptors into fully resolved, ready-to-use security descriptor strings by performing parameter substitution.

```c
NTSTATUS
StSecpGetStorageFolderStringSecurityDescriptor(
   PCUNICODE_STRING FolderPath,
   PWCHAR* OutStringSecurityDescriptor
)
```

Callstack overview:

![StSecGetSecurityDescriptor call stack]({{ '/assets/images/st-sec-get-security-descriptor-callstack.png' | relative_url }})

The function implements a template-based security descriptor system where Security policies are stored in the registry with parameter placeholders. Those parameters are resolved based on the actual file path being accessed, and the final SDDL string is constructed with all parameters substituted. `StSecpFindSecurityDescriptorPolicyElement` searches the cached security descriptor policies (loaded from the [registry][registrymachinesystemcontrolset001controlstsecsecuritydescriptors]) to find a matching entry. The cache contains entries of type [`CUSTOM_FC_STSEC_SEC_DESC_CACHE_LIST_ENTRY`][custom_fc_stsec_sec_desc_cache_list_entry]:

- `Path`: Registry path pattern (may contain parameters like `<PackageFamilyName>`)
- `SecurityDescriptor`: SDDL  template string
- `DebugValue`: Additional security descriptor for debug profiles

Then <span class="mark">`StSecGetSecurityDescriptor`</span> walks through the input paths segment by segment to find if there is a parameter in the path, for example: `C:\Users\<User>\AppData`. If a parameterized variable is found, it handles different parameter types through `StSecpGetParameterValue`:

[`StSecpGetStorageFolderStringSecurityDescriptor`][st-secp-get-storage-folder-string-security-descriptor-code]

```c
if (*parameterName.Buffer == L'<' &&
   parameterName.Buffer[(ulonglong)(parameterName.Length >> 1) - 1] == L'>')
{
   if (sid.Buffer == NULL || parameterCount == 2)
   {
       return_status = STATUS_UNSUCCESSFUL;
       goto StSecpGetStorageFolderStringSecurityDescriptor_cleanup_and_return;
   }


   return_status = StSecpGetParameterValue(
       &parameterName,
       &sid,
       (PWCHAR*)(&parameters + maxStringLength)
   );
...
```

`StSecpGetParameterValue` converts the extracted value based on the parameter type:
- `<User>`: Converts username to SID
- `<PackageFamilyName>`: Converts to app-specific SID
- `<PackageFullName>`: Extracts family name, then converts to SID
- `<ProductId>`: Converts Product identifier to SID

A [Windows Security Identifier][security-identifiers] (SID) is a unique digital "fingerprint" that Windows uses to identify and distinguish different security principals in the system. Examples include a user account, a computer account, or a thread or process that runs in the security context of a user or computer account. A SID is a variable-length binary value that gets represented as a readable string when you see it displayed. The string format looks like this:
`S-1-5-21-1234567890-987654321-1122334455-1001`.

The driver is particularly focused on app container SIDs, which Windows uses for sandboxed applications, such as those from the Microsoft Store. At this point, we should take a step back and explain the `PackageFamilyName`, `ProductId`, and `PackageFullName` business. Let us review the Windows App naming hierarchy and what each of those identifiers represents:

**`PackageFullName`** is the most complete identifier for a Windows App installation. It contains all the information needed to uniquely identify a specific version and variant of an app. The format follows this pattern:

`PublisherName.AppName_Version_Architecture_ResourceID_PublisherID`

For example:

`Microsoft.Office.Word_16.0.14228.20216_x64_en-us_8wekyb3d8bbwe`

This full name is crucial because it identifies the exact installation - the specific version, architecture, and language variant of an app installed on the system.

The **`PackageFamilyName`** is a simplified identifier that groups all versions and variants of an app. It follows this format:

`PublisherName.AppName_PublisherID`

Using our example above, the family name would be:

`Microsoft.Office.Word_8wekyb3d8bbwe`

This identifier is essential because different app versions don’t change it, and it's architecture-independent.

The **`ProductId`** is a more abstract identifier that can take multiple forms:
- Traditional GUID format: `{CF8E2E00-F4B3-11E3-AC10-0800200C9A66}`
- Microsoft Store ID: `9WZDNCRFJ364` (typically 12 characters)

As we saw previously, the driver uses a concept called "chambers" - isolated encryption contexts that segregate data. Each Windows app can have its own encryption chamber. This chamber system ensures that each app’s data is encrypted with unique keys, and apps cannot access each other's encrypted data even if they become aware of their own encryption keys.

Security descriptors in the registry? Parameterized registry paths? Why though?

In typical desktop environments, this allows system administrators (and potentially regular users) to define security policies with placeholders that are filled in at runtime. A couple of scenarios that demonstrate the usage of such a system:

<u>1. User-Centric Policies</u>

Parameter: `<User>`<br/>
Value: JohnDoe

→ Encrypt all files for a specific user, regardless of which app they use

With a `<User>` parameter,  the system admin can create user-specific encryption chambers. This can be used for machines that are shared between different users, where you want to protect a user's data regardless of which app created it.

<u>2. App Family Policies</u>

Parameter: `<PackageFamilyName>`<br/>
Value: Microsoft.Office.Word_8wekyb3d8bbwe

→ Encrypt all Word documents, regardless of Word's version

This is the most common scenario. When Word gets updated from version 16.0 to 16.1, the `PackageFamilyName` stays the same, so encrypted documents remain accessible after the update.

<u>3. Version-Specific Policies</u>

Parameter: `<PackageFullName>`<br/>
Value: Microsoft.Office.Word_16.0.14228.20216_x64_en-us_8wekyb3d8bbwe

→ Apply special encryption only to a specific version 

Sometimes, you need policies that target a specific version of an app, perhaps due to a potential security concern related to a particular app version. The `PackageFullName` includes version information, allowing for exact app targeting.

<u>4. Store-Based Policies</u>

Parameter: `<ProductId>`<br/>
Value: 9WZDNCRFJ364

→ Apply policies based on Microsoft Store product IDs

This allows policies to be defined using the same IDs that appear in the Microsoft Store, making it easier for administrators who work with store deployments.

<br/>

To recap up utill to this point:
When a file operation occurs, <span class="mark">`StSecGetSecurityDescriptor`</span> analyzes the file path against stored policy templates. For example, if an app tries to access:
`\Documents\Microsoft.Office.Word_8wekyb3d8bbwe\PrivateData\report.docx`
And there's a policy template:
`\Documents\<PackageFamilyName>\PrivateData`, The function recognizes that `Microsoft.Office.Word_8wekyb3d8bbwe` matches the position of `<PackageFamilyName>`. 
The driver then calls `StSecpGetParameterValue` with:

Parameter: `<PackageFamilyName>`<br/>
Value: `Microsoft.Office.Word_8wekyb3d8bbwe`

Based on the parameter type, `StSecpGetParameterValue` calls the appropriate SID resolver.

When the dust settles, we are back to `FCpObtainSecurityInfoCallout`:

[`FCpObtainSecurityInfoCallout`][fcp-obtain-security-info-callout-code]

```c
status = StSecGetSecurityDescriptor(chamberPath, securityDescriptor, chamberId, &ChamberData->ChamberType);

if (securityDescriptor == NULL && chamberId != NULL)
{
   ExFreePoolWithTag(chamberId, POOL_TAG_STsp);
}

if (status < 0)
{
  ...error...
}

if (ChamberData->ChamberId != NULL)
{
   goto FCpObtainSecurityInfoCallout_return;
}
```

But we are not done yet, as you can see, the driver takes into account the possibility of the ChamberId not being resolved after the <span class="mark">`StSecGetSecurityDescriptor`</span>, and it then resolves to some known values:

[`StSecGetSecurityDescriptor`][st-sec-get-security-descriptor-code]

```c
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
```

If we fail to find a specific chamber, we first check if the `EncryptAll` flag is set; if it is, a hardcoded GUID is assigned as the `ChamberId`. If the `EncryptAll` flag isn’t set, we check if the `EncryptMedia` flag is set. If it is, we compare the path being read to determine if it is indeed one of the known Windows media folders: `Pictures`, `Videos`, or `Music`. Note that in this case, the `ChamberType` is always assigned a value of `1`. This is important when we get to the chamber’s encryption key derivation process in the post-operation.

How did we get here again? 

Right, we were opening a file or something, back to `FCPreCreate`:

[`FcPreCreate`][fc-pre-create-code]

```c
kernelStackStatus = KeExpandKernelStackAndCalloutEx(
   FCpObtainSecurityInfoCallout,
   &chamberData,
   0x3000,
   0,
   0
);


if (kernelStackStatus < 0)
{
   ...
}
else
{
   securityDescriptor = chamberData.SecurityDescriptor;
   chamberIdStr = chamberData.ChamberId;
   accessMask = chamberData.ChamberType;
   chamberId = chamberData.ChamberId;
}
```

As stated previously, if the stack expansion fails, the same operations from `FCpObtainSecurityInfoCallout` occur inline in `FCPreCreate`.

Next up, the driver uses the security descriptor it now has to check for valid permissions for the current operation. But before we go about doing pesky access checks, we refer to the flag we set earlier in the instance setup:

[`FcPreCreate`][fc-pre-create-code]

```c
chamberData.Status = STATUS_SUCCESS;
if (volumeContext->VerificationNeeded == FALSE)
{
FCPreCreate_access_not_modified:
   isAccessModified = FALSE;
}
else
{
  ...
  /* Access check :( */
  chamberData.Status = FCpAccessCheck(Data, securityDescriptor, &accessMask);

}
```

`FCpAccessCheck` isn’t too exciting; it wraps a call to `SeAccessCheck` and ensures we have the current access (`ACCESS_MASK`) for the current operation. What is important to note is that the call to `SeAccessCheck` can be bypassed entirely when setting the `BypassAccessChecksFlagBit` flag:

[FCpAccessCheck][fcp-access-check]

```c
...
NTSTATUS return_status = STATUS_SUCCESS;
...

if ((gFCFlags & BypassAccessChecksFlagBit) == 0)
{
   isAllowed = SeAccessCheck(
       ...
   );
}

...

return return_status;
```

If `FCpAccessCheck` succeeds with a positive status, we continue:

[`FcPreCreate`][fc-pre-create-code]

```c
/* Access check :( */
chamberData.Status = FCpAccessCheck(Data, securityDescriptor, &accessMask);

if (-1 < chamberData.Status)
{
   goto FCPreCreate_access_not_modified;
}
```

If not, instead of just aborting the operation, the driver tries to change the original create options and retry the access check:

[`FcPreCreate`][fc-pre-create-code]

```c
if (chamberData.Status == STATUS_ACCESS_DENIED)
{
   fileCreateOptions = (Data->Iopb->Parameters).Create.Options;
   fileCreateDisposition = fileCreateOptions >> 0x18;
   callbackData = fileCreateDisposition;

   /* Checks if the create disposition is not FILE_OPEN_IF or FILE_OVERWRITE_IF */
   if ((fileCreateDisposition - 3 & 0xfffffffd) != 0)
   {
/* Checks if we are creating a file that is not a directory file */
       if (
           fileCreateDisposition == FILE_CREATE &&
           (fileCreateOptions & FILE_DIRECTORY_FILE) != 0
       )
       {
           chamberData.Status = STATUS_OBJECT_NAME_COLLISION;
           goto FCPreCreate_return_no_post_op;
       }
       goto FCPreCreate_access_not_modified_2;
   }

   newCreateDisposition = FILE_OVERWRITE;

   if (fileCreateDisposition != FILE_OVERWRITE_IF)
   {
       newCreateDisposition = FILE_OPEN;
   }

   /* Rebuild the create options:
    * Keep the original create/open flags and change the disposition */
   (Data->Iopb->Parameters).Create.Options =
       newCreateDisposition << 0x18 | fileCreateOptions & 0xffffff;

   /* Try access check again with modified disposition */
   chamberData.Status = FCpAccessCheck(Data, securityDescriptor, &accessMask);

   if (chamberData.Status != 0)
   {
       goto FCPreCreate_access_not_modified_2;
   }

   isAccessModified = '\x01';

   FltSetCallbackDataDirty(Data);
}
```

The driver tries its luck with a new create disposition of `FILE_OVERWRITE` or `FILE_OPEN` to make the operation work. If the second access check fails, the entire operation stops, and the post-operation won’t be called.

Next, if we were granted access, the driver would call the dreaded `FsRtlIsMobileOS` once again, one last fateful time:

[`FcPreCreate`][fc-pre-create-code]

```c
isMobile = FsRtlIsMobileOS();
if (isMobile == '\0')
{
    if (chamberData.ChamberType - 1 < 2)
    { 
        (((Data->Iopb->Parameters).Create.SecurityContext)->AccessState->Flags) =
        (((Data->Iopb->Parameters).Create.SecurityContext)->AccessState->Flags) |
               SPECIAL_ENCRYPTED_OPEN;
    }
    if (chamberId != NULL)
    { 
        /* Free chamber ID and return without completion context */
        goto FCPreCreate_cleanup;
    }
}
else if (chamberId != NULL)
{
    /* For mobile OS, create a completion context to pass to post-operation */

    lookasideListEntry = ExAllocateFromNPagedLookasideList(&gPre2PostCreateContextList);

    if (lookasideListEntry == NULL)
    {
        chamberData.Status = STATUS_BAD_INITIAL_STACK;
           
        return_status = FLT_PREOP_SUCCESS_WITH_CALLBACK;
        goto FCPreCreate_cleanup;
    }
    lookasideListEntry->ChamberId = chamberId;
    lookasideListEntry->ChamberType = chamberData.ChamberType;
    lookasideListEntry->IsAccessModified = isAccessModified;
}
*CompletionContext = lookasideListEntry;
goto FCPreCreate_cleanup;
```

If we are on a desktop machine, this is where our journey comes to an end, without any encryption or glory.

_“The grey rain-curtain of this world rolls back, and all turns to silver glass.”_

On the other hand, on a mobile machine, this is where the fun begins: We set up the completion context with our acquired chamber information.


# FCPostCreate

We are now at the IRP_MJ_CREATE post-operation, and without a doubt, on a mobile operating system. After performing some sanity checks, the driver calls `FltIsDirectory` to ensure that the file object is not a directory; if it is, the process does not proceed, and no encryption will occur.

The driver retrieves the volume context ([`CUSTOM_FC_VOLUME_CONTEXT`][custom_fc_volume_context]) and allocates a new stream context ([`CUSTOM_FC_STREAM_CONTEXT`][custom_fc_stream_context]), which will hold the chamber’s encryption key data ([`CUSTOM_FC_BCRYPT_KEY_DATA`][custom_fc_bcrypt_key_data]). After initializing the data of the stream context with default values, the driver calls `FCpEncStreamStart` to start the key acquisition process:	

[`FCPostCreate`][fc-post-create-code]

```c
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
       streamContext->KeyData.BcryptKeyHandle = NULL;
       streamContext->KeyData.KeyObject = NULL;
       streamContext->KeyData.KeyObjectSize = 0;
       streamContext->ChamberType = 0;

       streamContext->ChamberId = chamberId;
       streamContext->ChamberType = chamberType;
       chamberId = NULL;

       status = FCpEncStreamStart(
           &volumeContext->BcryptAlgHandle,
           streamContext->ChamberId,
           chamberType,
           &streamContext->KeyData
       );
...
```

The next sequence of events is the following:

![FcPostCreate call stack]({{ '/assets/images/fc-post-create-callstack.png' | relative_url }})

The driver will first attempt to call `StSecpGetChamberProfileKey` (the top green box on the left) to check if the chamber’s key already exists in its in-memory cache. If it exists, it generates a symmetric key and returns it via an output parameter, which will be assigned to the stream context. If it does not exist in the cache, the driver will call `StSecpDeriveChamberProfileKey` (the bottom green box on the left), which will go all the way down to the TPM to construct the chamber’s key.

Let’s get into it.

As stated, first try a cache lookup via `StSecpGetChamberProfileKey`:

[`FCpEncStreamStart`][fcp-Enc-stream-start-code]

```c
NTSTATUS
FCpEncStreamStart(
   PCUSTOM_FC_BCRYPT_DATA HAlgorithm,
   PWCHAR ChamberId,
   ULONG ChamberType,
   PCUSTOM_FC_BCRYPT_KEY_DATA OutKeyReceiver
)
{
...
chamberProfileKey = ExAllocatePool2(0x40, HAlgorithm->SecretKeySize, POOL_TAG_FCCr);

...
profileKeySize = HAlgorithm->SecretKeySize;
...

return_status = StSecpGetChamberProfileKey(ChamberId, ChamberType, chamberProfileKey, profileKeySize);

if (return_status < 0 && return_status == STATUS_OBJECT_NAME_NOT_FOUND)
{
   pbKeyObject = chamberProfileKey;

   return_status = StSecpDeriveChamberProfileKey(
       ChamberId,
       ChamberType,
       chamberProfileKey,
       profileKeySize
   );

   event = ChamberId;
}

...
```

The function takes a chamber identifier and type as input, then derives and outputs a cryptographic key of the specified length. The chamber type determines which of the two derived keys to return - each chamber can have two encryption keys.

```c
NTSTATUS
StSecpDeriveChamberProfileKey(
   PWCHAR ChamberId,
   ULONG ChamberType,
   PUCHAR OutputProfileKey,
   ULONG ProfileKeyLength
)
```

`StSecpDeriveChamberProfileKey` starts by first retrieving the Master Key by calling `StSecpGetMasterKey`:

[`StSecpDeriveChamberProfileKey`][st-secp-derive-chamber-profile-key-code]

```c
NTSTATUS return_status;
ULONG masterKeySize = 0;
PUCHAR masterKey = NULL;

return_status = StSecpGetMasterKey(&masterKey, &masterKeySize);
```

The driver stores an encrypted or sealed version of the master key in the [registry][registrymachinesoftwaremicrosoftsecuritymanagerstoragecardprofileschambers] **as well as an entirely unsealed (decrypted) version in memory in the `g_MasterKey` global variable** - maybe it would have been better to make the font colour red on top of making it bold, but we are not security researchers, so what do we know. The driver reads the sealed key from the registry, unseals it using the [TPM][trusted-platform-module-overview], and saves the raw unencrypted key in memory for subsequent use. We won’t delve into the code; the readable code is straightforward and essentially does what is stated above. The unreadable parts are the `StSecpUnsealKey` and `StSecpSealKey` functions, which contain calls to the TPM using the API from tbs.h. These two functions received the absolute worst end of Ghidra’s decompilation, and we did not bother to sort out the mess that it left aside from identifying the TPM calls and their parameters. One helpful thing to note is that the **TPM calls can be bypassed entirely** by setting a special registry flag, which is expanded upon [here][registrymachinesoftwaremicrosoftsecuritymanagerstoragecardprofileschambers].

Next, in `StSecpDeriveChamberProfileKey` of the Key Derivation Function (KDF), where it takes a secret key (the master key) and transforms it into multiple different keys. The function uses HMAC (Hash-based Message Authentication Code): First, we initialize a HMAC handle.

[`StSecpDeriveChamberProfileKey`][st-secp-derive-chamber-profile-key-code]

```c
BCRYPT_HASH_HANDLE ChamberIdHashHandle = NULL;
...

phMasterKeyHash = &ChamberIdHashHandle;

return_status = BCryptCreateHash(
   g_HmacHashProvider,
   phMasterKeyHash,
   pbMasterKeyHashObject,
   g_cbHashObjectLength,
   masterKey,
   masterKeySize,
   0
);

```

This creates an HMAC context using the master key as the HMAC secret. Next, we hash the chamber Id:

[`StSecpDeriveChamberProfileKey`][st-secp-derive-chamber-profile-key-code]

```c
pbChamberIdInput = ChamberId;
...

return_status = BCryptHashData(ChamberIdHashHandle, pbChamberIdInput, chamberIdLength, 0);
```

Why is this important? Each chamber needs unique encryption keys, but we can't just use the chamber Id directly as a key (that would be insecure). Instead, we're creating a key that's mathematically derived from both the master key (secret) and the chamber Id. Now, because we will be generating two keys, instead of doing the two previous operations again, the driver duplicates the result we have up until this point:

[`StSecpDeriveChamberProfileKey`][st-secp-derive-chamber-profile-key-code]

```c
return_status = BCryptDuplicateHash(
   ChamberIdHashHandle,
   &dupChamberIdHashHandle,
   pbHashObject,
   g_cbHashObjectLength,
   0
);
```

Next, we create the two keys, the “`Install`” and “`Data`” keys:

[`StSecpDeriveChamberProfileKey`][st-secp-derive-chamber-profile-key-code]

```c
return_status = BCryptHashData(ChamberIdHashHandle, L"Install", 0xe, 0);

installKey = ExAllocatePool2(0x40, g_cbHashOutputLength, POOL_TAG_StSn);

return_status = BCryptFinishHash(ChamberIdHashHandle, installKey, g_cbHashOutputLength, 0);

...

return_status = BCryptHashData(dupChamberIdHashHandle, L"Data", 8, 0);

dataKey = ExAllocatePool2(0x40, g_cbHashOutputLength, POOL_TAG_StSn);

return_status = BCryptFinishHash(dupChamberIdHashHandle, dataKey, g_cbHashOutputLength, 0);
```

And of course, this driver never misses a chance to cache whatever it can, so we add both keys to the in-memory cache stored in the `g_StSecCacheGenericTable` ([`CUSTOM_FC_STSEC_CACHE_TABLE_ENTRY`][custom_fc_stsec_cache_table_entry]) global variable:

[`StSecpDeriveChamberProfileKey`][st-secp-derive-chamber-profile-key-code]

```c
return_status = StSecpAddChamberProfileKey(
   ChamberId,
   installKey,
   dataKey,
   ProfileKeyLength
);
```

And finally, the driver selects and returns the key according to the chamber type:

[`StSecpDeriveChamberProfileKey`][st-secp-derive-chamber-profile-key-code]

```c
if (
   chosenOutputKey = installKey, ChamberType == 1 ||
   (chosenOutputKey = dataKey, ChamberType == 2)
)
{
   memcpy(OutputProfileKey, chosenOutputKey, ProfileKeyLength);
}

goto StSecpDeriveChamberProfileKey_return_and_cleanup;
```

After deriving our super-specific chamber key, we are back at `FCpEncStreamStart` at:

[`FCpEncStreamStart`][fcp-Enc-stream-start-code]

```c
NTSTATUS
FCpEncStreamStart(
   PCUSTOM_FC_BCRYPT_DATA HAlgorithm,
   PWCHAR ChamberId,
   ULONG ChamberType,
   PCUSTOM_FC_BCRYPT_KEY_DATA OutKeyReceiver
)
...
return_status = StSecpDeriveChamberProfileKey(
   ChamberId,
   ChamberType,
   chamberProfileKey,
   profileKeySize
);
```

Using the chamber key, we create yet another key. This time, we generate the final symmetric AES key for the driver’s stream context:

[`FCpEncStreamStart`][fcp-Enc-stream-start-code]

```c
return_status = BCryptGenerateSymmetricKey(
   HAlgorithm->BcryptAlgHandle,
   &OutKeyReceiver->BcryptKeyHandle,
   pbKeyObject,
   pbKeyObjectSize,
   chamberProfileKey,
   HAlgorithm->SecretKeySize,
   0
);
```

After successfully generating and deriving about 400 keys, the driver sets the newly created stream context in place by calling `FltSetStreamContext`, which ultimately ends the create operation.

---
<br/>
[→ Continue to Part 4][part-four-link]

[part-two-link]: {% post_url 2025-10-17-part-two %}
[altitudes-for-minifilter-drivers]: https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/load-order-groups-and-altitudes-for-minifilter-drivers
[fc-pre-create-code]: https://github.com/NoamGrdn/FileCrypt/blob/master/FileCrypt%20Reimagined/filecrypt/filter/fc.c#L1483
[fcp-obtain-security-info-callout-code]: https://github.com/NoamGrdn/FileCrypt/blob/master/FileCrypt%20Reimagined/filecrypt/filter/fc.c#L1076
[st-sec-get-security-descriptor-code]: https://github.com/NoamGrdn/FileCrypt/blob/master/FileCrypt%20Reimagined/filecrypt/filter/stsec.c#L129
[registrymachinesystemcontrolset001controlstsecsecuritydescriptors]: https://github.com/NoamGrdn/FileCrypt/blob/master/Technical%20Overview.md#registrymachinesystemcontrolset001controlstsecsecuritydescriptors
[custom_fc_stsec_sec_desc_cache_list_entry]: https://github.com/NoamGrdn/FileCrypt/blob/master/Technical%20Overview.md#custom_fc_stsec_sec_desc_cache_list_entry
[st-secp-get-storage-folder-string-security-descriptor-code]: https://github.com/NoamGrdn/FileCrypt/blob/master/FileCrypt%20Reimagined/filecrypt/filter/stsec.c#L2706
[security-identifiers]: https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers
[fcp-access-check]: https://github.com/NoamGrdn/FileCrypt/blob/master/FileCrypt%20Reimagined/filecrypt/filter/fc.c#L525
[custom_fc_volume_context]: https://github.com/NoamGrdn/FileCrypt/blob/master/Technical%20Overview.md#custom_fc_volume_context
[custom_fc_stream_context]: https://github.com/NoamGrdn/FileCrypt/blob/master/Technical%20Overview.md#custom_fc_stream_context
[custom_fc_bcrypt_key_data]: https://github.com/NoamGrdn/FileCrypt/blob/master/Technical%20Overview.md#custom_fc_bcrypt_key_data
[fc-post-create-code]: https://github.com/NoamGrdn/FileCrypt/blob/master/FileCrypt%20Reimagined/filecrypt/filter/fc.c#L1165
[fcp-Enc-stream-start-code]: https://github.com/NoamGrdn/FileCrypt/blob/master/FileCrypt%20Reimagined/filecrypt/filter/fc.c#L812
[st-secp-derive-chamber-profile-key-code]: https://github.com/NoamGrdn/FileCrypt/blob/master/FileCrypt%20Reimagined/filecrypt/filter/stsec.c#L949
[registrymachinesoftwaremicrosoftsecuritymanagerstoragecardprofileschambers]: https://github.com/NoamGrdn/FileCrypt/blob/master/Technical%20Overview.md#registrymachinesoftwaremicrosoftsecuritymanagerstoragecardprofileschambers
[trusted-platform-module-overview]: https://learn.microsoft.com/en-us/windows/security/hardware-security/tpm/trusted-platform-module-overview
[registrymachinesoftwaremicrosoftsecuritymanagerstoragecardprofileschambers]: https://github.com/NoamGrdn/FileCrypt/blob/master/Technical%20Overview.md#registrymachinesoftwaremicrosoftsecuritymanagerstoragecardprofileschambers
[custom_fc_stsec_cache_table_entry]: https://github.com/NoamGrdn/FileCrypt/blob/master/Technical%20Overview.md#custom_fc_stsec_cache_table_entry
[part-four-link]: {% post_url 2025-10-17-part-four %}