/*++

Module Name:

    kappx.h - Windows App Packages helper functions

--*/

#ifndef __FC_KAPPX_H__
#define __FC_KAPPX_H__

#include <ntdef.h>

NTSTATUS
KappxGetPackageRootPathForPackageFullName(
    PCUNICODE_STRING PackageFullName,
    PWCHAR* PackageRootPath
);

NTSTATUS
KappxGetPackageSidFromPackageFamilyNameInRegistry(
    PCUNICODE_STRING PackageFamilyName,
    PWCHAR* OutSid
);

NTSTATUS
KappxGetSecurityDescriptorStringForPackageFullName(
    PCUNICODE_STRING PackageFullName,
    PWCHAR* SecurityDescriptorString
);

#endif /* __FC_KAPPX_H__ */
