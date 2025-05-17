/*++

Module Name:

    rtlString.h - String helper functions

--*/

#ifndef __FC_RTL_STRING_H__
#define __FC_RTL_STRING_H__

#include <ntdef.h>
#include "fc.h"


wchar_t
RtlAnsiCharToUnicodeChar(
    int* ptr
);

NTSTATUS
RtlStringCbCatNW(
    PWCHAR Destination,
    SIZE_T DestinationSizeInBytes,
    PWCHAR Source,
    SIZE_T MaxCharactersToCopy
);

NTSTATUS
RtlStringCbCatW(
    PWCHAR Destination,
    SIZE_T DestinationSizeInBytes,
    PWCHAR Source
);

NTSTATUS
RtlStringCbCopyNW(
    PWCHAR Destination,
    SIZE_T DestinationSize,
    PWCHAR Source,
    SIZE_T MaxCharactersToCopy
);

NTSTATUS
RtlStringCbCopyW(
    PWCHAR Destination,
    SIZE_T DestinationSize,
    PWCHAR Source
);

NTSTATUS
RtlStringCbLengthW(
    PCWCHAR StringToCount,
    undefined8 unsued,
    long long* ResultLength
);

NTSTATUS
RtlStringCbPrintfW(
    PWCHAR Destination,
    SIZE_T DestinationSizeInBytes,
    PWCHAR PrintfFormat,
    va_list FormattingArgs
);

NTSTATUS
RtlStringCchCopyW(
    PWCHAR Destination,
    SIZE_T DestinationSizeInChars,
    PCWCHAR Source
);

NTSTATUS
RtlStringCopyWorkerW(
    PWCHAR Destination,
    SIZE_T DestinationSize,
    undefined8 unused,
    PWCHAR Source,
    SIZE_T MaxCharactersToCopy
);

NTSTATUS
RtlStringLengthWorkerW(
    PWCHAR StringToCount,
    SIZE_T MaxCharactersToCheck,
    long long* ResultLength
);

#endif /* __FC_RTL_STRING_H__ */
