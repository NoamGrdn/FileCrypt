/*++

Module Name:

    m.h - Memory helper functions

--*/

#ifndef __FC_M_H__
#define __FC_M_H__

#include <ntdef.h>

int
__cdecl
mbtowc (
    wchar_t *DestinationChar,
    char *SourceChar,
    size_t MaxSourceBytes
    );

void*
__cdecl
memcpy (
    void *Destination,
    void *Source,
    size_t ByteCount
    );

void*
__cdecl
memset (
    void *Destination,
    int ValueToSet,
    size_t NumberOfBytes
    );

#endif /* __FC_M_H__ */