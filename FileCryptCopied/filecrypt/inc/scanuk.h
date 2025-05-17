/*++

Copyright (c) 1999-2002  Microsoft Corporation

Module Name:

    scanuk.h

Abstract:

    Header file which contains the structures, type definitions,
    constants, global variables and function prototypes that are
    shared between kernel and user mode.

Environment:

    Kernel & user mode

--*/

#ifndef __SCANUK_H__
#define __SCANUK_H__

//
//  Name of port used to communicate
//

const PWSTR filecryptPortName = L"\\filecryptPort";


#define filecrypt_READ_BUFFER_SIZE   1024

typedef struct _filecrypt_NOTIFICATION {

    ULONG BytesToScan;
    ULONG Reserved;             // for quad-word alignement of the Contents structure
    UCHAR Contents[filecrypt_READ_BUFFER_SIZE];
    
} filecrypt_NOTIFICATION, *Pfilecrypt_NOTIFICATION;

typedef struct _filecrypt_REPLY {

    BOOLEAN SafeToOpen;
    
} filecrypt_REPLY, *Pfilecrypt_REPLY;

#endif //  __SCANUK_H__


