/*++

Copyright (c) 1999-2002  Microsoft Corporation

Module Name:

    filecryptuser.h

Abstract:

    Header file which contains the structures, type definitions,
    constants, global variables and function prototypes for the
    user mode part of the filecrypt.

Environment:

    Kernel & user mode

--*/
#ifndef __filecryptuser_H__
#define __filecryptuser_H__

#pragma pack(1)

typedef struct _filecrypt_MESSAGE {

    //
    //  Required structure header.
    //

    FILTER_MESSAGE_HEADER MessageHeader;


    //
    //  Private filecrypt-specific fields begin here.
    //

    filecrypt_NOTIFICATION Notification;

    //
    //  Overlapped structure: this is not really part of the message
    //  However we embed it instead of using a separately allocated overlap structure
    //

    OVERLAPPED Ovlp;
    
} filecrypt_MESSAGE, *Pfilecrypt_MESSAGE;

typedef struct _filecrypt_REPLY_MESSAGE {

    //
    //  Required structure header.
    //

    FILTER_REPLY_HEADER ReplyHeader;

    //
    //  Private filecrypt-specific fields begin here.
    //

    filecrypt_REPLY Reply;

} filecrypt_REPLY_MESSAGE, *Pfilecrypt_REPLY_MESSAGE;

#endif //  __filecryptuser_H__


