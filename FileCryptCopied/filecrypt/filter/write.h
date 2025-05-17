/*++

Module Name:

    write.h - char helper functions

--*/

#ifndef __FC_MC_H__
#define __FC_MC_H__

#include <stdio.h>

void
write_char(
    wchar_t CharToWrite,
    FILE* FileStream,
    int* CharacterWrittenCounter
);

void
write_multi_char(
    wchar_t CharacterToRepeat,
    int RepeatCount,
    FILE* FileStream,
    int* CharacterWrittenCount
);

void
write_string(
    wchar_t* StringToWrite,
    int MaxCharsToWrite,
    FILE* FileStream,
    int* CharacterWrittenCounter
);

#endif /* __FC_MC_H__ */
