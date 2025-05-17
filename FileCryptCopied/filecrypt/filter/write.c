#include "write.h"

/* This function is a helper function for writing a single wide character to a file stream */
void
write_char (
    wchar_t CharToWrite,
    FILE *FileStream,
    int *CharacterWrittenCounter
    )
{
    wint_t writeResult;
    
    /* Check if the file stream is valid for writing */
    if (((FileStream->_flag & 0x40U) == 0) || (FileStream->_base != NULL)) {
        /* Write the character to the file stream without locking */
        writeResult = _fputwc_nolock(CharToWrite, FileStream);
        if ((writeResult == 0xffff) && ((FileStream->_flag & 0x20U) != 0)) {
            /* Signal error through the counter */
            *CharacterWrittenCounter = -1;
        }
        else {
            /* Successful write - increment the character counter */
            *CharacterWrittenCounter = *CharacterWrittenCounter + 1;
        }
    }
    else {
        /* the stream isn't properly initialized for writing,
         * we increment the counter anyway (possibly for counting without actual output) */
        *CharacterWrittenCounter = *CharacterWrittenCounter + 1;
    }
}

/* This function provides an efficient way to output repeated characters */
void
write_multi_char (
    wchar_t CharacterToRepeat,
    int RepeatCount,
    FILE *FileStream,
    int *CharacterWrittenCount
    )
{
    if (0 >= RepeatCount)
    {
        return;
    }
    
    do {
        RepeatCount = RepeatCount + -1;
        write_char(CharacterToRepeat,FileStream,CharacterWrittenCount);
        
        if (*CharacterWrittenCount == -1)
        {
            return;
        }
    } while (0 < RepeatCount);
}

/* This function provides a way to write a wide-character string to a file stream */
void
write_string (
    wchar_t *StringToWrite,
    int MaxCharsToWrite,
    FILE *FileStream,
    int *CharacterWrittenCounter
    )
{
    /* Check if the file stream is valid for writing */
    if (((FileStream->_flag & 0x40U) == 0) || (FileStream->_base != NULL)) {
        if (0 < MaxCharsToWrite) {
            do {
                MaxCharsToWrite = MaxCharsToWrite + -1;
                write_char(*StringToWrite,FileStream,CharacterWrittenCounter);
                StringToWrite = StringToWrite + 1;
                if (*CharacterWrittenCounter == -1) {
                    return;
                }
            } while (0 < MaxCharsToWrite);
        }
    }
    else {
        *CharacterWrittenCounter = *CharacterWrittenCounter + MaxCharsToWrite;
    }
}