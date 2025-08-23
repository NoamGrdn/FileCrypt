#pragma warning(disable: 4100)

#include "write.h"

int __cdecl _flswbuf(int _Ch, FILE* _File)

{
    _File->_flag = _File->_flag | 0x20;
    return 0xffff;
}

wint_t __cdecl _fputwc_nolock(wchar_t _Ch, FILE* _File)

{
    int* piVar1;
    int iVar2;

    if (_File == (FILE*)0x0) {
        _guard_check_icall(0);
        _Ch = L'\xffff';
    }
    else {
        piVar1 = &_File->_cnt;
        *piVar1 = *piVar1 + -2;
        if (*piVar1 < 0) {
            iVar2 = _flswbuf((unsigned int)(unsigned short)_Ch, _File);
            _Ch = (wchar_t)iVar2;
        }
        else {
            *(wchar_t*)_File->_ptr = _Ch;
            _File->_ptr = _File->_ptr + 2;
        }
    }
    return _Ch;
}

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