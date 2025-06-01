/*#include <crtdefs.h>
#include <ntddk.h>
#include "rtlString.h"

// This function concatenates (appends) one byte-counted wide-character string to another
NTSTATUS
RtlStringCbCatNW (
  PWCHAR Destination,
  SIZE_T DestinationSizeInBytes,
  PWCHAR Source,
  SIZE_T MaxCharactersToCopy
  )
{
  NTSTATUS return_status;
  longlong maxCharactersToAppend;
  PWCHAR terminationPoint;
  ulonglong charsInDestBuffer = DestinationSizeInBytes >> 1;
  ulonglong destCharactersRemaining = charsInDestBuffer;
  PWCHAR currentPosition = Destination;
  SIZE_T remainingCharacters;
  SIZE_T offsetToSource;
  
  // Check if can the buffer size fit in a 32-bit signed int
  if (charsInDestBuffer - 1 < 0x7fffffff) {
    do {
      // Find the end of the existing string
      if (*currentPosition == L'\0')
      {
        break;
      }
      
      destCharactersRemaining = destCharactersRemaining - 1;
      currentPosition = currentPosition + 1;
    } while (destCharactersRemaining != 0);
    
    return_status = STATUS_INVALID_PARAMETER;
    
    // If we didn't find null terminator, return error
    if (destCharactersRemaining != 0) {
      maxCharactersToAppend = charsInDestBuffer - destCharactersRemaining;
      
      if (MaxCharactersToCopy >> 1 < 0x7fffffff) {
        currentPosition = Destination + maxCharactersToAppend;
        remainingCharacters = charsInDestBuffer - maxCharactersToAppend;
        
        if (remainingCharacters != 0) {
          maxCharactersToAppend =
            (maxCharactersToAppend - charsInDestBuffer) +
            remainingCharacters +
            (MaxCharactersToCopy >> 1);
          
          offsetToSource = (longlong)Source - (longlong)currentPosition;
          
          do {
            if ((maxCharactersToAppend == 0) || (*(WCHAR *)(offsetToSource + (longlong)currentPosition) == L'\0'))
            {
              break;
            }
            
            *currentPosition = *(WCHAR *)(offsetToSource + (longlong)currentPosition);
            maxCharactersToAppend = maxCharactersToAppend + -1;
            currentPosition = currentPosition + 1;
            remainingCharacters = remainingCharacters - 1;
          } while (remainingCharacters != 0);
        }
        
        terminationPoint = currentPosition + -1;
        
        if (remainingCharacters != 0) {
          terminationPoint = currentPosition;
        }
        
        return_status = STATUS_BUFFER_OVERFLOW;
        
        if (remainingCharacters != 0) {
          return_status = 0;
        }
        *terminationPoint = L'\0';
      }
      else {
        return_status = STATUS_INVALID_PARAMETER;
      }
    }
  }
  else {
    return_status = STATUS_INVALID_PARAMETER;
  }
  
  return return_status;
}

// This function concatenates (appends) a source string to a destination string
NTSTATUS
RtlStringCbCatW (
  PWCHAR Destination,
  SIZE_T DestinationSizeInBytes,
  PWCHAR Source
  )
{
  NTSTATUS return_status;
  ulonglong *resultLength;
  SIZE_T maxCharactersToCheck = DestinationSizeInBytes >> 1;
  ulonglong destinationLength = 0;
  
  if (maxCharactersToCheck - 1 < 0x7fffffff) {
    resultLength = &destinationLength;
    return_status = RtlStringLengthWorkerW(Destination,maxCharactersToCheck,(longlong *)resultLength);
    
    if (-1 < return_status) {
      return_status =
           RtlStringCopyWorkerW(
             Destination + destinationLength,
             maxCharactersToCheck - destinationLength,
             resultLength,
             Source,
             0x7ffffffe);
    }
  }
  else {
    return_status = STATUS_INVALID_PARAMETER;
  }
  
  return return_status;
}

// This function copies wide-character strings with size parameters specified in bytes rather than characters
NTSTATUS
RtlStringCbCopyNW(
  PWCHAR Destination,
  SIZE_T DestinationSize,
  PWCHAR Source,
  SIZE_T MaxCharactersToCopy
  )
{
  // Check if destination buffer size (in characters) fits in a 32-bit value
  if ((DestinationSize >> 1) - 1 < 0x7fffffff) {
    // Check if source buffer size (in characters) fits in a 32-bit value
    if (MaxCharactersToCopy >> 1 < 0x7fffffff) {
      return RtlStringCopyWorkerW(
        Destination,
        DestinationSize >> 1,
        Source,
        Source,
        MaxCharactersToCopy >> 1
        );
    }
    // If source size is too large, null-terminate destination
    *Destination = L'\0';
  }
  
  return STATUS_INVALID_PARAMETER;
}

// This function copies a wide-character string
NTSTATUS
RtlStringCbCopyW (
  PWCHAR Destination,
  SIZE_T DestinationSize,
  PWCHAR Source
  )
{
  NTSTATUS return_status;
  PWCHAR terminationPoin;
  ulonglong charsInDestBuffer = DestinationSize >> 1;
  SSIZE_T offsetToSource;
  SSIZE_T maxSourceLength;
     
  if (charsInDestBuffer - 1 < 0x7fffffff) {
    // 0x7ffffffe is close to INT_MAX, which is the maximum allowed string length
    maxSourceLength = 0x7ffffffe - charsInDestBuffer;
    offsetToSource = (longlong)Source - (longlong)Destination;
    do {
      if ((maxSourceLength + charsInDestBuffer == 0) ||(*(WCHAR *)(offsetToSource + (longlong)Destination) == L'\0'))
      {
        break;
      }
      
      *Destination = *(WCHAR *)(offsetToSource + (longlong)Destination);
      Destination = Destination + 1;
      charsInDestBuffer = charsInDestBuffer - 1;
    } while (charsInDestBuffer != 0);
    terminationPoin = Destination + -1;
    
    if (charsInDestBuffer != 0) {
      terminationPoin = Destination;
    }
    // Always null-terminate the string
    *terminationPoin = L'\0';
    return_status = STATUS_BUFFER_OVERFLOW;
    
    if (charsInDestBuffer != 0) {
      return_status = STATUS_SUCCESS;
    }
  }
  else {
    return_status = STATUS_INVALID_PARAMETER;
    
    if (charsInDestBuffer != 0) {
      *Destination = L'\0';
      return STATUS_INVALID_PARAMETER;
    }
  }
  return return_status;
}

// The function determines the length of a byte-counted wide-character string in bytes
NTSTATUS
RtlStringCbLengthW (
  PCWCHAR StringToCount,
  undefined8 unsued,
  longlong *ResultLength
  )
{
  longlong remainingCharacters;
  NTSTATUS return_status;
  longlong characterCount = 0;
  
  if (StringToCount == NULL) {
    return_status = STATUS_INVALID_PARAMETER;
    characterCount = 0;
  }
  else {
    // Start with maximum allowed string length
    remainingCharacters = 0x7fffffff;
    do {
      if (*StringToCount == L'\0')
      {
        break;
      }
      
      StringToCount = StringToCount + 1;
      remainingCharacters = remainingCharacters + -1;
    } while (remainingCharacters != 0);
    
    return_status = STATUS_INVALID_PARAMETER;
    
    if (remainingCharacters != 0) {
      characterCount = 0x7fffffff - remainingCharacters;
      return_status = STATUS_SUCCESS;
    }
  }
  if (ResultLength != NULL) {
    if (return_status < 0) {
      *ResultLength = 0;
      
      return return_status;
    }
    *ResultLength = characterCount * 2;
  }
  
  return return_status;
}

// This function provides a safer alternative to standard printf functions for wide-character strings
NTSTATUS
RtlStringCbPrintfW (
  PWCHAR Destination,
  SIZE_T DestinationSizeInBytes,
  PWCHAR PrintfFormat,
  va_list FormattingArgs
  )
{
  NTSTATUS return_status;
  int numOfcharactersWritten;
  SIZE_T maxCharacters = DestinationSizeInBytes >> 1;
  va_list args;
  size_t maxCharactersToWrite;
  
  if (maxCharacters - 1 < 0x7fffffff) {
    // Reserve space for null terminator
    maxCharactersToWrite = maxCharacters - 1;
    args = FormattingArgs;
    // Number of chars written not including null terminator
    numOfcharactersWritten = _snwprintf(Destination,maxCharactersToWrite,PrintfFormat,(va_list)&args);
    
    if (numOfcharactersWritten < 0 || maxCharactersToWrite < (ulonglong)(longlong)numOfcharactersWritten) {
      Destination[maxCharactersToWrite] = L'\0';
      return_status = STATUS_BUFFER_OVERFLOW;
    }
    else {
      return_status = STATUS_SUCCESS;
      
      if ((longlong)numOfcharactersWritten == maxCharactersToWrite) {
        Destination[maxCharactersToWrite] = L'\0';
        return_status = STATUS_SUCCESS;
      }
    }
  }
  else {
    return_status = STATUS_INVALID_PARAMETER;
    // If we have at least one character of space, null-terminate
    if (maxCharacters != 0) {
      *Destination = L'\0';
    }
  }
  
  return return_status;
}

// This function copies a wide-character string from source to destination
// "Cch" in the name indicates it's a character-counted function (as opposed to byte-counted).
NTSTATUS
RtlStringCchCopyW (
  PWCHAR Destination,
  SIZE_T DestinationSizeInChars,
  PCWCHAR Source
  )
{
  WCHAR WVar1;
  NTSTATUS return_status;
  PWCHAR pWVar2;
  longlong offsetToSource;
  longlong maxSourceLength;
  
  if (DestinationSizeInChars - 1 < 0x7fffffff) {
    maxSourceLength = 0x7ffffffe - DestinationSizeInChars;
    offsetToSource = (longlong)Source - (longlong)Destination;
    do {
      if ((maxSourceLength + DestinationSizeInChars == 0) ||
         (WVar1 = *(WCHAR *)(offsetToSource + (longlong)Destination), WVar1 == L'\0'))
      {
        break;
      }
      
      *Destination = WVar1;
      Destination = Destination + 1;
      DestinationSizeInChars = DestinationSizeInChars - 1;
    } while (DestinationSizeInChars != 0);
    
    pWVar2 = Destination + -1;
    if (DestinationSizeInChars != 0) {
      pWVar2 = Destination;
    }
    
    *pWVar2 = L'\0';
    return_status = STATUS_BUFFER_OVERFLOW;
    
    if (DestinationSizeInChars != 0) {
      return_status = STATUS_SUCCESS;
    }
  }
  else {
    return_status = STATUS_INVALID_PARAMETER;
    
    if (DestinationSizeInChars != 0) {
      *Destination = L'\0';
      return STATUS_INVALID_PARAMETER;
    }
  }
  return return_status;
}

// This function safely copies a wide-character string
NTSTATUS
RtlStringCopyWorkerW (
  PWCHAR Destination,
  SIZE_T DestinationSize,
  undefined8 unused,
  PWCHAR Source,
  SIZE_T MaxCharactersToCopy
  )
{
  NTSTATUS return_status;
  PWCHAR terminationPoint;
  SSIZE_T offset;
  
  if (DestinationSize != 0) {
    offset = (longlong)Source - (longlong)Destination;
    do {
      if ((MaxCharactersToCopy == 0) || (*(WCHAR *)(offset + (longlong)Destination) == L'\0'))
      {
        break;
      }
      
      *Destination = *(WCHAR *)(offset + (longlong)Destination);
      MaxCharactersToCopy = MaxCharactersToCopy - 1;
      Destination = Destination + 1;
      DestinationSize = DestinationSize - 1;
    } while (DestinationSize != 0);
  }
  
  terminationPoint = Destination + -1;
  if (DestinationSize != 0) {
    terminationPoint = Destination;
  }
  
  return_status = STATUS_BUFFER_OVERFLOW;
  
  if (DestinationSize != 0) {
    return_status = STATUS_SUCCESS;
  }
  
  *terminationPoint = L'\0';
  
  return return_status;
}

// This function measures the length of a wide-character string
NTSTATUS
RtlStringLengthWorkerW (
  PWCHAR StringToCount,
  SIZE_T MaxCharactersToCheck,
  longlong *ResultLength
  )
{
  NTSTATUS return_status;
  SIZE_T remainingCharacters = MaxCharactersToCheck;
  
  if (MaxCharactersToCheck != 0) {
    do {
      if (*StringToCount == L'\0')
      {
        break;
      }
      
      StringToCount = StringToCount + 1;
      remainingCharacters = remainingCharacters - 1;
    } while (remainingCharacters != 0);
  }
  return_status = STATUS_INVALID_PARAMETER;
  
  if (remainingCharacters != 0) {
    return_status = 0;
  }
  
  // If output parameter was provided, calculate and return the length
  if (ResultLength != NULL) {
    if (remainingCharacters == 0) {
      *ResultLength = 0;
      return return_status;
    }
    *ResultLength = MaxCharactersToCheck - remainingCharacters;
  }
  
  return return_status;
}*/