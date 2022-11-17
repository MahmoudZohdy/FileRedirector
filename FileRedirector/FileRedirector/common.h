#pragma once

#define COMMUNICATION_PORT_NAME L"\\FileRedirector"  


// structure used for communication on the PORT between driver and user-client
#define MAX_PATH          260
typedef struct _ORIGINAL_FILE_PATH {    
    WCHAR OriginalFilePath[MAX_PATH * 2];                   /*!< DOS File Name that is being opened. */
} ORIGINAL_FILE_PATH, * PORIGINAL_FILE_PATH;

typedef struct _REPALY_MESSAGE {
    ULONG ChangePath;                           /*!<If a match found return 1, otherwise return 0. */
    WCHAR ResultFilePath[MAX_PATH * 2];         /*!<file path to change to if ChangePath = 1. */
} REPALY_MESSAGE, * PREPALY_MESSAGE;
