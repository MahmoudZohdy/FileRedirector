#pragma warning(disable : 4996)

#include <stdio.h>
#include <windows.h>
#include <fltUser.h>

#pragma warning(disable:4201) // nonstandard extension used : nameless struct/union
#include <winioctl.h>
#include <TCHAR.H>
#include <stdlib.h>

#include "..\FileRedirector\common.h"


#pragma comment(lib, "FltLib.lib")


#define  NumberOfThreadsToConnectOnPort 5

WCHAR OldDOSName[MAX_PATH * 2] = { 0 };
WCHAR NewDOSName[MAX_PATH * 2] = { 0 };
WCHAR OldFileName[] = L"\\File1.txt";
WCHAR NewFileName[] = L"\\File2.txt";
HANDLE   hConnectionPort;
HANDLE   Completion;


// Message From the driver
typedef struct _Received_MESSAGE {

    FILTER_MESSAGE_HEADER MessageHeader;              /*!< Required structure header. */
    ORIGINAL_FILE_PATH    Fileinfo;                  /*!< DOS File Name that is being opened. */
    OVERLAPPED            Ovlp;

} Received_MESSAGE, * PReceived_MESSAGE;


// Reply to the driver 
typedef struct _REPLY_MESSAGE {

    FILTER_REPLY_HEADER    MessageHeader;            /*!< Required structure header. */
    REPALY_MESSAGE         Replay;                   /*!< Reply to the Driver. */

} REPLY_MESSAGE, * PREPLY_MESSAGE;

//
// this function is responsible for comunicating with the Kernel-Driver using Port Communication.
//
DWORD
UserWorker(_Inout_   LPVOID Parametar) {
    UNREFERENCED_PARAMETER(Parametar);

    HRESULT hr = S_OK;

    Received_MESSAGE* message = NULL;
    REPLY_MESSAGE replyMsg;
    LPOVERLAPPED pOvlp = NULL;

    DWORD outSize;
    ULONG_PTR key;
    BOOL  success = FALSE;

    ZeroMemory(&replyMsg, sizeof(replyMsg.MessageHeader) + sizeof(replyMsg.Replay.ResultFilePath) + sizeof(replyMsg.Replay.ChangePath));

    for (;;) {

        message = NULL;

        //  Get overlapped structure asynchronously, the overlapped structure 
        //  was previously pumped by FilterGetMessage(...)
        success = GetQueuedCompletionStatus(Completion, &outSize, &key, &pOvlp, INFINITE);

        if (!success) {

            hr = HRESULT_FROM_WIN32(GetLastError());

            if (hr == E_HANDLE) {

                printf("Completion port becomes unavailable.\n");
                hr = S_OK;

            }
            else if (hr == HRESULT_FROM_WIN32(ERROR_ABANDONED_WAIT_0)) {

                printf("Completion port was closed.\n");
                hr = S_OK;
            }

            break;
        }


        message = CONTAINING_RECORD(pOvlp, Received_MESSAGE, Ovlp);


        //TODO: Scan Process here and get result
        // ULONG ScanResult = ScanProcess( message->Processinfo.ProcFilePath);

        ZeroMemory(&replyMsg, sizeof(replyMsg.MessageHeader) + sizeof(replyMsg.Replay.ResultFilePath) + sizeof(replyMsg.Replay.ChangePath));

        // Check here if the path need to be changed.
        //till now it will not change

        if (!wcscmp(message->Fileinfo.OriginalFilePath, OldDOSName)) {
            printf("Found A match %S \n", message->Fileinfo.OriginalFilePath);

            replyMsg.Replay.ChangePath = 1;
            wcscpy_s(replyMsg.Replay.ResultFilePath, 69, NewDOSName);
        }
        else {
            replyMsg.Replay.ChangePath = 0;

        }

        replyMsg.MessageHeader.MessageId = message->MessageHeader.MessageId;
        FilterReplyMessage(hConnectionPort,
            &replyMsg.MessageHeader,
            sizeof(replyMsg.MessageHeader) + sizeof(replyMsg.Replay.ChangePath) + sizeof(replyMsg.Replay.ResultFilePath));


        //  After we process the message, pump a overlapped structure into completion port again.
        RtlZeroMemory(&message->Fileinfo, sizeof(ORIGINAL_FILE_PATH));
        hr = FilterGetMessage(hConnectionPort,
            &message->MessageHeader,
            FIELD_OFFSET(Received_MESSAGE, Ovlp),
            &message->Ovlp);

        if (hr == HRESULT_FROM_WIN32(ERROR_OPERATION_ABORTED)) {

            printf("FilterGetMessage aborted. Result 0x%x, 0x%08x\n", hr, HRESULT_FROM_WIN32(GetLastError()));
            break;

        }
        else if (hr != HRESULT_FROM_WIN32(ERROR_IO_PENDING)) {

            printf("Failed to get message from the minifilter. Result 0x%x, Last Error 0x%08x\n", hr, HRESULT_FROM_WIN32(GetLastError()));
            break;
        }

    }

    if (message) {
        //  Free the memory, which originally allocated at initilization
        HeapFree(GetProcessHeap(), 0, message);
    }


    return hr;
}


int main()
{

    WCHAR CurrentDirectory[MAX_PATH] = { 0 };

    GetCurrentDirectory(50, CurrentDirectory);

    TCHAR DriveLetter[3];
    DriveLetter[0] = CurrentDirectory[0];
    DriveLetter[1] = _T(':');
    DriveLetter[2] = _T('\0');
    QueryDosDevice(DriveLetter, OldDOSName, MAX_PATH);
    QueryDosDevice(DriveLetter, NewDOSName, MAX_PATH);

    wcscat(OldDOSName, CurrentDirectory + 2);
    wcsncpy_s(NewDOSName, MAX_PATH * 2, OldDOSName, MAX_PATH * 2);
    wcscat(OldDOSName, OldFileName);
    wcscat(NewDOSName, NewFileName);


    HANDLE hThreadArray[NumberOfThreadsToConnectOnPort]={0};
    RtlZeroMemory(hThreadArray, sizeof(HANDLE) * NumberOfThreadsToConnectOnPort);

    //Create the Workers Threads
    for (int i = 0; i < NumberOfThreadsToConnectOnPort; i++) {
        hThreadArray[i] = CreateThread(
            NULL,
            0,
            UserWorker,
            NULL,
            CREATE_SUSPENDED,
            NULL);

        if (!hThreadArray[i]) {
            printf("Failed to Create one of the user scan worker Error Code 0x%x\n", GetLastError());
        }
    }

    while (TRUE)
    {
        // connecting to the server (this requires the client to be ELEVATED)
        HRESULT hRes = FilterConnectCommunicationPort(
            COMMUNICATION_PORT_NAME, 0, NULL, 0, NULL,
            &hConnectionPort);

        // check if the connect is ok
        if (hRes != S_OK) {
            // connection failed, wait and reconnect (make sure the client is elevated)
            printf("Couldn't connect to the driver port, trying again\n");
            Sleep(1000);
        }
        else break;
    };

    //make the communication with the driver asynchronous (Number of threads to communicate with driver is NumberOfThreadsToConnectOnPort)
    Completion = CreateIoCompletionPort(hConnectionPort, NULL, NULL, NumberOfThreadsToConnectOnPort);
    if (!Completion) {
        printf("Couldn't create the I/O port, Error Code 0x%x\n", GetLastError());
        //CloseHandle(hConnectionPort);
        goto CleanUp;
    };

    for (int i = 0; i < NumberOfThreadsToConnectOnPort; i++) {
        if (hThreadArray[i] != NULL && ResumeThread(hThreadArray[i]) == -1) {
            printf("Failed to Resume one of the worker Threads Error Code 0x%x\n", GetLastError());
        }
    }

    for (int i = 0; i < NumberOfThreadsToConnectOnPort; i++) {

        HRESULT hr;
        // allocate memory that will be used to recieve messages from kernel driver
        Received_MESSAGE* msg = (Received_MESSAGE*)HeapAlloc(GetProcessHeap(), 0, sizeof(Received_MESSAGE));
        if (NULL == msg) {
            printf("Failed allocat memory 0x%x\n", GetLastError());
        }
        else {
            FillMemory(&msg->Ovlp, sizeof(OVERLAPPED), 0);
            hr = FilterGetMessage(hConnectionPort,
                &msg->MessageHeader,
                FIELD_OFFSET(Received_MESSAGE, Ovlp),
                &msg->Ovlp);

            if (hr == HRESULT_FROM_WIN32(ERROR_IO_PENDING)) {
                hr = S_OK;
            }
            else {
                printf("FilterGetMessage failed with Error code 0x%x\n", GetLastError());
            }
        }
    }

    WaitForMultipleObjects(NumberOfThreadsToConnectOnPort, hThreadArray, TRUE, INFINITE);

CleanUp:

    CloseHandle(hConnectionPort);
    if (Completion)
        CloseHandle(Completion);
    for (int i = 0; i < NumberOfThreadsToConnectOnPort; i++)
    {
        if (hThreadArray[i]) {
            TerminateThread(hThreadArray[i], 1);
            CloseHandle(hThreadArray[i]);
        }
    }

    return 0;

}