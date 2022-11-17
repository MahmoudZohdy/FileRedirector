//
//  Enabled warnings
//

#pragma warning(error:4100)     //  Enable-Unreferenced formal parameter
#pragma warning(error:4101)     //  Enable-Unreferenced local variable
#pragma warning(error:4061)     //  Enable-missing enumeration in switch statement
#pragma warning(error:4505)     //  Enable-identify dead functions

//
//  Includes
//


//
// This sample contains OS version specific code. If compiled for VISTA it
// will not run properly on older versions of Windows.
//
#define FileRedirector_VISTA (NTDDI_VERSION >= NTDDI_VISTA)

#include <fltKernel.h>
#include "common.h"

//
//  Memory Pool Tags
//

#define FileRedirector_STRING_TAG            'OTOT'

//
// Constants
//

#define REPLACE_ROUTINE_NAME_STRING L"IoReplaceFileObjectName"



//
//  Starting with windows 7, the IO Manager provides IoReplaceFileObjectName,
//  but old versions of Windows will not have this function. Rather than just
//  writing our own function, and forfeiting future windows functionality, we can
//  use MmGetRoutineAddr, which will allow us to dynamically import IoReplaceFileObjectName
//  if it exists. If not it allows us to implement the function ourselves.
//

typedef
NTSTATUS
(*PReplaceFileObjectName) (
    _In_ PFILE_OBJECT FileObject,
    _In_reads_bytes_(FileNameLength) PWSTR NewFileName,
    _In_ USHORT FileNameLength
    );




//
//  Context sample filter global data structures.
//


typedef struct _FileRedirector_GLOBAL_DATA {

    //
    // Handle to minifilter returned from FltRegisterFilter()
    //

    PFLT_FILTER Filter;


    //
    //  Pointer to the function we will use to
    //  replace file names.
    //

    PReplaceFileObjectName ReplaceFileNameFunction;

    //
    // Used for PORT communication with the user client
    //

    PFLT_PORT ScanServerPort;
    PFLT_PORT ScanClientPort;

#if DBG

    //
    // Field to control nature of debug output
    //

    ULONG DebugLevel;
#endif

} FileRedirector_GLOBAL_DATA, * PFileRedirector_GLOBAL_DATA;


//
//  Debug helper functions
//

#if DBG


#define DEBUG_TRACE_ERROR                               0x00000001  // Errors - whenever we return a failure code
#define DEBUG_TRACE_LOAD_UNLOAD                         0x00000002  // Loading/unloading of the filter
#define DEBUG_TRACE_INSTANCES                           0x00000004  // Attach / detach of instances

#define DEBUG_TRACE_REPARSE_OPERATIONS                  0x00000008  // Operations that are performed to determine if we should return STATUS_REPARSE
#define DEBUG_TRACE_REPARSED_OPERATIONS                 0x00000010  // Operations that return STATUS_REPARSE
#define DEBUG_TRACE_REPARSED_REISSUE                    0X00000020  // Operations that need to be reissued with an IRP.

#define DEBUG_TRACE_NAME_OPERATIONS                     0x00000040  // Operations involving name provider callbacks

#define DEBUG_TRACE_RENAME_REDIRECTION_OPERATIONS       0x00000080  // Operations involving rename or hardlink redirection

#define DEBUG_TRACE_ALL_IO                              0x00000100  // All IO operations tracked by this filter

#define DEBUG_TRACE_ALL                                 0xFFFFFFFF  // All flags


#define DebugTrace(Level, Data)                     \
    if ((Level) & Globals.DebugLevel) {             \
        DbgPrint Data;                              \
    }


#else

#define DebugTrace(Level, Data)             {NOTHING;}

#endif


//
//  Function that handle driver load/unload and instance setup/cleanup
//

DRIVER_INITIALIZE DriverEntry;

NTSTATUS
FileRedirectorUnload(
    FLT_FILTER_UNLOAD_FLAGS Flags
);


//
//  Functions that track operations on the volume
//

FLT_PREOP_CALLBACK_STATUS
FileRedirectorPreCreate(
    _Inout_ PFLT_CALLBACK_DATA Cbd,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
);

FLT_PREOP_CALLBACK_STATUS
FileRedirectorPreNetworkQueryOpen(
    _Inout_ PFLT_CALLBACK_DATA Cbd,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
);



//
//  Functions that provide string allocation support
//

_When_(return == 0, _Post_satisfies_(String->Buffer != NULL))
NTSTATUS
FileRedirectorAllocateUnicodeString(
    _Inout_ PUNICODE_STRING String
);

VOID
FileRedirectorFreeUnicodeString(
    _Inout_ PUNICODE_STRING String
);

NTSTATUS
FileRedirectorReplaceFileObjectName(
    _In_ PFILE_OBJECT FileObject,
    _In_reads_bytes_(FileNameLength) PWSTR NewFileName,
    _In_ USHORT FileNameLength
);

BOOLEAN
FileRedirectorCompareMapping(
    _In_ PFLT_FILE_NAME_INFORMATION NameInfo,
    _Out_opt_ REPALY_MESSAGE * Replay
);

NTSTATUS
FileRedirectorMungeName(
    _In_ PFLT_FILE_NAME_INFORMATION NameInfo,
    _Out_ PUNICODE_STRING MungedPath
);



//
//  Functions that implement PORT Communication with user client
//

//prepare the communication port that will be used to communicate with the user client
NTSTATUS FileRedirectorPrepareCommunicationPort();

//Called when user client disconnet from communication port
VOID FileRedirectorDisconnectNotifyCallback(
    _In_opt_ PVOID ConnectionCookie);

//Called when user client connet to Driver, gives the chance to vertify the user client
NTSTATUS FileRedirectorConnectNotifyCallback(
    IN PFLT_PORT ClientPort,
    IN PVOID ServerPortCookie,
    IN PVOID ConnectionContext,
    IN ULONG SizeOfContext,
    OUT PVOID * ConnectionPortCookie);



//Send Process name and PID To user Client for scan
NTSTATUS FileRedirectorSendDataToUserClientAndReceiveReply(_In_ PCUNICODE_STRING Process_Name, _Outptr_ REPALY_MESSAGE * Reply);

//
//  Filter callback routines
//

FLT_OPERATION_REGISTRATION Callbacks[] = {

    { IRP_MJ_CREATE,
        FLTFL_OPERATION_REGISTRATION_SKIP_PAGING_IO,
        FileRedirectorPreCreate,
        NULL },

    { IRP_MJ_NETWORK_QUERY_OPEN,
        FLTFL_OPERATION_REGISTRATION_SKIP_PAGING_IO,
        FileRedirectorPreNetworkQueryOpen,
        NULL },

    { IRP_MJ_OPERATION_END }
};

//
// Filter registration data structure
//

FLT_REGISTRATION FilterRegistration = {

    sizeof(FLT_REGISTRATION),                       //  Size
    FLT_REGISTRATION_VERSION,                       //  Version
    0,                                              //  Flags
    NULL,                                           //  Context
    Callbacks,                                      //  Operation callbacks
    FileRedirectorUnload,                           //  Filters unload routine
    NULL,                                           //  InstanceSetup routine
    NULL,                                           //  InstanceQueryTeardown routine
    NULL,                                           //  InstanceTeardownStart routine
    NULL,                                           //  InstanceTeardownComplete routine
    NULL,                                           //  Filename generation support callback
    NULL,                                           //  Filename normalization support callback
    NULL,                                           //  Normalize name component cleanup callback
#if FileRedirector_VISTA
    NULL,                                           //  Transaction notification callback
    NULL                                            //  Filename normalization support callback

#endif // FileRedirector_VISTA
};



//
//  Global variables
//

FileRedirector_GLOBAL_DATA Globals;
ULONG WaitDelay = 10;                   //time to wait replay from user-mode client (multiple of 0.1 sec)
LONG MaxNumberConnections = 1;          // Max number of connection to the Communication PORT


//
//  Assign text sections for each routine.
//

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, FileRedirectorUnload)
#pragma alloc_text(PAGE, FileRedirectorAllocateUnicodeString)
#pragma alloc_text(PAGE, FileRedirectorFreeUnicodeString)
#pragma alloc_text(PAGE, FileRedirectorReplaceFileObjectName)
#pragma alloc_text(PAGE, FileRedirectorCompareMapping)
#pragma alloc_text(PAGE, FileRedirectorMungeName)
#pragma alloc_text(PAGE, FileRedirectorPreCreate)

#pragma alloc_text(PAGE, FileRedirectorPrepareCommunicationPort)
#pragma alloc_text(PAGE, FileRedirectorDisconnectNotifyCallback)
#pragma alloc_text(PAGE, FileRedirectorConnectNotifyCallback)
#pragma alloc_text(PAGE, FileRedirectorSendDataToUserClientAndReceiveReply)

#endif



#pragma warning(push)
#pragma warning(disable:4152) // nonstandard extension, function/data pointer conversion in expression

NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
) {
    NTSTATUS status = STATUS_SUCCESS;
    UNICODE_STRING replaceRoutineName;
    PFLT_REGISTRATION Registration;

    UNREFERENCED_PARAMETER(RegistryPath);

    //
    //  Default to NonPagedPoolNx for non paged pool allocations where supported.
    //
    ExInitializeDriverRuntime(DrvRtPoolNxOptIn);


#if DBG

    Globals.DebugLevel = DEBUG_TRACE_ALL;

#endif


    Globals.ScanClientPort = NULL;
    Globals.ScanServerPort = NULL;

    //
    //  Import function to replace file names.
    //

    RtlInitUnicodeString(&replaceRoutineName, REPLACE_ROUTINE_NAME_STRING);

    Globals.ReplaceFileNameFunction = MmGetSystemRoutineAddress(&replaceRoutineName);
    if (Globals.ReplaceFileNameFunction == NULL) {

        Globals.ReplaceFileNameFunction = FileRedirectorReplaceFileObjectName;
    }




    DebugTrace(DEBUG_TRACE_LOAD_UNLOAD,
        ("[FileRedirector]: Driver being loaded\n"));


    //
    //  Register with the filter manager.
    //

    Registration = &FilterRegistration;

    status = FltRegisterFilter(DriverObject, Registration, &Globals.Filter);

    if (!NT_SUCCESS(status)) {

        goto DriverEntryCleanup;
    }

    //
    // Prepare the Communication Port
    //

    status = FileRedirectorPrepareCommunicationPort();
    if (!NT_SUCCESS(status)) {

        DebugTrace(DEBUG_TRACE_REPARSE_OPERATIONS | DEBUG_TRACE_ERROR,
            ("[FileRedirector]: Failed to Prepare the Communication PORT -> Failed (Status = 0x%08X)\n", status));
    }

    //
    //  Start filtering I/O
    //

    status = FltStartFiltering(Globals.Filter);

    if (!NT_SUCCESS(status)) {
        FltUnregisterFilter(Globals.Filter);
    }


DriverEntryCleanup:

    DebugTrace(DEBUG_TRACE_LOAD_UNLOAD,
        ("[FileRedirector]: Driver loaded complete (Status = 0x%08X)\n",
            status));


    return status;
}
#pragma warning(pop)


NTSTATUS
FileRedirectorUnload(
    FLT_FILTER_UNLOAD_FLAGS Flags
) {
    UNREFERENCED_PARAMETER(Flags);

    PAGED_CODE();


    DebugTrace(DEBUG_TRACE_LOAD_UNLOAD,
        ("[FileRedirector]: Unloading driver\n"));


    FltCloseCommunicationPort(Globals.ScanServerPort);
    Globals.ScanServerPort = NULL;

    FltUnregisterFilter(Globals.Filter);

    return STATUS_SUCCESS;
}


//
//  Instance IRP_MJ_CREATE/IRP_MJ_NETWORK_QUERY_OPEN routines.
//


//
//Because network query opens are FastIo operations, they cannot be reparsed.
//This means network query opens which need to be redirected must be failed
//with FLT_PREOP_DISALLOW_FASTIO.This will cause the Io Manager to reissue
//the open as a regular IRP based open.To prevent performance regression,
//only fail network query opens which need to be reparsed.
//
FLT_PREOP_CALLBACK_STATUS
FileRedirectorPreNetworkQueryOpen(
    _Inout_ PFLT_CALLBACK_DATA Cbd,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID * CompletionContext
) {
    PFLT_FILE_NAME_INFORMATION NameInfo = NULL;
    NTSTATUS Status;
    FLT_PREOP_CALLBACK_STATUS CallbackStatus;
    BOOLEAN Match;
    PIO_STACK_LOCATION IrpSp;

    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    PAGED_CODE();



    DebugTrace(DEBUG_TRACE_ALL_IO,
        ("[FileRedirector]: FileRedirectorPreNetworkQueryOpen -> Enter (Cbd = %p, FileObject = %p)\n",
            Cbd,
            FltObjects->FileObject));

    //
    // Initialize defaults
    //

    Status = STATUS_SUCCESS;
    CallbackStatus = FLT_PREOP_SUCCESS_NO_CALLBACK; // pass through - default is no post op callback

    //
    // We only registered for this IRP, so thats all we better get!
    //

    NT_ASSERT(Cbd->Iopb->MajorFunction == IRP_MJ_NETWORK_QUERY_OPEN);
    NT_ASSERT(FLT_IS_FASTIO_OPERATION(Cbd));

    IrpSp = IoGetCurrentIrpStackLocation(Cbd->Iopb->Parameters.NetworkQueryOpen.Irp);

    //
    //  Check if this is a paging file as we don't want to redirect
    //  the location of the paging file.
    //

    if (FlagOn(IrpSp->Flags, SL_OPEN_PAGING_FILE)) {

        DebugTrace(DEBUG_TRACE_ALL_IO,
            ("[FileRedirector]: FileRedirectorPreNetworkQueryOpen -> Ignoring paging file open (Cbd = %p, FileObject = %p)\n",
                Cbd,
                FltObjects->FileObject));

        goto FileRedirectorPreNetworkQueryOpenCleanup;
    }


    //
    //  Don't reparse an open by ID because it is not possible to determine create path intent.
    //

    if (FlagOn(IrpSp->Parameters.Create.Options, FILE_OPEN_BY_FILE_ID)) {

        goto FileRedirectorPreNetworkQueryOpenCleanup;
    }

    //
    //  A rename should never come on the fast IO path
    //

    NT_ASSERT(IrpSp->Flags != SL_OPEN_TARGET_DIRECTORY);

    Status = FltGetFileNameInformation(Cbd,
        FLT_FILE_NAME_OPENED |
        FLT_FILE_NAME_QUERY_DEFAULT,
        &NameInfo);

    if (!NT_SUCCESS(Status)) {

        DebugTrace(DEBUG_TRACE_REPARSE_OPERATIONS | DEBUG_TRACE_ERROR,
            ("[FileRedirector]: FileRedirectorPreNetworkQueryOpen -> Failed to get name information (Cbd = %p, FileObject = %p)\n",
                Cbd,
                FltObjects->FileObject));

        goto FileRedirectorPreNetworkQueryOpenCleanup;
    }


    DebugTrace(DEBUG_TRACE_REPARSE_OPERATIONS,
        ("[FileRedirector]: FileRedirectorPreNetworkQueryOpen -> Processing create for file %wZ (Cbd = %p, FileObject = %p)\n",
            &NameInfo->Name,
            Cbd,
            FltObjects->FileObject));

    //
    //  Parse the filename information
    //

    Status = FltParseFileNameInformation(NameInfo);
    if (!NT_SUCCESS(Status)) {

        DebugTrace(DEBUG_TRACE_REPARSE_OPERATIONS | DEBUG_TRACE_ERROR,
            ("[FileRedirector]: FileRedirectorPreNetworkQueryOpen -> Failed to parse name information for file %wZ (Cbd = %p, FileObject = %p)\n",
                &NameInfo->Name,
                Cbd,
                FltObjects->FileObject));

        goto FileRedirectorPreNetworkQueryOpenCleanup;
    }

    //
    //  Determine if this query involes a path that matches user-client matching criteria.
    //

    REPALY_MESSAGE Replay;
    Match = FileRedirectorCompareMapping(NameInfo, &Replay);

    if (Match) {

        DebugTrace(DEBUG_TRACE_REPARSE_OPERATIONS,
            ("[FileRedirector]: FileRedirectorPreNetworkQueryOpen -> File name %wZ matches mapping. (Cbd = %p, FileObject = %p)\n",
                &NameInfo->Name,
                Cbd,
                FltObjects->FileObject));

        //
        // We can't return STATUS_REPARSE because it is FastIO. Return
        // FLT_PREOP_DISALLOW_FASTIO, so it will be reissued down the slow path.
        //

        DebugTrace(DEBUG_TRACE_REPARSED_REISSUE,
            ("[FileRedirector]: Disallow fast IO that is to a mapped path! %wZ\n",
                &NameInfo->Name));

        CallbackStatus = FLT_PREOP_DISALLOW_FASTIO;

    }


FileRedirectorPreNetworkQueryOpenCleanup:

    //
    //  Release the references we have acquired
    //

    if (NameInfo != NULL) {

        FltReleaseFileNameInformation(NameInfo);
    }

    if (!NT_SUCCESS(Status)) {

        //
        //  An error occurred, fail the query
        //

        DebugTrace(DEBUG_TRACE_ERROR,
            ("[FileRedirector]: FileRedirectorPreNetworkQueryOpen -> Failed with status 0x%x \n",
                Status));

        Cbd->IoStatus.Status = Status;
        CallbackStatus = FLT_PREOP_COMPLETE;
    }

    DebugTrace(DEBUG_TRACE_ALL_IO,
        ("[FileRedirector]: FileRedirectorPreNetworkQueryOpen -> Exit (Cbd = %p, FileObject = %p)\n",
            Cbd,
            FltObjects->FileObject));

    return CallbackStatus;

}


FLT_PREOP_CALLBACK_STATUS
FileRedirectorPreCreate(
    _Inout_ PFLT_CALLBACK_DATA Cbd,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID * CompletionContext
) {

    PFLT_FILE_NAME_INFORMATION NameInfo = NULL;
    NTSTATUS Status = STATUS_SUCCESS;
    FLT_PREOP_CALLBACK_STATUS CallbackStatus = FLT_PREOP_SUCCESS_NO_CALLBACK; // pass through - default is no post op callback;
    UNICODE_STRING NewFileName;

    //Skip Operation From Kernel-Mode
    if (Cbd->RequestorMode == KernelMode)
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    PAGED_CODE();

    DebugTrace(DEBUG_TRACE_ALL_IO,
        ("[FileRedirector]: FileRedirectorPreCreate -> Enter (Cbd = %p, FileObject = %p)\n",
            Cbd,
            FltObjects->FileObject));


    RtlInitUnicodeString(&NewFileName, NULL);

    //
    // We only registered for this irp, so thats all we better get!
    //

    NT_ASSERT(Cbd->Iopb->MajorFunction == IRP_MJ_CREATE);

    //
    //  Check if this is a paging file as we don't want to redirect
    //  the location of the paging file.
    //

    if (FlagOn(Cbd->Iopb->OperationFlags, SL_OPEN_PAGING_FILE)) {

        DebugTrace(DEBUG_TRACE_ALL_IO,
            ("[FileRedirector]: FileRedirectorPreCreate -> Ignoring paging file open (Cbd = %p, FileObject = %p)\n",
                Cbd,
                FltObjects->FileObject));

        goto FileRedirectorPreCreateCleanup;
    }



    //
    //  Don't reparse an open by ID because it is not possible to determine create path intent.
    //

    if (FlagOn(Cbd->Iopb->Parameters.Create.Options, FILE_OPEN_BY_FILE_ID)) {

        goto FileRedirectorPreCreateCleanup;
    }

    //
    //  Get the name information.
    //
    if (FlagOn(Cbd->Iopb->OperationFlags, SL_OPEN_TARGET_DIRECTORY)) {

        //
        //  The SL_OPEN_TARGET_DIRECTORY flag indicates the caller is attempting
        //  to open the target of a rename or hard link creation operation. We
        //  must clear this flag when asking fltmgr for the name or the result
        //  will not include the final component. We need the full path in order
        //  to compare the name to our mapping.
        //


        ClearFlag(Cbd->Iopb->OperationFlags, SL_OPEN_TARGET_DIRECTORY);

        DebugTrace(DEBUG_TRACE_RENAME_REDIRECTION_OPERATIONS,
            ("[FileRedirector]: FileRedirectorPreCreate -> Clearing SL_OPEN_TARGET_DIRECTORY (Cbd = %p, FileObject = %p)\n",
                Cbd,
                FltObjects->FileObject));


        //
        //  Get the filename as it appears below this filter. Note that we use
        //  FLT_FILE_NAME_QUERY_FILESYSTEM_ONLY when querying the filename
        //  so that the filename as it appears below this filter does not end up
        //  in filter manager's name cache.
        //

        Status = FltGetFileNameInformation(Cbd,
            FLT_FILE_NAME_OPENED | FLT_FILE_NAME_QUERY_FILESYSTEM_ONLY,
            &NameInfo);

        //
        //  Restore the SL_OPEN_TARGET_DIRECTORY flag so the create will proceed
        //  for the target. The file systems depend on this flag being set in
        //  the target create in order for the subsequent SET_INFORMATION
        //  operation to proceed correctly.
        //

        SetFlag(Cbd->Iopb->OperationFlags, SL_OPEN_TARGET_DIRECTORY);

    }
    else {

        //
        //  Note that we use FLT_FILE_NAME_QUERY_DEFAULT when querying the
        //  filename. In the precreate the filename should not be in filter
        //  manager's name cache so there is no point looking there.
        //

        Status = FltGetFileNameInformation(Cbd,
            FLT_FILE_NAME_OPENED |
            FLT_FILE_NAME_QUERY_DEFAULT,
            &NameInfo);
    }

    if (!NT_SUCCESS(Status)) {

        DebugTrace(DEBUG_TRACE_REPARSE_OPERATIONS | DEBUG_TRACE_ERROR,
            ("[FileRedirector]: FileRedirectorPreCreate -> Failed to get name information (Cbd = %p, FileObject = %p)\n",
                Cbd,
                FltObjects->FileObject));

        goto FileRedirectorPreCreateCleanup;
    }


    DebugTrace(DEBUG_TRACE_REPARSE_OPERATIONS,
        ("[FileRedirector]: FileRedirectorPreCreate -> Processing create for file %wZ (Cbd = %p, FileObject = %p)\n",
            &NameInfo->Name,
            Cbd,
            FltObjects->FileObject));

    //
    //  Parse the filename information
    //

    Status = FltParseFileNameInformation(NameInfo);
    if (!NT_SUCCESS(Status)) {

        DebugTrace(DEBUG_TRACE_REPARSE_OPERATIONS | DEBUG_TRACE_ERROR,
            ("[FileRedirector]: FileRedirectorPreCreate -> Failed to parse name information for file %wZ (Cbd = %p, FileObject = %p)\n",
                &NameInfo->Name,
                Cbd,
                FltObjects->FileObject));

        goto FileRedirectorPreCreateCleanup;
    }


    Status = FileRedirectorMungeName(NameInfo, &NewFileName);

    if (!NT_SUCCESS(Status)) {

        if (Status == STATUS_NOT_FOUND) {
            Status = STATUS_SUCCESS;
        }

        goto FileRedirectorPreCreateCleanup;
    }


    DebugTrace(DEBUG_TRACE_REPARSE_OPERATIONS,
        ("[FileRedirector]: FileRedirectorPreCreate -> File name %wZ matches mapping. (Cbd = %p, FileObject = %p)\n",
            &NameInfo->Name,
            Cbd,
            FltObjects->FileObject));


    //
    //  Switch names
    //
    Status = Globals.ReplaceFileNameFunction(Cbd->Iopb->TargetFileObject,
        NewFileName.Buffer,
        NewFileName.Length);

    if (!NT_SUCCESS(Status)) {

        DebugTrace(DEBUG_TRACE_REPARSE_OPERATIONS | DEBUG_TRACE_ERROR,
            ("[FileRedirector]: FileRedirectorPreCreate -> Failed to allocate string for file %wZ (Cbd = %p, FileObject = %p)\n",
                &NameInfo->Name,
                Cbd,
                FltObjects->FileObject));

        goto FileRedirectorPreCreateCleanup;
    }

    Status = STATUS_REPARSE;


    DebugTrace(DEBUG_TRACE_REPARSE_OPERATIONS | DEBUG_TRACE_REPARSED_OPERATIONS,
        ("[FileRedirector]: FileRedirectorPreCreate -> Returning STATUS_REPARSE for file %wZ. (Cbd = %p, FileObject = %p)\n"
            "\tNewName = %wZ\n",
            &NameInfo->Name,
            Cbd,
            FltObjects->FileObject,
            &NewFileName));

FileRedirectorPreCreateCleanup:


    FileRedirectorFreeUnicodeString(&NewFileName);

    if (NameInfo != NULL) {

        FltReleaseFileNameInformation(NameInfo);
    }

    if (Status == STATUS_REPARSE) {

        //
        //  Reparse the open
        //

        Cbd->IoStatus.Status = STATUS_REPARSE;
        Cbd->IoStatus.Information = IO_REPARSE;
        CallbackStatus = FLT_PREOP_COMPLETE;

    }
    else if (!NT_SUCCESS(Status)) {

        //
        //  An error occurred, fail the open
        //

        DebugTrace(DEBUG_TRACE_ERROR,
            ("[FileRedirector]: FileRedirectorPreCreate -> Failed with status 0x%x \n",
                Status));

        Cbd->IoStatus.Status = Status;
        CallbackStatus = FLT_PREOP_COMPLETE;
    }

    DebugTrace(DEBUG_TRACE_ALL_IO,
        ("[FileRedirector]: FileRedirectorPreCreate -> Exit (Cbd = %p, FileObject = %p)\n",
            Cbd,
            FltObjects->FileObject));

    return CallbackStatus;

}


//
//  Support Routines
//

_When_(return == 0, _Post_satisfies_(String->Buffer != NULL))
//
// This routine allocates a unicode string
//
NTSTATUS
FileRedirectorAllocateUnicodeString(
    _Inout_ PUNICODE_STRING String
) {

    PAGED_CODE();

    String->Buffer = ExAllocatePoolWithTag(NonPagedPool,
        String->MaximumLength,
        FileRedirector_STRING_TAG);

    if (String->Buffer == NULL) {

        DebugTrace(DEBUG_TRACE_ERROR,
            ("[FileRedirector]: Failed to allocate unicode string of size 0x%x\n",
                String->MaximumLength));

        return STATUS_INSUFFICIENT_RESOURCES;
    }

    String->Length = 0;

    return STATUS_SUCCESS;
}

//
// This routine frees a unicode string
//
VOID
FileRedirectorFreeUnicodeString(
    _Inout_ PUNICODE_STRING String
) {
    PAGED_CODE();

    if (String->Buffer) {

        ExFreePoolWithTag(String->Buffer,
            FileRedirector_STRING_TAG);
        String->Buffer = NULL;
    }

    String->Length = String->MaximumLength = 0;
    String->Buffer = NULL;
}

//
//This routine is used to replace a file object's name with a provided name.This should only be called if IoReplaceFileObjectName is not on the system.
//
NTSTATUS
FileRedirectorReplaceFileObjectName(
    _In_ PFILE_OBJECT FileObject,
    _In_reads_bytes_(FileNameLength) PWSTR NewFileName,
    _In_ USHORT FileNameLength
) {
    PWSTR Buffer;
    PUNICODE_STRING FileName;
    USHORT NewMaxLength;

    PAGED_CODE();

    FileName = &FileObject->FileName;

    //
    // If the new name fits inside the current buffer we simply copy it over
    // instead of allocating a new buffer (and keep the MaximumLength value
    // the same).
    //
    if (FileNameLength <= FileName->MaximumLength) {

        goto CopyAndReturn;
    }

    //
    // Use an optimal buffer size
    //
    NewMaxLength = FileNameLength;

    Buffer = ExAllocatePoolWithTag(PagedPool,
        NewMaxLength,
        FileRedirector_STRING_TAG);

    if (!Buffer) {

        return STATUS_INSUFFICIENT_RESOURCES;
    }

    if (FileName->Buffer != NULL) {

        ExFreePool(FileName->Buffer);
    }

    FileName->Buffer = Buffer;
    FileName->MaximumLength = NewMaxLength;

CopyAndReturn:

    FileName->Length = FileNameLength;
    RtlZeroMemory(FileName->Buffer, FileName->MaximumLength);
    RtlCopyMemory(FileName->Buffer, NewFileName, FileNameLength);

    return STATUS_SUCCESS;
}


//
// This routine will create a new path based of the user-client replay
//
NTSTATUS
FileRedirectorMungeName(
    _In_ PFLT_FILE_NAME_INFORMATION NameInfo,
    _Out_ PUNICODE_STRING MungedPath
) {
    NTSTATUS Status = STATUS_NOT_FOUND;
    BOOLEAN Match;
    USHORT Length;

    PAGED_CODE();

    REPALY_MESSAGE Replay;
    Replay.ChangePath = 0;
    Match = FileRedirectorCompareMapping(NameInfo, &Replay);


    if (Match) {

        RtlInitUnicodeString(MungedPath, NULL);

        UNICODE_STRING FinalName;
        RtlInitUnicodeString(&FinalName, Replay.ResultFilePath);

        MungedPath->MaximumLength = (USHORT)FinalName.MaximumLength;
        Length = FinalName.MaximumLength;
        Status = FileRedirectorAllocateUnicodeString(MungedPath);

        if (!NT_SUCCESS(Status)) {

            goto FileRedirectorMungeNameCleanup;
        }

        RtlCopyUnicodeString(MungedPath, &FinalName);

        NT_ASSERT(NT_SUCCESS(Status));

        MungedPath->Length = Length - 2;

    }

FileRedirectorMungeNameCleanup:

    return Status;
}

//
// send file path you user-client for checing and returning the new path name to redirect to
//
BOOLEAN
FileRedirectorCompareMapping(
    _In_ PFLT_FILE_NAME_INFORMATION NameInfo,
    _Out_opt_ REPALY_MESSAGE * Replay
) {
    PAGED_CODE();


    NT_ASSERT(FlagOn(NameInfo->NamesParsed, FLTFL_FILE_NAME_PARSED_FINAL_COMPONENT) &&
        FlagOn(NameInfo->NamesParsed, FLTFL_FILE_NAME_PARSED_EXTENSION) &&
        FlagOn(NameInfo->NamesParsed, FLTFL_FILE_NAME_PARSED_STREAM) &&
        FlagOn(NameInfo->NamesParsed, FLTFL_FILE_NAME_PARSED_PARENT_DIR));


    NT_ASSERT(NameInfo->Name.Buffer == NameInfo->Volume.Buffer);
    NT_ASSERT(NameInfo->Name.Length >= NameInfo->Volume.Length);

    if (!Replay) {
        return FALSE;
    }
    NTSTATUS Status = FileRedirectorSendDataToUserClientAndReceiveReply(&NameInfo->Name, Replay);
    if (!NT_SUCCESS(Status)) {
        //  send\recieve data failed
        return FALSE;
    }

    if (Replay->ChangePath == 0) {
        return FALSE;
    }

    return TRUE;

}


//
//  PORT Communication Routines
//

//
// prepare the communication port
//
NTSTATUS
FileRedirectorPrepareCommunicationPort() {

    PAGED_CODE();
    NTSTATUS Status = STATUS_SUCCESS;
    OBJECT_ATTRIBUTES oa;
    UNICODE_STRING PortName = RTL_CONSTANT_STRING(COMMUNICATION_PORT_NAME);

    PFLT_PORT* ServerPort = NULL;

    PSECURITY_DESCRIPTOR SecurityDescriptor = NULL;
    Status = FltBuildDefaultSecurityDescriptor(&SecurityDescriptor, FLT_PORT_ALL_ACCESS);

    if (!NT_SUCCESS(Status)) {

        DebugTrace(DEBUG_TRACE_REPARSE_OPERATIONS | DEBUG_TRACE_ERROR,
            ("[FileRedirector]: FltBuildDefaultSecurityDescriptor -> Failed (Status = %x)\n", Status));

        return Status;
    }


    ServerPort = &(Globals.ScanServerPort);

    InitializeObjectAttributes(&oa,
        &PortName,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
        NULL,
        SecurityDescriptor);

    Status = FltCreateCommunicationPort(Globals.Filter,
        ServerPort,
        &oa,
        NULL,
        FileRedirectorConnectNotifyCallback,
        FileRedirectorDisconnectNotifyCallback,
        NULL,
        MaxNumberConnections);

    return Status;
}

//
// will be called when the user-client is connectign to the port to allow or deney the connection
//
NTSTATUS
FileRedirectorConnectNotifyCallback(
    IN PFLT_PORT ClientPort,
    IN PVOID ServerPortCookie,
    IN PVOID ConnectionContext,
    IN ULONG SizeOfContext,
    OUT PVOID * ConnectionPortCookie
) {

    PAGED_CODE();
    UNREFERENCED_PARAMETER(ServerPortCookie);
    UNREFERENCED_PARAMETER(SizeOfContext);
    UNREFERENCED_PARAMETER(ConnectionPortCookie);
    UNREFERENCED_PARAMETER(ConnectionContext);

    DebugTrace(DEBUG_TRACE_REPARSE_OPERATIONS | DEBUG_TRACE_ERROR,
        ("[FileRedirector]: User Client is Connecting\n"));

    Globals.ScanClientPort = ClientPort;

    //TODO
    //Should Validate the user Client to make sure it's ours

    return STATUS_SUCCESS;
}

//
// will be called when the user-client is disconnectign from the port.
//
VOID
FileRedirectorDisconnectNotifyCallback(
    _In_opt_ PVOID ConnectionCookie) {

    PAGED_CODE();
    UNREFERENCED_PARAMETER(ConnectionCookie);

    DebugTrace(DEBUG_TRACE_REPARSE_OPERATIONS | DEBUG_TRACE_ERROR,
        ("[FileRedirector]: User Client is Disconnecting \n"));

    FltCloseClientPort(Globals.Filter, &Globals.ScanClientPort);
    Globals.ScanClientPort = NULL;

}



//send data to user client and wait X sec for the reply
//return STATUS_SUCCESS if Received reply from user client, Error other wise
//default reply is Do not change file name
NTSTATUS
FileRedirectorSendDataToUserClientAndReceiveReply(
    _In_ PCUNICODE_STRING FileName,
    _Outptr_ REPALY_MESSAGE * Reply) {

    PAGED_CODE();

    if (!Reply) {
        return STATUS_UNSUCCESSFUL;
    }
    if (Globals.ScanClientPort == NULL) {

        DebugTrace(DEBUG_TRACE_REPARSE_OPERATIONS | DEBUG_TRACE_ERROR,
            ("[FileRedirector]: SendDataToUserClientAndReceiveReply -> Failed  User Client is not Connected\n"));

        return STATUS_PORT_DISCONNECTED;
    }

    ORIGINAL_FILE_PATH DriverMsg = { 0 };
    NTSTATUS Status = STATUS_SUCCESS;

    LARGE_INTEGER Timeout = { 0 };
    Timeout.QuadPart = -((LONGLONG)10) * (LONGLONG)1000 * (LONGLONG)100; // .1s
    Timeout.QuadPart *= WaitDelay;
    ULONG   ReplyLength = sizeof(REPALY_MESSAGE);

    RtlZeroMemory(Reply, sizeof(REPALY_MESSAGE));
    wcscpy_s(DriverMsg.OriginalFilePath, FileName->Length, FileName->Buffer);

    Status = FltSendMessage(Globals.Filter, &Globals.ScanClientPort, &DriverMsg,
        FileName->Length, Reply, &ReplyLength, &Timeout);


    if (Status == STATUS_TIMEOUT) {

        DebugTrace(DEBUG_TRACE_REPARSE_OPERATIONS | DEBUG_TRACE_ERROR,
            ("[FileRedirector]: FltSendMessage -> Failed Because Of TimeOut\n"));

        return Status;
    }
    else if (Status == STATUS_PORT_DISCONNECTED) {

        DebugTrace(DEBUG_TRACE_REPARSE_OPERATIONS | DEBUG_TRACE_ERROR,
            ("[FileRedirector]: FltSendMessage -> Failed Because PORT Disconnected\n"));

        return Status;
    }
    else if (!NT_SUCCESS(Status)) {

        DebugTrace(DEBUG_TRACE_REPARSE_OPERATIONS | DEBUG_TRACE_ERROR,
            ("[FileRedirector]: FltSendMessage -> Failed (Status = %x)\n", Status));

        return Status;
    }

    return STATUS_SUCCESS;
}