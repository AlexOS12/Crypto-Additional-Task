/*++

Copyright (c) 1999 - 2002  Microsoft Corporation

Module Name:

	passThrough.c

Abstract:

	This is the main module of the passThrough miniFilter driver.
	This filter hooks all IO operations for both pre and post operation
	callbacks.  The filter passes through the operations.

Environment:

	Kernel mode

--*/

#include <fltKernel.h>
#include <dontuse.h>
#include <suppress.h>
#include "aes.h"
#include <stdio.h>
//#include <fileapi.h>

#pragma prefast(disable:__WARNING_ENCODE_MEMBER_FUNCTION_POINTER, "Not valid for kernel mode drivers")

PFLT_PORT ServerPort;
PFLT_PORT ClientPort;

uint8_t* KEY[32];
uint8_t* IV[16];

NTSTATUS
ClientMessage(
	_In_ PVOID ConnectionCookie,
	_In_reads_bytes_opt_(InputBufferSize) PVOID InputBuffer,
	_In_ ULONG InputBufferSize,
	_Out_writes_bytes_to_opt_(OutputBufferSize, *ReturnOutputBufferLength) PVOID OutputBuffer,
	_In_ ULONG OutputBufferSize,
	_Out_ PULONG ReturnOutputBufferLength
);

NTSTATUS
ClientConnect(
	_In_ PFLT_PORT ClientPort,
	_In_ PVOID ServerPortCookie,
	_In_reads_bytes_(SizeOfContext) PVOID ConnectionContext,
	_In_ ULONG SizeOfContext,
	_Flt_ConnectionCookie_Outptr_ PVOID* ConnectionCookie
);

VOID
ClientDisconnect(
	_In_opt_ PVOID ConnectionCookie
);

PFLT_FILTER gFilterHandle;
ULONG_PTR OperationStatusCtx = 1;

#define PTDBG_TRACE_ROUTINES            0x00000001
#define PTDBG_TRACE_OPERATION_STATUS    0x00000002

ULONG gTraceFlags = 0;


#define PT_DBG_PRINT( _dbgLevel, _string )          \
    (FlagOn(gTraceFlags,(_dbgLevel)) ?              \
        DbgPrint _string :                          \
        ((int)0))

/*************************************************************************
	Prototypes
*************************************************************************/

DRIVER_INITIALIZE DriverEntry;
NTSTATUS
DriverEntry(
	_In_ PDRIVER_OBJECT DriverObject,
	_In_ PUNICODE_STRING RegistryPath
);

NTSTATUS
PtInstanceSetup(
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_ FLT_INSTANCE_SETUP_FLAGS Flags,
	_In_ DEVICE_TYPE VolumeDeviceType,
	_In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
);

VOID
PtInstanceTeardownStart(
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
);

VOID
PtInstanceTeardownComplete(
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
);

NTSTATUS
PtUnload(
	_In_ FLT_FILTER_UNLOAD_FLAGS Flags
);

NTSTATUS
PtInstanceQueryTeardown(
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
);

FLT_PREOP_CALLBACK_STATUS
PtPreOperationPassThrough(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID* CompletionContext
);

VOID
PtOperationStatusCallback(
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_ PFLT_IO_PARAMETER_BLOCK ParameterSnapshot,
	_In_ NTSTATUS OperationStatus,
	_In_ PVOID RequesterContext
);

FLT_POSTOP_CALLBACK_STATUS
PtPostOperationPassThrough(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_opt_ PVOID CompletionContext,
	_In_ FLT_POST_OPERATION_FLAGS Flags
);

FLT_PREOP_CALLBACK_STATUS
PtPreOperationNoPostOperationPassThrough(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID* CompletionContext
);

BOOLEAN
PtDoRequestOperationStatus(
	_In_ PFLT_CALLBACK_DATA Data
);

//
//  Assign text sections for each routine.
//

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, PtUnload)
#pragma alloc_text(PAGE, PtInstanceQueryTeardown)
#pragma alloc_text(PAGE, PtInstanceSetup)
#pragma alloc_text(PAGE, PtInstanceTeardownStart)
#pragma alloc_text(PAGE, PtInstanceTeardownComplete)
#pragma alloc_text(PAGE, ClientConnect)
#pragma alloc_text(PAGE, ClientDisconnect)
#pragma alloc_text(PAGE, ClientMessage)
#endif

//
//  operation registration
//

CONST FLT_OPERATION_REGISTRATION Callbacks[] = {
	{ IRP_MJ_CREATE,
	  0,
	  PtPreOperationPassThrough,
	  PtPostOperationPassThrough },

	{ IRP_MJ_CREATE_NAMED_PIPE,
	  0,
	  PtPreOperationPassThrough,
	  PtPostOperationPassThrough },

	{ IRP_MJ_CLOSE,
	  0,
	  PtPreOperationPassThrough,
	  PtPostOperationPassThrough },

	{ IRP_MJ_READ,
	  0,
	  PtPreOperationPassThrough,
	  PtPostOperationPassThrough },

	{ IRP_MJ_WRITE,
	  0,
	  PtPreOperationPassThrough,
	  PtPostOperationPassThrough },

	{ IRP_MJ_QUERY_INFORMATION,
	  0,
	  PtPreOperationPassThrough,
	  PtPostOperationPassThrough },

	{ IRP_MJ_SET_INFORMATION,
	  0,
	  PtPreOperationPassThrough,
	  PtPostOperationPassThrough },

	{ IRP_MJ_QUERY_EA,
	  0,
	  PtPreOperationPassThrough,
	  PtPostOperationPassThrough },

	{ IRP_MJ_SET_EA,
	  0,
	  PtPreOperationPassThrough,
	  PtPostOperationPassThrough },

	{ IRP_MJ_FLUSH_BUFFERS,
	  0,
	  PtPreOperationPassThrough,
	  PtPostOperationPassThrough },

	{ IRP_MJ_QUERY_VOLUME_INFORMATION,
	  0,
	  PtPreOperationPassThrough,
	  PtPostOperationPassThrough },

	{ IRP_MJ_SET_VOLUME_INFORMATION,
	  0,
	  PtPreOperationPassThrough,
	  PtPostOperationPassThrough },

	{ IRP_MJ_DIRECTORY_CONTROL,
	  0,
	  PtPreOperationPassThrough,
	  PtPostOperationPassThrough },

	{ IRP_MJ_FILE_SYSTEM_CONTROL,
	  0,
	  PtPreOperationPassThrough,
	  PtPostOperationPassThrough },

	{ IRP_MJ_DEVICE_CONTROL,
	  0,
	  PtPreOperationPassThrough,
	  PtPostOperationPassThrough },

	{ IRP_MJ_INTERNAL_DEVICE_CONTROL,
	  0,
	  PtPreOperationPassThrough,
	  PtPostOperationPassThrough },

	{ IRP_MJ_SHUTDOWN,
	  0,
	  PtPreOperationNoPostOperationPassThrough,
	  NULL },                               //post operations not supported

	{ IRP_MJ_LOCK_CONTROL,
	  0,
	  PtPreOperationPassThrough,
	  PtPostOperationPassThrough },

	{ IRP_MJ_CLEANUP,
	  0,
	  PtPreOperationPassThrough,
	  PtPostOperationPassThrough },

	{ IRP_MJ_CREATE_MAILSLOT,
	  0,
	  PtPreOperationPassThrough,
	  PtPostOperationPassThrough },

	{ IRP_MJ_QUERY_SECURITY,
	  0,
	  PtPreOperationPassThrough,
	  PtPostOperationPassThrough },

	{ IRP_MJ_SET_SECURITY,
	  0,
	  PtPreOperationPassThrough,
	  PtPostOperationPassThrough },

	{ IRP_MJ_QUERY_QUOTA,
	  0,
	  PtPreOperationPassThrough,
	  PtPostOperationPassThrough },

	{ IRP_MJ_SET_QUOTA,
	  0,
	  PtPreOperationPassThrough,
	  PtPostOperationPassThrough },

	{ IRP_MJ_PNP,
	  0,
	  PtPreOperationPassThrough,
	  PtPostOperationPassThrough },

	{ IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION,
	  0,
	  PtPreOperationPassThrough,
	  PtPostOperationPassThrough },

	{ IRP_MJ_RELEASE_FOR_SECTION_SYNCHRONIZATION,
	  0,
	  PtPreOperationPassThrough,
	  PtPostOperationPassThrough },

	{ IRP_MJ_ACQUIRE_FOR_MOD_WRITE,
	  0,
	  PtPreOperationPassThrough,
	  PtPostOperationPassThrough },

	{ IRP_MJ_RELEASE_FOR_MOD_WRITE,
	  0,
	  PtPreOperationPassThrough,
	  PtPostOperationPassThrough },

	{ IRP_MJ_ACQUIRE_FOR_CC_FLUSH,
	  0,
	  PtPreOperationPassThrough,
	  PtPostOperationPassThrough },

	{ IRP_MJ_RELEASE_FOR_CC_FLUSH,
	  0,
	  PtPreOperationPassThrough,
	  PtPostOperationPassThrough },

	{ IRP_MJ_FAST_IO_CHECK_IF_POSSIBLE,
	  0,
	  PtPreOperationPassThrough,
	  PtPostOperationPassThrough },

	{ IRP_MJ_NETWORK_QUERY_OPEN,
	  0,
	  PtPreOperationPassThrough,
	  PtPostOperationPassThrough },

	{ IRP_MJ_MDL_READ,
	  0,
	  PtPreOperationPassThrough,
	  PtPostOperationPassThrough },

	{ IRP_MJ_MDL_READ_COMPLETE,
	  0,
	  PtPreOperationPassThrough,
	  PtPostOperationPassThrough },

	{ IRP_MJ_PREPARE_MDL_WRITE,
	  0,
	  PtPreOperationPassThrough,
	  PtPostOperationPassThrough },

	{ IRP_MJ_MDL_WRITE_COMPLETE,
	  0,
	  PtPreOperationPassThrough,
	  PtPostOperationPassThrough },

	{ IRP_MJ_VOLUME_MOUNT,
	  0,
	  PtPreOperationPassThrough,
	  PtPostOperationPassThrough },

	{ IRP_MJ_VOLUME_DISMOUNT,
	  0,
	  PtPreOperationPassThrough,
	  PtPostOperationPassThrough },

	{ IRP_MJ_OPERATION_END }
};

//
//  This defines what we want to filter with FltMgr
//

CONST FLT_REGISTRATION FilterRegistration = {

	sizeof(FLT_REGISTRATION),         //  Size
	FLT_REGISTRATION_VERSION,           //  Version
	0,                                  //  Flags

	NULL,                               //  Context
	Callbacks,                          //  Operation callbacks

	PtUnload,                           //  MiniFilterUnload

	PtInstanceSetup,                    //  InstanceSetup
	PtInstanceQueryTeardown,            //  InstanceQueryTeardown
	PtInstanceTeardownStart,            //  InstanceTeardownStart
	PtInstanceTeardownComplete,         //  InstanceTeardownComplete

	NULL,                               //  GenerateFileName
	NULL,                               //  GenerateDestinationFileName
	NULL                                //  NormalizeNameComponent

};



NTSTATUS
PtInstanceSetup(
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_ FLT_INSTANCE_SETUP_FLAGS Flags,
	_In_ DEVICE_TYPE VolumeDeviceType,
	_In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
)
/*++

Routine Description:

	This routine is called whenever a new instance is created on a volume. This
	gives us a chance to decide if we need to attach to this volume or not.

	If this routine is not defined in the registration structure, automatic
	instances are alwasys created.

Arguments:

	FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
		opaque handles to this filter, instance and its associated volume.

	Flags - Flags describing the reason for this attach request.

Return Value:

	STATUS_SUCCESS - attach
	STATUS_FLT_DO_NOT_ATTACH - do not attach

--*/
{
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(Flags);
	UNREFERENCED_PARAMETER(VolumeDeviceType);
	UNREFERENCED_PARAMETER(VolumeFilesystemType);

	PAGED_CODE();

	PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
		("PassThrough!PtInstanceSetup: Entered\n"));

	return STATUS_SUCCESS;
}


NTSTATUS
PtInstanceQueryTeardown(
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
)
/*++

Routine Description:

	This is called when an instance is being manually deleted by a
	call to FltDetachVolume or FilterDetach thereby giving us a
	chance to fail that detach request.

	If this routine is not defined in the registration structure, explicit
	detach requests via FltDetachVolume or FilterDetach will always be
	failed.

Arguments:

	FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
		opaque handles to this filter, instance and its associated volume.

	Flags - Indicating where this detach request came from.

Return Value:

	Returns the status of this operation.

--*/
{
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(Flags);

	PAGED_CODE();

	PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
		("PassThrough!PtInstanceQueryTeardown: Entered\n"));

	return STATUS_SUCCESS;
}


VOID
PtInstanceTeardownStart(
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
)
/*++

Routine Description:

	This routine is called at the start of instance teardown.

Arguments:

	FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
		opaque handles to this filter, instance and its associated volume.

	Flags - Reason why this instance is been deleted.

Return Value:

	None.

--*/
{
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(Flags);

	PAGED_CODE();

	PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
		("PassThrough!PtInstanceTeardownStart: Entered\n"));
}


VOID
PtInstanceTeardownComplete(
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
)
/*++

Routine Description:

	This routine is called at the end of instance teardown.

Arguments:

	FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
		opaque handles to this filter, instance and its associated volume.

	Flags - Reason why this instance is been deleted.

Return Value:

	None.

--*/
{
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(Flags);

	PAGED_CODE();

	PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
		("PassThrough!PtInstanceTeardownComplete: Entered\n"));
}


/*************************************************************************
	MiniFilter initialization and unload routines.
*************************************************************************/

NTSTATUS
DriverEntry(
	_In_ PDRIVER_OBJECT DriverObject,
	_In_ PUNICODE_STRING RegistryPath
)
/*++

Routine Description:

	This is the initialization routine for this miniFilter driver.  This
	registers with FltMgr and initializes all global data structures.

Arguments:

	DriverObject - Pointer to driver object created by the system to
		represent this driver.

	RegistryPath - Unicode string identifying where the parameters for this
		driver are located in the registry.

Return Value:

	Returns STATUS_SUCCESS.

--*/
{
	NTSTATUS status;

	UNREFERENCED_PARAMETER(RegistryPath);

	status = FltRegisterFilter(DriverObject,
		&FilterRegistration,
		&gFilterHandle);

	FLT_ASSERT(NT_SUCCESS(status));

	if (NT_SUCCESS(status)) {

		DbgPrint("[PassThrough] DriverEntry\n");
		status = FltStartFiltering(gFilterHandle);

		if (!NT_SUCCESS(status))
		{
			DbgPrint("[PassThrough] Can`t start!\n");
			FltUnregisterFilter(gFilterHandle);
			return status;
		}

		memcpy(KEY, "1234123412341234123412341234123", 32);
		memcpy(IV, "1234123412341234123412341234123", 16);


		//HANDLE file;
		//DWORD m;
		//char buffer[128];
		//file = CreateFileA("%USERPROFILE%\ptsettings.pts", GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
		//ReadFile(file, buffer, sizeof(char), &m, NULL);
		//DbgPrint("[PassThrough] path: %s", buffer);


		//FILE file;
		//errno_t error;
		//error = fopen_s(&file, "%USERPROFILE%\ptsettings.pts", "r");
		//if (error == 0)
		//{
		//	DbgPrint("[PassThrough] path: %s", &file);
		//	/*char buffer[128];
		//	fread(buffer, sizeof(char), 128, &file);
		//	struct AES_ctx ctx;
		//	AES_init_ctx_iv(&ctx, "f800c4ed995194cb345c86f49e49b965e024670f623ca765e7ef95a2c19e6f27", "5d25d31af94a172607a171b14368ffa1");
		//	AES_CBC_encrypt_buffer(&ctx, buffer, 128);*/
		//}
		//if (&file)
		//{
		//	fclose(&file);
		//}

		// Создание сервера
		PSECURITY_DESCRIPTOR  securityDescriptor;
		OBJECT_ATTRIBUTES attr;
		UNICODE_STRING portName;

		NTSTATUS portsStatus = FltBuildDefaultSecurityDescriptor(&securityDescriptor, FLT_PORT_ALL_ACCESS);

		if (NT_SUCCESS(portsStatus))
		{
			DbgPrint("[PassThrough] Ports success\n");

			RtlInitUnicodeString(&portName, L"passThrough");
			DbgPrint("[PassThrough] Port name: %ws\n", &portName);

			InitializeObjectAttributes(&attr, &portName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, &securityDescriptor);

			NTSTATUS serverStatus = FltCreateCommunicationPort(gFilterHandle, &ServerPort, &attr, NULL, ClientConnect, ClientDisconnect, NULL, 1);
			//NTSTATUS serverStatus = FltCreateCommunicationPort(gFilterHandle, &ServerPort, &attr, NULL, ClientConnect, ClientDisconnect, ClientMessage, 1);

			FltFreeSecurityDescriptor(securityDescriptor);

			if (!NT_SUCCESS(serverStatus))
			{
				DbgPrint("[PassThrough] Server ERROR\n");
			}
		}
		/*else
		{
			DbgPrint("[PassThrough] Port %s, %d\n", ServerPort, ServerPort);
		}*/

	}

	return status;
}

NTSTATUS
ClientConnect(
	_In_ PFLT_PORT clientPort,
	_In_ PVOID ServerPortCookie,
	_In_reads_bytes_(SizeOfContext) PVOID ConnectionContext,
	_In_ ULONG SizeOfContext,
	_Flt_ConnectionCookie_Outptr_ PVOID* ConnectionCookie
)
{
	PAGED_CODE();

	UNREFERENCED_PARAMETER(ServerPortCookie);
	UNREFERENCED_PARAMETER(ConnectionContext);
	UNREFERENCED_PARAMETER(SizeOfContext);
	UNREFERENCED_PARAMETER(ConnectionCookie);

	FLT_ASSERT(ClientPort == NULL);
	ClientPort = clientPort;
	return STATUS_SUCCESS;
}


VOID
ClientDisconnect(_In_opt_ PVOID ConnectionCookie)
{
	PAGED_CODE();

	UNREFERENCED_PARAMETER(ConnectionCookie);

	FltCloseClientPort(gFilterHandle, &ClientPort);
}

NTSTATUS
ClientMessage(
	_In_ PVOID ConnectionCookie,
	_In_reads_bytes_opt_(InputBufferSize) PVOID InputBuffer,
	_In_ ULONG InputBufferSize,
	_Out_writes_bytes_to_opt_(OutputBufferSize, *ReturnOutputBufferLength) PVOID OutputBuffer,
	_In_ ULONG OutputBufferSize,
	_Out_ PULONG ReturnOutputBufferLength
)
{
	//MINISPY_COMMAND command;
	NTSTATUS status;

	PAGED_CODE();

	UNREFERENCED_PARAMETER(ConnectionCookie);

	//
	//                      **** PLEASE READ ****
	//
	//  The INPUT and OUTPUT buffers are raw user mode addresses.  The filter
	//  manager has already done a ProbedForRead (on InputBuffer) and
	//  ProbedForWrite (on OutputBuffer) which guarentees they are valid
	//  addresses based on the access (user mode vs. kernel mode).  The
	//  minifilter does not need to do their own probe.
	//
	//  The filter manager is NOT doing any alignment checking on the pointers.
	//  The minifilter must do this themselves if they care (see below).
	//
	//  The minifilter MUST continue to use a try/except around any access to
	//  these buffers.
	//

//	if ((InputBuffer != NULL) &&
//		(InputBufferSize >= (FIELD_OFFSET(COMMAND_MESSAGE, Command) +
//			sizeof(MINISPY_COMMAND)))) {
//
//		try {
//
//			//
//			//  Probe and capture input message: the message is raw user mode
//			//  buffer, so need to protect with exception handler
//			//
//
//			command = ((PCOMMAND_MESSAGE)InputBuffer)->Command;
//
//		} except(SpyExceptionFilter(GetExceptionInformation(), TRUE)) {
//
//			return GetExceptionCode();
//		}
//
//		switch (command) {
//
//		case GetMiniSpyLog:
//
//			//
//			//  Return as many log records as can fit into the OutputBuffer
//			//
//
//			if ((OutputBuffer == NULL) || (OutputBufferSize == 0)) {
//
//				status = STATUS_INVALID_PARAMETER;
//				break;
//			}
//
//			//
//			//  We want to validate that the given buffer is POINTER
//			//  aligned.  But if this is a 64bit system and we want to
//			//  support 32bit applications we need to be careful with how
//			//  we do the check.  Note that the way SpyGetLog is written
//			//  it actually does not care about alignment but we are
//			//  demonstrating how to do this type of check.
//			//
//
//#if defined(_WIN64)
//
//			if (IoIs32bitProcess(NULL)) {
//
//				//
//				//  Validate alignment for the 32bit process on a 64bit
//				//  system
//				//
//
//				if (!IS_ALIGNED(OutputBuffer, sizeof(ULONG))) {
//
//					status = STATUS_DATATYPE_MISALIGNMENT;
//					break;
//				}
//
//			}
//			else {
//
//#endif
//
//				if (!IS_ALIGNED(OutputBuffer, sizeof(PVOID))) {
//
//					status = STATUS_DATATYPE_MISALIGNMENT;
//					break;
//				}
//
//#if defined(_WIN64)
//
//			}
//
//#endif
//
//			//
//			//  Get the log record.
//			//
//
//			status = SpyGetLog(OutputBuffer,
//				OutputBufferSize,
//				ReturnOutputBufferLength);
//			break;
//
//
//		case GetMiniSpyVersion:
//
//			//
//			//  Return version of the MiniSpy filter driver.  Verify
//			//  we have a valid user buffer including valid
//			//  alignment
//			//
//
//			if ((OutputBufferSize < sizeof(MINISPYVER)) ||
//				(OutputBuffer == NULL)) {
//
//				status = STATUS_INVALID_PARAMETER;
//				break;
//			}
//
//			//
//			//  Validate Buffer alignment.  If a minifilter cares about
//			//  the alignment value of the buffer pointer they must do
//			//  this check themselves.  Note that a try/except will not
//			//  capture alignment faults.
//			//
//
//			if (!IS_ALIGNED(OutputBuffer, sizeof(ULONG))) {
//
//				status = STATUS_DATATYPE_MISALIGNMENT;
//				break;
//			}
//
//			//
//			//  Protect access to raw user-mode output buffer with an
//			//  exception handler
//			//
//
//			try {
//
//				((PMINISPYVER)OutputBuffer)->Major = MINISPY_MAJ_VERSION;
//				((PMINISPYVER)OutputBuffer)->Minor = MINISPY_MIN_VERSION;
//
//			} except(SpyExceptionFilter(GetExceptionInformation(), TRUE)) {
//
//				return GetExceptionCode();
//			}
//
//			*ReturnOutputBufferLength = sizeof(MINISPYVER);
//			status = STATUS_SUCCESS;
//			break;
//
//		default:
//			status = STATUS_INVALID_PARAMETER;
//			break;
//		}
//
//	}
//	else {
//
	//status = STATUS_INVALID_PARAMETER;
	//	}
	//
	//return status;


	STRING FNameString;
	DbgPrint(("[PassThrough] Content:%s | Size: %d\n", InputBuffer, InputBufferSize));

	return STATUS_ABANDONED;

}

NTSTATUS
PtUnload(
	_In_ FLT_FILTER_UNLOAD_FLAGS Flags
)
/*++

Routine Description:

	This is the unload routine for this miniFilter driver. This is called
	when the minifilter is about to be unloaded. We can fail this unload
	request if this is not a mandatory unloaded indicated by the Flags
	parameter.

Arguments:

	Flags - Indicating if this is a mandatory unload.

Return Value:

	Returns the final status of this operation.

--*/
{
	UNREFERENCED_PARAMETER(Flags);

	PAGED_CODE();

	PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
		("PassThrough!PtUnload: Entered\n"));

	FltCloseCommunicationPort(ServerPort);

	FltUnregisterFilter(gFilterHandle);

	return STATUS_SUCCESS;
}


/*************************************************************************
	MiniFilter callback routines.
*************************************************************************/
FLT_PREOP_CALLBACK_STATUS
PtPreOperationPassThrough(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID* CompletionContext
)
/*++

Routine Description:

	This routine is the main pre-operation dispatch routine for this
	miniFilter. Since this is just a simple passThrough miniFilter it
	does not do anything with the callbackData but rather return
	FLT_PREOP_SUCCESS_WITH_CALLBACK thereby passing it down to the next
	miniFilter in the chain.

	This is non-pageable because it could be called on the paging path

Arguments:

	Data - Pointer to the filter callbackData that is passed to us.

	FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
		opaque handles to this filter, instance, its associated volume and
		file object.

	CompletionContext - The context for the completion routine for this
		operation.

Return Value:

	The return value is the status of the operation.

--*/
{
	NTSTATUS status;

	PFLT_FILE_NAME_INFORMATION NameInfo = NULL;
	status = FltGetFileNameInformation(
		Data,
		FLT_FILE_NAME_NORMALIZED |
		FLT_FILE_NAME_QUERY_DEFAULT,
		&NameInfo);
	UNICODE_STRING required_extension = RTL_CONSTANT_STRING(L"supersecure");
	if (NT_SUCCESS(status))
	{
		if (RtlEqualUnicodeString(&required_extension, &NameInfo->Extension, FALSE) == TRUE) {

			if (Data->Iopb->MajorFunction == IRP_MJ_WRITE) {
				if (Data->Iopb->Parameters.Write.WriteBuffer) {
					try
					{
						DbgPrint("[PassThrough] InBuffer: %s\n", Data->Iopb->Parameters.Write.WriteBuffer);

						// Key and IV for AES
						uint8_t buffer[128];

						memcpy(buffer, Data->Iopb->Parameters.Write.WriteBuffer, 128);

						// Initializing AES
						struct AES_ctx ctx;

						AES_init_ctx_iv(&ctx, KEY, IV);
						AES_CBC_encrypt_buffer(&ctx, buffer, 128);

						memcpy(Data->Iopb->Parameters.Write.WriteBuffer, buffer, 128);

						DbgPrint("[PassThrough] OutBuffer: %s\n", Data->Iopb->Parameters.Write.WriteBuffer);

						leave;
					}
					finally
					{

					}
				}
				else {
					DbgPrint("[PassThrough] InBuffer is empty or null\n");
				}
			}
		}
	}


	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);

	PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
		("PassThrough!PtPreOperationPassThrough: Entered\n"));

	//
	//  See if this is an operation we would like the operation status
	//  for.  If so request it.
	//
	//  NOTE: most filters do NOT need to do this.  You only need to make
	//        this call if, for example, you need to know if the oplock was
	//        actually granted.
	//

	if (PtDoRequestOperationStatus(Data)) {

		status = FltRequestOperationStatusCallback(Data,
			PtOperationStatusCallback,
			(PVOID)(++OperationStatusCtx));
		if (!NT_SUCCESS(status)) {

			PT_DBG_PRINT(PTDBG_TRACE_OPERATION_STATUS,
				("PassThrough!PtPreOperationPassThrough: FltRequestOperationStatusCallback Failed, status=%08x\n",
					status));
		}
	}

	return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

VOID
PtOperationStatusCallback(
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_ PFLT_IO_PARAMETER_BLOCK ParameterSnapshot,
	_In_ NTSTATUS OperationStatus,
	_In_ PVOID RequesterContext
)
/*++

Routine Description:

	This routine is called when the given operation returns from the call
	to IoCallDriver.  This is useful for operations where STATUS_PENDING
	means the operation was successfully queued.  This is useful for OpLocks
	and directory change notification operations.

	This callback is called in the context of the originating thread and will
	never be called at DPC level.  The file object has been correctly
	referenced so that you can access it.  It will be automatically
	dereferenced upon return.

	This is non-pageable because it could be called on the paging path

Arguments:

	FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
		opaque handles to this filter, instance, its associated volume and
		file object.

	RequesterContext - The context for the completion routine for this
		operation.

	OperationStatus -

Return Value:

	The return value is the status of the operation.

--*/
{
	UNREFERENCED_PARAMETER(FltObjects);

	PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
		("PassThrough!PtOperationStatusCallback: Entered\n"));

	PT_DBG_PRINT(PTDBG_TRACE_OPERATION_STATUS,
		("PassThrough!PtOperationStatusCallback: Status=%08x ctx=%p IrpMj=%02x.%02x \"%s\"\n",
			OperationStatus,
			RequesterContext,
			ParameterSnapshot->MajorFunction,
			ParameterSnapshot->MinorFunction,
			FltGetIrpName(ParameterSnapshot->MajorFunction)));
}

FLT_POSTOP_CALLBACK_STATUS
PtPostOperationPassThrough(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_opt_ PVOID CompletionContext,
	_In_ FLT_POST_OPERATION_FLAGS Flags
)
/*++

Routine Description:

	This routine is the post-operation completion routine for this
	miniFilter.

	This is non-pageable because it may be called at DPC level.

Arguments:

	Data - Pointer to the filter callbackData that is passed to us.

	FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
		opaque handles to this filter, instance, its associated volume and
		file object.

	CompletionContext - The completion context set in the pre-operation routine.

	Flags - Denotes whether the completion is successful or is being drained.

Return Value:

	The return value is the status of the operation.

--*/
{
	UNREFERENCED_PARAMETER(Data);
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);
	UNREFERENCED_PARAMETER(Flags);

	NTSTATUS status;

	PFLT_FILE_NAME_INFORMATION NameInfo = NULL;
	status = FltGetFileNameInformation(
		Data,
		FLT_FILE_NAME_NORMALIZED |
		FLT_FILE_NAME_QUERY_DEFAULT,
		&NameInfo);
	UNICODE_STRING required_extension = RTL_CONSTANT_STRING(L"supersecure");
	if (NT_SUCCESS(status))
	{
		if (RtlEqualUnicodeString(&required_extension, &NameInfo->Extension, FALSE) == TRUE) {

			if (Data->Iopb->MajorFunction == IRP_MJ_READ) {
				DbgPrint("[PassThrough] Reading file: %wZ | %wZ\n", NameInfo->Name, NameInfo->Extension);
				// Decrypting is gonna be here
				if (Data->Iopb->Parameters.Read.ReadBuffer) {
					try
					{
						DbgPrint("[PassThrough] InBuffer: %s\n", Data->Iopb->Parameters.Read.ReadBuffer);

						// Создание и заполнение буфера
						uint8_t buffer[128];
						memcpy(buffer, Data->Iopb->Parameters.Read.ReadBuffer, 128);

						// Инициализация контекста для шифрования
						struct AES_ctx ctx;
						AES_init_ctx_iv(&ctx, KEY, IV);
						AES_CBC_decrypt_buffer(&ctx, buffer, 128);

						memcpy(Data->Iopb->Parameters.Read.ReadBuffer, buffer, 128);

						DbgPrint("[PassThrough] OutBuffer (Data->Iopb...): %s\n", Data->Iopb->Parameters.Read.ReadBuffer);

						leave;
					}
					finally
					{
					}
				}
				else {
					DbgPrint("[PassThrough] InBuffer is empty or null\n");
				}
			}
		}
	}

	return FLT_POSTOP_FINISHED_PROCESSING;
}

FLT_PREOP_CALLBACK_STATUS
PtPreOperationNoPostOperationPassThrough(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID* CompletionContext
)
/*++

Routine Description:

	This routine is the main pre-operation dispatch routine for this
	miniFilter. Since this is just a simple passThrough miniFilter it
	does not do anything with the callbackData but rather return
	FLT_PREOP_SUCCESS_WITH_CALLBACK thereby passing it down to the next
	miniFilter in the chain.

	This is non-pageable because it could be called on the paging path

Arguments:

	Data - Pointer to the filter callbackData that is passed to us.

	FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
		opaque handles to this filter, instance, its associated volume and
		file object.

	CompletionContext - The context for the completion routine for this
		operation.

Return Value:

	The return value is the status of the operation.

--*/
{
	UNREFERENCED_PARAMETER(Data);
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);

	PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
		("PassThrough!PtPreOperationNoPostOperationPassThrough: Entered\n"));

	return FLT_PREOP_SUCCESS_NO_CALLBACK;
}


BOOLEAN
PtDoRequestOperationStatus(
	_In_ PFLT_CALLBACK_DATA Data
)
/*++

Routine Description:

	This identifies those operations we want the operation status for.  These
	are typically operations that return STATUS_PENDING as a normal completion
	status.

Arguments:

Return Value:

	TRUE - If we want the operation status
	FALSE - If we don't

--*/
{
	PFLT_IO_PARAMETER_BLOCK iopb = Data->Iopb;

	//
	//  return boolean state based on which operations we are interested in
	//

	return (BOOLEAN)

		//
		//  Check for oplock operations
		//

		(((iopb->MajorFunction == IRP_MJ_FILE_SYSTEM_CONTROL) &&
			((iopb->Parameters.FileSystemControl.Common.FsControlCode == FSCTL_REQUEST_FILTER_OPLOCK) ||
				(iopb->Parameters.FileSystemControl.Common.FsControlCode == FSCTL_REQUEST_BATCH_OPLOCK) ||
				(iopb->Parameters.FileSystemControl.Common.FsControlCode == FSCTL_REQUEST_OPLOCK_LEVEL_1) ||
				(iopb->Parameters.FileSystemControl.Common.FsControlCode == FSCTL_REQUEST_OPLOCK_LEVEL_2)))

			||

			//
			//    Check for directy change notification
			//

			((iopb->MajorFunction == IRP_MJ_DIRECTORY_CONTROL) &&
				(iopb->MinorFunction == IRP_MN_NOTIFY_CHANGE_DIRECTORY))
			);
}

