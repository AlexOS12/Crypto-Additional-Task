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


PFLT_FILTER gFilterHandle;
PFLT_PORT ServerPort = NULL;
PFLT_PORT ClientPort = NULL;

uint8_t* KEY[32];
uint8_t* IV[16];

/*************************************************************************
	Prototypes
*************************************************************************/
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

//NTSTATUS
//ClientMessage(
//	_In_ PVOID ConnectionCookie,
//	_In_reads_bytes_opt_(InputBufferSize) PVOID InputBuffer,
//	_In_ ULONG InputBufferSize,
//	_Out_writes_bytes_to_opt_(OutputBufferSize, *ReturnOutputBufferLength) PVOID OutputBuffer,
//	_In_ ULONG OutputBufferSize,
//	_Out_ PULONG ReturnOutputBufferLength
//);

DRIVER_INITIALIZE DriverEntry;
NTSTATUS
DriverEntry(
	_In_ PDRIVER_OBJECT DriverObject,
	_In_ PUNICODE_STRING RegistryPath
);

NTSTATUS
PtUnload(
	_In_ FLT_FILTER_UNLOAD_FLAGS Flags
);

FLT_PREOP_CALLBACK_STATUS
PtPreOperationPassThrough(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID* CompletionContext
);

//VOID
//PtOperationStatusCallback(
//	_In_ PCFLT_RELATED_OBJECTS FltObjects,
//	_In_ PFLT_IO_PARAMETER_BLOCK ParameterSnapshot,
//	_In_ NTSTATUS OperationStatus,
//	_In_ PVOID RequesterContext
//);

FLT_POSTOP_CALLBACK_STATUS
PtPostOperationPassThrough(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_opt_ PVOID CompletionContext,
	_In_ FLT_POST_OPERATION_FLAGS Flags
);

//
//  operation registration
//

CONST FLT_OPERATION_REGISTRATION Callbacks[] = {
	{ IRP_MJ_READ,
	  0,
	  PtPreOperationPassThrough,
	  PtPostOperationPassThrough },
	{ IRP_MJ_WRITE,
	  0,
	  PtPreOperationPassThrough,
	  PtPostOperationPassThrough },
	{ IRP_MJ_OPERATION_END }
};

//
//  This defines what we want to filter with FltMgr
//

CONST FLT_REGISTRATION FilterRegistration = {

	sizeof(FLT_REGISTRATION),			//  Size
	FLT_REGISTRATION_VERSION,           //  Version
	0,                                  //  Flags

	NULL,                               //  Context
	Callbacks,                          //  Operation callbacks

	PtUnload,                           //  MiniFilterUnload

	NULL,                    //  InstanceSetup
	NULL,            //  InstanceQueryTeardown
	NULL,            //  InstanceTeardownStart
	NULL,         //  InstanceTeardownComplete

	NULL,                               //  GenerateFileName
	NULL,                               //  GenerateDestinationFileName
	NULL                                //  NormalizeNameComponent

};

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

	status = FltRegisterFilter(DriverObject,
		&FilterRegistration,
		&gFilterHandle);

	if (!NT_SUCCESS(status))
	{
		DbgPrint("[PassThrough] Can`t start!\n");
		return status;
	}
	DbgPrint("[PassThrough] FltRegisterFilter\n");

	memcpy(KEY, "1234123412341234123412341234123", 32);
	memcpy(IV, "1234123412341234123412341234123", 16);

	// Создание сервера
	PSECURITY_DESCRIPTOR  securityDescriptor;
	OBJECT_ATTRIBUTES attr = { 0 };
	UNICODE_STRING portName = RTL_CONSTANT_STRING(L"\\pt");

	status = FltBuildDefaultSecurityDescriptor(&securityDescriptor, FLT_PORT_ALL_ACCESS);

	if (NT_SUCCESS(status))
	{
		DbgPrint("[PassThrough] SecurityDescriptor success\n");
		InitializeObjectAttributes(&attr, &portName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, securityDescriptor);

		status = FltCreateCommunicationPort(gFilterHandle, &ServerPort, &attr, NULL, ClientConnect, ClientDisconnect, NULL, 1);

		FltFreeSecurityDescriptor(securityDescriptor);

		if (NT_SUCCESS(status))
		{
			DbgPrint("[PassThrough] Server start success\n");

			status = FltStartFiltering(gFilterHandle);

			if (NT_SUCCESS(status))
			{
				DbgPrint("[PassThrough] Filter start success\n");
				return status;
			}
			DbgPrint("[PassThrough] Filter start error\n");
			FltCloseCommunicationPort(ServerPort);
		}
		DbgPrint("[PassThrough] Server start error\n");

		FltUnregisterFilter(gFilterHandle);
	}

	return status;
}

NTSTATUS ClientConnect(
	_In_ PFLT_PORT clientPort,
	_In_ PVOID ServerPortCookie,
	_In_reads_bytes_(SizeOfContext) PVOID ConnectionContext,
	_In_ ULONG SizeOfContext,
	_Flt_ConnectionCookie_Outptr_ PVOID* ConnectionCookie
)
{
	ClientPort = clientPort;
	return STATUS_SUCCESS;
}


VOID ClientDisconnect(PVOID ConnectionCookie)
{
	FltCloseClientPort(gFilterHandle, &ClientPort);
}

//NTSTATUS
//ClientMessage(
//	_In_ PVOID ConnectionCookie,
//	_In_reads_bytes_opt_(InputBufferSize) PVOID InputBuffer,
//	_In_ ULONG InputBufferSize,
//	_Out_writes_bytes_to_opt_(OutputBufferSize, *ReturnOutputBufferLength) PVOID OutputBuffer,
//	_In_ ULONG OutputBufferSize,
//	_Out_ PULONG ReturnOutputBufferLength
//)
//{
//	//MINISPY_COMMAND command;
//	NTSTATUS status;
//
//	PAGED_CODE();
//
//	UNREFERENCED_PARAMETER(ConnectionCookie);
//
//	//
//	//                      **** PLEASE READ ****
//	//
//	//  The INPUT and OUTPUT buffers are raw user mode addresses.  The filter
//	//  manager has already done a ProbedForRead (on InputBuffer) and
//	//  ProbedForWrite (on OutputBuffer) which guarentees they are valid
//	//  addresses based on the access (user mode vs. kernel mode).  The
//	//  minifilter does not need to do their own probe.
//	//
//	//  The filter manager is NOT doing any alignment checking on the pointers.
//	//  The minifilter must do this themselves if they care (see below).
//	//
//	//  The minifilter MUST continue to use a try/except around any access to
//	//  these buffers.
//	//
//
////	if ((InputBuffer != NULL) &&
////		(InputBufferSize >= (FIELD_OFFSET(COMMAND_MESSAGE, Command) +
////			sizeof(MINISPY_COMMAND)))) {
////
////		try {
////
////			//
////			//  Probe and capture input message: the message is raw user mode
////			//  buffer, so need to protect with exception handler
////			//
////
////			command = ((PCOMMAND_MESSAGE)InputBuffer)->Command;
////
////		} except(SpyExceptionFilter(GetExceptionInformation(), TRUE)) {
////
////			return GetExceptionCode();
////		}
////
////		switch (command) {
////
////		case GetMiniSpyLog:
////
////			//
////			//  Return as many log records as can fit into the OutputBuffer
////			//
////
////			if ((OutputBuffer == NULL) || (OutputBufferSize == 0)) {
////
////				status = STATUS_INVALID_PARAMETER;
////				break;
////			}
////
////			//
////			//  We want to validate that the given buffer is POINTER
////			//  aligned.  But if this is a 64bit system and we want to
////			//  support 32bit applications we need to be careful with how
////			//  we do the check.  Note that the way SpyGetLog is written
////			//  it actually does not care about alignment but we are
////			//  demonstrating how to do this type of check.
////			//
////
////#if defined(_WIN64)
////
////			if (IoIs32bitProcess(NULL)) {
////
////				//
////				//  Validate alignment for the 32bit process on a 64bit
////				//  system
////				//
////
////				if (!IS_ALIGNED(OutputBuffer, sizeof(ULONG))) {
////
////					status = STATUS_DATATYPE_MISALIGNMENT;
////					break;
////				}
////
////			}
////			else {
////
////#endif
////
////				if (!IS_ALIGNED(OutputBuffer, sizeof(PVOID))) {
////
////					status = STATUS_DATATYPE_MISALIGNMENT;
////					break;
////				}
////
////#if defined(_WIN64)
////
////			}
////
////#endif
////
////			//
////			//  Get the log record.
////			//
////
////			status = SpyGetLog(OutputBuffer,
////				OutputBufferSize,
////				ReturnOutputBufferLength);
////			break;
////
////
////		case GetMiniSpyVersion:
////
////			//
////			//  Return version of the MiniSpy filter driver.  Verify
////			//  we have a valid user buffer including valid
////			//  alignment
////			//
////
////			if ((OutputBufferSize < sizeof(MINISPYVER)) ||
////				(OutputBuffer == NULL)) {
////
////				status = STATUS_INVALID_PARAMETER;
////				break;
////			}
////
////			//
////			//  Validate Buffer alignment.  If a minifilter cares about
////			//  the alignment value of the buffer pointer they must do
////			//  this check themselves.  Note that a try/except will not
////			//  capture alignment faults.
////			//
////
////			if (!IS_ALIGNED(OutputBuffer, sizeof(ULONG))) {
////
////				status = STATUS_DATATYPE_MISALIGNMENT;
////				break;
////			}
////
////			//
////			//  Protect access to raw user-mode output buffer with an
////			//  exception handler
////			//
////
////			try {
////
////				((PMINISPYVER)OutputBuffer)->Major = MINISPY_MAJ_VERSION;
////				((PMINISPYVER)OutputBuffer)->Minor = MINISPY_MIN_VERSION;
////
////			} except(SpyExceptionFilter(GetExceptionInformation(), TRUE)) {
////
////				return GetExceptionCode();
////			}
////
////			*ReturnOutputBufferLength = sizeof(MINISPYVER);
////			status = STATUS_SUCCESS;
////			break;
////
////		default:
////			status = STATUS_INVALID_PARAMETER;
////			break;
////		}
////
////	}
////	else {
////
//	//status = STATUS_INVALID_PARAMETER;
//	//	}
//	//
//	//return status;
//
//
//	STRING FNameString;
//	DbgPrint(("[PassThrough] Content:%s | Size: %d\n", InputBuffer, InputBufferSize));
//
//	return STATUS_ABANDONED;
//
//}

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
	DbgPrint("[PassThrough] Driver unload\n");
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
						DbgPrint("[PassThrough] Write. Input: %s\n", Data->Iopb->Parameters.Write.WriteBuffer);

						// Key and IV for AES
						uint8_t buffer[128];

						memcpy(buffer, Data->Iopb->Parameters.Write.WriteBuffer, 128);

						// Initializing AES
						struct AES_ctx ctx;

						AES_init_ctx_iv(&ctx, KEY, IV);
						AES_CBC_encrypt_buffer(&ctx, buffer, 128);

						memcpy(Data->Iopb->Parameters.Write.WriteBuffer, buffer, 128);

						DbgPrint("[PassThrough] Write. Output: %s\n", Data->Iopb->Parameters.Write.WriteBuffer);

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

	return FLT_PREOP_SUCCESS_WITH_CALLBACK;
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
					DbgPrint("[PassThrough] Read. Input: %s\n", Data->Iopb->Parameters.Read.ReadBuffer);
					try
					{
						// Создание и заполнение буфера
						uint8_t buffer[128];
						memcpy(buffer, Data->Iopb->Parameters.Read.ReadBuffer, 128);

						// Инициализация контекста для шифрования
						struct AES_ctx ctx;
						AES_init_ctx_iv(&ctx, KEY, IV);
						AES_CBC_decrypt_buffer(&ctx, buffer, 128);

						memcpy(Data->Iopb->Parameters.Read.ReadBuffer, buffer, 128);

						DbgPrint("[PassThrough] Read. Output: %s\n", Data->Iopb->Parameters.Read.ReadBuffer);

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