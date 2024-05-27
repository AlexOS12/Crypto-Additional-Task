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
#include <ntstrsafe.h>

#pragma prefast(disable:__WARNING_ENCODE_MEMBER_FUNCTION_POINTER, "Not valid for kernel mode drivers")

//struct AES_ctx ctx;

typedef struct _DriverData {
	wchar_t req[32];
	char key[33];
	//struct AES_ctx ctx;
} DriverData, * PDriverData;

struct ClientData {
	char key[33];
	wchar_t ext[32];
};

//wchar_t req[32];
PFLT_FILTER gFilterHandle;
PFLT_PORT ServerPort = NULL;
PFLT_PORT ClientPort = NULL;

uint8_t initStatus = 0;

PDriverData PrivateData;


/*************************************************************************
	Prototypes
*************************************************************************/
#pragma region prototypes


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

NTSTATUS
ClientMessage(IN PVOID ConnectionCookie,
	IN PVOID InputBuffer  OPTIONAL,
	IN ULONG InputBufferSize,
	OUT PVOID OutputBuffer OPTIONAL,
	IN ULONG OutputBufferSize,
	OUT PULONG ReturnOutputBufferLength);


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
#pragma endregion

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, PtUnload)
#endif

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
	PrivateData = ExAllocatePoolWithTag(NonPagedPool | POOL_FLAG_NON_PAGED_EXECUTE, sizeof(DriverData), 'reqE');

	//wchar_t temp[32] = { 0 };
	//memcpy(req, temp, sizeof(temp));
	//memcpy(PrivateData->req, temp, sizeof(temp));

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

	PSECURITY_DESCRIPTOR  securityDescriptor;
	OBJECT_ATTRIBUTES attr = { 0 };
	UNICODE_STRING portName = RTL_CONSTANT_STRING(L"\\PassThrough");

	status = FltBuildDefaultSecurityDescriptor(&securityDescriptor, FLT_PORT_ALL_ACCESS);

	if (NT_SUCCESS(status))
	{
		DbgPrint("[PassThrough] SecurityDescriptor success\n");
		InitializeObjectAttributes(&attr, &portName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, securityDescriptor);

		status = FltCreateCommunicationPort(gFilterHandle, &ServerPort, &attr, NULL, ClientConnect, ClientDisconnect, ClientMessage, 1);

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
			ExFreePoolWithTag(PrivateData, 'reqE');
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
	DbgPrint("[PassThrough] Connection");

	ClientPort = clientPort;
	DbgPrint("[PassThrough] Port: %d", ClientPort);

	return STATUS_SUCCESS;
}


VOID ClientDisconnect(PVOID ConnectionCookie)
{
	DbgPrint("[PassThrough] Disconnect");
	FltCloseClientPort(gFilterHandle, &ClientPort);
}

NTSTATUS
ClientMessage(IN PVOID ConnectionCookie,
	IN PVOID InputBuffer  OPTIONAL,
	IN ULONG InputBufferSize,
	OUT PVOID OutputBuffer OPTIONAL,
	IN ULONG OutputBufferSize,
	OUT PULONG ReturnOutputBufferLength) {
	DbgPrint("[PassThrough] Client message\n\r");
	if (InputBuffer) {
		DbgPrint("[PassThrough] Client length buffer: %d\n\r", InputBufferSize);

		struct ClientData input;
		memcpy(&input, InputBuffer, sizeof(struct ClientData));

		DbgPrint("[PassThrough] Client struct key: %s | extension: %ws\n", input.key, input.ext);

		memcpy(&PrivateData->req, input.ext, sizeof(PrivateData->req));
		DbgPrint("[PassThrough] Message req: %ws\n", input.ext);
		memcpy(&PrivateData->key, input.key, sizeof(PrivateData->key));
		DbgPrint("[PassThrough] Message key: %s\n", input.key);
		initStatus = 1;
	}
	return STATUS_SUCCESS;
}

NTSTATUS
PtUnload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags)
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
	PAGED_CODE();

	DbgPrint("[PassThrough] Driver unload\n\r");
	FltCloseCommunicationPort(ServerPort);
	FltUnregisterFilter(gFilterHandle);
	ExFreePoolWithTag(PrivateData, 'reqE');
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
	if (NT_SUCCESS(status)) {
		if (initStatus)
		{
			UNICODE_STRING required_extension;
			//RtlInitUnicodeString(&required_extension, req);
			RtlInitUnicodeString(&required_extension, &PrivateData->req);

			if (RtlCompareUnicodeString(&required_extension, &NameInfo->Extension, TRUE) == 0) {
				if (Data->Iopb->MajorFunction == IRP_MJ_WRITE) {
					DbgPrint("[PassThrough] WRITING\n");
					if (Data->Iopb->Parameters.Write.WriteBuffer) {
						try {
							DbgPrint("[PassThrough] Write. Input: %s\n", Data->Iopb->Parameters.Write.WriteBuffer);

							uint8_t buffer[256];
							memcpy(buffer, Data->Iopb->Parameters.Write.WriteBuffer, 256);

							struct AES_ctx ctx;
							AES_init_ctx_iv(&ctx, &PrivateData->key, &PrivateData->key);

							/*AES_CBC_encrypt_buffer(&ctx, buffer, 256);
							DbgPrint("[PassThrough] AES: %u\n", ctx.Iv);*/
							AES_CBC_encrypt_buffer(&ctx, buffer, 256);
							DbgPrint("[PassThrough] AES: %u\n", &ctx.Iv);


							memcpy(Data->Iopb->Parameters.Write.WriteBuffer, buffer, 256);
							DbgPrint("[PassThrough] Write. Output: %s\n", Data->Iopb->Parameters.Write.WriteBuffer);
						}
						finally {
						}
					}
					else {
						DbgPrint("[PassThrough] InBuffer is empty or null\n");
					}
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

	if (NT_SUCCESS(status)) {
		if (initStatus) {
			UNICODE_STRING required_extension;
			RtlInitUnicodeString(&required_extension, &PrivateData->req);

			if (RtlCompareUnicodeString(&required_extension, &NameInfo->Extension, TRUE) == 0) {
				if (Data->Iopb->MajorFunction == IRP_MJ_READ) {
					DbgPrint("[PassThrough] Reading file: %wZ | %wZ\n", NameInfo->Name, NameInfo->Extension);
					if (Data->Iopb->Parameters.Read.ReadBuffer && Data->Iopb->Parameters.Read.Length > 1) {
						DbgPrint("[PassThrough] Read. Input: %s\n", Data->Iopb->Parameters.Read.ReadBuffer);
						DbgPrint("[PassThrough] Read. Len: %d\n", Data->Iopb->Parameters.Read.Length);
						try {
							uint8_t buffer[256];
							memcpy(buffer, Data->Iopb->Parameters.Read.ReadBuffer, 256);

							struct AES_ctx ctx;
							AES_init_ctx_iv(&ctx, &PrivateData->key, &PrivateData->key);

							AES_CBC_decrypt_buffer(&ctx, buffer, 256);
							DbgPrint("[PassThrough] AES: %u\n", &ctx.Iv);

							memcpy(Data->Iopb->Parameters.Read.ReadBuffer, buffer, 256);
							DbgPrint("[PassThrough] Read. Output: %s\n", Data->Iopb->Parameters.Read.ReadBuffer);
						}
						finally {
						}
					}
					else {
						DbgPrint("[PassThrough] InBuffer is empty or null\n");
					}
				}
			}
		}
	}

	return FLT_POSTOP_FINISHED_PROCESSING;
}