#pragma warning( disable : 4201 4100 4101 4244 4333 4245 4366)

#include <ntddk.h>
#include <intrin.h>
#include "hypervisor_gateway.h"

void* NtCreateFileAddress;

extern "C"
NTSTATUS(NtCreateFile)(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes,
	PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes,
	ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength
	);

NTSTATUS(*OriginalNtCreateFile)(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes,
	PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes,
	ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength
	);


NTSTATUS NTAPI HookNtCreateFile(
	PHANDLE            FileHandle,
	ACCESS_MASK        DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PIO_STATUS_BLOCK   IoStatusBlock,
	PLARGE_INTEGER     AllocationSize,
	ULONG              FileAttributes,
	ULONG              ShareAccess,
	ULONG              CreateDisposition,
	ULONG              CreateOptions,
	PVOID              EaBuffer,
	ULONG              EaLength
)
{
	__try
	{
		ProbeForRead(FileHandle, sizeof(HANDLE), 1);
		ProbeForRead(ObjectAttributes, sizeof(OBJECT_ATTRIBUTES), 1);
		ProbeForRead(ObjectAttributes->ObjectName, sizeof(UNICODE_STRING), 1);
		ProbeForRead(ObjectAttributes->ObjectName->Buffer, ObjectAttributes->ObjectName->Length, 1);
		if (wcsstr(ObjectAttributes->ObjectName->Buffer, L"test.txt") != NULL)
		{
			return STATUS_INVALID_BUFFER_SIZE;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{

	}
	return OriginalNtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);
}


VOID driver_unload(PDRIVER_OBJECT driver_object)
{
	UNICODE_STRING dos_device_name;

	hvgt::ept_unhook(MmGetPhysicalAddress(NtCreateFileAddress).QuadPart);

	RtlInitUnicodeString(&dos_device_name, L"\\DosDevices\\airhvctrl");
	IoDeleteSymbolicLink(&dos_device_name);
	IoDeleteDevice(driver_object->DeviceObject);
}

NTSTATUS driver_create_close(_In_ PDEVICE_OBJECT device_object, _In_ PIRP irp)
{
	UNREFERENCED_PARAMETER(device_object);

	irp->IoStatus.Status = STATUS_SUCCESS;
	irp->IoStatus.Information = 0;

	IoCompleteRequest(irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

NTSTATUS driver_ioctl_dispatcher(_In_ PDEVICE_OBJECT device_object, _In_ PIRP irp)
{
	UNREFERENCED_PARAMETER(device_object);
	unsigned __int32 bytes_io = 0;

	NTSTATUS status = STATUS_SUCCESS;

	irp->IoStatus.Status = status;
	irp->IoStatus.Information = bytes_io;

	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return status;
}

extern "C"
NTSTATUS DriverEntry(PDRIVER_OBJECT driver_object, PCUNICODE_STRING reg)
{
	UNREFERENCED_PARAMETER(reg);

	NTSTATUS status = STATUS_SUCCESS;
	PDEVICE_OBJECT device_oject = 0;
	UNICODE_STRING driver_name, dos_device_name;

	RtlInitUnicodeString(&driver_name, L"\\Device\\airhvctrl");
	RtlInitUnicodeString(&dos_device_name, L"\\DosDevices\\airhvctrl");

	status = IoCreateDevice(driver_object, 0, &driver_name, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &device_oject);

	if (status == STATUS_SUCCESS)
	{
		driver_object->MajorFunction[IRP_MJ_CLOSE] = driver_create_close;
		driver_object->MajorFunction[IRP_MJ_CREATE] = driver_create_close;
		driver_object->MajorFunction[IRP_MJ_DEVICE_CONTROL] = driver_ioctl_dispatcher;

		driver_object->DriverUnload = driver_unload;
		driver_object->Flags |= DO_BUFFERED_IO;
		IoCreateSymbolicLink(&dos_device_name, &driver_name);
	}

	UNICODE_STRING routine_name;
	RtlInitUnicodeString(&routine_name,L"NtCreateFile");

	NtCreateFileAddress = MmGetSystemRoutineAddress(&routine_name);

	hvgt::hook_function(NtCreateFileAddress, HookNtCreateFile, (void**)&OriginalNtCreateFile);
	hvgt::send_irp_perform_allocation();

	return status;
}