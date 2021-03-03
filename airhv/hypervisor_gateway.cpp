#pragma warning( disable : 4201 4100 4101 4244 4333 4245 4366)

#include <ntddk.h>
#include "ntapi.h"
#include "asm\vm_intrin.h"
#include "vmcall_reason.h"
#include "log.h"

#define IOCTL_POOL_MANAGER_ALLOCATE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x900, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

namespace hvgt 
{
	void broadcast_vmoff(KDPC* Dpc, PVOID DeferredContext, PVOID SystemArgument1, PVOID SystemArgument2)
	{
		__vm_call(VMCALL_VMXOFF, 0, 0, 0);
		KeSignalCallDpcSynchronize(SystemArgument2);
		KeSignalCallDpcDone(SystemArgument1);
	}

	void broadcast_invept_all_contexts(KDPC* Dpc, PVOID DeferredContext, PVOID SystemArgument1, PVOID SystemArgument2)
	{
		__vm_call(VMCALL_INVEPT_CONTEXT, true, 0, 0);
		KeSignalCallDpcSynchronize(SystemArgument2);
		KeSignalCallDpcDone(SystemArgument1);
	}

	void broadcast_invept_single_context(KDPC* Dpc, PVOID DeferredContext, PVOID SystemArgument1, PVOID SystemArgument2)
	{
		__vm_call(VMCALL_INVEPT_CONTEXT, false, 0, 0);
		KeSignalCallDpcSynchronize(SystemArgument2);
		KeSignalCallDpcDone(SystemArgument1);
	}

	/// <summary>
	/// Turn off virtual machine
	/// </summary>
	void vmoff()
	{
		KeGenericCallDpc(broadcast_vmoff, NULL);
	}

	/// <summary>
	/// Invalidates mappings in the translation lookaside buffers (TLBs) 
	/// and paging-structure caches that were derived from extended page tables (EPT)
	/// </summary>
	/// <param name="invept_all"> If true invalidates all contexts otherway invalidate only single context (currently hv doesn't use more than 1 context)</param>
	void invept(bool invept_all)
	{
		if (invept_all == true) KeGenericCallDpc(broadcast_invept_all_contexts, NULL);
		else KeGenericCallDpc(broadcast_invept_single_context, NULL);
	}

	/// <summary>
	/// Unhook all pages and invalidate tlb
	/// </summary>
	/// <returns> status </returns>
	bool ept_unhook()
	{
		bool status = __vm_call(VMCALL_EPT_UNHOOK_PAGE, true, 0, 0);
		invept(false);
		return status;
	}

	/// <summary>
	/// Unhook single page and invalidate tlb
	/// </summary>
	/// <param name="page_physcial_address"></param>
	/// <returns> status </returns>
	bool ept_unhook(unsigned __int64 page_physcial_address)
	{
		bool status = __vm_call(VMCALL_EPT_UNHOOK_PAGE, false, page_physcial_address, 0);
		invept(false);
		return status;
	}

	/// <summary>
	/// Hook some page via ept and invalidates mappings
	/// </summary>
	/// <param name="target_address">Address of function which we want to hook</param>
	/// <param name="hook_function">Address of hook function</param>
	/// <param name="origin_function">Address of function which is used to call original function</param>
	/// <param name="read">If set ept violation will not occur on read access</param>
	/// <param name="write">If set ept violation will not occur on write access</param>
	/// <param name="execute">If set ept violation will not occur on execute access</param>
	/// <returns> status </returns>
	bool hook_page(void* target_address, void* hook_function, void** origin_function, bool read, bool write, bool execute)
	{
		unsigned __int8 protection_mask = read + (write << 1) + (execute << 2);
		bool status = __vm_call_ex(VMCALL_EPT_HOOK_PAGE, (unsigned __int64)target_address, (unsigned __int64)hook_function, (unsigned __int64)origin_function, protection_mask, 0, 0, 0, 0, 0);
		invept(false);

		return status;
	}

	/// <summary>
	/// Hook function via ept and invalidates mappings
	/// </summary>
	/// <param name="target_address">Address of function which we want to hook</param>
	/// <param name="hook_function">Address of function which is used to call original function</param>
	/// <param name="origin_function">Address of function which is used to call original function</param>
	/// <returns> status </returns>
	bool hook_function(void* target_address, void* hook_function, void** origin_function)
	{
		unsigned __int8 protection_mask = false + (false << 1) + (true << 2);
		bool status = __vm_call_ex(VMCALL_EPT_HOOK_PAGE, (unsigned __int64)target_address, (unsigned __int64)hook_function, (unsigned __int64)origin_function, protection_mask, 0, 0, 0, 0, 0);
		invept(false);

		return status;
	}

	/// <summary>
	/// Check if we can communicate with hypervisor
	/// </summary>
	/// <returns> status </returns>
	bool test_vmcall()
	{
		return __vm_call(VMCALL_TEST, 0, 0, 0);
	}

	/// <summary>
	/// Send irp with information to allocate memory
	/// If you use this function once you have then to derefence device object using "hvgt_dereference_hv_object" function
	/// </summary>
	/// <returns> status </returns>
	bool send_irp_perform_allocation()
	{
		PDEVICE_OBJECT airhv_device_object;
		NTSTATUS status;
		KEVENT event;
		PIRP irp;
		IO_STATUS_BLOCK io_status = { 0 };
		UNICODE_STRING airhv_name;
		PFILE_OBJECT file_object;

		RtlInitUnicodeString(&airhv_name, L"\\Device\\airhv");

		status = IoGetDeviceObjectPointer(&airhv_name, 0, &file_object, &airhv_device_object);

		ObReferenceObjectByPointer(airhv_device_object, FILE_ALL_ACCESS, NULL, KernelMode);

		// We don't need this so we instantly dereference file object
		ObDereferenceObject(file_object);

		if (NT_SUCCESS(status) == false)
		{
			LogError("Couldn't get hypervisor device object pointer");
			return false;
		}

		KeInitializeEvent(&event, NotificationEvent, 0);
		irp = IoBuildDeviceIoControlRequest(IOCTL_POOL_MANAGER_ALLOCATE, airhv_device_object, 0, 0, 0, 0, 0, &event, &io_status);

		if (irp == NULL)
		{
			LogError("Couldn't create Irp");
			ObDereferenceObject(airhv_device_object);
			return false;
		}

		else
		{
			status = IofCallDriver(airhv_device_object, irp);

			if (status == STATUS_PENDING)
				KeWaitForSingleObject(&event, Executive, KernelMode, 0, 0);

			ObDereferenceObject(airhv_device_object);
			return true;
		}
	}
}