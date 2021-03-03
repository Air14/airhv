#pragma once
namespace hvgt
{
	/// <summary>
	/// Turn off virtual machine
	/// </summary>
	void vmoff();

	/// <summary>
	/// Invalidates mappings in the translation lookaside buffers (TLBs) 
	/// and paging-structure caches that were derived from extended page tables (EPT)
	/// </summary>
	/// <param name="invept_all"> If true invalidates all contexts otherway invalidate only single context (currently hv doesn't use more than 1 context)</param>
	void invept(bool invept_all);

	/// <summary>
	/// Unhook all pages and invalidate tlb
	/// </summary>
	/// <returns> status </returns>
	bool ept_unhook();

	/// <summary>
	/// Unhook single page and invalidate tlb
	/// </summary>
	/// <param name="page_physcial_address"></param>
	/// <returns> status </returns>
	bool ept_unhook(unsigned __int64 page_physcial_address);

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
	bool hook_page(void* target_address, void* hook_function, void** origin_function, bool read, bool write, bool execute);

	/// <summary>
	/// Hook function via ept and invalidates mappings
	/// </summary>
	/// <param name="target_address">Address of function which we want to hook</param>
	/// <param name="hook_function">Address of function which is used to call original function</param>
	/// <param name="origin_function">Address of function which is used to call original function</param>
	/// <returns> status </returns>
	bool hook_function(void* target_address, void* hook_function, void** origin_function);

	/// <summary>
	/// Check if we can communicate with hypervisor
	/// </summary>
	/// <returns> status </returns>
	bool test_vmcall();

	/// <summary>
	/// Send irp with information to allocate memory
	/// </summary>
	/// <returns> status </returns>
	bool send_irp_perform_allocation();

	/// <summary>
	/// Dereference hvpervisor object
	/// </summary>
	void dereference_hv_object();
}
