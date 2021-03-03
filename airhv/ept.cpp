#pragma warning( disable : 4201 4100 4101 4244 4333 4245 4366 4309 4189 26451)
#include <ntddk.h>
#include <intrin.h>
#include <stdlib.h>
#include "common.h"
#include "ia32\msr.h"
#include "ia32\vmcs_encodings.h"
#include "ia32\ept.h"
#include "log.h"
#include "hypervisor_routines.h"
#include "ia32\mtrr.h"
#include "allocators.h"

namespace ept
{
	/// <summary>
	/// Build mtrr map to track physical memory type
	/// </summary>
	void build_mtrr_map()
	{
		__mtrr_cap_reg mtrr_cap = { 0 };
		__mtrr_physbase_reg current_phys_base = { 0 };
		__mtrr_physmask_reg current_phys_mask = { 0 };
		__mtrr_range_descriptor* descriptor;
		unsigned long bits_in_mask = 0;

		//
		// The memory type range registers (MTRRs) provide a mechanism for associating the memory types (see Section
		// 11.3, “Methods of Caching Available”) with physical - address ranges in system memory.They allow the processor to
		// optimize operations for different types of memory such as RAM, ROM, frame - buffer memory, and memory - mapped
		// I/O devices.They also simplify system hardware design by eliminating the memory control pins used for this func -
		// tion on earlier IA - 32 processors and the external logic needed to drive them.
		//

		mtrr_cap.all = __readmsr(IA32_MTRRCAP);

		//
		// Indicates the number of variable ranges
		// implemented on the processor.
		for (int i = 0; i < mtrr_cap.range_register_number; i++)
		{
			//
			// The first entry in each pair (IA32_MTRR_PHYSBASEn) defines the base address and memory type for the range;
			// the second entry(IA32_MTRR_PHYSMASKn) contains a mask used to determine the address range.The “n” suffix
			// is in the range 0 through m–1 and identifies a specific register pair.
			//
			current_phys_base.all = __readmsr(IA32_MTRR_PHYSBASE0 + (i * 2));
			current_phys_mask.all = __readmsr(IA32_MTRR_PHYSMASK0 + (i * 2));

			//
			// If range is enabled
			if (current_phys_mask.valid)
			{
				descriptor = &g_vmm_context->ept_state->memory_range[g_vmm_context->ept_state->enabled_memory_ranges++];

				//
				// Calculate base address, physbase is truncated by 12 bits so we have to left shift it by 12
				//
				descriptor->physcial_base_address = current_phys_base.physbase << PAGE_SHIFT;

				//
				// Index of first bit set to one determines how much do we have to bit shift to get size of range
				// physmask is truncated by 12 bits so we have to left shift it by 12
				//
				_BitScanForward64(&bits_in_mask, current_phys_mask.physmask << PAGE_SHIFT);

				//
				// Calculate the end of range specified by mtrr
				//
				descriptor->physcial_end_address = descriptor->physcial_base_address + ((1ULL << bits_in_mask) - 1ULL);

				//
				// Get memory type of range
				//
				descriptor->memory_type = (unsigned __int8)current_phys_base.type;

				//
				// WB memory type is our default memory type so we don't have to store this range
				//
				if (descriptor->memory_type == MEMORY_TYPE_WRITE_BACK)
				{
					g_vmm_context->ept_state->enabled_memory_ranges--;
				}
			}
		}
	}

	/// <summary>
	/// Setup page memory type
	/// </summary>
	/// <param name="entry"> Pointer to pml2 entry </param>
	/// <param name="pfn"> Page frame number </param>
	void setup_pml2_entry(__ept_pde& entry, unsigned __int64 pfn)
	{
		unsigned __int64 page_address;
		unsigned __int64 memory_type;

		entry.page_directory_entry.physical_address = pfn;

		page_address = pfn * LARGE_PAGE_SIZE;

		if (pfn == 0)
		{
			entry.page_directory_entry.memory_type = MEMORY_TYPE_UNCACHEABLE;
			return;
		}

		memory_type = MEMORY_TYPE_WRITE_BACK;
		for (unsigned __int64 i = 0; i < g_vmm_context->ept_state->enabled_memory_ranges; i++)
		{
			if (page_address <= g_vmm_context->ept_state->memory_range[i].physcial_end_address)
			{
				if ((page_address + LARGE_PAGE_SIZE - 1) >= g_vmm_context->ept_state->memory_range[i].physcial_base_address)
				{
					memory_type = g_vmm_context->ept_state->memory_range[i].memory_type;
					if (memory_type == MEMORY_TYPE_UNCACHEABLE)
					{
						break;
					}
				}
			}
		}

		entry.page_directory_entry.memory_type = memory_type;
	}

	/// <summary>
	/// Create ept page table
	/// </summary>
	/// <returns> status </returns>
	bool create_ept_page_table()
	{
		__vmm_ept_page_table* page_table;
		__ept_pdpte pdpte_template;
		__ept_pde pde_template;

		PHYSICAL_ADDRESS max_size;
		max_size.QuadPart = MAXULONG64;

		g_vmm_context->ept_state->ept_page_table = allocate_contignous_memory<__vmm_ept_page_table>();
		if (g_vmm_context->ept_state->ept_page_table == NULL)
		{
			LogError("Failed to allocate memory for PageTable");
			return false;
		}
		page_table = g_vmm_context->ept_state->ept_page_table;
		RtlSecureZeroMemory(page_table, sizeof(__vmm_ept_page_table));

		//
		// Set all pages as rwx to prevent unwanted ept violation
		//
		page_table->pml4[0].physical_address = GET_PFN(MmGetPhysicalAddress(&page_table->pml3[0]).QuadPart);
		page_table->pml4[0].read = 1;
		page_table->pml4[0].write = 1;
		page_table->pml4[0].execute = 1;

		pdpte_template.all = 0;

		pdpte_template.read = 1;
		pdpte_template.write = 1;
		pdpte_template.execute = 1;

		__stosq((unsigned __int64*)&page_table->pml3[0], pdpte_template.all, 512);

		for (int i = 0; i < 512; i++)
		{
			page_table->pml3[i].physical_address = GET_PFN(MmGetPhysicalAddress(&page_table->pml2[i][0]).QuadPart);
		}

		pde_template.all = 0;

		pde_template.page_directory_entry.read = 1;
		pde_template.page_directory_entry.write = 1;
		pde_template.page_directory_entry.execute = 1;

		pde_template.page_directory_entry.large_page = 1;

		__stosq((unsigned __int64*)&page_table->pml2[0], pde_template.all, 512 * 512);

		for (int i = 0; i < 512; i++)
		{
			for (int j = 0; j < 512; j++)
			{
				setup_pml2_entry(page_table->pml2[i][j], (i * 512) + j);
			}
		}

		return true;
	}

	/// <summary>
	/// Initialize ept structure
	/// </summary>
	/// <returns></returns>
	bool initialize()
	{
		__eptp* ept_pointer = allocate_pool<__eptp*>(PAGE_SIZE);
		if (ept_pointer == NULL)
		{
			return false;
		}
		RtlSecureZeroMemory(ept_pointer, PAGE_SIZE);

		if (create_ept_page_table() == false)
		{
			return false;
		}

		ept_pointer->memory_type = MEMORY_TYPE_WRITE_BACK;
		ept_pointer->page_walk_length = 3;
		ept_pointer->pml4_address = GET_PFN(MmGetPhysicalAddress(&g_vmm_context->ept_state->ept_page_table->pml4).QuadPart);

		g_vmm_context->ept_state->ept_pointer = ept_pointer;

		return true;
	}

	/// <summary>
	/// Get pml2 entry
	/// </summary>
	/// <param name="physical_address"></param>
	/// <returns> pointer to pml2 </returns>
	__ept_pde* get_pml2_entry(unsigned __int64 physical_address)
	{
		unsigned __int64 pml4_index = MASK_EPT_PML4_INDEX(physical_address);
		unsigned __int64 pml3_index = MASK_EPT_PML3_INDEX(physical_address);
		unsigned __int64 pml2_index = MASK_EPT_PML2_INDEX(physical_address);

		if (pml4_index > 0)
		{
			LogError("Address above 512GB is invalid");
			return nullptr;
		}

		return &g_vmm_context->ept_state->ept_page_table->pml2[pml3_index][pml2_index];
	}

	/// <summary>
	/// Get pml1 entry
	/// </summary>
	/// <param name="physical_address"></param>
	/// <returns></returns>
	__ept_pte* get_pml1_entry(unsigned __int64 physical_address)
	{
		__ept_pde* pml2;
		__ept_pte* pml1;
		PHYSICAL_ADDRESS pfn;

		unsigned __int64 pml4_index = MASK_EPT_PML4_INDEX(physical_address);
		unsigned __int64 pml3_index = MASK_EPT_PML3_INDEX(physical_address);
		unsigned __int64 pml2_index = MASK_EPT_PML2_INDEX(physical_address);

		if (pml4_index > 0)
		{
			LogError("Address above 512GB is invalid");
			return nullptr;
		}

		pml2 = &g_vmm_context->ept_state->ept_page_table->pml2[pml3_index][pml2_index];
		if (pml2->page_directory_entry.large_page == 1)
		{
			return nullptr;
		}

		pfn.QuadPart = pml2->large_page.physical_address << PAGE_SHIFT;
		pml1 = (__ept_pte*)MmGetVirtualForPhysical(pfn);

		if (pml1 == nullptr)
		{
			return nullptr;
		}

		pml1 = &pml1[MASK_EPT_PML1_INDEX(physical_address)];
		return pml1;
	}

	/// <summary>
	/// Split pml2 into 512 pml1 entries (From one 2MB page to 512 4KB pages)
	/// </summary>
	/// <param name="pre_allocated_buffer"> Pre allocated buffer for split </param>
	/// <param name="physical_address"></param>
	/// <returns> status </returns>
	bool split_pml2(void* pre_allocated_buffer, unsigned __int64 physical_address)
	{
		__ept_pte entry_template = { 0 };
		__ept_pde new_entry = { 0 };
		__ept_pde* entry = get_pml2_entry(physical_address);
		if (entry == NULL)
		{
			LogError("Invalid address passed");
			return false;
		}

		__ept_dynamic_split* new_split = (__ept_dynamic_split*)pre_allocated_buffer;
		RtlSecureZeroMemory(new_split, sizeof(__ept_dynamic_split));

		//
		// Set all pages as rwx to prevent unwanted ept violation
		//
		new_split->entry = entry;
		entry_template.read = 1;
		entry_template.write = 1;
		entry_template.execute = 1;
		entry_template.ept_memory_type = entry->page_directory_entry.memory_type;
		entry_template.ignore_pat = entry->page_directory_entry.ignore_pat;
		entry_template.suppress_ve = entry->page_directory_entry.suppressve;

		__stosq((unsigned __int64*)&new_split->pml1[0], entry_template.all, 512);
		for (int i = 0; i < 512; i++)
		{
			new_split->pml1[i].physical_address = ((entry->page_directory_entry.physical_address * LARGE_PAGE_SIZE) >> PAGE_SHIFT) + i;
		}

		new_entry.large_page.read = 1;
		new_entry.large_page.write = 1;
		new_entry.large_page.execute = 1;

		new_entry.large_page.physical_address = MmGetPhysicalAddress(&new_split->pml1[0]).QuadPart >> PAGE_SHIFT;

		RtlCopyMemory(entry, &new_entry, sizeof(new_entry));

		return true;
	}

	/// <summary>
	/// Swap physcial pages and invalidate tlb
	/// </summary>
	/// <param name="entry_address"> Pointer to page table entry which we want to change </param>
	/// <param name="entry_value"> Pointer to page table entry which we want use to change </param>
	/// <param name="invalidation_type"> Specifiy if we want to invalidate single context or all contexts  </param>
	void swap_pml1_and_invalidate_tlb(__ept_pte* entry_address, __ept_pte entry_value, invept_type invalidation_type)
	{
		// Acquire the lock
		spinlock::lock(&g_vmm_context->ept_state->pml_lock);

		// Set the value
		entry_address->all = entry_value.all;

		// Invalidate the cache
		if (invalidation_type == INVEPT_SINGLE_CONTEXT)
		{
			invept_single_context(g_vmm_context->ept_state->ept_pointer->all);
		}
		else
		{
			invept_all_contexts();
		}
		// Release the lock
		spinlock::unlock(&g_vmm_context->ept_state->pml_lock);
	}

	/// <summary>
	/// Swap physcial pages and invalidate tlb
	/// </summary>
	/// <param name="entry_address"> Pointer to page table entry which we want to change </param>
	/// <param name="entry_value"> Pointer to page table entry which we want use to change </param>
	void swap_pml1(__ept_pte* entry_address, __ept_pte entry_value)
	{
		// Acquire the lock
		spinlock::lock(&g_vmm_context->ept_state->pml_lock);

		// Set the value
		entry_address->all = entry_value.all;

		// Release the lock
		spinlock::unlock(&g_vmm_context->ept_state->pml_lock);
	}


	/// <summary>
	/// Write an absolute jump, We aren't touching any register except stack so it's the most safest trampoline
	/// Size: 14 bytes
	/// </summary>
	/// <param name="target_buffer"> Pointer to trampoline buffer </param>
	/// <param name="target_address"> Address of place where we want to jump </param>
	void hook_write_absolute_jump(unsigned __int8* target_buffer, unsigned __int64 target_address)
	{
		// push lower 32 bits of target	
		target_buffer[0] = 0x68;
		*((unsigned __int32*)&target_buffer[1]) = (unsigned __int32)target_address;

		// mov dword ptr [rsp + 4]
		target_buffer[5] = 0xc7;
		target_buffer[6] = 0x44;
		target_buffer[7] = 0x24;
		target_buffer[8] = 0x04;

		// higher 32 bits of target
		*((unsigned __int32*)&target_buffer[9]) = (unsigned __int32)(target_address >> 32);

		// ret
		target_buffer[13] = 0xc3;
	}

	/// <summary>
	/// Write relative jump,
	/// Size: 5 Bytes
	/// </summary>
	/// <param name="target_buffer"> Pointer to trampoline buffer </param>
	/// <param name="origin_address"> Address of place from which we want to jump </param>
	/// <param name="target_address"> Address of place where we want to jump </param>
	void hook_write_relative_jump(unsigned __int8* target_buffer, unsigned __int64 origin_address, unsigned __int64 target_address)
	{
		__int32 jmp_value = (__int64)target_address - (__int64)origin_address - 0x5;

		// relative jmp
		target_buffer[0] = 0xe9;

		// jmp offset
		*((unsigned __int32*)&target_buffer[1]) = jmp_value;
	}

	/// <summary>
	/// 
	/// </summary>
	/// <param name="hooked_page"> Pointer to __ept_hooked_page_info structure which holds info about hooked page </param>
	/// <param name="target_function"> Address of function which we want to hook </param>
	/// <param name="hook_function"> Address of hooked version of function which we are hooking </param>
	/// <param name="origin_function"> Address used to call original function </param>
	/// <returns></returns>
	bool hook_instruction_memory(__ept_hooked_page_info* hooked_page, void* target_function, void* hook_function, void** origin_function)
	{
		unsigned __int64 hooked_instructions_size = 0;
		unsigned __int64 page_offset = 0;

		// Get offset of hooked function within page
		page_offset = MASK_EPT_PML1_OFFSET((unsigned __int64)target_function);

		// If first 14 bytes of function are on 2 separate pages then return (We don't support function hooking at page boundaries)
		if ((page_offset + 14) > PAGE_SIZE - 1)
		{
			LogError("Function at page boundary");
			return false;
		}

		// Get the full size of instructions necessary to copy
		while (hooked_instructions_size < 14)
		{
			hooked_instructions_size += LDE((unsigned __int8*)target_function + hooked_instructions_size, 64);
		}

		// Copy overwritten instructions to trampoline buffer
		RtlCopyMemory(hooked_page->trampolines[hooked_page->current_trampoline_index], target_function, hooked_instructions_size);

		// Add the absolute jump back to the original function.
		hook_write_absolute_jump(&hooked_page->trampolines[hooked_page->current_trampoline_index][hooked_instructions_size], (unsigned __int64)target_function + hooked_instructions_size);

		// Return to user address of trampoline to call original function
		*origin_function = hooked_page->trampolines[hooked_page->current_trampoline_index];

		// Write the absolute jump to our shadow page memory to jump to our hooked_page.
		hook_write_absolute_jump(&hooked_page->fake_page_contents[page_offset], (unsigned __int64)hook_function);

		return true;
	}

	bool is_page_splitted(unsigned __int64 physical_address)
	{
		__ept_pde* entry = get_pml2_entry(physical_address);
		return !entry->page_directory_entry.large_page;
	}

	/// <summary>
	/// Perfrom a hook
	/// </summary>
	/// <param name="target_address" > Address of function which we want to hook </param>
	/// <param name="hook_function"> Address of hooked version of function which we are hooking </param>
	/// <param name="origin_function"> Address used to call original function </param>
	/// <param name="protection_mask"> Determine which type of access cause vmexit </param>
	/// <returns></returns>
	bool hook_page(void* target_address, void* hook_function, void** origin_function, unsigned __int8 protection_mask)
	{
		__ept_pte changed_entry = { 0 };
		__invept_descriptor descriptor = { 0 };
		unsigned __int64 physical_address = 0;
		void* virtual_page_beginning = 0;
		void* target_buffer = 0;
		__ept_pte* target_page = 0;
		__ept_hooked_page_info* hooked_page = 0;

		virtual_page_beginning = PAGE_ALIGN(target_address);

		physical_address = MmGetPhysicalAddress(virtual_page_beginning).QuadPart;

		if (physical_address == NULL)
		{
			LogError("Requested virtual memory doesn't exist in physical one");
			return false;
		}

		// Check if page isn't already hooked ????????????
		PLIST_ENTRY current = &g_vmm_context->ept_state->hooked_page_list;
		while (&g_vmm_context->ept_state->hooked_page_list != current->Flink)
		{
			current = current->Flink;
			__ept_hooked_page_info* hooked_entry = CONTAINING_RECORD(current, __ept_hooked_page_info, hooked_page_list);

			if (hooked_entry->physical_base_address == GET_PFN(physical_address))
			{
				LogInfo("Page already hooked");

				if (protection_mask & 4)
				{
					//
					// Because there is already hooked function within this page we have to allocate new trampoline for hook
					//
					hooked_entry->trampolines[++hooked_entry->current_trampoline_index] = pool_manager::request_pool<unsigned __int8*>(pool_manager::INTENTION_EXEC_TRAMPOLINE, TRUE, 100);
					if (hooked_entry->trampolines[hooked_entry->current_trampoline_index] == NULL)
					{
						hooked_entry->current_trampoline_index--;

						LogError("There is no pre-allocated pool for trampoline");
						return false;
					}

					hook_instruction_memory(hooked_entry, target_address, hook_function, origin_function);
				}

				//
				// Update page protection type
				//
				changed_entry.read = protection_mask & 1;
				changed_entry.write = (protection_mask & 2) >> 1;

				return true;
			}
		}

		if (is_page_splitted(physical_address) == false)
		{
			target_buffer = pool_manager::request_pool<void*>(pool_manager::INTENTION_SPLIT_PML2, true, sizeof(__ept_dynamic_split));
			if (target_buffer == NULL)
			{
				LogError("There is no preallocated buffer available");
				return false;
			}

			if (split_pml2(target_buffer, physical_address) == false)
			{
				pool_manager::release_pool(target_buffer);
				LogError("Split failed");
				return false;
			}
		}

		target_page = get_pml1_entry(physical_address);
		if (target_page == NULL)
		{
			LogError("Failed to get PML1 entry of the target address");
			return false;
		}

		hooked_page = pool_manager::request_pool<__ept_hooked_page_info*>(pool_manager::INTENTION_TRACK_HOOKED_PAGES, true, sizeof(__ept_hooked_page_info));
		if (hooked_page == NULL)
		{
			LogError("There is no pre-allocated pool for saving hooked page details");
			return false;
		}

		hooked_page->trampolines[hooked_page->current_trampoline_index] = pool_manager::request_pool<unsigned __int8*>(pool_manager::INTENTION_EXEC_TRAMPOLINE, TRUE, 100);
		if (hooked_page->trampolines == NULL)
		{
			pool_manager::release_pool(hooked_page);
			LogError("There is no pre-allocated pool for trampoline");
			return false;
		}

		hooked_page->virtual_address = (unsigned __int64)target_address;
		hooked_page->physical_base_address = GET_PFN(physical_address);
		hooked_page->physical_base_address_of_fake_page_contents = GET_PFN(MmGetPhysicalAddress(&hooked_page->fake_page_contents[0]).QuadPart);
		hooked_page->entry_address = target_page;
		hooked_page->original_entry = *target_page;

		changed_entry = *target_page;

		changed_entry.read = protection_mask & 1;
		changed_entry.write = (protection_mask & 2) >> 1;

		if (protection_mask & 4)
		{
			changed_entry.read = 0;
			changed_entry.write = 0;
			changed_entry.execute = 1;

			changed_entry.physical_address = hooked_page->physical_base_address_of_fake_page_contents;

			//
			// Copy unchanged page content, It will be used in ept read violation to show guest system original content of page
			//
			RtlCopyMemory(&hooked_page->fake_page_contents, virtual_page_beginning, PAGE_SIZE);

			hook_instruction_memory(hooked_page, target_address, hook_function, origin_function);
		}

		hooked_page->changed_entry = changed_entry;

		//
		// Track all hooked pages
		//
		InsertHeadList(&g_vmm_context->ept_state->hooked_page_list, &hooked_page->hooked_page_list);

		swap_pml1_and_invalidate_tlb(target_page, changed_entry, INVEPT_SINGLE_CONTEXT);

		return true;
	}

	/// <summary>
	/// Unhook single page
	/// </summary>
	/// <param name="physical_address"></param>
	/// <returns></returns>
	bool unhook_page(unsigned __int64 physical_address)
	{
		PLIST_ENTRY current;

		current = &g_vmm_context->ept_state->hooked_page_list;
		while (&g_vmm_context->ept_state->hooked_page_list != current->Flink)
		{
			current = current->Flink;
			__ept_hooked_page_info* hooked_entry = CONTAINING_RECORD(current, __ept_hooked_page_info, hooked_page_list);

			if (hooked_entry->physical_base_address == GET_PFN(physical_address))
			{
				swap_pml1_and_invalidate_tlb(hooked_entry->entry_address, hooked_entry->original_entry, INVEPT_SINGLE_CONTEXT);
				RemoveEntryList(current);

				// Set pools to refresh
				for (unsigned __int8 i = 0; i <= hooked_entry->current_trampoline_index; i++)
					pool_manager::set_refresh(hooked_entry->trampolines[i]);

				pool_manager::set_refresh(hooked_entry);
				pool_manager::refresh_pool();
				return true;
			}
		}
		return false;
	}

	/// <summary>
	/// Unhook all hooked pages and invalidate tlb
	/// </summary>
	void unhook_all_pages()
	{
		PLIST_ENTRY current;

		current = &g_vmm_context->ept_state->hooked_page_list;
		while (&g_vmm_context->ept_state->hooked_page_list != current->Flink)
		{
			current = current->Flink;
			__ept_hooked_page_info* hooked_entry = CONTAINING_RECORD(current, __ept_hooked_page_info, hooked_page_list);

			// Restore original pte value
			swap_pml1_and_invalidate_tlb(hooked_entry->entry_address, hooked_entry->original_entry, INVEPT_SINGLE_CONTEXT);

			RemoveEntryList(current);

			// Set pools to refresh
			for (unsigned __int8 i = 0; i <= hooked_entry->current_trampoline_index; i++)
				pool_manager::set_refresh(hooked_entry->trampolines[i]);

			pool_manager::set_refresh(hooked_entry);
		}

		// Refresh pool
		pool_manager::refresh_pool();
	}

	/// <summary>
	/// Set or unset mtf
	/// </summary>
	/// <param name="set"></param>
	void set_monitor_trap_flag(bool set)
	{
		unsigned __int64 vm_execution_controls = hv::vmread(CONTROL_PRIMARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS);

		if (set)
		{
			vm_execution_controls |= CPU_BASED_MONITOR_TRAP_FLAG;
		}
		else
		{
			vm_execution_controls &= ~CPU_BASED_MONITOR_TRAP_FLAG;
		}

		__vmx_vmwrite(CONTROL_PRIMARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, vm_execution_controls);
	}
}