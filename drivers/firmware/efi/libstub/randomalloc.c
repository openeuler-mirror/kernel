// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2016 Linaro Ltd;  <ard.biesheuvel@linaro.org>
 */

#include <linux/efi.h>
#include <linux/log2.h>
#include <asm/efi.h>

#include "efistub.h"

#if defined (CONFIG_KASLR_SKIP_MEM_RANGE) && defined (CONFIG_ARM64)
#define CAL_SLOTS_NUMBER	 0
#define CAL_SLOTS_PHYADDR	 1

#define MAX_MEMMAP_REGIONS 32
#define MAX_MEM_NOKASLR_REGIONS	4

enum mem_avoid_index {
	MAX_MEMMAP_REGIONS_BEGIN = 0,
	MAX_MEMMAP_REGIONS_END = MAX_MEMMAP_REGIONS_BEGIN + MAX_MEMMAP_REGIONS - 1,
	MEM_AVOID_MEM_NOKASLR_BEGIN,
	MEM_AVOID_MEM_NOKASLR_END = MEM_AVOID_MEM_NOKASLR_BEGIN + MAX_MEM_NOKASLR_REGIONS - 1,
	MEM_AVOID_MAX,
};

struct mem_vector {
	unsigned long long start;
	unsigned long long size;
};

static struct mem_vector mem_avoid[MEM_AVOID_MAX];

static bool mem_overlaps(struct mem_vector *one, struct mem_vector *two)
{
	if (one->start + one->size <= two->start)
		return false;
	if (one->start >= two->start + two->size)
		return false;
	return true;
}

static bool mem_avoid_overlap(struct mem_vector *region, struct mem_vector *overlap)
{
	int i;
	u64 earliest = region->start + region->size;
	bool is_overlapping = false;

	for (i = 0; i < MEM_AVOID_MAX; i++) {
		if (mem_overlaps(region, &mem_avoid[i]) &&
		    mem_avoid[i].start < earliest) {
			*overlap = mem_avoid[i];
			earliest = overlap->start;
			is_overlapping = true;
		}
	}
	return is_overlapping;
}

static unsigned long cal_slots_avoid_overlap(efi_memory_desc_t *md, unsigned long size, u8 cal_type,
					  unsigned long align_shift, unsigned long target)
{
	struct mem_vector region, overlap;
	unsigned long region_end, first, last;
	unsigned long align = 1UL << align_shift;
	unsigned long total_slots = 0, slots;

	region.start = md->phys_addr;
	region_end = min(md->phys_addr + md->num_pages * EFI_PAGE_SIZE - 1, (u64)ULONG_MAX);

	while (region.start < region_end) {
		first = round_up(region.start, align);
		last = round_down(region_end - size + 1, align);

		if (first > last)
			break;

		region.size = region_end - region.start + 1;

		if (!mem_avoid_overlap(&region, &overlap)) {
			slots = ((last - first) >> align_shift) + 1;
			total_slots += slots;

			if (cal_type == CAL_SLOTS_PHYADDR)
				return first + target * align;

			break;
		}

		if (overlap.start >= region.start + size) {
			slots = ((round_up(overlap.start - size + 1, align) - first) >>
				align_shift) + 1;
			total_slots += slots;

			if (cal_type == CAL_SLOTS_PHYADDR) {
				if (target > slots)
					target -= slots;
				else
					return first + target * align;
			}
		}

		/* Clip off the overlapping region and start over. */
		region.start = overlap.start + overlap.size;
	}

	return total_slots;
}

static void mem_check_memmaps(void)
{
	int i;
	efi_status_t status;
	unsigned long nr_pages;
	unsigned long long start, end;

	for (i = 0; i < MAX_MEMMAP_REGIONS; i++) {
		if (!mem_avoid[i].size)
			continue;
		start = round_down(mem_avoid[i].start, EFI_ALLOC_ALIGN);
		end = round_up(mem_avoid[i].start + mem_avoid[i].size, EFI_ALLOC_ALIGN);
		nr_pages = (end - start) / EFI_PAGE_SIZE;

		mem_avoid[i].start = start;
		mem_avoid[i].size = end - start;
		status = efi_bs_call(allocate_pages, EFI_ALLOCATE_ADDRESS,
				     EFI_LOADER_DATA, nr_pages, &mem_avoid[i].start);
		if (status == EFI_SUCCESS) {
			efi_free(mem_avoid[i].size, mem_avoid[i].start);
		} else {
			mem_avoid[i].size = 0;
			efi_err("Failed to reserve memmap, index: %d, status: %lu\n", i, status);
		}
	}
}

void mem_avoid_memmap(char *str)
{
	static int i;

	while (str && (i < MAX_MEMMAP_REGIONS)) {
		char *oldstr;
		u64 start, size;
		char *k = strchr(str, ',');

		if (k)
			*k++ = 0;

		oldstr = str;
		size = memparse(str, &str);
		if (str == oldstr || *str != '$') {
			efi_warn("memap values error.\n");
			break;
		}

		start = memparse(str + 1, &str);
		if (size <= 0) {
			efi_warn("memap values error, size should be more than 0.\n");
			break;
		}

		mem_avoid[MAX_MEMMAP_REGIONS_BEGIN + i].start = start;
		mem_avoid[MAX_MEMMAP_REGIONS_BEGIN + i].size = size;
		str = k;
		i++;
	}
	mem_check_memmaps();
}

void mem_avoid_mem_nokaslr(char *str)
{
	int i = 0;

	while (str && (i < MAX_MEM_NOKASLR_REGIONS)) {
		char *oldstr;
		u64 start, end;
		char *k = strchr(str, ',');

		if (k)
			*k++ = 0;

		oldstr = str;
		start = memparse(str, &str);
		if (str == oldstr || *str != '-') {
			efi_warn("nokaslr values error.\n");
			break;
		}

		end = memparse(str + 1, &str);
		if (start >= end) {
			efi_warn("nokaslr values error, start should be less than end.\n");
			break;
		}

		mem_avoid[MEM_AVOID_MEM_NOKASLR_BEGIN + i].start = start;
		mem_avoid[MEM_AVOID_MEM_NOKASLR_BEGIN + i].size = end - start;
		str = k;
		i++;
	}
}
#endif
/*
 * Return the number of slots covered by this entry, i.e., the number of
 * addresses it covers that are suitably aligned and supply enough room
 * for the allocation.
 */
static unsigned long get_entry_num_slots(efi_memory_desc_t *md,
					 unsigned long size,
					 unsigned long align_shift,
					 u64 alloc_min, u64 alloc_max)
{
	unsigned long align = 1UL << align_shift;
	u64 first_slot, last_slot, region_end;

	if (md->type != EFI_CONVENTIONAL_MEMORY)
		return 0;

	if (efi_soft_reserve_enabled() &&
	    (md->attribute & EFI_MEMORY_SP))
		return 0;

	region_end = min(md->phys_addr + md->num_pages * EFI_PAGE_SIZE - 1,
			 alloc_max);
	if (region_end < size)
		return 0;

	first_slot = round_up(max(md->phys_addr, alloc_min), align);
	last_slot = round_down(region_end - size + 1, align);

	if (first_slot > last_slot)
		return 0;
#if defined (CONFIG_KASLR_SKIP_MEM_RANGE) && defined (CONFIG_ARM64)
	return cal_slots_avoid_overlap(md, size, CAL_SLOTS_NUMBER, align_shift, 0);
#else
	return ((unsigned long)(last_slot - first_slot) >> align_shift) + 1;
#endif
}

/*
 * The UEFI memory descriptors have a virtual address field that is only used
 * when installing the virtual mapping using SetVirtualAddressMap(). Since it
 * is unused here, we can reuse it to keep track of each descriptor's slot
 * count.
 */
#define MD_NUM_SLOTS(md)	((md)->virt_addr)

efi_status_t efi_random_alloc(unsigned long size,
			      unsigned long align,
			      unsigned long *addr,
			      unsigned long random_seed,
			      int memory_type,
			      unsigned long alloc_min,
			      unsigned long alloc_max)
{
	unsigned long total_slots = 0, target_slot;
	unsigned long total_mirrored_slots = 0;
	struct efi_boot_memmap *map;
	efi_status_t status;
	int map_offset;

	status = efi_get_memory_map(&map, false);
	if (status != EFI_SUCCESS)
		return status;

	if (align < EFI_ALLOC_ALIGN)
		align = EFI_ALLOC_ALIGN;

	size = round_up(size, EFI_ALLOC_ALIGN);

	/* count the suitable slots in each memory map entry */
	for (map_offset = 0; map_offset < map->map_size; map_offset += map->desc_size) {
		efi_memory_desc_t *md = (void *)map->map + map_offset;
		unsigned long slots;

		slots = get_entry_num_slots(md, size, ilog2(align), alloc_min,
					    alloc_max);
		MD_NUM_SLOTS(md) = slots;
		total_slots += slots;
		if (md->attribute & EFI_MEMORY_MORE_RELIABLE)
			total_mirrored_slots += slots;
	}

	/* consider only mirrored slots for randomization if any exist */
	if (total_mirrored_slots > 0)
		total_slots = total_mirrored_slots;

	/* find a random number between 0 and total_slots */
	target_slot = (total_slots * (u64)(random_seed & U32_MAX)) >> 32;

	/*
	 * target_slot is now a value in the range [0, total_slots), and so
	 * it corresponds with exactly one of the suitable slots we recorded
	 * when iterating over the memory map the first time around.
	 *
	 * So iterate over the memory map again, subtracting the number of
	 * slots of each entry at each iteration, until we have found the entry
	 * that covers our chosen slot. Use the residual value of target_slot
	 * to calculate the randomly chosen address, and allocate it directly
	 * using EFI_ALLOCATE_ADDRESS.
	 */
	status = EFI_OUT_OF_RESOURCES;
	for (map_offset = 0; map_offset < map->map_size; map_offset += map->desc_size) {
		efi_memory_desc_t *md = (void *)map->map + map_offset;
		efi_physical_addr_t target;
		unsigned long pages;

		if (total_mirrored_slots > 0 &&
		    !(md->attribute & EFI_MEMORY_MORE_RELIABLE))
			continue;

		if (target_slot >= MD_NUM_SLOTS(md)) {
			target_slot -= MD_NUM_SLOTS(md);
			continue;
		}
#if defined (CONFIG_KASLR_SKIP_MEM_RANGE) && defined (CONFIG_ARM64)
		target = cal_slots_avoid_overlap(md, size, CAL_SLOTS_PHYADDR, ilog2(align),
			target_slot);
#else
		target = round_up(md->phys_addr, align) + target_slot * align;
#endif
		pages = size / EFI_PAGE_SIZE;

		status = efi_bs_call(allocate_pages, EFI_ALLOCATE_ADDRESS,
				     memory_type, pages, &target);
		if (status == EFI_SUCCESS)
			*addr = target;
		break;
	}

	efi_bs_call(free_pool, map);

	return status;
}
