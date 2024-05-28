// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2013, 2014 Linaro Ltd;  <roy.franz@linaro.org>
 *
 * This file implements the EFI boot stub for the arm64 kernel.
 * Adapted from ARM version by Mark Salter <msalter@redhat.com>
 */


#include <linux/efi.h>
#include <asm/efi.h>
#include <asm/memory.h>
#include <asm/sections.h>
#include <asm/sysreg.h>

#include "efistub.h"

#define MAX_MEMMAP_REGIONS 32

struct mem_vector {
	unsigned long long start;
	unsigned long long size;
};

static struct mem_vector mem_avoid[MAX_MEMMAP_REGIONS];

static int
efi_parse_memmap(char *p, unsigned long long *start, unsigned long long *size)
{
	char *oldp;
	u64 mem_size;

	if (!p)
		return -EINVAL;

	oldp = p;
	mem_size = memparse(p, &p);
	if (p == oldp)
		return -EINVAL;
	if (!mem_size)
		return -EINVAL;
	if (*p != '$')
		return -EINVAL;

	*start = memparse(p + 1, &p);
	*size = mem_size;

	return 0;
}

void efi_parse_option_memmap(const char *str)
{
	int rc;
	static int idx;
	char *k, *p = (char *)str;

	while (p && (idx < MAX_MEMMAP_REGIONS)) {
		k = strchr(p, ',');
		if (k)
			*k++ = 0;

		rc = efi_parse_memmap(p, &mem_avoid[idx].start, &mem_avoid[idx].size);
		if (rc < 0)
			efi_err("Failed to parse memmap cmdlines, index: %d, str: %s\n", idx, p);

		p = k;
		idx++;
	}
}

void mem_avoid_memmap(void)
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
		if (status != EFI_SUCCESS) {
			efi_err("Failed to reserve memmap, index: %d, status: %lu\n", i, status);
			mem_avoid[i].size = 0;
		}
	}
}

void free_avoid_memmap(void)
{
	int i;

	for (i = 0; i < MAX_MEMMAP_REGIONS; i++) {
		if (!mem_avoid[i].size)
			continue;
		efi_free(mem_avoid[i].size, mem_avoid[i].start);
	}
}

#ifdef CONFIG_NOKASLR_MEM_RANGE
#define MAX_MEM_NOKASLR_REGIONS 4

struct mem_region {
	unsigned long long start;
	unsigned long long size;
};

static struct mem_region mem_nokaslr[MAX_MEM_NOKASLR_REGIONS];

void efi_parse_option_nokaslr_ranges(char *str)
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
			efi_warn("Nokaslr values \"%s\" error.\n", oldstr);
			break;
		}
		end = memparse(str + 1, &str);
		if (start >= end) {
			efi_warn("Nokaslr values \"%s\" error, start >= end.\n", oldstr);
			break;
		}

		mem_nokaslr[i].start = start;
		mem_nokaslr[i].size = end - start;
		str = k;
		i++;
	}
}

static bool mem_overlaps(struct mem_region *one, struct mem_region *two)
{
	if (one->start + one->size <= two->start)
		return false;
	if (one->start >= two->start + two->size)
		return false;
	return true;
}

static bool mem_avoid_overlap(struct mem_region *region, struct mem_region *overlap)
{
	int i;
	u64 earliest = region->start + region->size;
	bool is_overlapping = false;

	for (i = 0; i < MAX_MEM_NOKASLR_REGIONS; i++) {
		if (mem_overlaps(region, &mem_nokaslr[i]) &&
		    mem_nokaslr[i].start < earliest) {
			*overlap = mem_nokaslr[i];
			earliest = overlap->start;
			is_overlapping = true;
		}
	}
	return is_overlapping;
}

unsigned long cal_slots_avoid_overlap(efi_memory_desc_t *md, unsigned long size, u8 cal_type,
					  unsigned long align_shift, unsigned long target)
{
	struct mem_region region, overlap;
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
#endif

efi_status_t check_platform_features(void)
{
	u64 tg;

	/* UEFI mandates support for 4 KB granularity, no need to check */
	if (IS_ENABLED(CONFIG_ARM64_4K_PAGES))
		return EFI_SUCCESS;

	tg = (read_cpuid(ID_AA64MMFR0_EL1) >> ID_AA64MMFR0_TGRAN_SHIFT) & 0xf;
	if (tg < ID_AA64MMFR0_TGRAN_SUPPORTED_MIN || tg > ID_AA64MMFR0_TGRAN_SUPPORTED_MAX) {
		if (IS_ENABLED(CONFIG_ARM64_64K_PAGES))
			efi_err("This 64 KB granular kernel is not supported by your CPU\n");
		else
			efi_err("This 16 KB granular kernel is not supported by your CPU\n");
		return EFI_UNSUPPORTED;
	}
	return EFI_SUCCESS;
}

/*
 * Distro versions of GRUB may ignore the BSS allocation entirely (i.e., fail
 * to provide space, and fail to zero it). Check for this condition by double
 * checking that the first and the last byte of the image are covered by the
 * same EFI memory map entry.
 */
static bool check_image_region(u64 base, u64 size)
{
	unsigned long map_size, desc_size, buff_size;
	efi_memory_desc_t *memory_map;
	struct efi_boot_memmap map;
	efi_status_t status;
	bool ret = false;
	int map_offset;

	map.map =	&memory_map;
	map.map_size =	&map_size;
	map.desc_size =	&desc_size;
	map.desc_ver =	NULL;
	map.key_ptr =	NULL;
	map.buff_size =	&buff_size;

	status = efi_get_memory_map(&map);
	if (status != EFI_SUCCESS)
		return false;

	for (map_offset = 0; map_offset < map_size; map_offset += desc_size) {
		efi_memory_desc_t *md = (void *)memory_map + map_offset;
		u64 end = md->phys_addr + md->num_pages * EFI_PAGE_SIZE;

		/*
		 * Find the region that covers base, and return whether
		 * it covers base+size bytes.
		 */
		if (base >= md->phys_addr && base < end) {
			ret = (base + size) <= end;
			break;
		}
	}

	efi_bs_call(free_pool, memory_map);

	return ret;
}

/*
 * Although relocatable kernels can fix up the misalignment with respect to
 * MIN_KIMG_ALIGN, the resulting virtual text addresses are subtly out of
 * sync with those recorded in the vmlinux when kaslr is disabled but the
 * image required relocation anyway. Therefore retain 2M alignment unless
 * KASLR is in use.
 */
static u64 min_kimg_align(void)
{
	return efi_nokaslr ? MIN_KIMG_ALIGN : EFI_KIMG_ALIGN;
}

efi_status_t handle_kernel_image(unsigned long *image_addr,
				 unsigned long *image_size,
				 unsigned long *reserve_addr,
				 unsigned long *reserve_size,
				 efi_loaded_image_t *image)
{
	efi_status_t status;
	unsigned long kernel_size, kernel_memsize = 0;
	u32 phys_seed = 0;

	if (IS_ENABLED(CONFIG_RANDOMIZE_BASE)) {
		if (!efi_nokaslr) {
			status = efi_get_random_bytes(sizeof(phys_seed),
						      (u8 *)&phys_seed);
			if (status == EFI_NOT_FOUND) {
				efi_info("EFI_RNG_PROTOCOL unavailable, KASLR will be disabled\n");
				efi_nokaslr = true;
			} else if (status != EFI_SUCCESS) {
				efi_err("efi_get_random_bytes() failed (0x%lx), KASLR will be disabled\n",
					status);
				efi_nokaslr = true;
			}
		} else {
			efi_info("KASLR disabled on kernel command line\n");
		}
	}

	if (image->image_base != _text)
		efi_err("FIRMWARE BUG: efi_loaded_image_t::image_base has bogus value\n");

	if (!IS_ALIGNED((u64)_text, SEGMENT_ALIGN))
		efi_err("FIRMWARE BUG: kernel image not aligned on %dk boundary\n",
			SEGMENT_ALIGN >> 10);

	kernel_size = _edata - _text;
	kernel_memsize = kernel_size + (_end - _edata);
	*reserve_size = kernel_memsize;

	if (IS_ENABLED(CONFIG_RANDOMIZE_BASE) && phys_seed != 0) {
		/*
		 * If KASLR is enabled, and we have some randomness available,
		 * locate the kernel at a randomized offset in physical memory.
		 */
		status = efi_random_alloc(*reserve_size, min_kimg_align(),
					  reserve_addr, phys_seed);
	} else {
		status = EFI_OUT_OF_RESOURCES;
	}

	if (status != EFI_SUCCESS) {
		if (!check_image_region((u64)_text, kernel_memsize)) {
			efi_err("FIRMWARE BUG: Image BSS overlaps adjacent EFI memory region\n");
		} else if (IS_ALIGNED((u64)_text, min_kimg_align())) {
			/*
			 * Just execute from wherever we were loaded by the
			 * UEFI PE/COFF loader if the alignment is suitable.
			 */
			*image_addr = (u64)_text;
			*reserve_size = 0;
			return EFI_SUCCESS;
		}

		status = efi_allocate_pages_aligned(*reserve_size, reserve_addr,
						    ULONG_MAX, min_kimg_align());

		if (status != EFI_SUCCESS) {
			efi_err("Failed to relocate kernel\n");
			*reserve_size = 0;
			return status;
		}
	}

	*image_addr = *reserve_addr;
	memcpy((void *)*image_addr, _text, kernel_size);

	return EFI_SUCCESS;
}
