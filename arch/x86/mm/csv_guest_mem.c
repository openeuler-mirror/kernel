// SPDX-License-Identifier: GPL-2.0-only
/*
 * Hygon China Secure Virtualization (CSV)
 *
 * Copyright (C) Hygon Info Technologies Ltd.
 *
 * Description: The file is used to reserve memblock for CSV3 guest.
 *
 * Author: Wencheng Yang <yangwencheng@hygon.cn>
 */

#include <linux/init.h>
#include <linux/atomic.h>
#include <linux/nodemask.h>
#include <linux/memblock.h>
#include <linux/sizes.h>
#include <linux/mutex.h>
#include <linux/cc_platform.h>
#include <linux/set_memory.h>
#include <asm/page.h>
#include <asm/csv.h>

#define CSV3_MEM_BLOCK_SIZE (SZ_1G)
#define CSV3_MEM_BLOCK_ALIGN (SZ_1G)

/**
 * The struct is used to record the memory block information.
 * If the block is the header of the large block, the head is true.
 * The size is the size of the large block, each sub block size is
 * mem_block->block_size.
 */
struct block {
	phys_addr_t start;
	unsigned long size; // the size of the large block
	bool used;
	bool head; // head of the block
};

struct mem_block {
	unsigned long block_align;
	unsigned long block_size;
	unsigned long nr_blocks;
	unsigned long nr_free;
	bool decrypted;
	bool decrypt_failed;
	struct block blocks[];
};

static struct mem_block *csv3_mem_block;

static phys_addr_t size_cmdline __initdata = -1;

static DEFINE_MUTEX(lock);

/**
 * Config string format: csv3_guest_rsv_mb=size
 * For example: csv3_guest_rsv_mb=1G
 *              csv3_guest_rsv_mb=2048M
 *
 * size: the size of memory to reserve, it should be multiple
 *       of CSV3_MEM_BLOCK_SIZE, i.e. 1G.
 */
static int __init early_csv3_reserve_mem_block(char *p)
{
	if (!p)
		return -EINVAL;

	size_cmdline = memparse(p, &p);

	return 0;
}

early_param("csv3_guest_rsv_mb", early_csv3_reserve_mem_block);

/**
 * csv3_reserve_mem_block() - reserve memblock for csv3 guest.
 */
static void __init csv3_reserve_mem_block(void)
{
	unsigned long csv3_mem_size;
	unsigned long size, reserved_size, meta_size;
	unsigned long block_cnt, reserved_cnt, try_cnt;
	size_t align = CSV3_MEM_BLOCK_ALIGN;
	size_t block_size = CSV3_MEM_BLOCK_SIZE;
	phys_addr_t base;
	int i;

	if (!csv3_active())
		return;

	if (size_cmdline == -1 || size_cmdline == 0)
		return;

	csv3_mem_size = size_cmdline;
	if (size_cmdline % align) {
		csv3_mem_size = ALIGN(size_cmdline, block_size);
		pr_warn("csv3_guest_rsv_mb: size must be multiple of %u MB, align up to %lu MB\n",
			CSV3_MEM_BLOCK_ALIGN / SZ_1M, csv3_mem_size / SZ_1M);
	}

	block_cnt = csv3_mem_size / block_size;
	meta_size = sizeof(struct mem_block) + block_cnt * sizeof(struct block);
	csv3_mem_block = memblock_alloc_node(meta_size, SMP_CACHE_BYTES,
					     NUMA_NO_NODE);
	if (!csv3_mem_block) {
		pr_err("csv3_guest_rsv_mb: fail to allocate size 0x%lx from memblock\n",
			meta_size);
		return;
	}

	memset(csv3_mem_block, 0, meta_size);
	csv3_mem_block->block_size = block_size;
	csv3_mem_block->block_align = align;

	try_cnt = 0;
	reserved_size = 0;
	reserved_cnt = 0;
	while (reserved_size < csv3_mem_size) {
		size = csv3_mem_size - reserved_size - try_cnt * SZ_1G;
		base = memblock_phys_alloc_try_nid(size,
						csv3_mem_block->block_align,
						NUMA_NO_NODE);
		if (!base) {
			pr_warn("csv3_guest_rsv_mb: reserve memblock failed\n");
			// can't alloc any more, no retry.
			if (size <= CSV3_MEM_BLOCK_SIZE)
				goto fail_free;

			try_cnt++;
			continue;
		} else {
			/* success, reset try_cnt */
			try_cnt = 0;
		}

		pr_debug("csv3_guest_rsv_mb: reserve memblock[%ld] 0x%lx MB memory, pa 0x%llx\n",
			reserved_cnt, size / SZ_1M, base);

		block_cnt = size / csv3_mem_block->block_size;
		csv3_mem_block->blocks[reserved_cnt].head = true;
		csv3_mem_block->blocks[reserved_cnt].size = size;
		for (i = 0; i < block_cnt; i++) {
			csv3_mem_block->blocks[reserved_cnt].start = base;
			csv3_mem_block->blocks[reserved_cnt].used = false;
			csv3_mem_block->nr_blocks++;
			csv3_mem_block->nr_free++;
			base += csv3_mem_block->block_size;
			reserved_cnt++;
		}

		reserved_size += size;
	}

	pr_info("csv3_guest_rsv_mb: reserved %lu MB memory from memblock\n",
		 reserved_size / SZ_1M);

	return;

fail_free:
	/* find the head block, free the block */
	for (i = 0; i < reserved_cnt; i++) {
		if (!csv3_mem_block->blocks[i].head)
			continue;
		base = csv3_mem_block->blocks[i].start;
		size = csv3_mem_block->blocks[i].size;
		memblock_phys_free(base, size);
	}

	memblock_phys_free(__pa(csv3_mem_block), meta_size);
	csv3_mem_block = NULL;
}

static bool decrypt_mem_block(void)
{
	unsigned long size;
	unsigned long virt;
	phys_addr_t phys_addr;
	int i, j;

	for (i = 0; i < csv3_mem_block->nr_blocks; i++) {
		if (!csv3_mem_block->blocks[i].head)
			continue;
		phys_addr = csv3_mem_block->blocks[i].start;
		size = csv3_mem_block->blocks[i].size;
		virt = (unsigned long)phys_to_virt(phys_addr);
		if (set_memory_decrypted(virt, size >> PAGE_SHIFT)) {
			pr_err("csv3_guest_rsv_mb: decrypt pa 0x%llx size 0x%lx va 0x%llx failed\n",
			       phys_addr, size, (u64)virt);
			break;
		}
	}

	if (i == csv3_mem_block->nr_blocks)
		return true;

	// decrypt failed, restore to encrypted state
	for (j = 0; j < i; j++) {
		if (!csv3_mem_block->blocks[j].head)
			continue;

		phys_addr = csv3_mem_block->blocks[j].start;
		size = csv3_mem_block->blocks[j].size;
		virt = (unsigned long)phys_to_virt(phys_addr);
		set_memory_encrypted(virt, size >> PAGE_SHIFT);
	}

	return false;
}

phys_addr_t csv3_alloc_mem_block(void)
{
	phys_addr_t phys_addr = 0;
	int i;

	if (!csv3_active())
		return 0;

	if (!csv3_mem_block)
		return 0;

	mutex_lock(&lock);

	if (unlikely(csv3_mem_block->decrypt_failed)) {
		mutex_unlock(&lock);
		return 0;
	}

	if (unlikely(!csv3_mem_block->decrypted)) {
		if (!decrypt_mem_block()) {
			csv3_mem_block->decrypt_failed = true;
			mutex_unlock(&lock);
			return 0;
		}

		csv3_mem_block->decrypted = true;
	}

	if (csv3_mem_block->nr_free == 0)
		goto out;

	// iterate csv3_mem_block->blocks to find a free block.
	for (i = 0; i < csv3_mem_block->nr_blocks; i++) {
		if (csv3_mem_block->blocks[i].used)
			continue;

		csv3_mem_block->blocks[i].used = true;
		csv3_mem_block->nr_free--;
		break;
	}

	if (i == csv3_mem_block->nr_blocks)
		goto out;
	else
		phys_addr = csv3_mem_block->blocks[i].start;
out:
	mutex_unlock(&lock);

	pr_debug("csv3_guest_rsv_mb: allocate 0x%lx MB memory, pa 0x%llx\n",
		 phys_addr ? csv3_mem_block->block_size / SZ_1M : 0, phys_addr);

	return phys_addr;
}
EXPORT_SYMBOL_GPL(csv3_alloc_mem_block);

void csv3_free_mem_block(phys_addr_t phys_addr)
{
	int i;
	bool free_done = false;

	if (!csv3_active())
		return;

	if (!csv3_mem_block || !phys_addr)
		return;

	mutex_lock(&lock);

	if (csv3_mem_block->nr_free >= csv3_mem_block->nr_blocks) {
		mutex_unlock(&lock);
		pr_err("csv3_guest_rsv_mb: all blocks are free, please check\n");
		return;
	}

	// find the block and mark it as free.
	for (i = 0; i < csv3_mem_block->nr_blocks; i++) {
		if (!csv3_mem_block->blocks[i].used ||
		    csv3_mem_block->blocks[i].start != phys_addr)
			continue;

		csv3_mem_block->blocks[i].used = false;

		csv3_mem_block->nr_free++;
		free_done = true;
		break;
	}

	mutex_unlock(&lock);

	if (free_done) {
		pr_debug("csv3_guest_rsv_mb: free 0x%lx MB memory, pa 0x%llx\n",
			 csv3_mem_block->block_size / SZ_1M, phys_addr);
	} else {
		pr_err("csv3_guest_rsv_mb: fail to free 0x%lx MB memory, pa 0x%llx\n",
		       csv3_mem_block->block_size / SZ_1M, phys_addr);
	}
}
EXPORT_SYMBOL_GPL(csv3_free_mem_block);

size_t csv3_get_mem_block_size(void)
{
	if (!csv3_mem_block)
		return 0;

	return csv3_mem_block->block_size;
}
EXPORT_SYMBOL_GPL(csv3_get_mem_block_size);

void __init early_csv_guest_mem_init(void)
{
	csv3_reserve_mem_block();
}

