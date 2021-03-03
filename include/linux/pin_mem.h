/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2021. Huawei Technologies Co., Ltd. All rights reserved.
 * Provide the pin memory method for checkpoint and restore task.
 */
#ifndef _LINUX_PIN_MEMORY_H
#define _LINUX_PIN_MEMORY_H

#ifdef CONFIG_PIN_MEMORY
#include <linux/errno.h>
#include <linux/mm_types.h>
#include <linux/err.h>
#ifdef CONFIG_ARM64
#include <linux/ioport.h>
#endif

#define PAGE_BUDDY_MAPCOUNT_VALUE  (~PG_buddy)

#define COLLECT_PAGES_FINISH         0
#define COLLECT_PAGES_NEED_CONTINUE  1
#define COLLECT_PAGES_FAIL           -1

#define COMPOUND_PAD_MASK  0xffffffff
#define COMPOUND_PAD_START  0x88
#define COMPOUND_PAD_DELTA  0x40
#define LIST_POISON4 0xdead000000000400
#define PAGE_FLAGS_CHECK_RESERVED  (1UL << PG_reserved)
#define SHA256_DIGEST_SIZE  32
#define next_pme(pme)  ((unsigned long *)(pme + 1) + pme->nr_pages)
#define PIN_MEM_DUMP_MAGIC  0xfeab000000001acd
struct page_map_entry {
	unsigned long virt_addr;
	unsigned int nr_pages;
	unsigned int is_huge_page;
	unsigned long redirect_start;
	unsigned long phy_addr_array[0];
};

struct page_map_info {
	int pid;
	int pid_reserved;
	unsigned int entry_num;
	int disable_free_page;
	struct page_map_entry *pme;
};

struct pin_mem_dump_info {
	char sha_digest[SHA256_DIGEST_SIZE];
	unsigned long magic;
	unsigned int pin_pid_num;
	struct page_map_info pmi_array[0];
};

struct redirect_info {
	unsigned int redirect_pages;
	unsigned int redirect_index[0];
};

extern struct page_map_info *get_page_map_info(int pid);
extern struct page_map_info *create_page_map_info(int pid);
extern vm_fault_t do_mem_remap(int pid, struct mm_struct *mm);
extern vm_fault_t do_anon_page_remap(struct vm_area_struct *vma, unsigned long address,
	pmd_t *pmd, struct page *page);
extern void clear_pin_memory_record(void);
extern int pin_mem_area(struct task_struct *task, struct mm_struct *mm,
		unsigned long start_addr, unsigned long end_addr);
extern vm_fault_t do_anon_huge_page_remap(struct vm_area_struct *vma, unsigned long address,
		pmd_t *pmd, struct page *page);
extern int finish_pin_mem_dump(void);

/* reserve space for pin memory*/
#ifdef CONFIG_ARM64
extern struct resource pin_memory_resource;
#endif
extern void init_reserve_page_map(unsigned long map_addr, unsigned long map_size);

#endif /* CONFIG_PIN_MEMORY */
#endif /* _LINUX_PIN_MEMORY_H */
