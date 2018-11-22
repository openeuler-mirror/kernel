/*
 * ARM64 SEA error recoery support
 *
 * Copyright 2017 Huawei Technologies Co., Ltd.
 *   Author: Xie XiuQi <xiexiuqi@huawei.com>
 *   Author: Wang Xiongfeng <wangxiongfeng2@huawei.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation;
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <linux/kernel.h>
#include <linux/cper.h>
#include <linux/mm.h>
#include <linux/preempt.h>
#include <linux/acpi.h>
#include <linux/sched/signal.h>
#include <linux/ras.h>

#include <acpi/actbl1.h>
#include <acpi/ghes.h>
#include <acpi/apei.h>

#include <asm/thread_info.h>
#include <asm/atomic.h>
#include <asm/ras.h>

/*
 * Need to save faulting physical address associated with a process
 * in the sea ghes handler some place where we can grab it back
 * later in sea_notify_process()
 */
#define SEA_INFO_MAX    16

struct sea_info {
	atomic_t                inuse;
	struct task_struct      *t;
	__u64                   paddr;
} sea_info[SEA_INFO_MAX];

static bool sea_save_info(__u64 addr)
{
	struct sea_info *si;

	for (si = sea_info; si < &sea_info[SEA_INFO_MAX]; si++) {
		if (atomic_cmpxchg(&si->inuse, 0, 1) == 0) {
			si->t = current;
			si->paddr = addr;
			return true;
		}
	}

	pr_err("Too many concurrent recoverable errors\n");
	return false;
}

static struct sea_info *sea_find_info(void)
{
	struct sea_info *si;

	for (si = sea_info; si < &sea_info[SEA_INFO_MAX]; si++)
		if (atomic_read(&si->inuse) && si->t == current)
			return si;
	return NULL;
}

static void sea_clear_info(struct sea_info *si)
{
	atomic_set(&si->inuse, 0);
}

/*
 * Called in process context that interrupted by SEA and marked with
 * TIF_SEA_NOTIFY, just before returning to erroneous userland.
 * This code is allowed to sleep.
 * Attempt possible recovery such as calling the high level VM handler to
 * process any corrupted pages, and kill/signal current process if required.
 * Action required errors are handled here.
 */
void sea_notify_process(void)
{
	unsigned long pfn;
	int fail = 0, flags = MF_ACTION_REQUIRED;
	struct sea_info *si = sea_find_info();

	if (!si)
		panic("Lost physical address for consumed uncorrectable error");

	clear_thread_flag(TIF_SEA_NOTIFY);
	do {
		pfn = si->paddr >> PAGE_SHIFT;


		pr_err("Uncorrected hardware memory error in user-access at %llx\n",
			si->paddr);
		/*
		 * We must call memory_failure() here even if the current process is
		 * doomed. We still need to mark the page as poisoned and alert any
		 * other users of the page.
		 */
		if (memory_failure(pfn, flags) < 0)
			fail++;

		sea_clear_info(si);

		si = sea_find_info();
	} while (si);

	if (fail) {
		pr_err("Memory error not recovered\n");
		force_sig(SIGBUS, current);
	}
}

void ghes_arm_process_error(struct ghes *ghes, struct cper_sec_proc_arm *err)
{
	int i;
	bool info_saved = false;
	struct cper_arm_err_info *err_info;

	log_arm_hw_error(err);

	if ((ghes->generic->notify.type != ACPI_HEST_NOTIFY_SEA) ||
	    (ghes->estatus->error_severity != CPER_SEV_RECOVERABLE))
		return;

	err_info = (struct cper_arm_err_info *)(err + 1);
	for (i = 0; i < err->err_info_num; i++, err_info++) {
		if ((err_info->validation_bits & CPER_ARM_INFO_VALID_PHYSICAL_ADDR) &&
		    (err_info->type == CPER_ARM_CACHE_ERROR))
			info_saved |= sea_save_info(err_info->physical_fault_addr);
	}

	if (info_saved)
		set_thread_flag(TIF_SEA_NOTIFY);
}

int ghes_mem_err_callback(struct notifier_block *nb, unsigned long val, void *data)
{
	bool info_saved = false;
	struct ghes_mem_err *ghes_mem = (struct ghes_mem_err *)data;
	struct cper_sec_mem_err *mem_err = ghes_mem->mem_err;

	if ((ghes_mem->notify_type != ACPI_HEST_NOTIFY_SEA) ||
	    (ghes_mem->severity != CPER_SEV_RECOVERABLE))
		return 0;

	if (mem_err->validation_bits & CPER_MEM_VALID_PA)
		info_saved = sea_save_info(mem_err->physical_addr);

	if (info_saved)
		set_thread_flag(TIF_SEA_NOTIFY);

	return 0;
}

static struct notifier_block ghes_mem_err_nb = {
	.notifier_call	= ghes_mem_err_callback,
};

static int arm64_err_recov_init(void)
{
	atomic_notifier_chain_register(&ghes_mem_err_chain, &ghes_mem_err_nb);
	return 0;
}

late_initcall(arm64_err_recov_init);
