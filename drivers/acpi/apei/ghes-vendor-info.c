// SPDX-License-Identifier: GPL-2.0
/*
 * Handle ARM processor vendor specific error info.
 * Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
 */

#define pr_fmt(fmt)	"GHES: VENDOR: " fmt

#include <linux/init.h>
#include <linux/acpi.h>
#include <linux/signal.h>
#include <linux/task_work.h>
#include <linux/genalloc.h>

#include <acpi/ghes.h>
#include <acpi/apei.h>

#include <asm/setup.h>

#include "apei-internal.h"

#define HISI_OEM	BIT(0)

static int vender_oem __ro_after_init;

#ifdef CONFIG_ARCH_HISI

#define HISI_VENDOR_MAGIC_NUM		0xCC08CC08CC08CC08
#define HISI_VENDOR_CRITICAL_ERR	BIT(0)

struct hisi_armp_vendor_info {
	u64 magic_num;
	u32 ver_info;
	u32 err_flag;	/* bit0:critical error, others: reserved */
	u32 *regs;
} __packed;

static bool ghes_hisi_critical_hw_error(struct cper_sec_proc_arm *err, bool sync)
{
	struct hisi_armp_vendor_info *vendor_info;
	unsigned long err_info_sz;
	char *p;

	if (!sync)
		return false;

	if (!(err->validation_bits & CPER_ARM_VALID_VENDOR_INFO))
		return false;

	p = (char *)(err + 1);
	err_info_sz = sizeof(struct cper_arm_err_info) * err->err_info_num;
	if (!err->context_info_num) {
		vendor_info = (struct hisi_armp_vendor_info *)
			(p + err_info_sz);
	} else {
		struct cper_arm_ctx_info *ctx_info = (struct cper_arm_ctx_info *)
			(p + err_info_sz);

		vendor_info = (struct hisi_armp_vendor_info *)
			(p + err_info_sz +
			ctx_info->size * err->context_info_num);
	}

	if (vendor_info->magic_num != HISI_VENDOR_MAGIC_NUM)
		return false;

	return (bool)(vendor_info->err_flag & HISI_VENDOR_CRITICAL_ERR);
}

struct sei_task_work {
	struct callback_head twork;
	u64 pfn;
};

static struct gen_pool *hisi_sei_pool;

static int ghes_hisi_sei_init(void)
{
	unsigned long addr, len = PAGE_SIZE;
	int rc;

	if (!IS_ENABLED(CONFIG_ARM64_SYNC_SEI))
		return 0;

	hisi_sei_pool = gen_pool_create(ilog2(sizeof(struct sei_task_work)), -1);
	if (!hisi_sei_pool)
		return -ENOMEM;

	addr = (unsigned long)kzalloc(PAGE_ALIGN(len), GFP_KERNEL);
	if (!addr)
		goto err_pool_alloc;

	rc = gen_pool_add(hisi_sei_pool, addr, PAGE_ALIGN(len), -1);
	if (rc)
		goto err_pool_add;

	return 0;

err_pool_add:
	kfree((void *)addr);

err_pool_alloc:
	gen_pool_destroy(hisi_sei_pool);
	hisi_sei_pool = NULL;

	pr_warn("%s init failed\n", __func__);
	return -ENOMEM;
}

static void hisi_sei_kill_task_work(struct callback_head *twork)
{
	struct sei_task_work *ctx = container_of(twork, struct sei_task_work, twork);

	kill_accessing_process(ctx->pfn, MF_ACTION_REQUIRED, true);
	gen_pool_free(hisi_sei_pool, (unsigned long)ctx, sizeof(*ctx));
}

/*
 * Read SEI error address from HiSilicon RAS registers.
 * - s3_3_c15_c0_1 lower 16 bits combined with s3_3_c15_c0_0 form the error physical address.
 * - Clear the registers after reading to acknowledge the error.
 */
static inline u64 hisi_sei_get_error_pa(void)
{
	u64 sw_res_reg0 = read_sysreg(s3_3_c15_c0_0);
	u64 sw_res_reg1 = read_sysreg(s3_3_c15_c0_1);
	u64 pa = ((sw_res_reg1 & 0xFFFFUL) << 32) | (sw_res_reg0 & 0xFFFFFFFFUL);

	write_sysreg(0, s3_3_c15_c0_0);
	write_sysreg(sw_res_reg1 & ~0xFFFFUL, s3_3_c15_c0_1);

	return pa;
}

/*
 * Handle fatal SEI error by scheduling a task work to kill the affected process.
 * @err_pa: The physical address that triggered the SEI.
 *
 * This function allocates a task work structure from a pre-allocated pool and
 * schedules it to run on the current task. The task work will invoke
 * kill_accessing_process() to send a SIGKILL to the process that has the
 * error address mapped. This mechanism is used for memory errors in user-space
 * accessible regions managed by drivers.
 *
 * Return: true if task work is successfully scheduled, false otherwise.
 */
static bool hisi_sei_kill_task(void)
{
	struct sei_task_work *ctx;
	unsigned long err_pa;

	if (!hisi_sei_pool)
		return false;

	ctx = (void *)gen_pool_alloc(hisi_sei_pool, sizeof(*ctx));
	if (!ctx) {
		pr_warn_ratelimited("alloc task work failed\n");
		return false;
	}

	err_pa = hisi_sei_get_error_pa();
	if (!err_pa) {
		pr_warn_ratelimited("err pa is not valid\n");
		gen_pool_free(hisi_sei_pool, (unsigned long)ctx, sizeof(*ctx));
		return false;
	}

	ctx->pfn = PHYS_PFN(err_pa);
	init_task_work(&ctx->twork, hisi_sei_kill_task_work);
	if (task_work_add(current, &ctx->twork, TWA_RESUME)) {
		pr_warn_ratelimited("task work add failed\n");
		gen_pool_free(hisi_sei_pool, (unsigned long)ctx, sizeof(*ctx));
		return false;
	}
	return true;
}

/*
 * Handle HiSilicon specific Synchronous External Interrupt (SEI) errors.
 * @regs: exception registers, NULL if from user space
 *
 * This function processes vendor-specific SEI errors for HiSilicon platforms.
 * For user space errors, it reads the error physical address from RAS registers
 * and schedules a task work to kill the accessing task. If recovery fails or
 * the error is from kernel space, the current process is terminated with SIGKILL.
 *
 * Return: 0 if SEI is handled, -ENOENT if not applicable or unsupported.
 */
static int ghes_hisi_handle_sei(struct pt_regs *regs)
{
	if (!IS_ENABLED(CONFIG_ARM64_SYNC_SEI))
		return -ENOENT;

	if (!arm64_sync_sei_enabled())
		return -ENOENT;

	if (!current->mm)
		return -ENOENT;

	if ((!regs || user_mode(regs)) && hisi_sei_kill_task())
		return 0;

	pr_err("Sending SIGKILL to comm: %s, pid: %d, tgid: %d due to sei not recovered\n",
	       current->comm, current->pid, current->tgid);
	force_sig(SIGKILL);
	return 0;
}
#else
static inline bool ghes_hisi_critical_hw_error(struct cper_sec_proc_arm *err, bool sync)
{
	return false;
}
static int ghes_hisi_sei_init(void) { return 0; }
static int ghes_hisi_handle_sei(struct pt_regs *regs) { return -ENOENT; }
#endif

bool ghes_armp_vendor_critical_error(struct cper_sec_proc_arm *err, bool sync)
{
	if (vender_oem & HISI_OEM)
		return ghes_hisi_critical_hw_error(err, sync);

	return false;
}

int ghes_armp_vendor_handle_sei(struct pt_regs *regs)
{
	if (vender_oem & HISI_OEM)
		return ghes_hisi_handle_sei(regs);

	return -ENOENT;
}

static int __init ghes_check_oem_table(void)
{
	struct acpi_table_header *tbl;
	acpi_status status = AE_OK;

	status = acpi_get_table(ACPI_SIG_HEST, 0, &tbl);
	if (ACPI_FAILURE(status) || !tbl)
		return -ENODEV;

	if (!memcmp(tbl->oem_id, "HISI  ", ACPI_OEM_ID_SIZE)) {
		vender_oem |= HISI_OEM;
		ghes_hisi_sei_init();
	}

	acpi_put_table(tbl);
	return 0;
}
subsys_initcall(ghes_check_oem_table);
