// SPDX-License-Identifier: GPL-2.0-only
/*
 * Userspace interface for CSV guest driver
 *
 * Copyright (C) 2024 Hygon Info Technologies Ltd.
 *
 * Author: fangbaoshun <fangbaoshun@hygon.cn>
 */
#include <linux/module.h>
#include <linux/uaccess.h>
#include <linux/miscdevice.h>
#include <linux/slab.h>
#include <linux/cc_platform.h>
#include <linux/psp-hygon.h>

#include <asm/cacheflush.h>
#include <asm/csv.h>

#include <uapi/linux/kvm_para.h>

#include "csv-guest.h"

/* Mutex to serialize the command handling. */
static DEFINE_MUTEX(csv_cmd_mutex);

static int csv_get_report(unsigned long arg)
{
	u8	*csv_report;
	long	ret;
	struct	csv_report_req req;

	if (copy_from_user(&req, (void __user *)arg,
			   sizeof(struct csv_report_req)))
		return -EFAULT;

	if (req.len < CSV_REPORT_INPUT_DATA_LEN || !req.report_data)
		return -EINVAL;

	csv_report = kzalloc(req.len, GFP_KERNEL);
	if (!csv_report) {
		ret = -ENOMEM;
		goto out;
	}

	/* Save user input data */
	if (copy_from_user(csv_report, req.report_data, CSV_REPORT_INPUT_DATA_LEN)) {
		ret = -EFAULT;
		goto out;
	}

	/* Generate CSV_REPORT using "KVM_HC_VM_ATTESTATION" VMMCALL */
	ret = kvm_hypercall2(KVM_HC_VM_ATTESTATION, __pa(csv_report), req.len);
	if (ret)
		goto out;

	if (copy_to_user(req.report_data, csv_report, req.len))
		ret = -EFAULT;

out:
	kfree(csv_report);
	return ret;
}

static int csv3_get_report(unsigned long arg)
{
	struct csv_report_req input;
	struct page *page = NULL;
	struct csv3_data_attestation_report *cmd_buff = NULL;
	void *req_buff = NULL;
	void *resp_buff = NULL;
	int ret;

	if (copy_from_user(&input, (void __user *)arg, sizeof(input)))
		return -EFAULT;

	if (input.len <= 0 || !input.report_data)
		return -EINVAL;

	/* Use alloc_page for alignment */
	page = alloc_page(GFP_KERNEL_ACCOUNT | __GFP_ZERO);
	if (!page)
		return -ENOMEM;
	cmd_buff = (struct csv3_data_attestation_report *)page_address(page);

	/*
	 * Query the firmware to get minimum length of request buffer and
	 * respond buffer.
	 */
	ret = csv3_issue_request_report(__pa(cmd_buff), sizeof(*cmd_buff));
	if (ret) {
		pr_err("%s: fail to query report length, ret:%d\n", __func__, ret);
		goto err;
	}

	/*
	 * The req_buff and resp_buff are both one page, so the lengths
	 * returned by firmware must not exceed PAGE_SIZE.
	 */
	if (cmd_buff->req_len > PAGE_SIZE || cmd_buff->resp_len > PAGE_SIZE) {
		ret = -EINVAL;
		goto err;
	}

	/*
	 * The input.len must be the maxinum length of the req and resp buffer
	 * at least, otherwise return with error.
	 */
	if (input.len < max(cmd_buff->req_len, cmd_buff->resp_len)) {
		ret = -EINVAL;
		goto err;
	}

	/* Use alloc_page for alignment */
	page = alloc_page(GFP_KERNEL_ACCOUNT | __GFP_ZERO);
	if (!page) {
		ret = -ENOMEM;
		goto err;
	}
	req_buff = page_address(page);

	/* Use alloc_page for alignment */
	page = alloc_page(GFP_KERNEL_ACCOUNT | __GFP_ZERO);
	if (!page) {
		ret = -ENOMEM;
		goto err;
	}
	resp_buff = page_address(page);

	/* Copy user's input data */
	if (copy_from_user(req_buff, input.report_data, cmd_buff->req_len)) {
		ret = -EFAULT;
		goto err;
	}

	/*
	 * The req_len and resp_len fields has already been filled by firmware
	 * when we query the lengths from firmware.
	 */
	cmd_buff->req_gpa  = __pa(req_buff);
	cmd_buff->resp_gpa = __pa(resp_buff);

	ret = csv3_issue_request_report(__pa(cmd_buff), sizeof(*cmd_buff));
	if (ret || (!ret && cmd_buff->fw_error_code)) {
		pr_err("%s: fail to generate report, fw_error:%#x ret:%d\n",
			__func__, cmd_buff->fw_error_code, ret);
		ret = -EIO;
		goto err;
	}

	/*
	 * The firmware may update resp_len, and it must not exceed the size
	 * of resp_buff, otherwise copy_to_user() would leak kernel memory.
	 */
	if (cmd_buff->resp_len > PAGE_SIZE) {
		ret = -EIO;
		goto err;
	}

	/*
	 * The report must also fit in the user buffer described by input.len,
	 * otherwise copy_to_user() would overwrite user memory beyond it.
	 */
	if (cmd_buff->resp_len > input.len) {
		ret = -EINVAL;
		goto err;
	}

	/* Copy attestation report to user */
	if (copy_to_user(input.report_data, resp_buff, cmd_buff->resp_len))
		ret = -EFAULT;

err:
	if (resp_buff)
		free_page((unsigned long)resp_buff);
	if (req_buff)
		free_page((unsigned long)req_buff);
	if (cmd_buff)
		free_page((unsigned long)cmd_buff);

	return ret;
}

static int get_report(unsigned long arg)
{
	int ret = -ENOTTY;

	lockdep_assert_held(&csv_cmd_mutex);

	if (csv3_active())
		ret = csv3_get_report(arg);
	else if (cc_platform_has(CC_ATTR_GUEST_MEM_ENCRYPT))
		ret = csv_get_report(arg);
	return ret;
}

static long csv_guest_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	int ret = -ENOTTY;

	mutex_lock(&csv_cmd_mutex);

	switch (cmd) {
	case CSV_CMD_GET_REPORT:
		ret = get_report(arg);
		break;
	default:
		break;
	}

	mutex_unlock(&csv_cmd_mutex);

	return ret;
}

static const struct file_operations csv_guest_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = csv_guest_ioctl,
	.compat_ioctl = csv_guest_ioctl,
};

static struct miscdevice csv_guest_dev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "csv-guest",
	.fops = &csv_guest_fops,
	.mode = 0777,
};

static int __init csv_guest_init(void)
{
	// This module only working on CSV guest vm.
	if (!cc_platform_has(CC_ATTR_GUEST_MEM_ENCRYPT))
		return -ENODEV;

	return misc_register(&csv_guest_dev);
}

static void __exit csv_guest_exit(void)
{
	misc_deregister(&csv_guest_dev);
}

MODULE_LICENSE("GPL");
MODULE_VERSION("1.0.0");
MODULE_DESCRIPTION("HYGON CSV Guest Driver");
module_init(csv_guest_init);
module_exit(csv_guest_exit);
