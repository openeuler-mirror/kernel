/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hinic5_hinic5_vram.c
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   : hinic5_hinic5_vram.c
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": [COMM]" fmt

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/async.h>

#include "ossl_knl.h"
#include "hinic5_typedef_inner.h"
#include "hinic5_mt.h"
#include "hinic5_hwdev.h"
#include "hinic5_common.h"
#include "hinic5_crm.h"
#include "hinic5_sriov.h"
#include "hinic5_dev_mgmt.h"
#include "hinic5_nictool.h"
#include "hinic5_hw.h"

#include "hinic5_vram_common.h"
#include "hinic5_hinic5_vram.h"

static ASYNC_DOMAIN_EXCLUSIVE(g_hiudk_async_domain);
static hiudk_async_ctrl g_hiudk_async_ctrl;

int hiudk5_register_flush_fn(void *lld_dev, hiudk_flush_fn fn)
{
	int i;
	int cur_idx = -1;

	if (!lld_dev) {
		pr_err("Sdk: register flush function para is null.\n");
		return -ENODEV;
	}

	spin_lock(&g_hiudk_async_ctrl.lock);

	for (i = CMD_MAX_MAX_PF_NUM - 1; i >= 0; i--) {
		if (!g_hiudk_async_ctrl.flush_infos[i].lld_dev) {
			cur_idx = i;
			break;
		}
	}

	if (cur_idx == -1) {
		spin_unlock(&g_hiudk_async_ctrl.lock);
		pr_err("Sdk: register flush function failed, no available async crtl info.\n");
		return -ENOMEM;
	}

	g_hiudk_async_ctrl.flush_infos[cur_idx].lld_dev = lld_dev;
	g_hiudk_async_ctrl.flush_infos[cur_idx].flush_ops = fn;
	g_hiudk_async_ctrl.flush_infos[cur_idx].ret = 0;

	spin_unlock(&g_hiudk_async_ctrl.lock);

	return 0;
}
EXPORT_SYMBOL(hiudk5_register_flush_fn);

int hiudk5_unregister_flush_fn(void *lld_dev)
{
	int i;

	if (!lld_dev) {
		pr_err("Sdk: unregister flush function para is null.\n");
		return -ENODEV;
	}

	spin_lock(&g_hiudk_async_ctrl.lock);

	for (i = CMD_MAX_MAX_PF_NUM - 1; i >= 0; i--) {
		if (lld_dev == g_hiudk_async_ctrl.flush_infos[i].lld_dev) {
			g_hiudk_async_ctrl.flush_infos[i].lld_dev = NULL;
			g_hiudk_async_ctrl.flush_infos[i].flush_ops = NULL;
			g_hiudk_async_ctrl.flush_infos[i].ret = 0;

			spin_unlock(&g_hiudk_async_ctrl.lock);
			return 0;
		}
	}

	spin_unlock(&g_hiudk_async_ctrl.lock);

	return -ENODEV;
}
EXPORT_SYMBOL(hiudk5_unregister_flush_fn);

void hinic5_flush_dev(void *priv_data, async_cookie_t cookie)
{
	hiudk_dev_flush_infos *cur_dev = priv_data;

	if (!cur_dev->lld_dev || !cur_dev->flush_ops)
		return;

	cur_dev->ret = cur_dev->flush_ops(cur_dev->lld_dev);
}

STATIC int hisdk5_notify_flush_dev(struct notifier_block *nb,
				   unsigned long action,
				   void *data)
{
	int i;

	rtnl_lock();

	for (i = 0; i < CMD_MAX_MAX_PF_NUM; i++)
		if (g_hiudk_async_ctrl.flush_infos[i].lld_dev)
			async_schedule_domain(hinic5_flush_dev,
					      &g_hiudk_async_ctrl.flush_infos[i],
					      &g_hiudk_async_domain);

	rtnl_unlock();

	return 0;
}

STATIC int hiudk_os_hotreplace_msg_to_mpu(u8 replace_flag)
{
	int ret;
	void *dev = NULL;

	dev = hinic5_get_ppf_dev();
	if (!dev) {
		pr_err("Get ppf dev failed before os hotreplace.\n");
		return -ENXIO;
	}

	ret = hinic5_set_ppf_tbl_hotreplace_flag(dev, replace_flag);
	if (ret != 0) {
		pr_err("Send mbox to mpu failed in hiudk, ret:%d, flag:%u.\n", ret, replace_flag);
		return ret;
	}

	return 0;
}

STATIC int hiudk_notify_pre_update(struct notifier_block *nb,
				   unsigned long action,
				   void *data)
{
	int ret;

	pr_info("Set driver flag and mpu flag before os hotreplace.\n");
	// set kexec status set to 1, indicate doing kexec
	ret = hinic5_set_kexec_status(1);
	if (ret != 0) {
		pr_err("Set kexec flag failed before os hotreplace.\n");
		return ret;
	}

	ret = hiudk_os_hotreplace_msg_to_mpu(MPU_OS_HOTREPLACE_FLAG);
	if (ret != 0) {
		pr_err("Send mbox to mpu failed before os hotreplace.\n");
		return ret;
	}

	return 0;
}

STATIC int hiudk_notify_post_update(struct notifier_block *nb,
				    unsigned long action,
				    void *data)
{
	int ret;

	pr_info("Clear driver flag and mpu flag after os hotreplace.\n");
	// set kexec status set to 0, indicate kexec done
	ret = hinic5_set_kexec_status(0);
	if (ret != 0) {
		pr_err("Set kexec flag failed after os hotreplace.\n");
		return ret;
	}

	ret = hiudk_os_hotreplace_msg_to_mpu(0);
	if (ret != 0) {
		pr_err("Send mbox to mpu failed after os hotreplace.\n");
		return ret;
	}

	return 0;
}

int hinic5_wait_for_devices_flush(struct notifier_block *nb,
				  unsigned long action,
				  void *data)
{
	int i;
	int ret = 0;

	async_synchronize_full_domain(&g_hiudk_async_domain);

	for (i = 0; i < CMD_MAX_MAX_PF_NUM; i++) {
		if (g_hiudk_async_ctrl.flush_infos[i].ret != 0) {
			ret = g_hiudk_async_ctrl.flush_infos[i].ret;
			pr_err("Sdk: wait netdev[%d] flush done error, ret:%d.\n", i, ret);
			return ret;
		}
	}

	return 0;
}
EXPORT_SYMBOL(hinic5_wait_for_devices_flush);

static struct notifier_block hiudk_notifier_pre_update = {
	.notifier_call	= hiudk_notify_pre_update,
	.next		= NULL,
	.priority	= 0
};

static struct notifier_block  hisdk5_notifier_flush_dev = {
	.notifier_call  = hisdk5_notify_flush_dev,
	.next           = NULL,
	.priority       = 0
};

static struct notifier_block hisdk5_notifier_wait_flush_done = {
	.notifier_call  = hinic5_wait_for_devices_flush,
	.next           = NULL,
	.priority       = 0
};

static struct notifier_block hiudk_notifier_post_update = {
	.notifier_call	= hiudk_notify_post_update,
	.next		= NULL,
	.priority	= 0
};

int hisdk5_hinic5_vram_init(void)
{
	int err;

	spin_lock_init(&g_hiudk_async_ctrl.lock);
	lookup_hinic5_vram_related_symbols();

	err = hinic5_get_kexec_status();
	if (err != 0) {
		pr_err("Get in kexec status failed, err: %d\n", err);
		goto get_kexec_status_err;
	}

	err = hi_register_nvwa_notifier(PRE_UPDATE_KERNEL, &hiudk_notifier_pre_update);
	if (err != 0) {
		pr_err("Register nvwa pre update failed, err: %d\n", err);
		goto register_pre_update_nvwa_err;
	}

	err = hi_register_nvwa_notifier(POST_UPDATE_KERNEL, &hiudk_notifier_post_update);
	if (err != 0) {
		pr_err("Register nvwa post update failed, err: %d\n", err);
		goto register_post_update_nvwa_err;
	}

	err = hi_register_nvwa_notifier(FLUSH_DURING_KUP, &hisdk5_notifier_flush_dev);
	if (err != 0) {
		pr_err("Register nvwa flush device failed, err: %d\n", err);
		goto register_flush_dev_err;
	}

	err = hi_register_euleros_reboot_notifier(&hisdk5_notifier_wait_flush_done);
	if (err != 0) {
		pr_err("Register wait flush device notify failed, err: %d\n", err);
		goto register_reboot_err;
	}

	return 0;

register_reboot_err:
	(void)hi_unregister_nvwa_notifier(FLUSH_DURING_KUP, &hisdk5_notifier_flush_dev);
register_flush_dev_err:
	(void)hi_unregister_nvwa_notifier(POST_UPDATE_KERNEL, &hiudk_notifier_post_update);
register_post_update_nvwa_err:
	(void)hi_unregister_nvwa_notifier(PRE_UPDATE_KERNEL, &hiudk_notifier_pre_update);
register_pre_update_nvwa_err:
get_kexec_status_err:
	spin_lock_deinit(&g_hiudk_async_ctrl.lock);
	return err;
}

void hisdk5_hinic5_vram_deinit(void)
{
	(void)hi_unregister_euleros_reboot_notifier(&hisdk5_notifier_wait_flush_done);
	(void)hi_unregister_nvwa_notifier(FLUSH_DURING_KUP, &hisdk5_notifier_flush_dev);
	(void)hi_unregister_nvwa_notifier(POST_UPDATE_KERNEL, &hiudk_notifier_pre_update);
	(void)hi_unregister_nvwa_notifier(PRE_UPDATE_KERNEL, &hiudk_notifier_post_update);

	spin_lock_deinit(&g_hiudk_async_ctrl.lock);
}
