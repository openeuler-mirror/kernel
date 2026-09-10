// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: Call ID Service (CIS) core module, manages inter-process communication
 *              via call identifiers with local/remote handling and UVB integration.
 * Author: zhangrui
 * Create: 2025-04-18
 */
#define pr_fmt(fmt) "[UVB]: " fmt

#include <linux/module.h>
#include <linux/printk.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/hashtable.h>
#include <linux/io.h>
#include <linux/auxiliary_bus.h>
#include <ub/ubase/ubase_comm_dev.h>
#include "cis_info_process.h"
#include "uvb_info_process.h"
#include "cis_ub.h"

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Call ID Service Framework");

static struct task_struct *uvb_poll_window_thread;
DECLARE_HASHTABLE(uvb_desc_table, MAX_UVB_DESC_BITS);

int create_uvb_poll_window_thread(void)
{
	uvb_poll_window_thread = kthread_run(uvb_poll_window, NULL, "uvb_poll_window_thread");
	if (IS_ERR(uvb_poll_window_thread)) {
		pr_err("Failed to create uvb polling thread\n");
		return PTR_ERR(uvb_poll_window_thread);
	}

	pr_info("create uvb poll window thread successfully\n");

	return 0;
}

void uvb_poll_window_thread_stop(void)
{
	if (uvb_poll_window_thread) {
		kthread_stop(uvb_poll_window_thread);
		uvb_poll_window_thread = NULL;
	}
}

static void free_uvb_win_desc_map(void)
{
	struct uvb_win_desc_map *entry;
	struct hlist_node *tmp;
	u32 bkt;

	if (hash_empty(uvb_desc_table))
		return;

	hash_for_each_safe(uvb_desc_table, bkt, tmp, entry, node) {
		hash_del(&entry->node);
		if (entry->map_address)
			memunmap(entry->map_address);
		if (entry->map_obtain)
			memunmap(entry->map_obtain);
		if (entry->map_buffer)
			memunmap(entry->map_buffer);
		kfree(entry);
	}
}

static int uvb_win_desc_map_init(void)
{
	struct uvb *uvb;
	struct uvb_win_desc_map *entry;
	u16 i, j;
	u32 size = 0;
	u64 obtain = 0, address = 0, buffer = 0;

	for (i = 0; i < g_uvb_info->uvb_count; i++) {
		uvb = g_uvb_info->uvbs[i];
		for (j = 0; j < uvb->window_count; j++) {
			address = uvb->wd[j].address;
			obtain = uvb->wd[j].obtain;
			buffer = uvb->wd[j].buffer;
			size = uvb->wd[j].size;
			if (!address || !obtain || !buffer) {
				pr_err("uvb window description map init failed\n");
				free_uvb_win_desc_map();
				return -EINVAL;
			}

			entry = kzalloc(sizeof(struct uvb_win_desc_map), GFP_KERNEL);
			if (!entry) {
				free_uvb_win_desc_map();
				return -ENOMEM;
			}
			atomic_set(&entry->lock, 0);
			entry->window_address = address;
			entry->map_address = memremap(address, sizeof(struct uvb_window),
								MEMREMAP_WC);
			entry->map_obtain = memremap(obtain, sizeof(u64), MEMREMAP_WC);
			entry->map_buffer = memremap(buffer, size, MEMREMAP_WC);
			if (!entry->map_address || !entry->map_obtain || !entry->map_buffer) {
				pr_err("uvb window desc  memremap failed\n");
				free_uvb_win_desc_map();
				return -ENOMEM;
			}

			hash_add(uvb_desc_table, &entry->node, uvb->wd[j].address);
		}
	}
	pr_info("uvb window lock init success.\n");

	return 0;
}

int init_uvb(void)
{
	int err = 0;

	if (!g_uvb_info) {
		pr_err("uvb is invalid, please try to use smc\n");
		return -EOPNOTSUPP;
	}

	err = uvb_win_desc_map_init();
	if (err) {
		pr_err("Init uvb window lock failed\n");
		return err;
	}

	err = create_uvb_poll_window_thread();
	if (err) {
		pr_err("create uvb poll thread did failed, err=%d\n", err);
		free_uvb_win_desc_map();
		return err;
	}

	return 0;
}

int init_cis_table(void)
{
	if (!g_cis_info) {
		pr_err("failed to get cis info from odf\n");
		return -EOPNOTSUPP;
	}

	return 0;
}

void uninit_uvb(void)
{
	uvb_poll_window_thread_stop();
	msleep(1000);
	free_uvb_win_desc_map();
}

static const struct auxiliary_device_id uvb_id_table[] = {
	{
		.name = UBASE_ADEV_NAME ".uvb",
	},
	{},
};

MODULE_DEVICE_TABLE(auxiliary, uvb_id_table);

static struct auxiliary_driver uvb_drv = {
	.probe = uvb_probe,
	.remove = uvb_remove,
	.name = "uvb",
	.id_table = uvb_id_table,
};

static int __init cis_init(void)
{
	int err = 0;

	err = init_cis_table();
	if (err) {
		pr_err("cis info init failed, err=%d\n", err);
	} else {
		err = init_uvb();
		if (err) {
			pr_err("uvb init failed, err=%d\n", err);
			return err;
		}
		pr_info("cis uvb init success\n");
	}

	err = auxiliary_driver_register(&uvb_drv);
	if (err) {
		pr_err("failed to register uvb drv\n");
		return err;
	}

	pr_info("register uvb over ub drv success\n");

	return 0;
}

static void __exit cis_exit(void)
{
	uninit_uvb();
	auxiliary_driver_unregister(&uvb_drv);
	pr_info("cis exit success\n");
}

module_init(cis_init);
module_exit(cis_exit);

