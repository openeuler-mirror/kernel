// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) Huawei Technologies Co., Ltd. 2024. All rights reserved.
 */

#define pr_fmt(fmt) "hisi_l3t: " fmt

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kallsyms.h>
#include <linux/mm.h>

#include "hisi_l3t.h"

struct hisi_l3t_ops {
	bool (*l3t_slot_test)(struct hisi_l3t *l3t, int slot_idx,
			      unsigned long addr, int size);
	void (*l3t_slot_action)(struct hisi_l3t *l3t, int slot_idx,
				unsigned long addr, int size);
};

static int hisi_l3t_sccl_action(int nid, unsigned long addr,
				int size, struct hisi_l3t_ops *ops)
{
	struct hisi_l3t *l3t;
	struct hisi_sccl *sccl;
	int i, slot_idx;

	mutex_lock(&l3t_mutex);

	/*
	 * Probe publishes the slots and the release action clears
	 * them under l3t_mutex, so stay under it from the lookup
	 * to the last dereference.
	 */
	sccl = hisi_l3t_get_sccl(nid);
	if (!sccl || !sccl->ccl_cnt || !sccl->l3t)
		goto enodev;

	/*
	 * in shared mode, all l3t belongs to one sccl is the same.
	 * use the first l3t to test.
	 */
	for (i = 0; i < sccl->ccl_cnt; i++) {
		if (sccl->l3t[i])
			break;
	}
	if (i >= sccl->ccl_cnt)
		goto enodev;
	l3t = sccl->l3t[i];

	for (slot_idx = 0; slot_idx < L3T_REG_NUM; slot_idx++) {
		if (ops->l3t_slot_test(l3t, slot_idx, addr, size))
			break;
	}

	if (slot_idx >= L3T_REG_NUM) {
		mutex_unlock(&l3t_mutex);
		return -EINVAL;
	}

	for (i = 0; i < sccl->ccl_cnt; i++) {
		l3t = sccl->l3t[i];
		if (l3t)
			ops->l3t_slot_action(l3t, slot_idx, addr, size);
	}
	mutex_unlock(&l3t_mutex);

	return 0;

enodev:
	mutex_unlock(&l3t_mutex);
	return -ENODEV;
}

static bool hisi_l3t_test_empty(struct hisi_l3t *l3t, int slot_idx,
				     unsigned long __always_unused addr,
				     int __always_unused size)
{
	unsigned long _addr;
	int _size;

	hisi_l3t_read(l3t, slot_idx, &_addr, &_size);

	return _addr == 0;
}

int l3t_shared_lock(int nid, unsigned long pfn, unsigned long size)
{
	struct hisi_l3t_ops ops = {
		.l3t_slot_test = hisi_l3t_test_empty,
		.l3t_slot_action = hisi_l3t_lock,
	};
	int ret;

	ret = hisi_l3t_sccl_action(nid, pfn << PAGE_SHIFT, size, &ops);
	if (ret == -EINVAL)
		return -ENOSPC;

	return ret;
}
EXPORT_SYMBOL_GPL(l3t_shared_lock);

static bool hisi_l3t_test_equal(struct hisi_l3t *l3t, int slot_idx,
				unsigned long addr, int size)
{
	unsigned long _addr;
	int _size;

	hisi_l3t_read(l3t, slot_idx, &_addr, &_size);

	return (_addr == addr && _size == size);
}

static void hisi_l3t_do_unlock(struct hisi_l3t *l3t, int slot_idx,
			       unsigned long __always_unused addr,
			       int __always_unused size)
{
	hisi_l3t_unlock(l3t, slot_idx);
}

int l3t_shared_unlock(int nid, unsigned long pfn, unsigned long size)
{
	struct hisi_l3t_ops ops = {
		.l3t_slot_test = hisi_l3t_test_equal,
		.l3t_slot_action = hisi_l3t_do_unlock,
	};
	int ret;

	ret = hisi_l3t_sccl_action(nid, pfn << PAGE_SHIFT, size, &ops);
	if (ret == -EINVAL)
		return -ENOENT;

	return ret;
}
EXPORT_SYMBOL_GPL(l3t_shared_unlock);
