// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.
 * Description: export-user backend, EXPORT_PID ioctl and its uapi checks.
 */

#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/pid.h>
#include <linux/pid_namespace.h>
#include <linux/rcupdate.h>
#include <linux/scatterlist.h>
#include <linux/nodemask.h>
#include <linux/atomic.h>
#include <linux/printk.h>
#include <linux/slab.h>
#include <linux/numa.h>
#include <linux/err.h>

#include "obmm_core.h"
#include "obmm_cache.h"
#include "obmm_backend.h"
#include "obmm_export_region_ops.h"
#include "obmm_export.h"
#include "obmm_shm_dev.h"

static struct task_struct *get_tsk_struct(pid_t pid)
{
	struct task_struct *task;

	if (!pid) {
		get_task_struct(current);
		return current;
	}

	rcu_read_lock();
	task = pid_task(find_pid_ns(pid, &init_pid_ns), PIDTYPE_PID);
	if (task)
		get_task_struct(task);
	rcu_read_unlock();

	return task;
}

/* Reverse ladder of export_user_alloc_memory; pages live in exp.sgt. */
static void export_user_free_memory(struct obmm_export_user_backend *ub)
{
	struct mm_struct *mm = NULL;
	struct task_struct *tsk;
	struct scatterlist *sg;
	unsigned int i;

	WARN_ON(ub->pid == 0);
	tsk = get_tsk_struct(ub->pid);
	if (tsk && tsk->start_time != ub->start_time) {
		/* if the process is still alive or its PID has not been reused */
		pr_err("pid(%d) is reused.\n", ub->pid);
		put_task_struct(tsk);
		tsk = NULL;
	}

	if (tsk)
		mm = get_task_mm(tsk);

	if (mm) {
		atomic64_sub(ub->pinned, &mm->pinned_vm);
		WARN_ON(modify_pgtable_prot(mm, ub->user_va, ub->base.mem_size, true));
		mmput(mm);
	}

	if (tsk)
		put_task_struct(tsk);

	WARN_ON(kernel_pgtable_set_export_invalid(&ub->exp.sgt, 0, ub->base.mem_size, false));

	/* unpin all pages from sgt */
	for_each_sgtable_sg(&ub->exp.sgt, sg, i)
		unpin_user_page_range_dirty_lock(sg_page(sg), DIV_ROUND_UP(sg->length, PAGE_SIZE),
						 true);

	sg_free_table(&ub->exp.sgt);
}

static bool hisi_workarounds_check_page_list(struct obmm_export_user_backend *ub,
					     struct page **pages, int count)
{
	nodemask_t node_mask;
	unsigned int node;
	int i, nid;

	nodes_clear(node_mask);
	for (i = 0; i < count; i++) {
		struct page *p = pages[i];

		if (!PageHuge(p)) {
			pr_err("Only hugetlbfs pages are allowed\n");
			return false;
		}

#ifdef CONFIG_NUMA
		nid = page_to_nid(p);
#else
		nid = 0;
#endif
		if (nid < 0 || nid >= OBMM_MAX_LOCAL_NUMA_NODES) {
			pr_err("Invalid node ID %d.\n", nid);
			return false;
		}

		node_set(nid, node_mask);
		ub->exp.node_mem_size[nid] += PAGE_SIZE;
	}

	for_each_node_mask(node, node_mask) {
		pr_debug("Page resides in node %u\n", node);
		ub->exp.node_count = node + 1;
	}
	if (ub->exp.affinity > OBMM_MAX_LOCAL_NUMA_NODES ||
	    ub->exp.affinity < 0) {
		pr_err("Invalid pxm_numa %d\n", ub->exp.affinity);
		return false;
	}
	node_set(ub->exp.affinity, node_mask);

	return nodes_on_same_package(&node_mask);
}

/* Pin the backend's pages and account them; the flush calls the per-chunk
 * export core because obmm_region_flush_range needs an attached shell.
 */
static int export_user_alloc_memory(struct obmm_export_user_backend *ub)
{
	unsigned long nrpages;
	struct page **page_list;
	struct task_struct *tsk;
	struct mm_struct *mm;
	bool remote_mm;
	int pinned, ret = 0;
	int locked = 0;

	nrpages = ub->base.mem_size >> PAGE_SHIFT;
	if (!nrpages) {
		pr_err("export pages must > 1\n");
		return -EINVAL;
	}

	tsk = get_tsk_struct(ub->pid);
	if (!tsk) {
		pr_err("get tsk from pid(%d) failed.\n", ub->pid);
		return -ESRCH;
	}

	mm = get_task_mm(tsk);
	if (!mm) {
		ret = -ESRCH;
		pr_err("get mm from pid(%d) failed.\n", ub->pid);
		goto drop_tsk;
	}
	ub->start_time = tsk->start_time;

	remote_mm = mm != current->mm;
	if (!remote_mm)
		ub->pid = current->tgid;

	pr_debug("exporting from %s\n", remote_mm ? "remote" : "current");

	/* account the pages to be pinned; released in export_user_free_memory() */
	atomic64_add(nrpages, &mm->pinned_vm);

	page_list = kvmalloc_array(nrpages, sizeof(struct page *), GFP_KERNEL);
	if (!page_list) {
		ret = -ENOMEM;
		goto drop_pinned;
	}

	pr_debug("exporting useraddr: pid(%d) va(%#llx) size(%#llx)\n", ub->pid,
		 (u64)(uintptr_t)ub->user_va, ub->base.mem_size);

	mmap_read_lock(mm);
	locked = 1;
	if (remote_mm) {
		pinned = pin_user_pages_remote(mm, (uintptr_t)ub->user_va, nrpages, FOLL_WRITE,
					       page_list, &locked);
	} else {
		pinned = pin_user_pages_fast((uintptr_t)ub->user_va, nrpages, FOLL_WRITE,
					     page_list);
	}
	if (locked)
		mmap_read_unlock(mm);

	if (pinned < 0) {
		pr_err("pin memory failed, %d.\n", pinned);
		ret = pinned;
		goto free_page_list;
	}

	if (pinned != (int)nrpages) {
		pr_err("failed to pin user pages(%d/%lu)!\n", pinned, nrpages);
		ret = -ENOMEM;
		goto free_page_list;
	}

	if (!hisi_workarounds_check_page_list(ub, page_list, nrpages)) {
		pr_err("hisi workarounds check no passing.\n");
		ret = -EOPNOTSUPP;
		goto free_page_list;
	}

	ret = sg_alloc_table_from_pages_segment(&ub->exp.sgt, page_list, nrpages, 0,
						ub->base.mem_size, SZ_1G, GFP_KERNEL);
	if (ret) {
		pr_err("alloc sg table failed, %pe.\n", ERR_PTR(ret));
		goto free_page_list;
	}

	ret = kernel_pgtable_set_export_invalid(&ub->exp.sgt, 0, ub->base.mem_size, true);
	if (ret)
		goto out_free_sg;

	ret = modify_pgtable_prot(mm, ub->user_va, ub->base.mem_size, false);
	if (ret)
		goto out_set_kernel_cacheable;

	ret = export_flush_sgt(&ub->exp.sgt, 0, ub->base.mem_size, OBMM_SHM_CACHE_WB_INVAL);
	if (ret)
		goto out_reset_pgtable_prot;

	ub->pinned = pinned;
	kvfree(page_list); /* all pages saved in scatterlist */
	mmput(mm);
	put_task_struct(tsk);
	pr_debug("exporting memory prepared.\n");

	return 0;

out_reset_pgtable_prot:
	WARN_ON(modify_pgtable_prot(mm, ub->user_va, ub->base.mem_size, true));
out_set_kernel_cacheable:
	WARN_ON(kernel_pgtable_set_export_invalid(&ub->exp.sgt, 0, ub->base.mem_size, false));
out_free_sg:
	sg_free_table(&ub->exp.sgt);
free_page_list:
	if (pinned > 0)
		unpin_user_pages_dirty_lock(page_list, pinned, 0);
	kvfree(page_list);
drop_pinned:
	atomic64_sub(nrpages, &mm->pinned_vm);
	mmput(mm);
drop_tsk:
	put_task_struct(tsk);
	return ret;
}

/*
 * ops->destroy: teardown_ummu, then the reverse ladder above, plus the
 * vendor copy; the object is freed by obmm_backend_put regardless of the
 * result.
 */
static int export_user_destroy(struct obmm_backend *be)
{
	struct obmm_export_user_backend *ub = obmm_backend_to_export_user(be);
	int ret;

	ret = teardown_ummu(&ub->exp);
	if (ret)
		goto out_free_vendor;

	export_user_free_memory(ub);

out_free_vendor:
	kfree(ub->exp.vendor_info);
	return ret;
}

/*
 * EXPORT_USER ops: mmap ops stay NULL (mem_cap == 0, all flags rejected),
 * so no mapping or flush path can reach it. query/covers_pa, shared with
 * the pool backend, still work by PA and are not mmap-gated.
 */
static const struct obmm_backend_ops obmm_export_user_backend_ops = {
	.query		= export_query,
	.covers_pa	= export_covers_pa,
	.destroy	= export_user_destroy,
};

/*
 * Create a user-memory export backend; spec->vendor_info ownership
 * transfers here (obmm_backend.h); returns the existence ref or an ERR_PTR.
 */
struct obmm_backend *
obmm_export_user_backend_create(const struct obmm_export_user_spec *spec)
{
	struct obmm_export_user_backend *ub;
	int ret;

	ub = kzalloc(sizeof(*ub), GFP_KERNEL);
	if (!ub) {
		/* hand-off not reached: the vendor buffer is still ours */
		kfree(spec->vendor_info);
		return ERR_PTR(-ENOMEM);
	}

	ub->base.type = OBMM_BACKEND_EXPORT_USER;
	ub->base.mem_size = spec->length;
	ub->base.mem_cap = 0;	/* never mmapable */
	ub->base.ops = &obmm_export_user_backend_ops;
	refcount_set(&ub->base.refcnt, 1); /* the existence reference */

	ub->pid = spec->pid;
	ub->user_va = spec->user_va;
	ub->exp.affinity = spec->pxm_numa;
	memcpy(ub->exp.deid, spec->deid, sizeof(ub->exp.deid));
	ub->exp.vendor_info = spec->vendor_info;
	ub->exp.vendor_len = spec->vendor_len;

	ret = export_user_alloc_memory(ub);
	if (ret)
		goto out_free_vendor;

	ret = setup_ummu(&ub->exp);
	if (ret)
		goto out_free_memory;

	return &ub->base;

out_free_memory:
	export_user_free_memory(ub);
out_free_vendor:
	kfree(ub->exp.vendor_info);
	kfree(ub);
	return ERR_PTR(ret);
}

static int obmm_cmd_export_pid_allowed(struct obmm_cmd_export_pid *cmd)
{
	if (cmd->flags & ~(OBMM_EXPORT_FLAG_MASK)) {
		pr_err("invalid flags %#llx encountered in export_user_addr.\n", cmd->flags);
		return -EINVAL;
	}
	if (cmd->flags & OBMM_EXPORT_FLAG_ALLOW_MMAP) {
		pr_err("ALLOW_MMAP flag is not allowed in export_user_addr.\n");
		return -EINVAL;
	}
	if (cmd->flags & OBMM_EXPORT_FLAG_FAST) {
		pr_err("FAST flag is not allowed in export_user_addr.\n");
		return -EINVAL;
	}

	if (cmd->length == 0) {
		pr_err("export sizeof 0 memory is not allowed.\n");
		return -EINVAL;
	}

	if (cmd->length % PMD_SIZE) {
		pr_err("export memory size is not aligned to PMD_SIZE.\n");
		return -EINVAL;
	}

	return 0;
}

static void user_spec_from_cmd(const struct obmm_cmd_export_pid *export_pid,
			       struct obmm_export_user_spec *spec)
{
	spec->pid = export_pid->pid;
	spec->user_va = export_pid->va;
	spec->length = export_pid->length;
	spec->pxm_numa = export_pid->pxm_numa;
	memcpy(spec->deid, export_pid->deid, sizeof(spec->deid));
}

static void print_export_pid_param(const struct obmm_cmd_export_pid *cmd_export_pid)
{
	pr_debug("obmm_export_useraddr: pid=%d length=%#llx priv_len=%u deid="
		EID_FMT64 " vendor_len=%u\n",
		cmd_export_pid->pid, cmd_export_pid->length, cmd_export_pid->priv_len,
		EID_ARGS64_H(cmd_export_pid->deid), EID_ARGS64_L(cmd_export_pid->deid),
		cmd_export_pid->vendor_len);
}

int obmm_export_pid(struct obmm_cmd_export_pid *export_pid)
{
	struct obmm_export_user_spec spec = { 0 };
	struct obmm_region *reg;
	struct obmm_backend *be;
	void *vendor;
	uint64_t uba, mem_id;
	uint32_t token_id;
	int ret;

	print_export_pid_param(export_pid);
	ret = obmm_cmd_export_pid_allowed(export_pid);
	if (ret)
		return ret;

	user_spec_from_cmd(export_pid, &spec);

	reg = kzalloc(sizeof(struct obmm_region), GFP_KERNEL);
	if (reg == NULL)
		return -ENOMEM;

	reg->created_as = OBMM_EXPORT_REGION;
	reg->mem_size = export_pid->length;
	ret = export_flags_to_region_flags(&reg->flags, export_pid->flags);
	if (ret)
		goto out_free_reg;
	reg->flags |= OBMM_REGION_FLAG_MEMORY_FROM_USER;
	ret = set_obmm_region_priv(reg, export_pid->priv_len, export_pid->priv);
	if (ret)
		goto out_free_reg;

	/* baseline order: the vendor blob is validated and copied before the
	 * region id and device exist, then handed off to the creator below
	 * (obmm_backend.h contract)
	 */
	vendor = dup_export_vendor(export_pid->vendor_info, export_pid->vendor_len);
	if (IS_ERR(vendor)) {
		ret = PTR_ERR(vendor);
		goto out_free_reg;
	}
	spec.vendor_info = vendor;
	spec.vendor_len = export_pid->vendor_len;

	ret = init_obmm_region(reg);
	if (ret)
		goto out_free_reg;

	/* from here on the device core owns the region's memory */
	ret = obmm_shm_dev_init_device(reg);
	if (ret)
		goto out_unit_reg;

	be = obmm_export_user_backend_create(&spec);
	if (IS_ERR(be)) {
		ret = PTR_ERR(be);
		pr_err("Failed to prepare export memory: ret=%pe\n", ERR_PTR(ret));
		goto out_dev_put;
	}

	token_id = obmm_backend_to_export_common(be)->tokenid;
	uba = obmm_backend_to_export_common(be)->uba;
	mem_id = (uint64_t)reg->regionid;

	ret = obmm_region_publish(reg, be, "export");
	if (ret)
		return ret;

	export_pid->tokenid = token_id;
	export_pid->uba = uba;
	export_pid->mem_id = mem_id;

	pr_debug("obmm_export_useraddr: mem_id=%llu online.\n", mem_id);
	return 0;

out_dev_put:
	uninit_obmm_region(reg);
	/* frees the region via the device release callback */
	obmm_shm_dev_put(reg);
	return ret;
out_unit_reg:
	uninit_obmm_region(reg);
out_free_reg:
	kfree(spec.vendor_info);
	kfree(reg);
	return ret;
}
