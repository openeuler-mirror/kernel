// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025. All rights reserved.
 * Description：OBMM Framework's implementations.
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

#include "obmm_core.h"
#include "obmm_cache.h"
#include "obmm_export_region_ops.h"
#include "obmm_export.h"

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

void free_export_memory_pid(struct obmm_export_region *e_reg)
{
	struct mem_description_pid *desc = &e_reg->mem_desc_pid;
	struct mm_struct *mm = NULL;
	struct task_struct *tsk;
	struct scatterlist *sg;
	unsigned int i;

	WARN_ON(desc->pid == 0);
	tsk = get_tsk_struct(desc->pid);
	if (tsk && tsk->start_time != desc->start_time) {
		/* if the process is still alive or its PID has not been reused */
		pr_err("pid(%d) is reused.\n", desc->pid);
		put_task_struct(tsk);
		tsk = NULL;
	}

	if (tsk)
		mm = get_task_mm(tsk);

	if (mm) {
		atomic64_sub(desc->pinned, &mm->pinned_vm);
		WARN_ON(modify_pgtable_prot(mm, desc->user_va, e_reg->region.mem_size, true));
		mmput(mm);
	}

	if (tsk)
		put_task_struct(tsk);

	WARN_ON(kernel_pgtable_set_export_invalid(e_reg, 0, e_reg->region.mem_size, false));

	/* unpin all pages from sgt */
	for_each_sgtable_sg(&e_reg->sgt, sg, i)
		unpin_user_page_range_dirty_lock(sg_page(sg), DIV_ROUND_UP(sg->length, PAGE_SIZE),
						 true);

	sg_free_table(&e_reg->sgt);
}

static bool hisi_workarounds_check_page_list(struct obmm_export_region *reg, struct page **pages,
					     int count)
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
		reg->node_mem_size[nid] += PAGE_SIZE;
	}

	for_each_node_mask(node, node_mask) {
		pr_debug("Page resides in node %u\n", node);
		reg->node_count = node + 1;
	}
	if (reg->affinity > OBMM_MAX_LOCAL_NUMA_NODES ||
	    reg->affinity < 0) {
		pr_err("Invalid pxm_numa %d\n", reg->affinity);
		return false;
	}
	node_set(reg->affinity, node_mask);

	return nodes_on_same_package(&node_mask);
}

int alloc_export_memory_pid(struct obmm_export_region *e_reg)
{
	unsigned long new_pinned, nrpages;
	struct mem_description_pid *desc = &e_reg->mem_desc_pid;
	struct page **page_list;
	struct task_struct *tsk;
	struct mm_struct *mm;
	bool remote_mm;
	int pinned, ret = 0;
	int locked = 0;

	nrpages = e_reg->region.mem_size >> PAGE_SHIFT;
	if (!nrpages) {
		pr_err("export pages must > 1\n");
		return -EINVAL;
	}

	tsk = get_tsk_struct(desc->pid);
	if (!tsk) {
		pr_err("get tsk from pid(%d) failed.\n", desc->pid);
		return -ESRCH;
	}

	mm = get_task_mm(tsk);
	if (!mm) {
		ret = -ESRCH;
		pr_err("get mm from pid(%d) failed.\n", desc->pid);
		goto drop_tsk;
	}
	desc->start_time = tsk->start_time;

	remote_mm = mm != current->mm;
	if (!remote_mm)
		desc->pid = current->tgid;

	pr_debug("exporting from %s\n", remote_mm ? "remote" : "current");

	new_pinned = (unsigned long)atomic64_add_return(nrpages, &mm->pinned_vm);

	page_list = kvmalloc_array(nrpages, sizeof(struct page *), GFP_KERNEL);
	if (!page_list) {
		ret = -ENOMEM;
		goto drop_pinned;
	}

	pr_debug("exporting useraddr: pid(%d) va(%p) size(%#llx)\n", desc->pid, desc->user_va,
		 e_reg->region.mem_size);

	mmap_read_lock(mm);
	locked = 1;
	if (remote_mm) {
		pinned = pin_user_pages_remote(mm, (uintptr_t)desc->user_va, nrpages, FOLL_WRITE,
					       page_list, &locked);
	} else {
		pinned = pin_user_pages_fast((uintptr_t)desc->user_va, nrpages, FOLL_WRITE,
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

	if (!hisi_workarounds_check_page_list(e_reg, page_list, nrpages)) {
		pr_err("hisi workarounds check no passing.\n");
		ret = -EOPNOTSUPP;
		goto free_page_list;
	}

	ret = sg_alloc_table_from_pages_segment(&e_reg->sgt, page_list, nrpages, 0,
						e_reg->region.mem_size, SZ_1G, GFP_KERNEL);
	if (ret) {
		pr_err("alloc sg table failed, %pe.\n", ERR_PTR(ret));
		goto free_page_list;
	}

	ret = kernel_pgtable_set_export_invalid(e_reg, 0, e_reg->region.mem_size, true);
	if (ret)
		goto out_free_sg;

	ret = modify_pgtable_prot(mm, desc->user_va, e_reg->region.mem_size, false);
	if (ret)
		goto out_set_kernel_cacheable;

	ret = obmm_region_flush_range(&e_reg->region, 0, e_reg->region.mem_size,
				      OBMM_SHM_CACHE_WB_INVAL);
	if (ret)
		goto out_reset_pgtable_prot;

	desc->pinned = pinned;
	kvfree(page_list); /* all pages saved in scatterlist */
	mmput(mm);
	put_task_struct(tsk);
	pr_debug("exporting memory prepared.\n");

	return 0;

out_reset_pgtable_prot:
	WARN_ON(modify_pgtable_prot(mm, desc->user_va, e_reg->region.mem_size, true));
out_set_kernel_cacheable:
	WARN_ON(kernel_pgtable_set_export_invalid(e_reg, 0, e_reg->region.mem_size, false));
out_free_sg:
	sg_free_table(&e_reg->sgt);
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

static struct obmm_export_region *
alloc_export_region_from_obmm_cmd_export_pid(const struct obmm_cmd_export_pid *export_pid)
{
	int ret;

	struct obmm_export_region *e_reg = kzalloc(sizeof(struct obmm_export_region), GFP_KERNEL);

	if (e_reg == NULL)
		return ERR_PTR(-ENOMEM);

	atomic_set(&e_reg->region.device_released, 1);

	e_reg->mem_desc_pid.pid = export_pid->pid;
	e_reg->mem_desc_pid.user_va = export_pid->va;
	e_reg->region.mem_size = export_pid->length;
	e_reg->region.type = OBMM_EXPORT_REGION;
	e_reg->region.mem_cap = 0;
	e_reg->affinity = export_pid->pxm_numa;
	memcpy(e_reg->deid, export_pid->deid, sizeof(e_reg->deid));
	ret = export_flags_to_region_flags(&e_reg->region.flags, export_pid->flags);
	if (ret) {
		kfree(e_reg);
		return ERR_PTR(ret);
	}
	e_reg->region.flags |= OBMM_REGION_FLAG_MEMORY_FROM_USER;
	ret = set_obmm_region_priv(&e_reg->region, export_pid->priv_len, export_pid->priv);
	if (ret) {
		kfree(e_reg);
		return ERR_PTR(ret);
	}
	ret = set_export_vendor(e_reg, export_pid->vendor_info, export_pid->vendor_len);
	if (ret) {
		kfree(e_reg);
		return ERR_PTR(ret);
	}
	return e_reg;
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
	struct obmm_export_region *e_reg;
	uint64_t uba, mem_id;
	uint32_t token_id;
	int ret;

	print_export_pid_param(export_pid);
	ret = obmm_cmd_export_pid_allowed(export_pid);
	if (ret)
		return ret;

	e_reg = alloc_export_region_from_obmm_cmd_export_pid(export_pid);
	if (IS_ERR(e_reg))
		return PTR_ERR(e_reg);

	ret = init_obmm_region(&e_reg->region);
	if (ret)
		goto out_free_reg;

	ret = obmm_export_common(e_reg);
	if (ret)
		goto out_unit_reg;

	token_id = e_reg->tokenid;
	uba = e_reg->uba;
	mem_id = (uint64_t)e_reg->region.regionid;

	ret = register_obmm_region(&e_reg->region);
	if (ret)
		goto out_unexport;
	activate_obmm_region(&e_reg->region);

	export_pid->tokenid = token_id;
	export_pid->uba = uba;
	export_pid->mem_id = mem_id;

	pr_debug("obmm_export_useraddr: mem_id=%llu online.\n", mem_id);
	return 0;

out_unexport:
	obmm_unexport_common(e_reg);
out_unit_reg:
	uninit_obmm_region(&e_reg->region);
out_free_reg:
	free_export_region(e_reg);
	return ret;
}
