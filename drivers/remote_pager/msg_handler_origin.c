// SPDX-License-Identifier: GPL-2.0-only
/*
 * Generalized Memory Management.
 *
 * Copyright (c) 2023- Huawei, Inc.
 * Author: Bin Wang
 * Co-Author: Chunsheng Luo, Cunshu Ni
 *
 */
#include <linux/slab.h>
#include <linux/gmem.h>
#include <linux/sched/mm.h>
#include <linux/vm_object.h>
#include <linux/dma-mapping.h>
#include <linux/version.h>

#include "msg_handler.h"
#include "wait_station.h"
#include "svm_proc_mng.h"

#define NPU_PAGE_SIZE PAGE_SIZE
#define MAX_NR_NPU 8
#define GMEM_DEBUG 0

static gm_dev_t *gm_devs[MAX_NR_NPU];

gm_dev_t *gmem_id_to_device(unsigned int id)
{
	if (id >= MAX_NR_NPU) {
		pr_err("device id is invalid. (dev_id = %u)\n", id);
		return NULL;
	}

	return gm_devs[id];
}

int gmem_register_pair_remote_task(int origin_nid, int origin_pid, int remote_nid, int remote_pid)
{
	struct gm_pair_msg_rq req;
	struct comm_msg_rsp *rsp;
	int ret = 0;
	struct wait_station *ws;

	/* open msg chan */
	pr_err("%s origin_nid %d, origin_pid %d, remote_nid %d, remote_pid %d\n", __func__,
	origin_nid, origin_pid, remote_nid, remote_pid);
	ret = msg_open(remote_nid);
	if (ret < 0) {
		pr_err("%s open msg chan failed\n", __func__);
		return ret;
	}

	/* start pairing */
	ws = get_wait_station();
	req.my_pid = origin_pid;
	req.my_ws = ws->id;
	req.peer_nid = remote_nid;
	req.peer_pid = remote_pid;

	ret = msg_send_nid(GMEM_TASK_PAIRING_REQUEST, origin_nid,
					   remote_nid, &req, sizeof(struct gm_pair_msg_rq));
	rsp = wait_at_station(ws);
	if ((long)rsp != -ETIMEDOUT) {
		ret = rsp->ret;
		kfree(rsp);
		gmem_add_to_svm_proc(origin_nid, origin_pid, remote_nid, remote_pid);
	}

	return ret;
}
EXPORT_SYMBOL(gmem_register_pair_remote_task);

int gmem_handle_dev_fault(struct rpg_kmsg_message *msg)
{
	int ret;
	struct gm_pager_msg_rq *recv = (struct gm_pager_msg_rq *)msg;
	unsigned int my_pid = recv->peer_pid;
	unsigned int nid = recv->header.to_nid;
	unsigned int peer_nid = recv->header.from_nid;
	unsigned int peer_ws = recv->my_ws;
	gm_dev_t *dev = gm_devs[peer_nid];
	struct task_struct *tsk;
	struct mm_struct *mm;

	tsk = find_get_task_by_vpid(my_pid);
	if (!tsk) {
		pr_err("svm process does not have task_struct\n");
		ret = GM_RET_FAILURE_UNKNOWN;
		goto out;
	}

	mm = get_task_mm(tsk);
	if (!mm) {
		pr_err("no mm\n");
		ret = GM_RET_FAILURE_UNKNOWN;
		goto put_task;
	}

	if (!dev) {
		pr_info("gmem: device get failed, dev_id %ld\n", (unsigned long)peer_nid);
		ret = -ENODEV;
		goto put_mm;
	}

	ret = gm_dev_fault(mm, recv->va, dev, 0);
	if (ret != GM_RET_SUCCESS && ret != GM_RET_PAGE_EXIST) {
		pr_info("gmem dev fault failed\n");
		ret = -EFAULT;
		goto put_mm;
	}

put_mm:
	mmput(mm);
put_task:
	put_task_struct(tsk);
out:
	gmem_send_comm_msg_reply(nid, peer_nid, peer_ws, ret);
	kfree(msg);
	return ret;
}

gm_ret_t gmem_map(struct gm_fault_t *gmf)
{
	int ret = 0;
	struct wait_station *ws;
	struct comm_msg_rsp *rsp;
	struct mm_struct *mm = gmf->mm;
	struct svm_proc *proc = search_svm_proc_by_mm(mm);
	struct gm_pager_msg_rq req = {
		.peer_pid = proc->peer_pid,
		.va = gmf->va,
		.size = gmf->size,
		.behavior = gmf->behavior
	};

	if (!proc) {
		pr_err("can not find proc\n");
		return -EBUSY;
	}

	ws = get_wait_station();
	req.my_ws = ws->id;

	if (gmf->copy) {
		req.flags |= GMEM_COPY_PAGE;
		req.dma_addr = gmf->dma_addr;
	}

	ret = msg_send_nid(GMEM_ALLOC_PAGE_REQUEST, proc->nid, proc->peer_nid,
			&req, sizeof(struct gm_pager_msg_rq));
	rsp = wait_at_station(ws);
	if ((long)rsp == -ETIMEDOUT)
		return -EBUSY;
	ret |= rsp->ret;
	kfree(rsp);
	if (ret) {
		if (ret == GM_RET_MIGRATING) {
			pr_info("gmem: race with migrating\n");
			return ret;
		} else {
			pr_info("send alloc page message failed %d\n", ret);
			return GM_RET_FAILURE_UNKNOWN;
		}
	}

	return GM_RET_SUCCESS;
}

gm_ret_t gmem_unmap(struct gm_fault_t *gmf)
{
	int ret;
	struct wait_station *ws;
	struct comm_msg_rsp *rsp;
	struct mm_struct *mm = gmf->mm;
	struct svm_proc *proc = search_svm_proc_by_mm(mm);
	struct gm_pager_msg_rq req = {
		.peer_pid = proc->peer_pid,
		.va = gmf->va,
		.size = gmf->size,
	};

	if (!proc) {
		pr_err("can not find proc\n");
		return -EBUSY;
	}

	if (gmf->copy) {
		req.flags |= GMEM_COPY_PAGE;
		req.dma_addr = gmf->dma_addr;
	}

	ws = get_wait_station();
	req.my_ws = ws->id;

	ret = msg_send_nid(GMEM_FREE_PAGE_REQUEST, proc->nid, proc->peer_nid,
						&req, sizeof(struct gm_pager_msg_rq));
	rsp = wait_at_station(ws);
	if ((long)rsp == -ETIMEDOUT)
		return -EBUSY;
	ret |= rsp->ret;
	kfree(rsp);
	if (ret) {
		pr_info("send free page message failed %d\n", ret);
		return GM_RET_FAILURE_UNKNOWN;
	}

	return GM_RET_SUCCESS;
}

gm_ret_t gmem_alloc(struct gm_fault_t *gmf)
{
	int ret = 0;
	struct wait_station *ws;
	struct comm_msg_rsp *rsp;
	struct mm_struct *mm = gmf->mm;
	struct svm_proc *proc = search_svm_proc_by_mm(mm);
	struct gm_pager_msg_rq req = {
		.peer_pid = proc->peer_pid,
		.va = gmf->va,
		.size = gmf->size,
		.prot = gmf->prot,
	};

	if (!proc) {
		pr_err("can not find proc\n");
		return -EBUSY;
	}

	ws = get_wait_station();
	req.my_ws = ws->id;
	ret = msg_send_nid(GMEM_ALLOC_VMA_REQUEST, proc->nid, proc->peer_nid,
						&req, sizeof(struct gm_pager_msg_rq));
	rsp = wait_at_station(ws);
	if ((long)rsp == -ETIMEDOUT)
		return -EBUSY;
	ret |= rsp->ret;
	kfree(rsp);
	if (ret) {
		pr_info("send alloc vma message failed %d\n", ret);
		return GM_RET_NOMEM;
	}

	return GM_RET_SUCCESS;
}

gm_ret_t gmem_free(struct gm_fault_t *gmf)
{
	int ret = 0;
	struct wait_station *ws;
	struct comm_msg_rsp *rsp;
	struct mm_struct *mm = gmf->mm;
	struct svm_proc *proc = search_svm_proc_by_mm(mm);
	struct gm_pager_msg_rq req = {
		.peer_pid = proc->peer_pid,
		.va = gmf->va,
		.size = gmf->size,
	};

	if (!proc) {
		pr_err("can not find proc\n");
		return -EBUSY;
	}

	ws = get_wait_station();
	req.my_ws = ws->id;
	ret = msg_send_nid(GMEM_FREE_VMA_REQUEST, proc->nid, proc->peer_nid,
						&req, sizeof(struct gm_pager_msg_rq));
	rsp = wait_at_station(ws);
	if ((long)rsp == -ETIMEDOUT)
		return -EBUSY;
	ret |= rsp->ret;
	kfree(rsp);
	if (ret) {
		pr_info("send free vma message failed %d\n", ret);
		return GM_RET_FAILURE_UNKNOWN;
	}

	return GM_RET_SUCCESS;
}

int gmem_handle_evict_page(struct rpg_kmsg_message *msg)
{
	struct gm_evict_page_msg_rq *recv = (struct gm_evict_page_msg_rq *)msg;
	unsigned int nid = recv->header.to_nid;
	unsigned int peer_nid = recv->header.from_nid;
	unsigned int peer_ws = recv->ws;
	unsigned int pid = recv->peer_pid;
	unsigned long size = recv->size;
	unsigned long addr = recv->va;
	struct vm_area_struct *vma;
	struct page *page;
	dma_addr_t dma_addr;
	gm_mapping_t *gm_page;
	struct device *dma_dev;
	struct gm_fault_t gmf;
	struct svm_proc *proc;
	struct task_struct *tsk;
	struct mm_struct *mm;
	int ret;
	struct folio *folio = NULL;

	proc = search_svm_proc_by_pid(pid);
	if (!proc) {
		pr_err("can not find svm_proc of task-%d\n", pid);
		ret = -EINVAL;
		goto response;
	}

	tsk = find_get_task_by_vpid(pid);
	if (!tsk) {
		pr_err("can not find task of task-%d\n", pid);
		ret = -EINVAL;
		goto response;
	}

	mm = get_task_mm(tsk);
	if (!mm) {
		pr_err("task-%d exited\n", pid);
		ret = -EINTR;
		goto put_task;
	}

	if (mm != proc->mm) {
		pr_err("miss match\n");
		ret = -EINTR;
		goto put_mm;
	}

	gmf.mm = mm;
	gmf.va = addr;
	gmf.size = size;
	gmf.copy = GMEM_COPY_PAGE;

	vma = find_vma(mm, addr);
	if (!vma || !vma->vm_obj) {
		pr_err("evict addr %lx vma %lx vm_obj %lx, no vma or vm_obj\n", addr,
			(unsigned long)vma, vma ? (unsigned long)vma->vm_obj : 0);
		ret = -EINVAL;
		goto put_mm;
	}

	gm_page = vm_object_lookup(vma->vm_obj, addr);
	if (!gm_page) {
		pr_err("evictim gm_page is NULL\n");
		ret = -EINVAL;
		goto put_mm;
	}

	mutex_lock(&gm_page->lock);
	if (gm_mapping_willneed(gm_page)) {
		pr_info("gmem: racing with prefetch or willneed so cancel evict\n");
		clear_gm_mapping_willneed(gm_page);
		ret = -EINVAL;
		goto unlock;
	}

	if (!gm_mapping_device(gm_page)) {
		pr_info("gmem: page is not in device\n");
		ret = -EINVAL;
		goto unlock;
	}

	if (size == HPAGE_PMD_SIZE) {
		folio = vma_alloc_folio(GFP_TRANSHUGE, HPAGE_PMD_ORDER, vma, addr, true);
		page = &folio->page;
	} else {
		page = alloc_page(GFP_KERNEL);
	}

	if (!page) {
		pr_err("gmem: gmem_evict_page alloc hugepage failed\n");
		ret = -ENOMEM;
		goto unlock;
	}

	dma_dev = gm_page->dev->dma_dev;
	dma_addr = dma_map_page(dma_dev, page, 0, size, DMA_BIDIRECTIONAL);
	gmf.dev = gm_page->dev;
	gmf.dma_addr = dma_addr;

	ret = gmem_unmap(&gmf);
	dma_unmap_page(dma_dev, dma_addr, size, DMA_BIDIRECTIONAL);
	if (ret) {
		pr_err("gmem_unmap failed, ret %d\n", ret);
		put_page(page);
		goto unlock;
	}

	set_gm_mapping_host(gm_page, page);

unlock:
	mutex_unlock(&gm_page->lock);
put_mm:
	mmput(mm);
put_task:
	put_task_struct(tsk);
response:
	gmem_send_comm_msg_reply(nid, peer_nid, peer_ws, ret);
	kfree(msg);
	return ret;
}

gm_ret_t gmem_create(gm_dev_t *dev, void **pmap)
{
	return GM_RET_SUCCESS;
}

gm_mmu_t gm_mmu = {
	.peer_va_alloc_fixed = gmem_alloc,
	.pmap_create = gmem_create,
	.peer_va_free = gmem_free,
	.peer_map = gmem_map,
	.peer_unmap = gmem_unmap,
};

#define ASCEND910_HBM_START 0x0000000800000000
#define ASCEND910_HBM_END   0x0000000fffffffff

gm_ret_t mmu_dev_create(struct device *dev, int devid)
{
	gm_ret_t ret;

	ret = gm_dev_create(&gm_mmu, NULL, GM_DEV_CAP_REPLAYABLE | GM_DEV_CAP_PEER, &dev->gm_dev);
	if (ret != GM_RET_SUCCESS) {
		pr_err("NPU gmem device create failed\n");
		return ret;
	}

	ret = gm_dev_register_physmem(dev->gm_dev, ASCEND910_HBM_START, ASCEND910_HBM_END);
	if (ret != GM_RET_SUCCESS) {
		pr_err("NPU gmem device register physical memory failed\n");
		goto free_gm_dev;
	}

	dev->gm_dev->dma_dev = dev;
	gm_devs[devid] = dev->gm_dev;

	pr_info("Create NPU gmem device and register HBM\n");
	return ret;
free_gm_dev:
	gm_dev_destroy(dev->gm_dev);
	dev->gm_dev = NULL;
	return ret;
}
EXPORT_SYMBOL(mmu_dev_create);

gm_ret_t mmu_as_attach(struct device *dev)
{
	gm_ret_t ret;
	gm_dev_t *gm_dev = dev->gm_dev;
	gm_context_t *gm_ctx;

	if (!gm_dev) {
		pr_err("NPU device gm_dev is NULL\n");
		return GM_RET_FAILURE_UNKNOWN;
	}

	if (!current->mm->gm_as) {
		ret = gm_as_create(0, ULONG_MAX, GM_AS_ALLOC_DEFAULT, NPU_PAGE_SIZE,
						   &current->mm->gm_as);
		if (ret != GM_RET_SUCCESS) {
			pr_err("Process %d create gm_as failed\n", current->pid);
			return ret;
		}
	}

	ret = gm_as_attach(current->mm->gm_as, gm_dev, 0, 1, &gm_ctx);
	if (ret != GM_RET_SUCCESS) {
		pr_err("gm_dev attach to process %d failed\n", current->pid);
		return ret;
	}

	pr_info("Attach gm_dev to process %d\n", current->pid);
	return ret;
}
EXPORT_SYMBOL(mmu_as_attach);
