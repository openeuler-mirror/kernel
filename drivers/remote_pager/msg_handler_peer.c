// SPDX-License-Identifier: GPL-2.0-only
/*
 * Generalized Memory Management.
 *
 * Copyright (C) 2023- Huawei, Inc.
 * Author: Chunsheng Luo
 * Co-Author: Weixi Zhu, Jun Chen, Jiangtian Feng
 */

#include <linux/mm.h>
#include <linux/dma-mapping.h>
#include <linux/mman.h>
#include <linux/mutex.h>
#include <linux/completion.h>
#include <linux/ktime.h>
#include <linux/list_lru.h>
#include <linux/page-flags.h>
#include <linux/rmap.h>
#include <linux/kallsyms.h>
#include <linux/kprobes.h>
#include <asm-generic/pgalloc.h>
#include <linux/sched/mm.h>

#include "msg_handler.h"
#include "svm_proc_mng.h"
#include "swap/device/swap_manager.h"

#define GM_READ	0x00000001
#define GM_WRITE 0x00000002
#define GM_EXEC	0x00000004

#define MAX_RETRY_TIME 10

#ifndef WITH_GMEM
enum gm_ret {
	GM_RET_SUCCESS = 0,
	GM_RET_NOMEM,
	GM_RET_PAGE_EXIST,
	GM_RET_DMA_ERROR,
	GM_RET_MIGRATING,
	GM_RET_FAILURE_UNKNOWN,
	GM_RET_UNIMPLEMENTED,
};
#endif

static inline vm_fault_t get_page_size(enum page_entry_size pe_size,
				       unsigned int *page_size,
				       unsigned long *addr)
{
	switch (pe_size) {
	case PE_SIZE_PTE:
		*page_size = PAGE_SIZE;
		break;
	case PE_SIZE_PMD:
		*page_size = HPAGE_SIZE;
		*addr = round_down(*addr, HPAGE_SIZE);
		break;
	default:
		return VM_FAULT_FALLBACK;
	}
	return 0;
}

static inline bool addr_is_mapped(unsigned long addr, pmd_t *pmd,
				  enum page_entry_size pe_size)
{
	pte_t *pte;
	bool ret;

	if (pe_size == PE_SIZE_PMD)
		return !pmd_none(*pmd);
	if (pmd_none(*pmd))
		return false;
	pte = pte_offset_map(pmd, addr);
	ret = !pte_none(*pte);
	pte_unmap(pte);
	return ret;
}

static vm_fault_t __gmem_fault(struct vm_fault *vmf,
			       enum page_entry_size pe_size)
{
	vm_fault_t ret = VM_FAULT_SIGBUS;
	int msg_ret = GM_RET_FAILURE_UNKNOWN;
	unsigned long addr = vmf->address;
	unsigned int page_size;
	struct gm_pager_msg_rq req = { 0 };
	struct comm_msg_rsp *rsp;
	struct wait_station *ws;
	struct page_info *page_info;
	struct mm_struct *mm;
	struct svm_proc *proc;

	ret = get_page_size(pe_size, &page_size, &addr);
	if (ret)
		return ret;

	mm = vmf->vma->vm_mm;
	proc = search_svm_proc_by_mm(mm);
	if (!proc) {
		pr_err("%s: failed to get svm proc\n", __func__);
		return VM_FAULT_SIGBUS;
	}

	page_info = get_page_info(&proc->pager, addr, page_size, page_size);
	if (!page_info) {
		pr_err("%s: failed to get page_info\n", __func__);
		return VM_FAULT_SIGBUS;
	}
	mutex_lock(&page_info->lock);

	if (addr_is_mapped(addr, vmf->pmd, pe_size))
		goto unlock;

	req.va = addr;
	req.size = page_size;

	/* start fault */
	ws = get_wait_station();
	req.my_ws = ws->id;
	req.peer_pid = proc->peer_pid;

	ret = msg_send_nid(GMEM_PAGE_FAULT_REQUEST, proc->nid, proc->peer_nid,
			   &req, sizeof(req));
	rsp = wait_at_station(ws);
	if ((long)rsp != -ETIMEDOUT) {
		msg_ret = rsp->ret;
		kfree(rsp);
	}
	if (msg_ret == GM_RET_PAGE_EXIST) {
		pr_warn("gmem: weird page exist\n");
	} else if (msg_ret != GM_RET_SUCCESS) {
		ret = VM_FAULT_SIGBUS;
		goto unlock;
	}

	ret = VM_FAULT_NOPAGE;

unlock:
	mutex_unlock(&page_info->lock);
	return ret;
}

static vm_fault_t gmem_fault(struct vm_fault *vmf)
{
	return __gmem_fault(vmf, PE_SIZE_PTE);
}

static vm_fault_t gmem_huge_fault(struct vm_fault *vmf,
				 enum page_entry_size pe_size)
{
	int ret = 0;

	ret = __gmem_fault(vmf, pe_size);

	return ret;
}

static const struct vm_operations_struct gmem_vma_ops = {
	.fault = gmem_fault,
	.huge_fault = gmem_huge_fault,
};

int gmem_handle_task_pairing(struct rpg_kmsg_message *msg)
{
	struct gm_pair_msg_rq *recv = (struct gm_pair_msg_rq *)msg;
	unsigned int peer_nid = recv->header.from_nid;
	unsigned int peer_pid = recv->my_pid;
	unsigned int peer_ws = recv->my_ws;
	unsigned int my_nid = recv->peer_nid;
	unsigned int my_pid = recv->peer_pid;
	int ret = 0;

	gmem_add_to_svm_proc(my_nid, my_pid, peer_nid, peer_pid);
	gmem_send_comm_msg_reply(my_nid, peer_nid, peer_ws, ret);
	kfree(msg);
	return 0;
}

#define VM_PEER_SHARED BIT(56)

int vma_is_gmem(struct vm_area_struct *vma)
{
	return (vma->vm_flags & VM_PEER_SHARED) != 0;
}

int gmem_handle_alloc_vma_fixed(struct rpg_kmsg_message *msg)
{
	struct gm_pager_msg_rq *data = (struct gm_pager_msg_rq *)msg;
	unsigned long va = data->va;
	unsigned long size = data->size;
	unsigned long gmem_prot = data->prot;
	unsigned int my_pid = data->peer_pid;
	unsigned int peer_nid = data->header.from_nid;
	unsigned int nid = data->header.to_nid;
	unsigned int peer_ws = data->my_ws;
	unsigned long prot = 0;
	unsigned long populate;
	struct task_struct *tsk;
	struct mm_struct *mm;
	unsigned long addr;
	struct vm_area_struct *vma;
	int ret = GM_RET_SUCCESS;

	if (gmem_prot & GM_READ)
		prot |= PROT_READ;
	if (gmem_prot & GM_WRITE)
		prot |= PROT_WRITE;
	if (gmem_prot & GM_EXEC)
		prot |= PROT_EXEC;

	tsk = find_get_task_by_vpid(my_pid);
	if (!tsk) {
		pr_err("svm process does not have task_struct\n");
		ret = GM_RET_FAILURE_UNKNOWN;
		goto out;
	}

	mm = get_task_mm(tsk);
	if (!mm) {
		pr_err("no mm\n");
		ret = -1;
		goto put_task;
	}

	mmap_write_lock(mm);
	current->mm = mm;
	addr = __do_mmap_mm(mm, NULL, va, size, prot,
			    MAP_SHARED | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, 0,
			    0, &populate, NULL);
	if (IS_ERR_VALUE(addr)) {
		ret = addr;
		goto unlock;
	}

	vma = find_vma(mm, addr);
	if (!vma) {
		ret = GM_RET_FAILURE_UNKNOWN;
		goto unlock;
	}

	vma->vm_ops = &gmem_vma_ops;
	vma->vm_flags |= VM_HUGEPAGE;
	vma->vm_flags |= VM_PEER_SHARED;

unlock:
	current->mm = NULL;
	mmap_write_unlock(mm);
	mmput(mm);
put_task:
	put_task_struct(tsk);
out:
	pr_info("%s va %lx vma message %d\n", __func__, va, ret);
	gmem_send_comm_msg_reply(nid, peer_nid, peer_ws, ret);
	kfree(msg);
	return ret;
}

int gmem_handle_free_vma(struct rpg_kmsg_message *msg)
{
	struct gm_pager_msg_rq *recv = (struct gm_pager_msg_rq *)msg;
	unsigned long va = recv->va;
	unsigned long size = recv->size;
	unsigned int my_pid = recv->peer_pid;
	unsigned int nid = recv->header.to_nid;
	unsigned int peer_nid = recv->header.from_nid;
	unsigned int peer_ws = recv->my_ws;
	struct task_struct *tsk;
	struct mm_struct *mm;

	int ret = 0;

	tsk = find_get_task_by_vpid(my_pid);
	if (!tsk) {
		pr_err("svm process does not have task_struct\n");
		ret = GM_RET_FAILURE_UNKNOWN;
		goto out;
	}

	mm = get_task_mm(tsk);
	if (!mm) {
		pr_err("no mm\n");
		ret = -1;
		goto put_task;
	}

	mmap_write_lock(mm);
	ret = __do_munmap(mm, va, size, NULL, false);
	mmap_write_unlock(mm);

	if (ret < 0)
		ret = GM_RET_FAILURE_UNKNOWN;
	else
		ret = GM_RET_SUCCESS;

	mmput(mm);
put_task:
	put_task_struct(tsk);
out:
	gmem_send_comm_msg_reply(nid, peer_nid, peer_ws, ret);
	kfree(msg);
	return ret;
}

pmd_t *get_huge_pmd(const struct vm_area_struct *vma, u64 va)
{
	pgd_t *pgd = NULL;
	p4d_t *p4d = NULL;
	pud_t *pud = NULL;
	pmd_t *pmd = NULL;

	if ((vma == NULL) || (vma->vm_mm == NULL)) {
		pr_err("Vm_mm none. (va=0x%llx)\n", va);
		return NULL;
	}
	/* too much log, not print */
	pgd = pgd_offset(vma->vm_mm, va);
	if (PXD_JUDGE(pgd))
		return NULL;

	p4d = p4d_offset(pgd, va);
	if (PXD_JUDGE(p4d) != 0)
		return NULL;

	/* if kernel version is above 4.11.0,then 5 level pt arrived.
	pud_offset(pgd,va) changed to pud_offset(p4d,va) for x86
	but not changed in arm64 */
	pud = pud_offset(p4d, va);
	if (PXD_JUDGE(pud) != 0)
		return NULL;

	pmd = pmd_offset(pud, va);
	return pmd;
}

static inline struct page *alloc_transhuge_page_node(int nid, int zero)
{
	struct page *page;
	gfp_t gfp_mask = GFP_TRANSHUGE | __GFP_THISNODE | __GFP_NOWARN;

	if (zero)
		gfp_mask |= __GFP_ZERO;

	page = alloc_pages_node(nid, gfp_mask, HPAGE_PMD_ORDER);
	if (!page)
		return NULL;

	INIT_LIST_HEAD(&page->lru);
	INIT_LIST_HEAD(page_deferred_list(page));
	set_compound_page_dtor(page, TRANSHUGE_PAGE_DTOR);

	return page;
}

int gmem_hugepage_remap_owner(struct svm_proc *svm_proc, u64 addr,
			     pgprot_t prot, struct page *hpage)
{
	int ret;

	ret = hugetlb_insert_hugepage_pte(svm_proc->mm, addr, prot, hpage);
	if (ret != 0) {
		pr_err("insert_hugepage owner fail. (va=0x%llx)\n", addr);
		return ret;
	}

	return 0;
}

int gmem_hugepage_remap_local(struct svm_proc *svm_proc, u64 addr,
			     pgprot_t prot, struct page *hpage)
{
	int ret = 0;
	struct local_pair_proc *item = NULL;
	struct local_pair_proc *next = NULL;

	list_for_each_entry_safe(item, next, &svm_proc->tasks_list, node) {
		ret = hugetlb_insert_hugepage_pte(item->mm, addr, prot, hpage);
		if (ret != 0) {
			pr_err("insert_hugepage local fail. (va=0x%llx)\n", addr);
			return ret;
		}
	}

	return 0;
}


int gmem_hugepage_remap(struct svm_proc *svm_proc, u64 addr, pgprot_t prot,
		       struct page *hpage)
{
	int ret;

	ret = gmem_hugepage_remap_owner(svm_proc, addr, prot, hpage);
	if (ret != 0) {
		pr_err("gmem_hugepage_remap_owner fail. (va=0x%llx)\n", addr);
		return ret;
	}

	ret = gmem_hugepage_remap_local(svm_proc, addr, prot, hpage);
	if (ret != 0) {
		pr_err("gmem_hugepage_remap_local fail. (va=0x%llx)\n", addr);
		return ret;
	}

	return 0;
}

int gmem_handle_alloc_page(struct rpg_kmsg_message *msg)
{
	struct gm_pager_msg_rq *recv = (struct gm_pager_msg_rq *)msg;
	unsigned long addr = recv->va;
	unsigned int page_size = recv->size;
	unsigned int my_pid = recv->peer_pid;
	unsigned int peer_ws = recv->my_ws;
	int nid = recv->header.to_nid;
	int peer_nid = recv->header.from_nid;
	struct page_info *page_info;
	struct svm_proc *proc = search_svm_proc_by_pid(my_pid);
	struct page *page;
	unsigned long long prot_val;
	struct task_struct *tsk;
	struct mm_struct *mm;
	struct vm_area_struct *vma;
	struct page *pgtable;
	pmd_t *pmd;
	spinlock_t *ptl;
	int n_retry = 0;
	int ret = 0;

	if (!proc) {
		pr_info("can not find proc of %d\n", my_pid);
		ret = -EINVAL;
		goto out;
	}

	page_info = get_page_info(&proc->pager, addr, page_size, page_size);
	if (!page_info) {
		pr_err("%s: failed to get page_info\n", __func__);
		ret = -EINVAL;
		goto out;
	}

	if (recv->behavior == MADV_WILLNEED) {
		if (!page_info->page)
			goto new_page;

		ret = update_page(page_info->page);
		if (ret)
			pr_err("update_page failed, error: %d\n", ret);

		goto out;
	}

new_page:
	/* TODO: How Can Know HBM node */
	page = alloc_transhuge_page_node(1, !recv->dma_addr);
	if (!page) {
		do_swap();
		if (n_retry++ < MAX_RETRY_TIME) {
			goto new_page;
		} else {
			ret = -ENOMEM;
			goto out;
		}
	}

	/* We need a condition */
	if (need_wake_up_swapd())
		wake_up_swapd();

	if (recv->dma_addr) {
		handle_migrate_page((void *)recv->dma_addr, page, page_size,
				    FORM_PEER);
	}

	tsk = find_get_task_by_vpid(my_pid);
	if (!tsk) {
		pr_err("svm process does not have task_struct\n");
		ret = GM_RET_FAILURE_UNKNOWN;
		goto out;
	}

	mm = get_task_mm(tsk);
	if (!mm) {
		pr_err("no mm\n");
		ret = -1;
		goto put_task;
	}

	vma = find_vma(mm, addr);
	if (vma->vm_flags & VM_WRITE) {
		prot_val = (pgprot_val(PAGE_SHARED_EXEC) & (~PTE_RDONLY)) |
			   PTE_DIRTY;
	} else {
		prot_val = pgprot_val(PAGE_READONLY_EXEC);
	}

	/* TODO: 9 Consider multiple processes bind */
	ret = gmem_hugepage_remap(proc, addr, __pgprot(prot_val), page);
	if (ret)
		goto put_mm;

	vma = find_vma(mm, addr);
	if (!vma->anon_vma)
		__anon_vma_prepare_symbol(vma);
	__page_set_anon_rmap_symbol(page, vma, addr, 1);
	add_swap_page(page);

	pmd = get_huge_pmd(vma, addr);
	pgtable = alloc_pages(GFP_KERNEL | ___GFP_ZERO, 0);
	ptl = pmd_lock(vma->vm_mm, pmd);
	pgtable_trans_huge_deposit_symbol(vma->vm_mm, pmd, pgtable);
	spin_unlock(ptl);
	page_info->page = page;

put_mm:
	mmput(mm);
put_task:
	put_task_struct(tsk);
out:
	gmem_send_comm_msg_reply(nid, peer_nid, peer_ws, ret);
	kfree(msg);
	return ret;
}

static inline void zap_clear_pmd(struct vm_area_struct *vma, u64 vaddr,
				pmd_t *pmd)
{
	pmd_clear(pmd);
	flush_tlb_range(vma, vaddr, vaddr + HPAGE_SIZE);
}

void zap_vma_pmd(struct vm_area_struct *vma, u64 vaddr)
{
	pmd_t *pmd = NULL;

	pmd = get_huge_pmd(vma, vaddr);

	if (pmd == NULL)
		return;

	zap_clear_pmd(vma, vaddr, pmd);
}

void gmem_hugepage_unmap_local(struct svm_proc *svm_proc, u64 addr)
{
	struct local_pair_proc *item = NULL;
	struct local_pair_proc *next = NULL;
	struct vm_area_struct *vma;

	list_for_each_entry_safe(item, next, &svm_proc->tasks_list, node) {
		vma = find_vma(item->mm, addr);
		if (!vma)
			zap_vma_pmd(vma, addr);
	}
}

void gmem_unmap_hugepage(struct svm_proc *svm_proc, u64 addr)
{
	struct vm_area_struct *vma;

	vma = find_vma(svm_proc->mm, addr);

	if (!vma)
		zap_vma_pmd(vma, addr);

	gmem_hugepage_unmap_local(svm_proc, addr);
}

int gmem_handle_free_page(struct rpg_kmsg_message *msg)
{
	struct gm_pager_msg_rq *recv = (struct gm_pager_msg_rq *)msg;
	unsigned long addr = recv->va;
	unsigned long page_size = recv->size;
	unsigned int my_pid = recv->peer_pid;
	unsigned int peer_ws = recv->my_ws;
	int peer_nid = recv->header.from_nid;
	int nid = recv->header.to_nid;
	struct task_struct *tsk;
	struct mm_struct *mm;
	struct vm_area_struct *vma;
	pmd_t *pmd;
	struct page_info *page_info;
	struct svm_proc *proc = search_svm_proc_by_pid(my_pid);
	struct page *page = NULL;
	struct page *pgtable;
	spinlock_t *ptl;
	int ret = 0;

	if (!proc) {
		pr_info("can not find proc of %d\n", my_pid);
		ret = -EINVAL;
		goto out;
	}

	page_info = get_page_info(&proc->pager, addr, page_size, page_size);
	if (!page_info) {
		pr_err("%s: failed to get page_info\n", __func__);
		ret = -EINVAL;
		goto out;
	}

	page = page_info->page;
	if (!page) {
		pr_err("%s: page reference in page_info is NULL\n", __func__);
		ret = -EINVAL;
		goto out;
	}

	tsk = find_get_task_by_vpid(my_pid);
	if (!tsk) {
		pr_err("svm process does not have task_struct\n");
		ret = GM_RET_FAILURE_UNKNOWN;
		goto out;
	}

	mm = get_task_mm(tsk);
	if (!mm) {
		pr_err("no mm\n");
		ret = -1;
		goto put_task;
	}

	vma = find_vma(mm, addr);
	pmd = get_huge_pmd(vma, addr);
	ptl = pmd_lock(vma->vm_mm, pmd);
	pgtable = pgtable_trans_huge_withdraw_symbol(proc->mm, pmd);
	spin_unlock(ptl);
	pte_free(mm, pgtable);
	/* mm should be freed at first */
	smp_rmb();

	del_swap_page(page);
	zap_clear_pmd(vma, addr, pmd);

	mmput(mm);

	if (recv->dma_addr)
		handle_migrate_page((void *)recv->dma_addr, page, page_size,
				    TO_PEER);

	free_page_info(&proc->pager, page_info);
	put_page(page);

put_task:
	put_task_struct(tsk);
out:
	gmem_send_comm_msg_reply(nid, peer_nid, peer_ws, ret);
	kfree(msg);
	return ret;
}

int gmem_handle_hmadvise(struct rpg_kmsg_message *msg)
{
	kfree(msg);
	return 0;
}

int gmem_handle_hmemcpy(struct rpg_kmsg_message *msg)
{
	kfree(msg);
	return 0;
}

static int sync_gmem_vma_to_custom_process(struct svm_proc *svm_proc,
					  struct local_pair_proc *local_proc)
{
	struct mm_struct *mm = svm_proc->mm;
	struct vm_area_struct *vma, *local_vma;
	unsigned long populate;
	struct mm_struct *old_mm = current->mm;
	unsigned long addr;
	unsigned long prot = PROT_READ;


	mmap_write_lock(mm);
	for (vma = mm->mmap; vma; vma = vma->vm_next) {
		if (!vma_is_gmem(vma))
			continue;
		current->mm = local_proc->mm;
		pr_err("%s cur %lx local %lx start %lx -- end %lx\n", __func__,
		       (unsigned long)current->mm,
		       (unsigned long)local_proc->mm, vma->vm_start,
		       vma->vm_end);
		prot = PROT_READ;
		if (vma->vm_flags & VM_WRITE)
			prot |= PROT_WRITE;
		addr = __do_mmap_mm(local_proc->mm, NULL, vma->vm_start,
				    vma->vm_end - vma->vm_start, prot,
				    MAP_SHARED | MAP_ANONYMOUS |
				    MAP_FIXED_NOREPLACE, 0,
				    0, &populate, NULL);
		if (IS_ERR_VALUE(addr)) {
			pr_err("%s failed start %lx - end %lx ret %ld\n",
			       __func__, vma->vm_start, vma->vm_end, addr);
			continue;
		}
		local_vma = find_vma(local_proc->mm, addr);
		if (!local_vma) {
			local_vma->vm_ops = vma->vm_ops;
			local_vma->vm_flags |= VM_HUGEPAGE;
		}
	}
	mmap_write_unlock(mm);
	current->mm = old_mm;

	return 0;
}

int gmem_register_pair_local_task(unsigned int bind_to_pid,
				 unsigned int local_pid)
{
	int ret = 0;
	struct svm_proc *proc = search_svm_proc_by_pid(bind_to_pid);
	struct local_pair_proc *local_proc;

	pr_debug("%s bind_to_pid %d local_pid %d\n", __func__, bind_to_pid,
	       local_pid);

	local_proc = insert_local_proc(proc, local_pid);
	if (IS_ERR(local_proc)) {
		pr_err("%s failed\n", __func__);
		return PTR_ERR(local_proc);
	}

	/* sync vma and vma_ops to local_pid */
	sync_gmem_vma_to_custom_process(proc, local_proc);

	return ret;
}
EXPORT_SYMBOL(gmem_register_pair_local_task);
