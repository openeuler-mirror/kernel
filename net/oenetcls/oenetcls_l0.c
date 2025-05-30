// SPDX-License-Identifier: GPL-2.0-only
#include <linux/fs.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/miscdevice.h>
#include <linux/kallsyms.h>
#include <linux/mm.h>
#include <linux/gfp.h>
#include <linux/mempolicy.h>
#include <linux/pfn_t.h>
#include <linux/delay.h>
#include "oenetcls.h"

static struct vm_area_struct *oecls_l0_cache __ro_after_init;
static void *oecls_l0_cache_head;
static atomic_t alloc_num_l0 = ATOMIC_INIT(0);
static int cur_offset_l0;
static u8 slot_l0[L0_MAX_PAGE_NUM] = { 0 };

void *alloc_from_l0(int size)
{
	int i;
	void *addr = NULL;

	if (!oecls_l0_cache_head)
		return kzalloc(size, GFP_ATOMIC);

	if (size > L0_MAX_PAGE_SIZE) {
		oecls_error("size(%d) >= max_size(%d)!\n", size, L0_MAX_PAGE_SIZE);
		return NULL;
	}

	if (atomic_read(&alloc_num_l0) >= L0_MAX_PAGE_NUM) {
		oecls_error("alloc_num_l0:%d exceed max num!\n", atomic_read(&alloc_num_l0));
		return NULL;
	}

	for (i = 0; i < L0_MAX_PAGE_NUM; i++) {
		cur_offset_l0 = (cur_offset_l0 + 1) % L0_MAX_PAGE_NUM;
		if (slot_l0[cur_offset_l0] == 0) {
			addr = oecls_l0_cache_head + cur_offset_l0 * L0_MAX_PAGE_SIZE;
			atomic_inc(&alloc_num_l0);
			slot_l0[cur_offset_l0] = 1;
			break;
		}
	}

	if (!addr)
		oecls_error("app:%s, pid:%d alloc fail!\n", current->comm, current->pid);
	return addr;
}

void free_to_l0(void *addr)
{
	int offset = 0;

	if (!addr)
		return;

	if (!oecls_l0_cache_head) {
		kfree(addr);
		return;
	}

	if (atomic_read(&alloc_num_l0) <= 0) {
		oecls_error("alloc_num_l0:%d <= 0!\n", atomic_read(&alloc_num_l0));
		return;
	}

	offset = (addr - oecls_l0_cache_head) / L0_MAX_PAGE_SIZE;
	if (offset >= L0_MAX_PAGE_NUM) {
		oecls_error("app:%s, pid:%d, offset:%d\n", current->comm, current->pid, offset);
		return;
	}

	slot_l0[offset] = 0;
	atomic_dec(&alloc_num_l0);
}

static int get_node_node(struct vm_area_struct *vma)
{
	struct mempolicy *pol;
	nodemask_t *nmask;
	int nid;

	nid = get_vma_policy_node(vma, vma->vm_start, GFP_KERNEL, &pol, &nmask);
	if (pol->mode == MPOL_BIND || pol->mode == MPOL_PREFERRED_MANY)
		nid = first_node(*nmask);

	return nid;
}

static int oecls_l0_cache_mmap(struct file *filp, struct vm_area_struct *vma)
{
	unsigned long cont_size = PAGE_ALIGN(vma->vm_end - vma->vm_start);
	struct page *page = NULL;
	struct l0_vma_data *data;
	int page_cnt, nid;
	int ret = 0;

	if ((vma->vm_start % PMD_SIZE) || (vma->vm_end % PMD_SIZE)) {
		oecls_error("error vma_start: %#lx, vma_end: %#lx\n", vma->vm_start, vma->vm_end);
		return -EINVAL;
	}

	data = kzalloc(sizeof(*data), GFP_KERNEL);
	if (!data) {
		oecls_error("kzalloc l0_vma_data fail!\n");
		return -ENOMEM;
	}

	page_cnt = cont_size >> PAGE_SHIFT;
	nid = get_node_node(vma);
#ifdef CONFIG_CONTIG_ALLOC
	page = alloc_contig_pages(page_cnt, GFP_KERNEL, nid, NULL);
#endif
	if (!page) {
		ret = -ENOMEM;
		oecls_error("alloc_contig_pages fail! page_cnt:%d, nid:%d\n", page_cnt, nid);
		goto free_data;
	}

#if IS_ENABLED(CONFIG_HISI_L3T)
	ret = l3t_shared_lock(nid, page_to_pfn(page), cont_size);
#endif
	if (ret) {
		ret = -EOPNOTSUPP;
		oecls_error("l3t_shared_lock fail! ret: %d\n", ret);
		goto free_page;
	}

	data->page = page;
	data->size = cont_size;
	data->nid = nid;
	vma->vm_private_data = data;
	return 0;
free_page:
	free_contig_range(page_to_pfn(page), page_cnt);
free_data:
	kfree(data);
	return ret;
}

void init_oecls_l0_cache(void)
{
	int ret = 0;
	struct l0_vma_data *sbkpages;

	oecls_l0_cache = kzalloc(sizeof(*oecls_l0_cache), GFP_KERNEL);
	if (!oecls_l0_cache) {
		oecls_error("kzalloc oecls_l0_cache fail!\n");
		return;
	}
	oecls_l0_cache->vm_start = 0;
	oecls_l0_cache->vm_end = L0_MAX_PAGE_NUM * L0_MAX_PAGE_SIZE;

	ret = oecls_l0_cache_mmap(NULL, oecls_l0_cache);
	if (ret != 0) {
		kfree(oecls_l0_cache);
		oecls_l0_cache = NULL;
		return;
	}
	sbkpages = (struct l0_vma_data *)(oecls_l0_cache->vm_private_data);
	oecls_l0_cache_head = page_to_virt(sbkpages->page);

	atomic_set(&alloc_num_l0, 0);
	oecls_debug("l0_cache:%p, l0_cache_head:%p\n", oecls_l0_cache, oecls_l0_cache_head);
}

void clean_oecls_l0_cache(void)
{
	struct l0_vma_data *sbkpages;

	if (!oecls_l0_cache)
		return;

	oecls_debug("alloc_num_l0:%d\n", atomic_read(&alloc_num_l0));
	while (atomic_read(&alloc_num_l0) != 0)
		mdelay(1);

	sbkpages = (struct l0_vma_data *)(oecls_l0_cache->vm_private_data);
	if (sbkpages) {
#if IS_ENABLED(CONFIG_HISI_L3T)
		l3t_shared_unlock(sbkpages->nid, page_to_pfn(sbkpages->page), sbkpages->size);
#endif
		free_contig_range(page_to_pfn(sbkpages->page), sbkpages->size >> PAGE_SHIFT);
		kfree(sbkpages);
		oecls_l0_cache_head = NULL;
	}

	kfree(oecls_l0_cache);
}
