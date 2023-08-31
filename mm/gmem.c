/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Generalized Memory Management.
 *
 * Copyright (C) 2023- Huawei, Inc.
 * Author: Weixi Zhu
 *
 */

#include <linux/errno.h>
#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/mman.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/sched/coredump.h>
#include <linux/rwsem.h>
#include <linux/pagemap.h>
#include <linux/rmap.h>
#include <linux/spinlock.h>
#include <linux/xxhash.h>
#include <linux/delay.h>
#include <linux/kthread.h>
#include <linux/wait.h>
#include <linux/slab.h>
#include <linux/rbtree.h>
#include <linux/memory.h>
#include <linux/mmu_notifier.h>
#include <linux/swap.h>
#include <linux/ksm.h>
#include <linux/hashtable.h>
#include <linux/freezer.h>
#include <linux/oom.h>
#include <linux/numa.h>
#include <linux/mempolicy.h>
#include <linux/gmem.h>
#include <linux/xarray.h>
#include <linux/syscalls.h>
#include <linux/dma-mapping.h>
#include <linux/vm_object.h>
#include <linux/dma-direct.h>
#include <linux/workqueue.h>
#include <linux/proc_fs.h>

DEFINE_STATIC_KEY_FALSE(gmem_status);
EXPORT_SYMBOL_GPL(gmem_status);

static struct kmem_cache *gm_as_cache;
static struct kmem_cache *gm_dev_cache;
static struct kmem_cache *gm_ctx_cache;
static struct kmem_cache *gm_region_cache;
static DEFINE_XARRAY_ALLOC(gm_dev_id_pool);

static bool enable_gmem;

static inline unsigned long pe_mask(enum page_entry_size pe_size)
{
	if (pe_size == PE_SIZE_PTE)
		return PAGE_MASK;
	if (pe_size == PE_SIZE_PMD)
		return HPAGE_PMD_MASK;
	if (pe_size == PE_SIZE_PUD)
		return HPAGE_PUD_MASK;
	return ~0;
}

static struct percpu_counter g_gmem_stats[NR_GMEM_STAT_ITEMS];

void gmem_state_counter(enum gmem_stat_item item, int val)
{
	if (!gmem_is_enabled())
		return;

	if (WARN_ON_ONCE(unlikely(item >= NR_GMEM_STAT_ITEMS)))
		return;

	percpu_counter_add(&g_gmem_stats[item], val);
}

#ifdef CONFIG_PROC_FS
static int gmemstat_show(struct seq_file *m, void *arg)
{
	if (!gmem_is_enabled())
		return 0;

	seq_printf(m, "migrating     : %lld\n",
		percpu_counter_read_positive(&g_gmem_stats[NR_PAGE_MIGRATING]));

	return 0;
}
#endif /* CONFIG_PROC_FS */

static struct workqueue_struct *prefetch_wq;

#define GM_WORK_CONCURRENCY 4

static int __init gmem_init(void)
{
	int err = -ENOMEM;

	if (!enable_gmem)
		return 0;

	gm_as_cache = KMEM_CACHE(gm_as, 0);
	if (!gm_as_cache)
		goto out;

	gm_dev_cache = KMEM_CACHE(gm_dev, 0);
	if (!gm_dev_cache)
		goto free_as;

	gm_ctx_cache = KMEM_CACHE(gm_context, 0);
	if (!gm_ctx_cache)
		goto free_dev;

	gm_region_cache = KMEM_CACHE(gm_region, 0);
	if (!gm_region_cache)
		goto free_ctx;

	err = vm_object_init();
	if (err)
		goto free_ctx;

	prefetch_wq = alloc_workqueue("prefetch",
		__WQ_LEGACY | WQ_UNBOUND | WQ_HIGHPRI | WQ_CPU_INTENSIVE, GM_WORK_CONCURRENCY);
	if (!prefetch_wq) {
		pr_info("fail to alloc workqueue prefetch_wq\n");
		err = -EFAULT;
		goto free_ctx;
	}

#ifdef CONFIG_PROC_FS
	proc_create_single("gmemstat", 0444, NULL, gmemstat_show);
#endif

	static_branch_enable(&gmem_status);

	return 0;

free_ctx:
	kmem_cache_destroy(gm_ctx_cache);
free_dev:
	kmem_cache_destroy(gm_dev_cache);
free_as:
	kmem_cache_destroy(gm_as_cache);
out:
	return -ENOMEM;
}
subsys_initcall(gmem_init);

static int __init setup_gmem(char *str)
{
	strtobool(str, &enable_gmem);

	return 1;
}
__setup("gmem=", setup_gmem);

/*
 * Create a GMEM device, register its MMU function and the page table.
 * The returned device pointer will be passed by new_dev.
 * A unique id will be assigned to the GMEM device, using Linux's xarray.
 */
gm_ret_t gm_dev_create(gm_mmu_t *mmu, void *dev_data, gm_dev_cap_t cap, gm_dev_t **new_dev)
{
	gm_dev_t *dev;

	if (!gmem_is_enabled())
		return GM_RET_FAILURE_UNKNOWN;

	dev = kmem_cache_alloc(gm_dev_cache, GFP_KERNEL);
	if (!dev)
		return GM_RET_NOMEM;

	if (xa_alloc(&gm_dev_id_pool, &dev->id, dev, xa_limit_32b, GFP_KERNEL)) {
		kmem_cache_free(gm_dev_cache, dev);
		return GM_RET_NOMEM;
	}

	dev->capability = cap;
	dev->mmu = mmu;
	dev->dev_data = dev_data;
	dev->current_ctx = NULL;
	INIT_LIST_HEAD(&dev->gm_ctx_list);
	*new_dev = dev;
	nodes_clear(dev->registered_hnodes);
	return GM_RET_SUCCESS;
}
EXPORT_SYMBOL_GPL(gm_dev_create);

// Destroy a GMEM device and reclaim the resources.
gm_ret_t gm_dev_destroy(gm_dev_t *dev)
{
	// TODO: implement it
	xa_erase(&gm_dev_id_pool, dev->id);
	return GM_RET_SUCCESS;
}
EXPORT_SYMBOL_GPL(gm_dev_destroy);

/* Handle the page fault triggered by a given device */
gm_ret_t gm_dev_fault(struct mm_struct *mm, gm_va_t addr, gm_dev_t *dev, int behavior)
{
	gm_ret_t ret = GM_RET_SUCCESS;
	gm_mmu_t *mmu = dev->mmu;
	struct device *dma_dev = dev->dma_dev;
	struct vm_area_struct *vma;
	vm_object_t *obj;
	gm_mapping_t *gm_mapping;
	gm_va_t size = HPAGE_SIZE;
	struct gm_fault_t gmf = {
		.mm = mm,
		.va = addr,
		.dev = dev,
		.size = size,
		.copy = false,
		.behavior = behavior
	};
	struct page *page = NULL;

	mmap_read_lock(mm);

	vma = find_vma(mm, addr);
	if (!vma) {
		pr_info("gmem: %s no vma\n", __func__);
		ret = GM_RET_FAILURE_UNKNOWN;
		goto mmap_unlock;
	}
	obj = vma->vm_obj;
	if (!obj) {
		pr_info("gmem: %s no vm_obj\n", __func__);
		ret = GM_RET_FAILURE_UNKNOWN;
		goto mmap_unlock;
	}

	xa_lock(obj->logical_page_table);
	gm_mapping = vm_object_lookup(obj, addr);
	if (!gm_mapping) {
		vm_object_mapping_create(obj, addr);
		gm_mapping = vm_object_lookup(obj, addr);
	}
	xa_unlock(obj->logical_page_table);

	mutex_lock(&gm_mapping->lock);
	if (gm_mapping_nomap(gm_mapping)) {
		goto peer_map;
	} else if (gm_mapping_device(gm_mapping)) {
		if (behavior == MADV_WILLNEED || behavior == MADV_PINNED) {
			goto peer_map;
		} else {
			ret = 0;
			goto unlock;
		}
	} else if (gm_mapping_cpu(gm_mapping)) {
		page = gm_mapping->page;
		if (!page) {
			pr_err("gmem: host gm_mapping page is NULL. Set nomap\n");
			set_gm_mapping_nomap(gm_mapping);
			goto unlock;
		}
		get_page(page);
		zap_page_range_single(vma, addr, size, NULL);
		gmf.dma_addr = dma_map_page(dma_dev, page, 0, size, DMA_BIDIRECTIONAL);
		if (dma_mapping_error(dma_dev, gmf.dma_addr))
			pr_info("gmem: dma map failed\n");

		gmf.copy = true;
	}

peer_map:
	ret = mmu->peer_map(&gmf);
	if (ret != GM_RET_SUCCESS) {
		if (ret == GM_RET_MIGRATING) {
			/*
			 * gmem page is migrating due to overcommit.
			 * update page to willneed and this will stop page evicting
			 */
			set_gm_mapping_willneed(gm_mapping);
			gmem_state_counter(NR_PAGE_MIGRATING, 1);
			ret = GM_RET_SUCCESS;
		} else {
			pr_err("gmem: peer map failed\n");
			if (page) {
				set_gm_mapping_nomap(gm_mapping);
				put_page(page);
			}
		}
		goto unlock;
	}

	if (page) {
		dma_unmap_page(dma_dev, gmf.dma_addr, size, DMA_BIDIRECTIONAL);
		put_page(page);
	}

	set_gm_mapping_device(gm_mapping, dev);
unlock:
	mutex_unlock(&gm_mapping->lock);
mmap_unlock:
	mmap_read_unlock(mm);
	return ret;
}
EXPORT_SYMBOL_GPL(gm_dev_fault);

vm_fault_t gm_host_fault_locked(struct vm_fault *vmf, enum page_entry_size pe_size)
{
	vm_fault_t ret = 0;
	struct vm_area_struct *vma = vmf->vma;
	unsigned long addr = vmf->address & pe_mask(pe_size);
	vm_object_t *obj = vma->vm_obj;
	gm_mapping_t *gm_mapping;
	gm_va_t size = HPAGE_SIZE;
	gm_dev_t *dev;
	struct device *dma_dev;
	struct gm_fault_t gmf = {
		.mm = vma->vm_mm,
		.va = addr,
		.size = size,
		.copy = true,
	};

	gm_mapping = vm_object_lookup(obj, addr);
	if (!gm_mapping) {
		pr_err("gmem: host fault gm_mapping should not be NULL\n");
		return VM_FAULT_SIGBUS;
	}

	dev = gm_mapping->dev;
	gmf.dev = dev;
	dma_dev = dev->dma_dev;
	gmf.dma_addr = dma_map_page(dma_dev, vmf->page, 0, size, DMA_BIDIRECTIONAL);
	if (dma_mapping_error(dma_dev, gmf.dma_addr)) {
		pr_err("gmem: host fault dma mapping error\n");
		return VM_FAULT_SIGBUS;
	}
	if (dev->mmu->peer_unmap(&gmf) != GM_RET_SUCCESS) {
		pr_err("gmem: peer unmap failed\n");
		dma_unmap_page(dma_dev, gmf.dma_addr, size, DMA_BIDIRECTIONAL);
		return VM_FAULT_SIGBUS;
	}

	dma_unmap_page(dma_dev, gmf.dma_addr, size, DMA_BIDIRECTIONAL);
	return ret;
}

/*
 * Register the local physical memory of a gmem device.
 * This implies dynamically creating
 * the struct page data structures.
 */
gm_ret_t gm_dev_register_physmem(gm_dev_t *dev, gm_pa_t begin, gm_pa_t end)
{
	gm_mapping_t *mapping;
	gm_pa_t addr = PAGE_ALIGN(begin);
	unsigned int nid;
	int i, page_num = (end - addr) >> PAGE_SHIFT;
	struct hnode *hnode = kmalloc(sizeof(struct hnode), GFP_KERNEL);

	if (!hnode)
		goto err;

	nid = alloc_hnode_id();
	if (nid == MAX_NUMNODES)
		goto free_hnode;
	hnode_init(hnode, nid, dev);

	mapping = kvmalloc(sizeof(gm_mapping_t) * page_num, GFP_KERNEL);
	if (!mapping)
		goto deinit_hnode;

	for (i = 0; i < page_num; i++, addr += PAGE_SIZE) {
		mapping[i].node_id = hnode->id;
		mapping[i].pfn = addr >> PAGE_SHIFT;
		mapping[i].flag = 0;
	}

	xa_lock(&hnode->pages);
	for (i = 0; i < page_num; i++) {
		if (xa_err(__xa_store(&hnode->pages, i, mapping + i, GFP_KERNEL))) {
			/* Probably nomem */
			kvfree(mapping);
			xa_unlock(&hnode->pages);
			goto deinit_hnode;
		}
		__xa_set_mark(&hnode->pages, i, XA_MARK_0);
	}
	xa_unlock(&hnode->pages);

	return GM_RET_SUCCESS;

deinit_hnode:
	hnode_deinit(nid, dev);
	free_hnode_id(nid);
free_hnode:
	kfree(hnode);
err:
	return -ENOMEM;
}
EXPORT_SYMBOL_GPL(gm_dev_register_physmem);

void gm_dev_unregister_physmem(gm_dev_t *dev, unsigned int nid)
{
	struct hnode *hnode = get_hnode(nid);
	gm_mapping_t *mapping = xa_load(&hnode->pages, 0);

	kvfree(mapping);
	hnode_deinit(nid, dev);
	free_hnode_id(nid);
	kfree(hnode);
}
EXPORT_SYMBOL_GPL(gm_dev_unregister_physmem);

gm_mapping_t *gm_mappings_alloc(unsigned int nid, unsigned int order)
{
	gm_mapping_t *mapping;
	struct hnode *node = get_hnode(nid);
	XA_STATE(xas, &node->pages, 0);

	/* TODO: support order > 0 */
	if (order != 0)
		return ERR_PTR(-EINVAL);

	xa_lock(&node->pages);
	mapping = xas_find_marked(&xas, ULONG_MAX, XA_MARK_0);
	if (!mapping) {
		xa_unlock(&node->pages);
		return ERR_PTR(-ENOMEM);
	}

	xas_clear_mark(&xas, XA_MARK_0);
	xa_unlock(&node->pages);

	return mapping;
}
EXPORT_SYMBOL_GPL(gm_mappings_alloc);

void gm_mappings_free(gm_mapping_t *mapping, unsigned int order)
{
	gm_mapping_t *entry;
	struct hnode *node = get_hnode(mapping->node_id);
	XA_STATE(xas, &node->pages, 0);

	/* TODO: support order > 0 */
	if (order != 0)
		return;

	xas_for_each(&xas, entry, ULONG_MAX) {
		if (entry == mapping) {
			xas_set_mark(&xas, XA_MARK_0);
			break;
		}
	}
}
EXPORT_SYMBOL_GPL(gm_mappings_free);

/* GMEM Virtual Address Space API */
gm_ret_t gm_as_create(gm_va_t begin, gm_va_t end, gm_as_alloc_t policy,
		gm_va_t cache_quantum, gm_as_t **new_as)
{
	gm_as_t *as;

	if (!new_as)
		return -EINVAL;

	as = kmem_cache_alloc(gm_as_cache, GFP_ATOMIC);
	if (!as)
		return -ENOMEM;

	spin_lock_init(&as->rbtree_lock);
	as->rbroot = RB_ROOT;
	as->start_va = begin;
	as->end_va = end;
	as->policy = policy;

	INIT_LIST_HEAD(&as->gm_ctx_list);

	*new_as = as;
	return GM_RET_SUCCESS;
}
EXPORT_SYMBOL_GPL(gm_as_create);

gm_ret_t gm_as_destroy(gm_as_t *as)
{
	gm_context_t *ctx, *tmp_ctx;

	list_for_each_entry_safe(ctx, tmp_ctx, &as->gm_ctx_list, gm_as_link)
		kfree(ctx);

	kmem_cache_free(gm_as_cache, as);

	return GM_RET_SUCCESS;
}
EXPORT_SYMBOL_GPL(gm_as_destroy);

gm_ret_t gm_as_attach(gm_as_t *as, gm_dev_t *dev, gm_mmu_mode_t mode,
		bool activate, gm_context_t **out_ctx)
{
	gm_context_t *ctx;
	int nid;
	int ret;

	ctx = kmem_cache_alloc(gm_ctx_cache, GFP_KERNEL);
	if (!ctx)
		return GM_RET_NOMEM;

	ctx->as = as;
	ctx->dev = dev;
	ctx->pmap = NULL;
	ret = dev->mmu->pmap_create(dev, &ctx->pmap);
	if (ret) {
		kmem_cache_free(gm_ctx_cache, ctx);
		return ret;
	}

	INIT_LIST_HEAD(&ctx->gm_dev_link);
	INIT_LIST_HEAD(&ctx->gm_as_link);
	list_add_tail(&dev->gm_ctx_list, &ctx->gm_dev_link);
	list_add_tail(&ctx->gm_as_link, &as->gm_ctx_list);

	if (activate) {
		/*
		 * Here we should really have a callback function to perform the context switch
		 * for the hardware. E.g. in x86 this function is effectively flushing the CR3 value.
		 * Currently we do not care time-sliced context switch, unless someone wants to support it.
		 */
		dev->current_ctx = ctx;
	}
	*out_ctx = ctx;

	/*
	 * gm_as_attach will be used to attach device to process address space.
	 * Handle this case and add hnodes registered by device to process mems_allowed.
	 */
	for_each_node_mask(nid, dev->registered_hnodes)
		node_set(nid, current->mems_allowed);
	return GM_RET_SUCCESS;
}
EXPORT_SYMBOL_GPL(gm_as_attach);

DEFINE_SPINLOCK(hnode_lock);
struct hnode *hnodes[MAX_NUMNODES];

void __init hnuma_init(void)
{
	unsigned int node;

	for_each_node(node)
		node_set(node, hnode_map);
}

unsigned int alloc_hnode_id(void)
{
	unsigned int node;

	spin_lock(&hnode_lock);
	node = first_unset_node(hnode_map);
	node_set(node, hnode_map);
	spin_unlock(&hnode_lock);

	return node;
}

void free_hnode_id(unsigned int nid)
{
	node_clear(nid, hnode_map);
}

void hnode_init(struct hnode *hnode, unsigned int hnid, gm_dev_t *dev)
{
	hnodes[hnid] = hnode;
	hnodes[hnid]->id = hnid;
	hnodes[hnid]->dev = dev;
	node_set(hnid, dev->registered_hnodes);
	xa_init(&hnodes[hnid]->pages);
}

void hnode_deinit(unsigned int hnid, gm_dev_t *dev)
{
	hnodes[hnid]->id = 0;
	hnodes[hnid]->dev = NULL;
	node_clear(hnid, dev->registered_hnodes);
	xa_destroy(&hnodes[hnid]->pages);
	hnodes[hnid] = NULL;
}

struct prefetch_data {
	struct mm_struct *mm;
	gm_dev_t *dev;
	unsigned long addr;
	size_t size;
	struct work_struct work;
	int *res;
};

static void prefetch_work_cb(struct work_struct *work)
{
	struct prefetch_data *d =
		container_of(work, struct prefetch_data, work);
	unsigned long addr = d->addr, end = d->addr + d->size;
	int page_size = HPAGE_SIZE;
	int ret;

	do {
		/* MADV_WILLNEED: dev will soon access this addr. */
		ret = gm_dev_fault(d->mm, addr, d->dev, MADV_WILLNEED);
		if (ret == GM_RET_PAGE_EXIST) {
			pr_info("%s: device has done page fault, ignore prefetch\n", __func__);
		} else if (ret != GM_RET_SUCCESS) {
			*d->res = -EFAULT;
			pr_err("%s: call dev fault error %d\n", __func__, ret);
		}
	} while (addr += page_size, addr != end);

	kfree(d);
}

static int hmadvise_do_prefetch(gm_dev_t *dev, unsigned long addr, size_t size)
{
	unsigned long start, end, per_size;
	int page_size = HPAGE_SIZE;
	struct prefetch_data *data;
	struct vm_area_struct *vma;
	int res = GM_RET_SUCCESS;

	/* Align addr by rounding outward to make page cover addr. */
	end = round_up(addr + size, page_size);
	start = round_down(addr, page_size);
	size = end - start;

	mmap_read_lock(current->mm);
	vma = find_vma(current->mm, start);
	if (!vma || start < vma->vm_start || end > vma->vm_end) {
		mmap_read_unlock(current->mm);
		return GM_RET_FAILURE_UNKNOWN;
	}
	mmap_read_unlock(current->mm);

	per_size = (size / GM_WORK_CONCURRENCY) & ~(page_size - 1);

	while (start < end) {
		data = kzalloc(sizeof(struct prefetch_data), GFP_KERNEL);
		if (!data) {
			flush_workqueue(prefetch_wq);
			return GM_RET_NOMEM;
		}

		INIT_WORK(&data->work, prefetch_work_cb);
		data->mm = current->mm;
		data->dev = dev;
		data->addr = start;
		data->res = &res;
		if (per_size == 0)
			data->size = size;
		else
			/* Process (1.x * per_size) for the last time */
			data->size = (end - start < 2 * per_size) ? (end - start) : per_size;
		queue_work(prefetch_wq, &data->work);
		start += data->size;
	}

	flush_workqueue(prefetch_wq);
	return res;
}

static int hmadvise_do_eagerfree(unsigned long addr, size_t size)
{
	int page_size = HPAGE_SIZE;
	struct vm_area_struct *vma;
	int ret = GM_RET_SUCCESS;
	unsigned long start, end;
	gm_mapping_t *gm_mapping;
	struct gm_fault_t gmf = {
		.mm = current->mm,
		.size = page_size,
		.copy = false,
	};
	vm_object_t *obj;

	/* Align addr by rounding inward to avoid excessive page release. */
	end = round_down(addr + size, page_size);
	start = round_up(addr, page_size);
	if (start >= end)
		return ret;

	mmap_read_lock(current->mm);
	do {
		vma = find_vma(current->mm, start);
		if (!vma || !vma_is_peer_shared(vma)) {
			pr_err("gmem: not peer-shared vma, skip dontneed\n");
			continue;
		}
		obj = vma->vm_obj;
		if (!obj) {
			pr_err("gmem: peer-shared vma should have vm_object\n");
			mmap_read_unlock(current->mm);
			return -EINVAL;
		}
		xa_lock(obj->logical_page_table);
		gm_mapping = vm_object_lookup(obj, start);
		if (!gm_mapping) {
			xa_unlock(obj->logical_page_table);
			continue;
		}
		xa_unlock(obj->logical_page_table);
		mutex_lock(&gm_mapping->lock);
		if (gm_mapping_nomap(gm_mapping)) {
			mutex_unlock(&gm_mapping->lock);
			continue;
		} else if (gm_mapping_cpu(gm_mapping)) {
			zap_page_range_single(vma, start, page_size, NULL);
		} else {
			gmf.va = start;
			gmf.dev = gm_mapping->dev;
			ret = gm_mapping->dev->mmu->peer_unmap(&gmf);
			if (ret) {
				pr_err("gmem: peer_unmap failed. ret %d\n", ret);
				mutex_unlock(&gm_mapping->lock);
				continue;
			}
		}
		set_gm_mapping_nomap(gm_mapping);
		mutex_unlock(&gm_mapping->lock);
	} while (start += page_size, start != end);

	mmap_read_unlock(current->mm);
	return ret;
}

static bool check_hmadvise_behavior(int behavior)
{
	return behavior == MADV_DONTNEED;
}

int hmadvise_inner(int hnid, unsigned long start, size_t len_in, int behavior)
{
	int error = -EINVAL;
	struct hnode *node;

	if (hnid == -1) {
		if (check_hmadvise_behavior(behavior)) {
			goto no_hnid;
		} else {
			pr_err("hmadvise: behavior %d need hnid or is invalid\n",
				behavior);
			return error;
		}
	}

	if (hnid < 0)
		return error;

	if (!is_hnode(hnid) || !is_hnode_allowed(hnid))
		return error;

	node = get_hnode(hnid);
	if (!node) {
		pr_err("hmadvise: hnode id %d is invalid\n", hnid);
		return error;
	}

no_hnid:
	switch (behavior) {
	case MADV_PREFETCH:
		return hmadvise_do_prefetch(node->dev, start, len_in);
	case MADV_DONTNEED:
		return hmadvise_do_eagerfree(start, len_in);
	default:
		pr_err("hmadvise: unsupported behavior %d\n", behavior);
	}

	return error;
}
EXPORT_SYMBOL_GPL(hmadvise_inner);
