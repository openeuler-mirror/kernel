/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Logical Mapping Management
 *
 * Copyright (C) 2023- Huawei, Inc.
 * Author: Weixi zhu, chao Liu
 *
 */
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
#include <linux/vm_object.h>

/*
 * Sine VM_OBJECT maintains the logical page table under each VMA, and each VMA
 * points to a VM_OBJECT. Ultimately VM_OBJECTs must be maintained as long as VMA
 * gets changed: merge, split, adjust
 */
static struct kmem_cache *vm_object_cachep;
static struct kmem_cache *gm_mapping_cachep;

/* gm_mapping will not be release dynamically */
gm_mapping_t *alloc_gm_mapping(void)
{
	gm_mapping_t *gm_mapping = kmem_cache_zalloc(gm_mapping_cachep, GFP_KERNEL);

	if (!gm_mapping)
		return NULL;

	set_gm_mapping_nomap(gm_mapping);
	mutex_init(&gm_mapping->lock);

	return gm_mapping;
}
EXPORT_SYMBOL(alloc_gm_mapping);

static inline void release_gm_mapping(gm_mapping_t *mapping)
{
	kmem_cache_free(gm_mapping_cachep, mapping);
}

static inline gm_mapping_t *lookup_gm_mapping(vm_object_t *obj, unsigned long pindex)
{
	return xa_load(obj->logical_page_table, pindex);
}

int __init vm_object_init(void)
{
	vm_object_cachep = KMEM_CACHE(vm_object, 0);
	if (!vm_object_cachep)
		goto out;

	gm_mapping_cachep = KMEM_CACHE(gm_mapping, 0);
	if (!gm_mapping_cachep)
		goto free_vm_object;

	return 0;
free_vm_object:
	kmem_cache_destroy(vm_object_cachep);
out:
	return -ENOMEM;
}

/*
 * Create a VM_OBJECT and attach it to a VMA
 * This should be called when a VMA is created.
 */
vm_object_t *vm_object_create(struct vm_area_struct *vma)
{
	vm_object_t *obj = kmem_cache_alloc(vm_object_cachep, GFP_KERNEL);

	if (!obj)
		return NULL;

	spin_lock_init(&obj->lock);
	obj->vma = vma;

	/*
	 * The logical page table maps linear_page_index(obj->vma, va)
	 * to pointers of struct gm_mapping.
	 */
	obj->logical_page_table = kmalloc(sizeof(struct xarray), GFP_KERNEL);
	if (!obj->logical_page_table) {
		kmem_cache_free(vm_object_cachep, obj);
		return NULL;
	}

	xa_init(obj->logical_page_table);
	atomic_set(&obj->nr_pages, 0);
	atomic_set(&obj->ref_count, 1);

	return obj;
}

/* This should be called when a VMA no longer refers to a VM_OBJECT */
void vm_object_drop_locked(struct vm_area_struct *vma)
{
	vm_object_t *obj = vma->vm_obj;

	if (!obj) {
		pr_err("vm_object: vm_obj of the vma is NULL\n");
		return;
	}

	/*
	 * We must enter this with VMA write-locked, which is unfortunately a giant lock.
	 * Note that Linux 6.0 has per-VMA lock:
	 * https://lwn.net/Articles/906852/
	 * https://lwn.net/Articles/906833/
	 */
	free_gm_mappings(vma);
	mmap_assert_write_locked(vma->vm_mm);
	vma->vm_obj = NULL;

	if (atomic_dec_and_test(&obj->ref_count)) {
		xa_destroy(obj->logical_page_table);
		kfree(obj->logical_page_table);
		kmem_cache_free(vm_object_cachep, obj);
	}
}

void dup_vm_object(struct vm_area_struct *dst, struct vm_area_struct *src)
{
	unsigned long index;
	gm_mapping_t *mapping;
	unsigned long moved_pages = 0;

	XA_STATE(xas, src->vm_obj->logical_page_table, linear_page_index(src, src->vm_start));

	xa_lock(dst->vm_obj->logical_page_table);
	rcu_read_lock();
	xas_for_each(&xas, mapping, linear_page_index(src, src->vm_end)) {
		index = xas.xa_index - src->vm_pgoff + dst->vm_pgoff +
			((src->vm_start - dst->vm_start) >> PAGE_SHIFT);
		__xa_store(dst->vm_obj->logical_page_table, index, mapping, GFP_KERNEL);
		moved_pages++;
	}
	rcu_read_unlock();
	atomic_add(moved_pages, &dst->vm_obj->nr_pages);
	xa_unlock(dst->vm_obj->logical_page_table);
}

void vm_object_adjust(struct vm_area_struct *vma, unsigned long start, unsigned long end)
{
	/* remove logical mapping in [vma->vm_start, start) and [end, vm->vm_end) */
	unsigned long removed_pages = 0;
	gm_mapping_t *mapping;

	XA_STATE(xas, vma->vm_obj->logical_page_table, linear_page_index(vma, vma->vm_start));

	xas_lock(&xas);
	if (vma->vm_start < start) {
		xas_for_each(&xas, mapping, linear_page_index(vma, start)) {
			xas_store(&xas, NULL);
			removed_pages++;
		}
	}

	if (vma->vm_end > end) {
		xas_set(&xas, linear_page_index(vma, end));

		xas_for_each(&xas, mapping, linear_page_index(vma, vma->vm_end)) {
			xas_store(&xas, NULL);
			removed_pages++;
		}
	}
	atomic_sub(removed_pages, &vma->vm_obj->nr_pages);
	xas_unlock(&xas);
}

/*
 * Given a VA, the page_index is computed by
 * page_index = linear_page_index(struct vm_area_struct *vma, unsigned long address)
 */
struct gm_mapping *vm_object_lookup(vm_object_t *obj, gm_va_t va)
{
	return lookup_gm_mapping(obj, linear_page_index(obj->vma, va));
}
EXPORT_SYMBOL_GPL(vm_object_lookup);

void vm_object_mapping_create(vm_object_t *obj, gm_va_t start)
{
	pgoff_t index = linear_page_index(obj->vma, start);
	gm_mapping_t *gm_mapping;

	gm_mapping = alloc_gm_mapping();
	if (!gm_mapping)
		return;

	__xa_store(obj->logical_page_table, index, gm_mapping, GFP_KERNEL);
}

void free_gm_mappings(struct vm_area_struct *vma)
{
	gm_mapping_t *gm_mapping;
	XA_STATE(xas, vma->vm_obj->logical_page_table, linear_page_index(vma, vma->vm_start));

	xa_lock(vma->vm_obj->logical_page_table);
	xas_for_each(&xas, gm_mapping, linear_page_index(vma, vma->vm_end)) {
		release_gm_mapping(gm_mapping);
		xas_store(&xas, NULL);
	}
	xa_unlock(vma->vm_obj->logical_page_table);
}
