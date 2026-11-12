// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 Huawei Technologies Co., Ltd.
 * Author: Kunkun Jiang <jiangkunkun@huawei.com>
 */

/* Reverse indices of published 4K PVM shadow leaves and their walk dependencies. */

#include <linux/kvm_host.h>
#include <linux/overflow.h>
#include <linux/slab.h>
#include <asm/kvm_mmu.h>
#include <asm/kvm_pgtable.h>

#include "mmu.h"
#include "rmap.h"

#define PVM_RMAP_MAX_PT_GFNS	8U

/* Common 39-bit walks fit in one 256-byte leaf allocation. */
#define PVM_RMAP_INLINE_DEPS	3U

struct pvm_rmap_entry;

struct pvm_rmap_dep {
	struct list_head leaf_link;
	struct hlist_node bucket_link;
	struct pvm_rmap_entry *entry;
	struct pvm_rmap_bucket *bucket;
};

struct pvm_rmap_entry {
	union {
		struct rb_node gfn_node;
		struct list_head free;
	};
	struct rb_node va_node;
	struct kvm_s2_mmu *mmu;
	u64 addr;
	gfn_t gfn;
	struct list_head deps;
	unsigned int nr_deps;
	struct pvm_rmap_dep inline_deps[PVM_RMAP_INLINE_DEPS];
};

struct pvm_rmap_bucket {
	union {
		struct rb_node node;
		struct list_head free;
	};
	gfn_t gfn;
	struct hlist_head deps;
};

/* Objects are allocated before taking mmu_lock, and consumed without allocation. */
struct kvm_pvm_rmap_cache {
	struct list_head entries;
	struct list_head deps;
	struct list_head buckets;
	unsigned int nr_entries;
	unsigned int nr_deps;
	unsigned int nr_buckets;
};

int kvm_pvm_rmap_topup(struct kvm_pvm_rmap_cache **cachep, unsigned int nr)
{
	struct kvm_pvm_rmap_cache *cache = *cachep;
	struct pvm_rmap_entry *entry;
	struct pvm_rmap_bucket *bucket;
	struct pvm_rmap_dep *dep;
	unsigned int nr_deps;

	if (WARN_ON_ONCE(!nr || check_mul_overflow(nr, PVM_RMAP_MAX_PT_GFNS,
						   &nr_deps)))
		return -EINVAL;
	if (!cache) {
		cache = kzalloc(sizeof(*cache), GFP_KERNEL_ACCOUNT);
		if (!cache)
			return -ENOMEM;
		INIT_LIST_HEAD(&cache->entries);
		INIT_LIST_HEAD(&cache->deps);
		INIT_LIST_HEAD(&cache->buckets);
		*cachep = cache;
	}
	while (cache->nr_entries < nr) {
		entry = kmalloc(sizeof(*entry), GFP_KERNEL_ACCOUNT);
		if (!entry)
			return -ENOMEM;
		list_add(&entry->free, &cache->entries);
		cache->nr_entries++;
	}
	while (cache->nr_deps < nr_deps) {
		dep = kmalloc(sizeof(*dep), GFP_KERNEL_ACCOUNT);
		if (!dep)
			return -ENOMEM;
		list_add(&dep->leaf_link, &cache->deps);
		cache->nr_deps++;
	}
	while (cache->nr_buckets < nr_deps) {
		bucket = kmalloc(sizeof(*bucket), GFP_KERNEL_ACCOUNT);
		if (!bucket)
			return -ENOMEM;
		list_add(&bucket->free, &cache->buckets);
		cache->nr_buckets++;
	}
	return 0;
}

void kvm_pvm_rmap_free_cache(struct kvm_pvm_rmap_cache *cache)
{
	struct pvm_rmap_entry *entry, *enext;
	struct pvm_rmap_bucket *bucket, *bnext;
	struct pvm_rmap_dep *dep, *dnext;

	if (!cache)
		return;
	list_for_each_entry_safe(entry, enext, &cache->entries, free) {
		list_del(&entry->free);
		kfree(entry);
	}
	list_for_each_entry_safe(dep, dnext, &cache->deps, leaf_link) {
		list_del(&dep->leaf_link);
		kfree(dep);
	}
	list_for_each_entry_safe(bucket, bnext, &cache->buckets, free) {
		list_del(&bucket->free);
		kfree(bucket);
	}
	kfree(cache);
}

/* The identity root is embedded in kvm_arch, not in a kvm_pvm_mmu. */
struct kvm_pvm_mmu_rmap *kvm_pvm_mmu_rmap(struct kvm_s2_mmu *mmu)
{
	struct kvm *kvm = kvm_s2_mmu_to_kvm(mmu);

	if (mmu == &kvm->arch.mmu)
		return &kvm_to_pvm(kvm)->identity_rmap;
	return &container_of(mmu, struct kvm_pvm_mmu, mmu)->rmap;
}

static struct kvm_pvm_rmap *pvm_rmap_from_mmu(struct kvm_s2_mmu *mmu)
{
	return &kvm_to_pvm(kvm_s2_mmu_to_kvm(mmu))->rmap;
}

void kvm_pvm_rmap_mmu_init(struct kvm_s2_mmu *mmu)
{
	struct kvm_pvm_mmu_rmap *mrmap = kvm_pvm_mmu_rmap(mmu);

	spin_lock_init(&mrmap->map_lock);
	mrmap->vas = RB_ROOT;
	mrmap->ctx = NULL;
	mrmap->trans = NULL;
}

void kvm_pvm_rmap_init(struct kvm *kvm)
{
	struct kvm_pvm_rmap *rmap = &kvm_to_pvm(kvm)->rmap;

	*rmap = (struct kvm_pvm_rmap) {
		.gfns = RB_ROOT,
		.deps = RB_ROOT,
		.state = PVM_RMAP_COMPLETE,
	};
	spin_lock_init(&rmap->lock);
	kvm_pvm_rmap_mmu_init(&kvm->arch.mmu);
}

void kvm_pvm_rmap_destroy(struct kvm *kvm)
{
	struct kvm_pvm_rmap *rmap = &kvm_to_pvm(kvm)->rmap;

	WARN_ON_ONCE(rmap->entries || rmap->edges ||
		     !RB_EMPTY_ROOT(&rmap->gfns) || !RB_EMPTY_ROOT(&rmap->deps));
}

static struct pvm_rmap_entry *pvm_rmap_find_va(struct kvm_s2_mmu *mmu, u64 addr)
{
	struct kvm_pvm_mmu_rmap *mrmap = kvm_pvm_mmu_rmap(mmu);
	struct rb_node *node = mrmap->vas.rb_node;

	while (node) {
		struct pvm_rmap_entry *entry;

		entry = rb_entry(node, struct pvm_rmap_entry, va_node);
		if (addr < entry->addr)
			node = node->rb_left;
		else if (addr > entry->addr)
			node = node->rb_right;
		else
			return entry;
	}
	return NULL;
}

static struct pvm_rmap_entry *pvm_rmap_find_gfn(struct kvm_pvm_rmap *rmap,
						gfn_t start, gfn_t end)
{
	struct rb_node *node = rmap->gfns.rb_node;
	struct pvm_rmap_entry *first = NULL;

	while (node) {
		struct pvm_rmap_entry *entry;

		entry = rb_entry(node, struct pvm_rmap_entry, gfn_node);
		if (entry->gfn >= start) {
			first = entry;
			node = node->rb_left;
		} else {
			node = node->rb_right;
		}
	}
	return first && first->gfn < end ? first : NULL;
}

static struct pvm_rmap_bucket *pvm_rmap_find_bucket(struct kvm_pvm_rmap *rmap,
						    gfn_t start, gfn_t end)
{
	struct rb_node *node = rmap->deps.rb_node;
	struct pvm_rmap_bucket *first = NULL;

	while (node) {
		struct pvm_rmap_bucket *bucket;

		bucket = rb_entry(node, struct pvm_rmap_bucket, node);
		if (bucket->gfn >= start) {
			first = bucket;
			node = node->rb_left;
		} else {
			node = node->rb_right;
		}
	}
	return first && first->gfn < end ? first : NULL;
}

static void pvm_rmap_link_bucket(struct kvm_pvm_rmap *rmap,
				 struct pvm_rmap_bucket *bucket)
{
	struct rb_node **link = &rmap->deps.rb_node, *parent = NULL;

	while (*link) {
		struct pvm_rmap_bucket *cur;

		parent = *link;
		cur = rb_entry(parent, struct pvm_rmap_bucket, node);
		if (bucket->gfn < cur->gfn)
			link = &parent->rb_left;
		else
			link = &parent->rb_right;
	}
	rb_link_node(&bucket->node, parent, link);
	rb_insert_color(&bucket->node, &rmap->deps);
}

static bool pvm_rmap_has_dep(struct pvm_rmap_entry *entry, gfn_t gfn)
{
	struct pvm_rmap_dep *dep;

	list_for_each_entry(dep, &entry->deps, leaf_link)
		if (dep->bucket->gfn == gfn)
			return true;
	return false;
}

static void pvm_rmap_add_deps(struct pvm_rmap_entry *entry)
{
	struct kvm_s2_mmu *mmu = entry->mmu;
	struct kvm_pvm_mmu_rmap *mrmap = kvm_pvm_mmu_rmap(mmu);
	const struct kvm_s1_trans *trans = mrmap->trans;
	struct kvm_pvm_rmap_ctx *ctx = mrmap->ctx;
	struct kvm_pvm_rmap_cache *cache = ctx->cache;
	struct kvm_pvm_rmap *rmap = pvm_rmap_from_mmu(mmu);
	unsigned int i;

	if (!trans)
		return;
	for (i = 0; i < trans->nr_pt_gfns; i++) {
		struct pvm_rmap_bucket *bucket;
		struct pvm_rmap_dep *dep;
		gfn_t gfn = trans->pt_gfns[i];

		if (pvm_rmap_has_dep(entry, gfn))
			continue;
		bucket = pvm_rmap_find_bucket(rmap, gfn, gfn + 1);
		if (!bucket) {
			bucket = list_first_entry(&cache->buckets,
						  struct pvm_rmap_bucket, free);
			list_del(&bucket->free);
			cache->nr_buckets--;
			bucket->gfn = gfn;
			INIT_HLIST_HEAD(&bucket->deps);
			pvm_rmap_link_bucket(rmap, bucket);
		}
		if (entry->nr_deps < PVM_RMAP_INLINE_DEPS) {
			dep = &entry->inline_deps[entry->nr_deps];
		} else {
			dep = list_first_entry(&cache->deps, struct pvm_rmap_dep, leaf_link);
			list_del(&dep->leaf_link);
			cache->nr_deps--;
		}
		dep->entry = entry;
		dep->bucket = bucket;
		list_add(&dep->leaf_link, &entry->deps);
		hlist_add_head(&dep->bucket_link, &bucket->deps);
		entry->nr_deps++;
		rmap->edges++;
		ctx->reserved_deps--;
	}
}

static void pvm_rmap_link_gfn(struct kvm_pvm_rmap *rmap, struct pvm_rmap_entry *entry)
{
	struct rb_node **link = &rmap->gfns.rb_node, *parent = NULL;

	while (*link) {
		struct pvm_rmap_entry *cur;

		parent = *link;
		cur = rb_entry(parent, struct pvm_rmap_entry, gfn_node);
		if (entry->gfn < cur->gfn)
			link = &parent->rb_left;
		else
			link = &parent->rb_right;
	}
	rb_link_node(&entry->gfn_node, parent, link);
	rb_insert_color(&entry->gfn_node, &rmap->gfns);
}

static void pvm_rmap_link_va(struct kvm_s2_mmu *mmu, struct pvm_rmap_entry *entry)
{
	struct kvm_pvm_mmu_rmap *mrmap = kvm_pvm_mmu_rmap(mmu);
	struct rb_node **link = &mrmap->vas.rb_node, *parent = NULL;

	while (*link) {
		struct pvm_rmap_entry *cur;

		parent = *link;
		cur = rb_entry(parent, struct pvm_rmap_entry, va_node);
		if (entry->addr < cur->addr)
			link = &parent->rb_left;
		else
			link = &parent->rb_right;
	}
	rb_link_node(&entry->va_node, parent, link);
	rb_insert_color(&entry->va_node, &mrmap->vas);
}

static bool pvm_rmap_dep_is_inline(struct pvm_rmap_entry *entry,
				   struct pvm_rmap_dep *dep)
{
	unsigned long addr = (unsigned long)dep;

	return addr >= (unsigned long)entry->inline_deps &&
	       addr < (unsigned long)(entry->inline_deps + PVM_RMAP_INLINE_DEPS);
}

static void pvm_rmap_remove(struct pvm_rmap_entry *entry)
{
	struct kvm_pvm_rmap *rmap = pvm_rmap_from_mmu(entry->mmu);
	struct pvm_rmap_dep *dep, *next;

	list_for_each_entry_safe(dep, next, &entry->deps, leaf_link) {
		struct pvm_rmap_bucket *bucket = dep->bucket;

		list_del(&dep->leaf_link);
		hlist_del(&dep->bucket_link);
		if (hlist_empty(&bucket->deps)) {
			rb_erase(&bucket->node, &rmap->deps);
			kfree(bucket);
		}
		rmap->edges--;
		if (!pvm_rmap_dep_is_inline(entry, dep))
			kfree(dep);
	}
	rb_erase(&entry->gfn_node, &rmap->gfns);
	rb_erase(&entry->va_node, &kvm_pvm_mmu_rmap(entry->mmu)->vas);
	rmap->entries--;
	kfree(entry);
}

void kvm_pvm_rmap_purge(struct kvm_s2_mmu *mmu)
{
	struct kvm_pvm_mmu_rmap *mrmap = kvm_pvm_mmu_rmap(mmu);
	struct kvm_pvm_rmap *rmap = pvm_rmap_from_mmu(mmu);
	struct rb_node *node;

	lockdep_assert_held_write(&kvm_s2_mmu_to_kvm(mmu)->mmu_lock);
	spin_lock(&rmap->lock);
	while ((node = rb_first(&mrmap->vas)))
		pvm_rmap_remove(rb_entry(node, struct pvm_rmap_entry, va_node));
	spin_unlock(&rmap->lock);
}

int kvm_pvm_rmap_begin(struct kvm_s2_mmu *mmu, struct kvm_pvm_rmap_ctx *ctx,
		       const struct kvm_s1_trans *trans)
{
	struct kvm *kvm = kvm_s2_mmu_to_kvm(mmu);
	struct kvm_pvm *pvm = kvm_to_pvm(kvm);
	struct kvm_pvm_rmap *rmap = &pvm->rmap;
	struct kvm_pvm_mmu_rmap *mrmap = kvm_pvm_mmu_rmap(mmu);
	struct kvm_pvm_rmap_cache *cache = ctx->cache;
	struct pvm_rmap_entry *entry;
	unsigned int j, entries = 0, deps = 0;
	int ret = -EAGAIN;

	lockdep_assert_held(&kvm->mmu_lock);
	spin_lock(&mrmap->map_lock);
	spin_lock(&rmap->lock);
	if (kvm->mmu_invalidate_in_progress || pvm->invalidating ||
	    rmap->blocked || rmap->state != PVM_RMAP_COMPLETE)
		goto out;
	ret = -EINVAL;
	if ((ctx->addr & (PAGE_SIZE - 1)) ||
	    (trans && (!trans->nr_pt_gfns ||
		       trans->nr_pt_gfns > ARRAY_SIZE(trans->pt_gfns) ||
		       trans->nr_pt_gfns > PVM_RMAP_MAX_PT_GFNS)))
		goto out;

	entry = pvm_rmap_find_va(mmu, ctx->addr);
	if (!entry)
		entries++;
	if (trans) {
		for (j = 0; j < trans->nr_pt_gfns; j++) {
			unsigned int k;

			for (k = 0; k < j; k++)
				if (trans->pt_gfns[k] == trans->pt_gfns[j])
					break;
			if (k != j)
				continue;
			if (!entry || !pvm_rmap_has_dep(entry, trans->pt_gfns[j]))
				deps++;
		}
	}
	ret = -E2BIG;
	if (entry && entry->nr_deps + deps > PVM_RMAP_MAX_PT_GFNS)
		goto out;
	ret = -ENOMEM;
	if ((entries || deps) &&
	    (!cache || cache->nr_entries < entries || cache->nr_deps < deps ||
	     cache->nr_buckets < deps))
		goto out;
	ctx->reserved_entries = entries;
	ctx->reserved_deps = deps;
	mrmap->ctx = ctx;
	mrmap->trans = trans;
	/* Permission-only and -EAGAIN paths also contribute walk dependencies. */
	if (entry)
		pvm_rmap_add_deps(entry);
	spin_unlock(&rmap->lock);
	return 0;
out:
	spin_unlock(&rmap->lock);
	spin_unlock(&mrmap->map_lock);
	return ret;
}

void kvm_pvm_rmap_end(struct kvm_s2_mmu *mmu)
{
	struct kvm_pvm_mmu_rmap *mrmap = kvm_pvm_mmu_rmap(mmu);

	lockdep_assert_held(&mrmap->map_lock);
	mrmap->ctx = NULL;
	mrmap->trans = NULL;
	spin_unlock(&mrmap->map_lock);
}

void kvm_pvm_rmap_check(struct kvm_s2_mmu *mmu, u64 addr, gfn_t gfn)
{
	struct kvm_pvm_mmu_rmap *mrmap = kvm_pvm_mmu_rmap(mmu);
	struct kvm_pvm_rmap *rmap = pvm_rmap_from_mmu(mmu);
	struct pvm_rmap_entry *entry;

	lockdep_assert_held(&mrmap->map_lock);
	spin_lock(&rmap->lock);
	entry = pvm_rmap_find_va(mmu, addr & PAGE_MASK);
	if (!entry || entry->gfn != gfn)
		rmap->state = PVM_RMAP_UNTRUSTED;
	spin_unlock(&rmap->lock);
}

int kvm_pvm_rmap_map(struct kvm_s2_mmu *mmu, u64 addr, u64 size)
{
	struct kvm_pvm_mmu_rmap *mrmap = kvm_pvm_mmu_rmap(mmu);
	struct kvm_pvm_rmap *rmap = pvm_rmap_from_mmu(mmu);
	struct kvm_pvm_rmap_ctx *ctx = mrmap->ctx;
	struct pvm_rmap_entry *entry;
	struct kvm_pvm_rmap_cache *cache;
	gfn_t gfn;
	int ret = -EINVAL;

	addr &= PAGE_MASK;
	spin_lock(&rmap->lock);
	if (size != PAGE_SIZE || !ctx || rmap->state != PVM_RMAP_COMPLETE)
		goto untrusted;
	lockdep_assert_held(&mrmap->map_lock);
	cache = ctx->cache;
	if (addr != ctx->addr)
		goto untrusted;
	gfn = ctx->gfn;
	entry = pvm_rmap_find_va(mmu, addr);
	if (entry) {
		if (entry->gfn != gfn) {
			rb_erase(&entry->gfn_node, &rmap->gfns);
			entry->gfn = gfn;
			pvm_rmap_link_gfn(rmap, entry);
		}
		ret = 0;
		goto out;
	}
	if (WARN_ON_ONCE(!ctx->reserved_entries || !cache || !cache->nr_entries))
		goto untrusted;
	entry = list_first_entry(&cache->entries, struct pvm_rmap_entry, free);
	list_del(&entry->free);
	cache->nr_entries--;
	entry->mmu = mmu;
	entry->addr = addr;
	entry->gfn = gfn;
	INIT_LIST_HEAD(&entry->deps);
	entry->nr_deps = 0;
	pvm_rmap_add_deps(entry);
	pvm_rmap_link_va(mmu, entry);
	pvm_rmap_link_gfn(rmap, entry);
	rmap->entries++;
	ctx->reserved_entries--;
	ret = 0;
	goto out;
untrusted:
	rmap->state = PVM_RMAP_UNTRUSTED;
out:
	spin_unlock(&rmap->lock);
	return ret;
}

void kvm_pvm_rmap_unmap(struct kvm_s2_mmu *mmu, u64 addr, u64 size)
{
	struct kvm_pvm_rmap *rmap = pvm_rmap_from_mmu(mmu);
	struct pvm_rmap_entry *entry;

	lockdep_assert_held_write(&kvm_s2_mmu_to_kvm(mmu)->mmu_lock);
	spin_lock(&rmap->lock);
	entry = pvm_rmap_find_va(mmu, addr & PAGE_MASK);
	if ((size != PAGE_SIZE || !entry) &&
	    rmap->state == PVM_RMAP_COMPLETE)
		rmap->state = PVM_RMAP_UNTRUSTED;
	if (entry)
		pvm_rmap_remove(entry);
	spin_unlock(&rmap->lock);
}

void kvm_pvm_rmap_reclaim_leaf(struct kvm_s2_mmu *mmu, u64 addr)
{
	struct kvm *kvm = kvm_s2_mmu_to_kvm(mmu);
	struct kvm_pvm *pvm = kvm_to_pvm(kvm);
	int ret;

	lockdep_assert_held_write(&kvm->mmu_lock);
	addr &= PAGE_MASK;
	/* Another writer may already have removed the leaf. */
	if (!pvm_rmap_find_va(mmu, addr))
		return;
	pvm->rmap.blocked++;
	pvm->invalidate_seq++;
	ret = kvm_pgtable_stage2_unmap(mmu->pgt, addr, PAGE_SIZE);
	if (ret || pvm_rmap_find_va(mmu, addr) ||
	    pvm->rmap.state != PVM_RMAP_COMPLETE) {
		pvm->rmap.state = PVM_RMAP_UNTRUSTED;
		kvm_pvm_rmap_recover(kvm, true);
	}
	pvm->rmap.blocked--;
}

struct pvm_rmap_unmap_batch {
	struct kvm_pvm_unmap_page pages[KVM_PVM_UNMAP_BATCH_SIZE];
	struct kvm_pgtable_visit_ctx *scratch;
};

static unsigned int pvm_rmap_collect(struct kvm_pvm_rmap *rmap,
				     gfn_t start, gfn_t end,
				     struct pvm_rmap_unmap_batch *batch)
{
	struct pvm_rmap_entry *entry = pvm_rmap_find_gfn(rmap, start, end);
	struct pvm_rmap_bucket *bucket;
	struct rb_node *node;
	unsigned int nr = 0;

	for (node = entry ? &entry->gfn_node : NULL; node; node = rb_next(node)) {
		entry = rb_entry(node, struct pvm_rmap_entry, gfn_node);
		if (entry->gfn >= end)
			break;
		batch->pages[nr++] = (struct kvm_pvm_unmap_page) {
			.pgt = entry->mmu->pgt, .addr = entry->addr,
		};
		if (nr == KVM_PVM_UNMAP_BATCH_SIZE)
			return nr;
	}
	bucket = pvm_rmap_find_bucket(rmap, start, end);
	for (node = bucket ? &bucket->node : NULL; node; node = rb_next(node)) {
		struct pvm_rmap_dep *dep;

		bucket = rb_entry(node, struct pvm_rmap_bucket, node);
		if (bucket->gfn >= end)
			break;
		hlist_for_each_entry(dep, &bucket->deps, bucket_link) {
			unsigned int i;

			entry = dep->entry;
			for (i = 0; i < nr; i++)
				if (batch->pages[i].pgt == entry->mmu->pgt &&
				    batch->pages[i].addr == entry->addr)
					break;
			if (i != nr)
				continue;
			batch->pages[nr++] = (struct kvm_pvm_unmap_page) {
				.pgt = entry->mmu->pgt, .addr = entry->addr,
			};
			if (nr == KVM_PVM_UNMAP_BATCH_SIZE)
				return nr;
		}
	}
	return nr;
}

bool kvm_pvm_rmap_invalidate(struct kvm *kvm, gfn_t start, gfn_t end,
			     bool may_block)
{
	struct kvm_pvm *pvm = kvm_to_pvm(kvm);
	struct kvm_pvm_rmap *rmap = &pvm->rmap;
	struct pvm_rmap_unmap_batch *batch = NULL;
	bool success = false;

	lockdep_assert_held_write(&kvm->mmu_lock);
	if (start >= end)
		return true;
	pvm->invalidate_seq++;
	if (rmap->state != PVM_RMAP_COMPLETE)
		goto out;
	batch = kmalloc(sizeof(*batch), GFP_NOWAIT);
	if (batch) {
		batch->scratch = kmalloc_array(KVM_PVM_UNMAP_BATCH_SIZE,
					       sizeof(*batch->scratch), GFP_NOWAIT);
		if (!batch->scratch) {
			kfree(batch);
			batch = NULL;
		}
	}
	for (;;) {
		struct pvm_rmap_entry *entry;
		struct pvm_rmap_bucket *bucket;
		struct kvm_s2_mmu *mmu;
		u64 addr;
		int ret;

		if (batch) {
			unsigned int i, nr;

			nr = pvm_rmap_collect(rmap, start, end, batch);
			if (!nr)
				break;
			ret = kvm_pvm_unmap_shadow_pages(batch->pages, nr,
							 batch->scratch);
			for (i = 0; !ret && i < nr; i++)
				if (pvm_rmap_find_va(batch->pages[i].pgt->mmu,
						     batch->pages[i].addr))
					ret = -EINVAL;
			if (ret || rmap->state != PVM_RMAP_COMPLETE) {
				rmap->state = PVM_RMAP_UNTRUSTED;
				goto out;
			}
			if (may_block)
				cond_resched_rwlock_write(&kvm->mmu_lock);
			if (rmap->state != PVM_RMAP_COMPLETE)
				goto out;
			continue;
		}

		entry = pvm_rmap_find_gfn(rmap, start, end);
		if (!entry) {
			bucket = pvm_rmap_find_bucket(rmap, start, end);
			if (!bucket)
				break;
			entry = hlist_entry(bucket->deps.first, struct pvm_rmap_dep,
					    bucket_link)->entry;
		}
		mmu = entry->mmu;
		addr = entry->addr;
		/* The walker must revoke borrowed kernel roots before freeing tables. */
		ret = mmu->pgt ? kvm_pgtable_stage2_unmap(mmu->pgt, addr, PAGE_SIZE) :
				 -EINVAL;
		/* The helper can free entry and every associated dependency. */
		if (ret || pvm_rmap_find_va(mmu, addr) ||
		    rmap->state != PVM_RMAP_COMPLETE)
			rmap->state = PVM_RMAP_UNTRUSTED;
		if (rmap->state != PVM_RMAP_COMPLETE)
			goto out;
		if (may_block)
			cond_resched_rwlock_write(&kvm->mmu_lock);
		/* Re-query after every removal and after any MMU teardown. */
		if (rmap->state != PVM_RMAP_COMPLETE)
			goto out;
	}
	success = true;
out:
	if (batch)
		kfree(batch->scratch);
	kfree(batch);
	return success;
}
