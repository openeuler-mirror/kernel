/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2026 Huawei Technologies Co., Ltd.
 * Author: Kunkun Jiang <jiangkunkun@huawei.com>
 */

#ifndef __ARM64_KVM_PVM_RMAP_H__
#define __ARM64_KVM_PVM_RMAP_H__

#include <linux/kvm_types.h>
#include <linux/rbtree.h>
#include <linux/spinlock.h>

struct kvm;
struct kvm_s2_mmu;
struct kvm_s1_trans;
struct kvm_pvm_rmap_cache;
struct kvm_pvm_rmap_ctx;

enum kvm_pvm_rmap_state {
	PVM_RMAP_COMPLETE,
	PVM_RMAP_UNTRUSTED,
	PVM_RMAP_RECOVERING,
};

/* mmu_lock -> map_lock -> VM rmap lock. */
struct kvm_pvm_mmu_rmap {
	/* Serialize a root's leaf publication and its ctx/trans pointers. */
	spinlock_t map_lock;
	struct rb_root vas;
	struct kvm_pvm_rmap_ctx *ctx;
	const struct kvm_s1_trans *trans;
};

/* Shared by the identity root and both shadow MMU pools of one PVM VM. */
struct kvm_pvm_rmap {
	/* Protect both VM indices and their counts under mmu_lock. */
	spinlock_t lock;
	struct rb_root gfns;
	struct rb_root deps;
	unsigned long entries;
	unsigned long edges;
	unsigned int blocked;
	enum kvm_pvm_rmap_state state;
};

/* Valid only during a serialized map transaction under mmu_lock. */
struct kvm_pvm_rmap_ctx {
	u64 addr;
	gfn_t gfn;
	struct kvm_pvm_rmap_cache *cache;
	unsigned int reserved_entries;
	unsigned int reserved_deps;
};

/* PVM MMUs only; mmu->arch must already identify the owning VM. */
struct kvm_pvm_mmu_rmap *kvm_pvm_mmu_rmap(struct kvm_s2_mmu *mmu);
void kvm_pvm_rmap_mmu_init(struct kvm_s2_mmu *mmu);
/* Initialize the empty VM indices and its identity root exactly once. */
void kvm_pvm_rmap_init(struct kvm *kvm);
void kvm_pvm_rmap_destroy(struct kvm *kvm);
void kvm_pvm_rmap_purge(struct kvm_s2_mmu *mmu);
int kvm_pvm_rmap_topup(struct kvm_pvm_rmap_cache **cache, unsigned int nr);
void kvm_pvm_rmap_free_cache(struct kvm_pvm_rmap_cache *cache);
/* The shadow address must be page-aligned. */
int kvm_pvm_rmap_begin(struct kvm_s2_mmu *mmu,
		       struct kvm_pvm_rmap_ctx *ctx,
		       const struct kvm_s1_trans *trans);
void kvm_pvm_rmap_end(struct kvm_s2_mmu *mmu);
void kvm_pvm_rmap_check(struct kvm_s2_mmu *mmu, u64 addr, gfn_t gfn);
int kvm_pvm_rmap_map(struct kvm_s2_mmu *mmu, u64 addr, u64 size);
void kvm_pvm_rmap_unmap(struct kvm_s2_mmu *mmu, u64 addr, u64 size);
/* Write-locked caller must block publication across any rescheduling. */
bool kvm_pvm_rmap_invalidate(struct kvm *kvm, gfn_t start, gfn_t end,
			     bool may_block);
bool kvm_pvm_rmap_recover(struct kvm *kvm, bool may_block);
void kvm_pvm_rmap_reclaim_leaf(struct kvm_s2_mmu *mmu, u64 addr);

#endif /* __ARM64_KVM_PVM_RMAP_H__ */
