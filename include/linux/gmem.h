/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Generalized Memory Management.
 *
 * Copyright (C) 2023- Huawei, Inc.
 * Author: Weixi Zhu
 *
 */
#ifndef _GMEM_H
#define _GMEM_H

#include <linux/mm.h>

typedef unsigned long gm_region_placement_t;
typedef unsigned long gm_prot_t;
typedef enum gm_ret gm_ret_t;
typedef struct gm_region gm_region_t;
typedef struct gm_mapping_set gm_mapping_set_t;
typedef enum gm_mmu_mode gm_mmu_mode_t;
typedef struct gm_mmu gm_mmu_t;
typedef unsigned long gm_dev_cap_t;
typedef struct gm_context gm_context_t;
typedef struct gm_dev gm_dev_t;
typedef struct gm_mapping gm_mapping_t;

struct hnode;

/*
 * enum gm_ret - The return value of GMEM KPI that can be used to tell
 * the core VM or peripheral driver whether the GMEM KPI was
 * executed successfully.
 *
 * @GM_RET_SUCCESS:	The invoked GMEM KPI behaved as expected.
 * @GM_RET_FAILURE_UNKNOWN:	The GMEM KPI failed with unknown reason.
 * Any external status related to this KPI invocation changes must be rolled back.
 */
enum gm_ret {
	GM_RET_SUCCESS = 0,
	GM_RET_NOMEM,
	GM_RET_PAGE_EXIST,
	GM_RET_DMA_ERROR,
	GM_RET_MIGRATING,
	GM_RET_FAILURE_UNKNOWN,
	GM_RET_UNIMPLEMENTED,
};

/*
 * Defines a contiguous range of virtual addresses inside a gm_as_t
 * As an analogy, this is conceptually similar as virtual_address_struct
 */
struct gm_region {
	gm_va_t start_va;
	gm_va_t end_va;
	struct rb_node node;
	gm_as_t *as; /* The address space that it belongs to */

	/* Do we need another list_node to maintain a tailQ of allocated VMAs inside a gm_as? */
	struct list_head mapping_set_link;

	void (*callback_op)(void *args);
	void *cb_args;
};

/* This holds a list of regions that must not be concurrently manipulated. */
struct gm_mapping_set {
	unsigned int region_cnt;
	struct list_head gm_region_list;
};

/**
 * enum gm_mmu_mode - defines the method to share a physical page table.
 *
 * @GM_MMU_MODE_SHARE: Literally share a physical page table with another
 * attached device's MMU. Nothing is guaranteed about the allocated address.
 * @GM_MMU_MODE_COHERENT_EXCLUSIVE: Maintain a coherent page table that holds
 * exclusive mapping entries, so that device memory accesses can trigger fault-driven
 * migration for automatic data locality optimizations.
 * @GM_MMU_MODE_REPLICATE: Maintain a coherent page table that replicates physical
 * mapping entries whenever a physical mapping is installed inside the address space, so
 * that it may minimize the page faults to be triggered by this device.
 */
enum gm_mmu_mode {
	GM_MMU_MODE_SHARE,
	GM_MMU_MODE_COHERENT_EXCLUSIVE,
	GM_MMU_MODE_REPLICATE,
};

/*
 * This is the parameter list of peer_map/unmap mmu operations.
 * if device should copy data to/from host, set copy and dma_addr
 */
struct gm_fault_t {
	struct mm_struct *mm;
	gm_dev_t *dev;
	gm_va_t va;
	gm_pa_t size;
	gm_prot_t prot;
	bool copy;
	dma_addr_t dma_addr;
	int behavior;
};

struct gm_memcpy_t {
	struct mm_struct *mm;
	gm_dev_t *dev;
	gm_va_t src;
	gm_va_t dest;
	dma_addr_t dma_addr;
	size_t size;
};

/**
 *
 * This struct defines a series of MMU functions registered by a peripheral
 * device that is to be invoked by GMEM.
 *
 * pmap is an opaque pointer that identifies a physical page table of a device.
 * A physical page table holds the physical mappings that can be interpreted by
 * the hardware MMU.
 */
struct gm_mmu {
	/*
	 * Each bit indicates a supported page size for page-based TLB.
	 * Currently we do not consider range TLBs.
	 */
	unsigned long pgsize_bitmap;

	/*
	 * cookie identifies the type of the MMU. If two gm_mmu shares the same cookie,
	 * then it means their page table formats are compatible.
	 * In that case, they can share the same void *pmap as the input arg.
	 */
	unsigned long cookie;

	/* Synchronize VMA in a peer OS to interact with the host OS */
	gm_ret_t (*peer_va_alloc_fixed)(struct gm_fault_t *gmf);
	gm_ret_t (*peer_va_free)(struct gm_fault_t *gmf);

	/* Create physical mappings on peer host.
	 * If copy is set, copy data [dma_addr, dma_addr + size] to peer host
	 */
	gm_ret_t (*peer_map)(struct gm_fault_t *gmf);
	/*
	 * Destroy physical mappings on peer host.
	 * If copy is set, copy data back to [dma_addr, dma_addr + size]
	 */
	gm_ret_t (*peer_unmap)(struct gm_fault_t *gmf);

	/* Create or destroy a device's physical page table. */
	gm_ret_t (*pmap_create)(gm_dev_t *dev, void **pmap);
	gm_ret_t (*pmap_destroy)(void *pmap);

	/* Create or destroy a physical mapping of a created physical page table */
	gm_ret_t (*pmap_enter)(void *pmap, gm_va_t va, gm_va_t size,
			     gm_pa_t pa, gm_prot_t prot);
	gm_ret_t (*pmap_release)(void *pmap, gm_va_t va, gm_va_t size);

	/* Change the protection of a virtual page */
	gm_ret_t (*pmap_protect)(void *pmap, gm_va_t va, gm_va_t size, gm_prot_t new_prot);

	/* Invalidation functions of the MMU TLB */
	gm_ret_t (*tlb_invl)(void *pmap, gm_va_t va, gm_va_t size);
	gm_ret_t (*tlb_invl_coalesced)(void *pmap, struct list_head *mappings);
};

/**
 * gm_dev_cap_t defines a composable flag to describe the capabilities of a device.
 *
 * @GM_DEV_CAP_REPLAYABLE: Memory accesses can be replayed to recover page faults.
 * @GM_DEV_CAP_PEER: The device has its own VMA/PA management, controlled by another peer OS
 */
#define GM_DEV_CAP_REPLAYABLE	0x00000001
#define GM_DEV_CAP_PEER		0x00000010

#define gm_dev_is_peer(dev) (((dev)->capability & GM_DEV_CAP_PEER) != 0)

struct gm_context {
	gm_as_t *as;
	gm_dev_t *dev;
	void *pmap;
	/*
	 * consider a better container to maintain multiple ctx inside a device or multiple ctx
	 * inside a va space.
	 * A device may simultaneously have multiple contexts for time-sliced ctx switching
	 */
	struct list_head gm_dev_link;

	/* A va space may have multiple gm_context */
	struct list_head gm_as_link;
};
#define get_gm_context(head) (list_entry((head)->prev, gm_context_t, ctx_link))

struct gm_dev {
	int id;

	/* identifies the device capability
	 * For example, whether the device supports page faults or whether it has its
	 * own OS that manages the VA and PA resources.
	 */
	gm_dev_cap_t capability;
	gm_mmu_t *mmu;
	void *dev_data;
	/*
	 * TODO: Use a better container of gm_context_t to support time-sliced context switch.
	 * A collection of device contexts. If the device does not support time-sliced context
	 * switch, then the size of the collection should never be greater than one.
	 * We need to think about what operators should the container be optimized for.
	 * A list, a radix-tree or what? What would gm_dev_activate require?
	 * Are there any accelerators that are really going to support time-sliced context switch?
	 */
	gm_context_t *current_ctx;

	struct list_head gm_ctx_list;

	/* Add tracking of registered device local physical memory. */
	nodemask_t registered_hnodes;
	struct device *dma_dev;

	gm_mapping_t *gm_mapping;
};

#define HOST_NODE_ID	(-1)

#define GM_PAGE_DIRTY	0x8 /* Whether the page is dirty */
#define GM_PAGE_CPU	0x10 /* Determines whether page is a pointer or a pfn number. */
#define GM_PAGE_DEVICE	0x20
#define GM_PAGE_NOMAP	0x40
#define GM_PAGE_PINNED	0x80
#define GM_PAGE_WILLNEED	0x100

#define GM_PAGE_TYPE_MASK	(GM_PAGE_CPU | GM_PAGE_DEVICE | GM_PAGE_NOMAP)

/* Records the status of a page-size physical page */
struct gm_mapping {
	/*
	 * The node index may have three definitions:
	 * 1. a common CPU node
	 * 2. a hetero-node, e.g. GPU (that not necessarily supports CC ld/st)
	 * 3. a network ip (another OS that may have multiple hNUMA nodes), dynamically attached by dsm_attach
	 * Among these definitions, #1 and #2 in combination defines an h-NUMA topology
	 */
	unsigned int node_id;

	unsigned int flag;

	union {
		struct page *page;	/* CPU node */
		gm_dev_t *dev;	/* hetero-node */
		gm_pa_t pfn;
	};

	struct mutex lock;
};

static inline bool gm_mapping_cpu(gm_mapping_t *gm_mapping)
{
	return !!(gm_mapping->flag & GM_PAGE_CPU);
}

static inline void set_gm_mapping_host(gm_mapping_t *gm_mapping, struct page *page)
{
	gm_mapping->node_id = HOST_NODE_ID;
	gm_mapping->flag &= ~GM_PAGE_TYPE_MASK;
	gm_mapping->flag |= GM_PAGE_CPU;
	gm_mapping->page = page;
}

static inline bool gm_mapping_device(gm_mapping_t *gm_mapping)
{
	return !!(gm_mapping->flag & GM_PAGE_DEVICE);
}

static inline void set_gm_mapping_device(gm_mapping_t *gm_mapping, gm_dev_t *dev)
{
	gm_mapping->flag &= ~GM_PAGE_TYPE_MASK;
	gm_mapping->flag |= GM_PAGE_DEVICE;
	gm_mapping->dev = dev;
}

static inline bool gm_mapping_nomap(gm_mapping_t *gm_mapping)
{
	return !!(gm_mapping->flag & GM_PAGE_NOMAP);
}

static inline void set_gm_mapping_nomap(gm_mapping_t *gm_mapping)
{
	gm_mapping->flag &= ~GM_PAGE_TYPE_MASK;
	gm_mapping->flag |= GM_PAGE_NOMAP;
	gm_mapping->page = NULL;
}

static inline void set_gm_mapping_willneed(gm_mapping_t *gm_mapping)
{
	gm_mapping->flag |= GM_PAGE_WILLNEED;
}

static inline void clear_gm_mapping_willneed(gm_mapping_t *gm_mapping)
{
	gm_mapping->flag &= ~GM_PAGE_WILLNEED;
}

static inline bool gm_mapping_willneed(gm_mapping_t *gm_mapping)
{
	return !!(gm_mapping->flag & GM_PAGE_WILLNEED);
}

static inline void set_gm_mapping_pinned(gm_mapping_t *gm_mapping)
{
	gm_mapping->flag |= GM_PAGE_PINNED;
}

static inline void clear_gm_mapping_pinned(gm_mapping_t *gm_mapping)
{
	gm_mapping->flag &= ~GM_PAGE_PINNED;
}

static inline bool gm_mapping_pinned(gm_mapping_t *gm_mapping)
{
	return !!(gm_mapping->flag & GM_PAGE_PINNED);
}

#define test_gm_mapping_mapped_on_node(i) { /* implement this */ }
#define set_gm_mapping_mapped_on_node(i) { /* implement this */ }
#define unset_gm_mapping_mapped_on_node(i) { /* implement this */ }

/* GMEM Device KPI */
extern gm_ret_t gm_dev_create(gm_mmu_t *mmu, void *dev_data, gm_dev_cap_t cap, gm_dev_t **new_dev);
extern gm_ret_t gm_dev_destroy(gm_dev_t *dev);
extern gm_ret_t gm_dev_switch(gm_dev_t *dev, gm_as_t *as);
extern gm_ret_t gm_dev_detach(gm_dev_t *dev, gm_as_t *as);
extern gm_ret_t gm_dev_register_physmem(gm_dev_t *dev, gm_pa_t begin, gm_pa_t end);
gm_ret_t gm_dev_fault(struct mm_struct *mm, gm_va_t addr, gm_dev_t *dev, int behavior);
vm_fault_t gm_host_fault_locked(struct vm_fault *vmf, enum page_entry_size pe_size);

/* GMEM address space KPI */
extern gm_ret_t gm_dev_register_physmem(gm_dev_t *dev, gm_pa_t begin, gm_pa_t end);
extern void gm_dev_unregister_physmem(gm_dev_t *dev, unsigned int nid);
extern gm_mapping_t *gm_mappings_alloc(unsigned int nid, unsigned int order);
extern void gm_mappings_free(gm_mapping_t *mapping, unsigned int order);
extern gm_ret_t gm_as_create(gm_va_t begin, gm_va_t end, gm_as_alloc_t policy, gm_va_t cache_quantum, gm_as_t **new_as);
extern gm_ret_t gm_as_destroy(gm_as_t *as);
extern gm_ret_t gm_as_attach(gm_as_t *as, gm_dev_t *dev, gm_mmu_mode_t mode, bool activate, gm_context_t **out_ctx);
extern gm_va_t gm_as_alloc(gm_as_t *as, gm_va_t hint, gm_va_t size, gm_va_t align, gm_va_t no_cross,
		gm_va_t max_va, gm_region_t **new_region);

extern int hmadvise_inner(int hnid, unsigned long start, size_t len_in, int behavior);

enum gmem_stat_item {
	NR_PAGE_MIGRATING,
	NR_GMEM_STAT_ITEMS
};

extern void gmem_state_counter(enum gmem_stat_item item, int val);
extern void gmem_state_counter_show(void);

/* h-NUMA topology */
struct hnode {
	unsigned int id;

	gm_dev_t *dev;

	struct xarray pages;
};

extern struct hnode *hnodes[];

static inline bool is_hnode(int node)
{
	return !node_isset(node, node_possible_map)
		&& node_isset(node, hnode_map);
}

static inline bool is_hnode_allowed(int node)
{
	return is_hnode(node) && node_isset(node, current->mems_allowed);
}

static inline struct hnode *get_hnode(unsigned int hnid)
{
	return hnodes[hnid];
}

void __init hnuma_init(void);
unsigned int alloc_hnode_id(void);
void free_hnode_id(unsigned int nid);
void hnode_init(struct hnode *hnode, unsigned int hnid, gm_dev_t *dev);
void hnode_deinit(unsigned int hnid, gm_dev_t *dev);

#endif /* _GMEM_H */
