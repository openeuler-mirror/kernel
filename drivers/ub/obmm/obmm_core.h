/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2025. All rights reserved.
 * Description：OBMM Framework's implementations.
 * Author:
 */

#ifndef OBMM_CORE_H
#define OBMM_CORE_H

#include <uapi/ub/obmm.h>
#include <linux/atomic.h>
#include <linux/device.h>
#include <linux/cdev.h>
#include <linux/printk.h>
#include <linux/mm_types.h>
#include <linux/nodemask.h>
#include <linux/refcount.h>
#include <linux/numa_remote.h>
#include <linux/scatterlist.h>

#define OBMM_DEV_NAME "obmm"

#ifdef pr_fmt
#undef pr_fmt
#endif
#define pr_fmt(fmt) "OBMM: " fmt

#define EID_BYTES 16
#define EID_FMT64 "%#llx:%#llx"
#define EID_ALIGNED_FMT64 "%#0*llx:%#0*llx"

#define EID_ARGS64_H(eid) (*(u64 *)&(eid)[8])
#define EID_ARGS64_L(eid) (*(u64 *)&(eid)[0])

extern size_t __obmm_memseg_size;
#define OBMM_MEMSEG_SIZE __obmm_memseg_size
/*
 * The maximum of {OBMM_MEMSEG_SIZE, PAGE_SIZE and CACHE_MAINTAIN_GRANU}.
 */
#define OBMM_BASIC_GRANU ((unsigned long)SZ_2M)

#define MAX_MEMINFO_COUNT MAX_IMPORT_COUNT

struct ubmem_resource;

enum obmm_region_type {
	OBMM_EXPORT_REGION,
	OBMM_IMPORT_REGION
};

enum obmm_mmap_mode {
	OBMM_MMAP_INIT,
	OBMM_MMAP_NORMAL,
	OBMM_MMAP_OSYNC
};

enum obmm_mmap_granu {
	OBMM_MMAP_GRANU_NONE,
	OBMM_MMAP_GRANU_PAGE,
	OBMM_MMAP_GRANU_PMD
};

#define OBMM_REGION_FLAG_NUMA_REMOTE		0x1
#define OBMM_REGION_FLAG_ALLOW_MMAP		0x2
#define OBMM_REGION_FLAG_MEMORY_FROM_USER	0x4
#define OBMM_REGION_FLAG_FAST_ALLOC		0x8
#define OBMM_REGION_FLAG_PREIMPORT		0x10

#define OBMM_INVALID_REGIONID	0
#define OBMM_MIN_VALID_REGIONID 1
#define OBMM_MAX_VALID_REGIONID MINORMASK
#define OBMM_REGIONID_MAX_COUNT (OBMM_MAX_VALID_REGIONID - OBMM_MIN_VALID_REGIONID + 1)

#define OBMM_MEM_ALLOW_CACHEABLE_MMAP 0x1
#define OBMM_MEM_ALLOW_NONCACHEABLE_MMAP 0x2

/* invalidate cache **on start-up** */
/* region models a set of memory to share across hosts: a unit of sharing. */
struct obmm_region {
	/* unique within host -- can be used as an access handle */
	int regionid;

	/* import or export */
	enum obmm_region_type type;

	unsigned long flags;

	struct cdev cdevice;
	struct device device;
	atomic_t device_released;

	refcount_t refcnt;

	/* the total size of all memory segments included in meminfo */
	u64 mem_size;
	/*
	 * current mapping mode.
	 * init: mmap_mode = OBMM_MMAP_INIT
	 * cc-mmap: mmap_mode = OBMM_MMAP_NORMAL
	 * nc-mmap: mmap_mode = OBMM_MMAP_OSYNC
	 */
	enum obmm_mmap_mode mmap_mode;
	/*
	 * the granularity of memory mapping, initially OBMM_MMAP_GRANU_NONE.
	 * When users call mmap, the mmap granularity is determined based on
	 * the mmap flags and OBMM_REGION_FLAG_ALLOW_MMAP.
	 */
	enum obmm_mmap_granu mmap_granu;
	/*
	 * Determines what mode the memory can be mapped with.
	 * OBMM_MEM_ALLOW_CACHEABLE_MMAP: Supports cacheable mapping
	 * OBMM_MEM_ALLOW_NONCACHEABLE_MMAP: Supports non-cacheable mapping
	 */
	unsigned long mem_cap;
	/* number of mmap (atomic to avoid deadlock in vma_open during split) */
	atomic_t mmap_count;

	struct obmm_ownership_info *ownership_info;
	/* protect ownership_info and serialize concurrent page table change requests */
	struct mutex state_mutex;

	/* regions are chained into a list for management */
	struct list_head node;

	unsigned int priv_len;
	unsigned char priv[OBMM_MAX_PRIV_LEN];
};

static inline bool region_numa_remote(const struct obmm_region *reg)
{
	return reg->flags & OBMM_REGION_FLAG_NUMA_REMOTE;
}
static inline bool region_allow_mmap(const struct obmm_region *reg)
{
	return reg->flags & OBMM_REGION_FLAG_ALLOW_MMAP;
}
static inline bool region_memory_from_user(const struct obmm_region *reg)
{
	return reg->flags & OBMM_REGION_FLAG_MEMORY_FROM_USER;
}
static inline bool region_preimport(const struct obmm_region *reg)
{
	return reg->flags & OBMM_REGION_FLAG_PREIMPORT;
}
static inline bool region_fast_alloc(const struct obmm_region *reg)
{
	return reg->flags & OBMM_REGION_FLAG_FAST_ALLOC;
}

struct obmm_import_region {
	struct obmm_region region;

	u32 dcna;
	u32 scna;

	/* resource of the PA range */
	struct ubmem_resource *ubmem_res;
	/* the resource for this region */
	struct resource *memdev_res;
	u64 pa;

	/* imported NUMA node */
	int numa_id;
	/* the base_dist passed in import, which in some scenario might be an ignored value. It is
	 * stored here make error rollback feasible.
	 */
	u8 base_dist;

	/* handle to manage associated preimport range */
	void *preimport_handle;
	u8 deid[16];
	u8 seid[16];
};

struct mem_description_pid {
	int pid;
	void __user *user_va;
	int pinned;
	u64 start_time;
};
struct mem_description_pool {
	struct list_head head[OBMM_MAX_LOCAL_NUMA_NODES];
};

struct obmm_export_region {
	struct obmm_region region;

	/* export region may use physical memory from NUMA node[0] to node[node_count-1] */
	unsigned int node_count;
	uint64_t node_mem_size[OBMM_MAX_LOCAL_NUMA_NODES];

	/* physical pages */
	union {
		struct mem_description_pid mem_desc_pid;
		struct mem_description_pool mem_desc;
	};

	/* DMA mapping */
	struct sg_table sgt;

	/* UMMU device for the tokenid */
	struct device *ummu_dev;
	/* UMMU RAS event notifier */
	struct ummu_event_block *ummu_event_block;

	unsigned int tokenid;
	u64 uba;
	unsigned int vendor_len;
	void *vendor_info;
	int affinity;
	u8 deid[16];
};

struct obmm_datapath {
	u32 scna;
	u32 dcna;
	const u8 *seid;
	const u8 *deid;
};

struct obmm_ctx_info {
	/* active */
	struct list_head regions;
	spinlock_t lock;
};

void activate_obmm_region(struct obmm_region *region);
struct obmm_region *try_get_obmm_region(struct obmm_region *region);
/* Return a valid pointer or a NULL pointer. */
struct obmm_region *search_get_obmm_region(int regionid);
/* Return a valid pointer or an error pointer, which will never be null. */
struct obmm_region *search_deactivate_obmm_region(int regionid);
void put_obmm_region(struct obmm_region *region);

void obmm_region_flush(struct obmm_region *reg, unsigned long cache_ops);

/* Extended information of a byte address */
struct obmm_ext_addr {
	/* OBMM related */
	enum obmm_region_type region_type;
	u32 regionid;
	u64 offset;

	/* UB bus related */
	u32 tid;
	u64 uba;

	/* host machine related */
	s32 numa_id;
	u64 pa;
};

/*
 * Get the extended OBMM information from a PA
 *
 * @pa: physical address to query
 * @filter: the type of regions to check against
 * @ext_addr: (output) the extended information related to the @pa
 *
 * Return 0 on success, negative value on failure (region not found).
 */
int obmm_query_by_pa(unsigned long pa, struct obmm_ext_addr *ext_addr);
/*
 * Get the extended OBMM address information of a region by offset
 *
 * @region: the region to query about; refcount must held before calling this
 *          function
 * @offset: the offset within the region (UBA offset)
 * @ext_addr: (output) the extended information related to @region and @offset
 *
 * Return 0 on success, negative value on failure (region not found).
 */
int obmm_query_by_offset(struct obmm_region *reg, unsigned long offset,
			 struct obmm_ext_addr *ext_addr);

bool nodes_on_same_package(const nodemask_t *nodes);

/* return true if scna is a registered primary CNA of a bus controller. */
bool validate_scna(u32 scna);
/* return true if the @mem_id is within valid range. It does not guarantee that the @mem_id is
 * associated with a present region. Use search_get_obmm_region if one wants to make sure that the
 * @mem_id is backed by an actual memdev.
 */
bool validate_obmm_mem_id(__u64 mem_id);

/* internal helpers */
static inline bool is_online_local_node(int node)
{
	return node_online(node) && !numa_is_remote_node(node);
}
static inline int __maybe_unused next_online_local_node(int node)
{
	do {
		node = (int)next_node(node, node_online_map);
	} while (node < MAX_NUMNODES && numa_is_remote_node(node));
	return node;
}
static inline int __maybe_unused first_online_local_node(void)
{
	int node = (int)first_node(node_online_map);

	while (node < MAX_NUMNODES && numa_is_remote_node(node))
		node = (int)next_node(node, node_online_map);
	return node;
}
#define for_each_online_local_node(node)                                \
	for ((node) = first_online_local_node(); (node) < MAX_NUMNODES; \
	     (node) = next_online_local_node(node))

int set_obmm_region_priv(struct obmm_region *region, unsigned int priv_len,
			 const void __user *priv);

int init_obmm_region(struct obmm_region *region);
void uninit_obmm_region(struct obmm_region *region);

int register_obmm_region(struct obmm_region *region);
void deregister_obmm_region(struct obmm_region *region);

#endif
