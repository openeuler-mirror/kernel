/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2026. All rights reserved.
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
#include <linux/rwsem.h>
#include <linux/seqlock.h>
#include <linux/rcupdate.h>
#include <linux/scatterlist.h>
#include <linux/wait.h>
#include <linux/workqueue.h>

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
struct resource;
struct obmm_backend;
struct attribute_group;

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
#define OBMM_REGION_FLAG_PREIMPORT		0x10

#define OBMM_INVALID_REGIONID	0
#define OBMM_MIN_VALID_REGIONID 1
#define OBMM_MAX_VALID_REGIONID MINORMASK
#define OBMM_REGIONID_MAX_COUNT (OBMM_MAX_VALID_REGIONID - OBMM_MIN_VALID_REGIONID + 1)

#include "obmm_switch_logic.h"

/*
 * region models a set of memory to share across hosts: a unit of sharing.
 * Backend-independent shell over the attached struct obmm_backend.
 */
struct obmm_region {
	/* unique within host -- can be used as an access handle */
	int regionid;

	/* how it was created (import or export ioctl); reg->backend->type is
	 * authoritative, a switch may attach a backend of the other kind;
	 * teardown accepts either identity (obmm_region_teardown_matches()).
	 */
	enum obmm_region_type created_as;

	unsigned long flags;

	struct cdev cdevice;
	struct device device;
	/* identity sysfs group (import_info/ or export_info/) tracks backend */
	const struct attribute_group *sysfs_identity_group;

	refcount_t refcnt;
	/* OR of attached backends' mem_cap while entitled fds could exist:
	 * the open-time entitlement gate, deflated at the shrink points.
	 */
	u32 promised_cap;

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
	/* number of mmap (atomic to avoid deadlock in vma_open during split) */
	atomic_t mmap_count;
	/* open fds holding cacheability entitlements */
	atomic_t fd_count;

	/* MEMID_{regionid} iomem leaf of the CURRENT import backend;
	 * attach/detach-managed (obmm_backend.c); NULL for export backends.
	 */
	struct resource *memdev_res;

	/* current backend: written under state_mutex; read under state_mutex,
	 * the fault gate's switch_lock(read) or rcu_read_lock (lockless sysfs
	 * views), and unlocked at region free; RCU-published on swap and freed
	 * only after a grace period; NULL while detached, dispatch sites
	 * NULL-guard it.
	 */
	struct obmm_backend __rcu *backend;

	/* old backend held across a switch gap: detach keeps its existence
	 * reference so a keep-old-alive abort can restore it. state_mutex +
	 * switch_lock(write).
	 */
	struct obmm_backend *switch_old;

	/* Cross-process zap channel: the first open caches the device node's
	 * address_space and igrabs its inode so unmap_mapping_range() outlives
	 * unlink; iput in uninit_obmm_region(). Kept ahead of switch_lock so
	 * the rwsem's count and owner share a cacheline with each other and
	 * not with the hot refcount/mmap counters.
	 */
	struct address_space *i_mapping;
	struct inode *i_inode;

	/* switch machinery: switch_state is written under switch_lock(write)
	 * except the teardown force-strand's lock-free STRANDED publish, and is
	 * read with READ_ONCE; the rwsem serializes the fault gate against
	 * begin/finisher swaps, switch_wqh is its wait channel, switch_work is
	 * the finisher armed by switch_end. No timeout.
	 */
	struct rw_semaphore switch_lock;
	enum obmm_switch_state switch_state;
	/* gap generation, bumped by every begin under state_mutex +
	 * switch_lock(write): a gap-scoped VMA is served only in the
	 * generation its mmap tagged it with (vm_private_data).
	 */
	u32 switch_generation;
	wait_queue_head_t switch_wqh;
	struct work_struct switch_work;
	bool switch_finish_success;
	bool switch_keep_old_alive;
	bool switch_old_mapped;
	bool switch_new_mapped;
	int switch_flush_result;

	struct obmm_ownership_info *ownership_info;
	/* protect ownership_info and serialize concurrent page table change requests */
	struct mutex state_mutex;

	/* regions are chained into a list for management */
	struct list_head node;

	/* staged priv: committed by the finisher's success branch, else lost */
	unsigned int switch_pending_priv_len;
	unsigned char switch_pending_priv[OBMM_MAX_PRIV_LEN];

	unsigned int priv_len;
	/* sequences priv against the finisher's commit for the lockless sysfs
	 * views; writers hold state_mutex
	 */
	seqcount_t priv_seq;
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
/* A switch in flight: identity/typed views and query ioctls answer -EAGAIN. */
static inline bool region_switch_in_flight(const struct obmm_region *reg)
{
	return obmm_switch_state_transitional(READ_ONCE(reg->switch_state));
}

/* per-node memseg lists of an export-pool backend (obmm_backend.h) */
struct mem_description_pool {
	struct list_head head[OBMM_MAX_LOCAL_NUMA_NODES];
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

/* Called under state_mutex: with no entitled fds and no mappings the
 * promise deflates to the attached backend's own capability.
 */
void obmm_promised_cap_shrink_maybe(struct obmm_region *region);

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
	return node < OBMM_MAX_LOCAL_NUMA_NODES &&
	       node_online(node) && !numa_is_remote_node(node);
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

#define for_each_online_local_node(node)                                        \
	for ((node) = first_online_local_node(); (node) < OBMM_MAX_LOCAL_NUMA_NODES; \
	     (node) = next_online_local_node(node))

int set_obmm_region_priv(struct obmm_region *region, unsigned int priv_len,
			 const void __user *priv);

int init_obmm_region(struct obmm_region *region);
void uninit_obmm_region(struct obmm_region *region);

int register_obmm_region(struct obmm_region *region);
void deregister_obmm_region(struct obmm_region *region);

/* shared shell teardown for unimport/unexport: deregister, uninit, free */
int obmm_region_teardown(struct obmm_region *region);

/* creation identity or live-backend kind, either accepts the teardown */
bool obmm_region_teardown_matches(struct obmm_region *region,
				  enum obmm_region_type kind);

#endif
