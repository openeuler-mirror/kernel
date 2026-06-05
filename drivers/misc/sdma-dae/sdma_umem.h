/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef __HISI_SDMA_UMEM_H__
#define __HISI_SDMA_UMEM_H__

#include <linux/hashtable.h>
#include <linux/pagemap.h>
#include <linux/slab.h>
#include "sdma_hal.h"

#define HISI_SDMA_HASH_BUCKETS_BITS	3
#define COOKIE_IDA_SHIFT		32
#define COOKIE_IDA_MASK			0xffffffff

struct page_node {
	struct page **page_list;
	int pinned;
};

struct p_list {
	struct page_node pnode;
	struct list_head list;
};

struct hisi_sdma_ht {
	DECLARE_HASHTABLE(sdma_fd_ht, HISI_SDMA_HASH_BUCKETS_BITS);
	spinlock_t hash_lock;
};

struct pin_mem {
	int idr;
	u64 addr;
	struct list_head *list_head;
};

struct hash_entry {
	int ida;
	struct hlist_node node;
	struct idr pin_mem_region;
};

/* sdma_umem_get - Pin userspace memory.
 *
 * @addr: userspace virtual address to start at
 * @size: length of region to pin
 * @ida: identifies the file descriptor and is also the key to the hash table
 * @cookie: identity for pinned memory
 */
int sdma_umem_get(u64 addr, u32 size, int ida, u64 *cookie);

/* sdma_umem_release - release userspace memory.
 *
 * @cookie: identity for pinned memory
 */
int sdma_umem_release(u64 cookie);

int sdma_hash_init(void);

void sdma_hash_free(void);

void sdma_hash_free_entry(int key);

#endif
