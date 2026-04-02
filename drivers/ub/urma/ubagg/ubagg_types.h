/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 *
 * Description: ubagg kernel module
 * Author: Weicheng Zhang
 * Create: 2025-8-6
 * Note:
 * History: 2025-8-6: Create file
 */

#ifndef UBAGG_TYPE_H
#define UBAGG_TYPE_H

#include <linux/types.h>
#include <ub/urma/ubcore_types.h>

#define UBAGG_DEV_MAX_NUM (20)
#define UBAGG_BITMAP_SIZE (10240)
#define UBAGG_MAX_DEV_NAME_LEN (64)
#define UBAGG_MAX_DEV_NUM (20)
#define UBAGG_MAX_PORT_NUM (9)
#define ubagg_container_of(ptr, type, member) \
	(((ptr) == NULL) ? NULL : container_of(ptr, type, member))

enum ubagg_ht_param_num {
	UBAGG_HT_SEGMENT_HT,
	UBAGG_HT_JETTY_HT,
	UBAGG_HT_JFR_HT,
	UBAGG_HT_MAX,
};

struct ubagg_ht_param {
	uint32_t size;
	uint32_t node_offset; /* offset of hlist node in the hash table object */
	uint32_t key_offset;
	uint32_t key_size;
};

struct ubagg_hash_table {
	struct hlist_head *head;
	struct ubagg_ht_param p;
	spinlock_t lock;
	struct kref kref;
};

struct ubagg_ubva {
	union ubcore_eid eid;
	uint32_t uasid;
	uint64_t va;
} __packed;

struct ubagg_seg_info {
	struct ubagg_ubva ubva;
	uint64_t len;
	union ubcore_seg_attr attr;
	uint32_t token_id;
};

// must be consistent with urma_bond_seg_info_out_t
struct ubagg_seg_exchange_info {
	struct ubagg_seg_info base;
	struct ubagg_seg_info slaves[UBAGG_DEV_MAX_NUM];
	int dev_num;
};

struct ubagg_seg_hash_node {
	// ubagg_seg must be first!
	struct ubcore_target_seg ubagg_seg;
	// unaccessable for ubcore
	uint32_t token_id; // key
	struct ubagg_seg_exchange_info ex_info;
	struct hlist_node hnode;
};

struct ubagg_jetty_id {
	union ubcore_eid eid;
	uint32_t uasid;
	uint32_t id;
};

struct ubagg_jetty_exchange_info {
	struct ubagg_jetty_id slaves[UBAGG_DEV_MAX_NUM];
	int dev_num;
	bool is_multipath;
	bool is_health_check_enable;
	struct ubagg_seg_exchange_info health_check_seg;
};

struct ubagg_jetty_hash_node {
	// base must be first!
	struct ubcore_jetty base;
	// unaccessable for ubcore
	uint32_t token_id; // key
	struct ubagg_jetty_exchange_info ex_info;
	struct hlist_node hnode;
};

struct ubagg_jfr_hash_node {
	// base must be first!
	struct ubcore_jfr base;
	// unaccessable for ubcore
	uint32_t token_id; // key
	struct ubagg_jetty_exchange_info ex_info;
	struct hlist_node hnode;
};

struct ubagg_jfc {
	struct ubcore_jfc base;
};

struct ubagg_jfs {
	struct ubcore_jfs base;
};

struct ubagg_physical_device {
	char dev_name[UBCORE_MAX_DEV_NAME];
	uint32_t chip_id;
	uint32_t primary_eid_idx;
	uint32_t port_eid_idx[UBAGG_MAX_PORT_NUM];
};

struct ubagg_device {
	struct ubcore_device ub_dev;
	char master_dev_name[UBAGG_MAX_DEV_NAME_LEN];
	int slave_dev_num;
	char slave_dev_name[UBAGG_MAX_DEV_NUM][UBAGG_MAX_DEV_NAME_LEN];
	struct ubagg_hash_table ubagg_ht[UBAGG_HT_MAX];
	struct ubagg_bitmap *segment_bitmap;
	struct ubagg_bitmap *jfs_bitmap;
	struct ubagg_bitmap *jfr_bitmap;
	struct ubagg_bitmap *jfc_bitmap;
	struct ubagg_bitmap *jetty_bitmap;
	struct list_head list_node;
	struct kref ref;
};

static inline struct ubagg_device *
to_ubagg_dev(const struct ubcore_device *ub_dev)
{
	return (struct ubagg_device *)ubagg_container_of(
		ub_dev, struct ubagg_device, ub_dev);
}

#endif // UBAGG_TYPE_H
