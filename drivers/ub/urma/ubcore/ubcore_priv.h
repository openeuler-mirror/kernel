/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2025. All rights reserved.
 *
 * Description: ubcore's private data structure and function declarations
 * Author: Qian Guoxin
 * Create: 2022-7-22
 * Note:
 * History: 2022-7-22: Create file
 */

#ifndef UBCORE_PRIV_H
#define UBCORE_PRIV_H

#include <linux/jhash.h>
#include <linux/types.h>
#include <ub/urma/ubcore_types.h>
#include "ubcore_tp.h"

#define UBCORE_MAX_UVS_NAME_LEN 64
#define UBCORE_MAX_UVS_CNT 64
#define UBCORE_MAX_MUE_NUM 16
/* between 1 and MAX_ERRNO */
#define UBCORE_DRV_ERRNO 2048

/*
 * Pure UB device, netdev type is Unified Bus (UB).
 * On the Internet Assigned Numbers Authority, add Hardware Types: Unified Bus (UB)
 */
#define UBCORE_NETDEV_UB_TYPE (38) /* Unified Bus(UB) */
#define UCBORE_INVALID_UPI 0xffffffff
#define UBCORE_TYPICAL_TIMEOUT 30000 /* 30s */
#define UBCORE_DESTROY_TIMEOUT 2000 /* 2s */
#define UCBORE_DEFAULT_UPI 0

enum ubcore_uvs_state {
	UBCORE_UVS_STATE_DEAD = 0,
	UBCORE_UVS_STATE_ALIVE,
};

enum ubcore_restore_policy {
	UBCORE_RESTORE_POLICY_KEEP = 0,
	UBCORE_RESTORE_POLICY_CLEANUP,
	UBCORE_RESTORE_POLICY_MAX,
};

struct sip_idx_node {
	struct list_head node;
	uint32_t sip_idx;
	struct ubcore_sip_info *sip_info;
};

struct ubcore_uvs_instance {
	struct list_head list_node;
	struct kref ref;

	char name[UBCORE_MAX_UVS_NAME_LEN]; /* name to identify UVS */
	enum ubcore_uvs_state state;
	uint32_t id;
	uint32_t policy;

	uint32_t genl_port; /* uvs genl port */
	struct sock *genl_sock;
	uint32_t pid;
	atomic_t map2ue;
	atomic_t nl_wait_buffer;
	spinlock_t sip_list_lock;
	struct list_head sip_list;
};

struct ubcore_ue_entry {
	struct ubcore_uvs_instance *uvs_inst;
	DECLARE_BITMAP(eid_bitmap, UBCORE_MAX_EID_CNT);
};

struct ubcore_ue_table {
	char mue_name[UBCORE_MAX_DEV_NAME];
	struct ubcore_ue_entry ue_entries[UBCORE_MAX_UE_CNT];
	spinlock_t ue2uvs_lock;
};

struct ubcore_mue_file {
	struct kref ref;
	atomic_t driver_get;
	char mue_name[UBCORE_MAX_DEV_NAME];
};

struct ubcore_global_file {
	struct kref ref;
	struct ubcore_uvs_instance *uvs;
};

static inline struct ubcore_ucontext *
ubcore_get_uctx(struct ubcore_udata *udata)
{
	return udata == NULL ? NULL : udata->uctx;
}

static inline bool
ubcore_check_trans_mode_valid(enum ubcore_transport_mode trans_mode)
{
	return trans_mode == UBCORE_TP_RM || trans_mode == UBCORE_TP_RC ||
	       trans_mode == UBCORE_TP_UM;
}

/* combine order_type and share_tp -> uint16_t? */
static inline bool is_create_rc_shared_tp(enum ubcore_transport_mode trans_mode,
					  uint32_t order_type,
					  uint32_t share_tp)
{
	if (trans_mode == UBCORE_TP_RC && order_type == UBCORE_OT &&
	    share_tp == 1)
		return true;

	return false;
}

/* Caller must put device */
struct ubcore_device *ubcore_find_device(union ubcore_eid *eid,
					 enum ubcore_transport_type type);
struct ubcore_device *ubcore_find_device_with_name(const char *dev_name);
bool ubcore_check_dev_is_exist(const char *dev_name);
void ubcore_get_device(struct ubcore_device *dev);
void ubcore_put_device(struct ubcore_device *dev);
struct ubcore_device *
ubcore_find_mue_device(union ubcore_net_addr_union *netaddr,
		       enum ubcore_transport_type type);
struct ubcore_device *ubcore_find_mue_by_dev(struct ubcore_device *dev);
struct ubcore_device *ubcore_find_mue_device_by_name(char *dev_name);
/* returned list should be freed by caller */
struct ubcore_device **
ubcore_get_all_mue_device(enum ubcore_transport_type type, uint32_t *dev_cnt);

int ubcore_update_eidtbl_by_idx(struct ubcore_device *dev,
				union ubcore_eid *eid, uint32_t eid_idx,
				bool is_alloc_eid, struct net *net);
int ubcore_update_eidtbl_by_eid(struct ubcore_device *dev,
				union ubcore_eid *eid, uint32_t *eid_idx,
				bool is_alloc_eid, struct net *net);

int ubcore_find_upi_with_dev_name(const char *dev_name, uint32_t *upi);
int ubcore_add_upi_list(struct ubcore_device *dev, uint32_t upi);

/* Must call ubcore_put_devices to put and release the returned devices */
struct ubcore_device **ubcore_get_devices_from_netdev(struct net_device *netdev,
						      uint32_t *cnt);
void ubcore_put_devices(struct ubcore_device **devices, uint32_t cnt);
void ubcore_update_netdev_addr(struct ubcore_device *dev,
			       struct net_device *netdev,
			       enum ubcore_net_addr_op op, bool async);
void ubcore_update_netaddr(struct ubcore_device *dev, struct net_device *netdev,
			   bool add);
int ubcore_fill_netaddr_macvlan(struct ubcore_net_addr *netaddr,
				struct net_device *netdev,
				enum ubcore_net_addr_type type);

void ubcore_set_tp_init_cfg(struct ubcore_tp *tp, struct ubcore_tp_cfg *cfg);
struct ubcore_tp *ubcore_create_tp(struct ubcore_device *dev,
				   struct ubcore_tp_cfg *cfg,
				   struct ubcore_udata *udata);

void ubcore_update_all_vlan_netaddr(struct ubcore_device *dev,
				    enum ubcore_net_addr_op op);

static inline uint32_t ubcore_get_jetty_hash(struct ubcore_jetty_id *jetty_id)
{
	return jhash(jetty_id, sizeof(struct ubcore_jetty_id), 0);
}

static inline uint32_t ubcore_get_tseg_hash(struct ubcore_ubva *ubva)
{
	return jhash(ubva, sizeof(struct ubcore_ubva), 0);
}

static inline uint32_t ubcore_get_eid_hash(union ubcore_eid *eid)
{
	return jhash(eid, sizeof(union ubcore_eid), 0);
}

static inline uint32_t ubcore_get_vtp_hash(union ubcore_eid *local_eid)
{
	return jhash(local_eid,
		     sizeof(union ubcore_eid) + sizeof(union ubcore_eid), 0);
}

static inline uint32_t ubcore_get_rc_vtp_hash(union ubcore_eid *peer_eid)
{
	return jhash(peer_eid, sizeof(union ubcore_eid) + sizeof(uint32_t), 0);
}

static inline uint32_t ubcore_get_vtpn_hash(struct ubcore_hash_table *ht,
					    void *key_addr)
{
	return jhash(key_addr, ht->p.key_size, 0);
}

static inline uint32_t ubcore_get_ex_tp_hash(uint64_t *tp_handle)
{
	return jhash(tp_handle, sizeof(uint64_t), 0);
}

static inline bool ubcore_is_ub_device(struct ubcore_device *dev)
{
	return (dev->transport_type == UBCORE_TRANSPORT_UB);
}

#endif
