/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
 * for more details.
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
#include <urma/ubcore_types.h>
#include "ubcore_tp.h"

/*
 * Pure UB device, netdev type is Unified Bus (UB).
 * On the Internet Assigned Numbers Authority, add Hardware Types: Unified Bus (UB)
 */
#define UBCORE_NETDEV_UB_TYPE (38) /* Unified Bus(UB) */
#define UCBORE_INVALID_UPI 0xffffffff
#define UBCORE_TIMEOUT 30000 /* 30s */

union ubcore_set_global_cfg_mask {
	struct {
		uint32_t suspend_period : 1;
		uint32_t suspend_cnt    : 1;
		uint32_t reserved       : 30;
	} bs;
	uint32_t value;
};

struct ubcore_set_global_cfg {
	union ubcore_set_global_cfg_mask mask;
	uint32_t suspend_period;
	uint32_t suspend_cnt;
};

union ubcore_set_vport_cfg_mask {
	struct {
		uint32_t pattern             : 1;
		uint32_t virtualization      : 1;
		uint32_t min_jetty_cnt       : 1;
		uint32_t max_jetty_cnt       : 1;
		uint32_t min_jfr_cnt         : 1;
		uint32_t max_jfr_cnt         : 1;
		uint32_t tp_cnt              : 1;
		uint32_t slice               : 1;
		uint32_t reserved            : 24;
	} bs;
	uint32_t value;
};

struct ubcore_set_vport_cfg {
	union ubcore_set_vport_cfg_mask mask;
	char dev_name[UBCORE_MAX_DEV_NAME];
	uint16_t fe_idx;
	uint32_t pattern;
	uint32_t virtualization;
	uint32_t min_jetty_cnt;
	uint32_t max_jetty_cnt;
	uint32_t min_jfr_cnt;
	uint32_t max_jfr_cnt;
	uint32_t tp_cnt;
	uint32_t slice;
};

static inline struct ubcore_ucontext *ubcore_get_uctx(struct ubcore_udata *udata)
{
	return udata == NULL ? NULL : udata->uctx;
}

static inline bool ubcore_check_trans_mode_valid(enum ubcore_transport_mode trans_mode)
{
	return trans_mode == UBCORE_TP_RM ||
		trans_mode == UBCORE_TP_RC || trans_mode == UBCORE_TP_UM;
}

/* Caller must put device */
struct ubcore_device *ubcore_find_device(union ubcore_eid *eid, enum ubcore_transport_type type);
struct ubcore_device *ubcore_find_device_with_name(const char *dev_name);
void ubcore_get_device(struct ubcore_device *dev);
void ubcore_put_device(struct ubcore_device *dev);
struct ubcore_device *ubcore_find_tpf_device(struct ubcore_net_addr *netaddr,
	enum ubcore_transport_type type);
struct ubcore_device *ubcore_find_tpf_by_dev(struct ubcore_device *dev,
	enum ubcore_transport_type type);
struct ubcore_device *ubcore_find_tpf_device_by_name(char *dev_name,
	enum ubcore_transport_type type);
/* returned list should be freed by caller */
struct ubcore_device **ubcore_get_all_tpf_device(enum ubcore_transport_type type,
	uint32_t *dev_cnt);

int ubcore_tpf_device_set_global_cfg(struct ubcore_set_global_cfg *cfg);
int ubcore_update_eidtbl_by_idx(struct ubcore_device *dev, union ubcore_eid *eid,
	uint32_t eid_idx, bool is_alloc_eid, struct net *net);
int ubcore_update_eidtbl_by_eid(struct ubcore_device *dev, union ubcore_eid *eid,
	uint32_t *eid_idx, bool is_alloc_eid);

struct ubcore_device *ubcore_find_upi_with_dev_name(const char *dev_name, uint32_t *upi);
int ubcore_add_upi_list(struct ubcore_device *dev, uint32_t upi);

/* Must call ubcore_put_devices to put and release the returned devices */
struct ubcore_device **ubcore_get_devices_from_netdev(struct net_device *netdev, uint32_t *cnt);
void ubcore_put_devices(struct ubcore_device **devices, uint32_t cnt);
void ubcore_update_default_eid(struct ubcore_device *dev, bool is_add);
void ubcore_update_netaddr(struct ubcore_device *dev, struct net_device *netdev, bool add);
int ubcore_fill_netaddr_macvlan(struct ubcore_net_addr *netaddr, struct net_device *netdev,
	enum ubcore_net_addr_type type);

void ubcore_sync_sip_table(void);
int ubcore_query_all_device_tpf_dev_info(void);

void ubcore_set_tp_init_cfg(struct ubcore_tp *tp, struct ubcore_tp_cfg *cfg);
struct ubcore_tp *ubcore_create_tp(struct ubcore_device *dev, struct ubcore_tp_cfg *cfg,
	struct ubcore_udata *udata);
int ubcore_modify_tp(struct ubcore_device *dev, struct ubcore_tp_node *tp_node,
	struct ubcore_tp_attr *tp_attr, struct ubcore_udata udata);

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
	return jhash(local_eid, sizeof(union ubcore_eid) + sizeof(union ubcore_eid), 0);
}

static inline uint32_t ubcore_get_rc_vtp_hash(union ubcore_eid *peer_eid)
{
	return jhash(peer_eid, sizeof(union ubcore_eid) + sizeof(uint32_t), 0);
}

static inline uint32_t ubcore_get_vtpn_hash(struct ubcore_hash_table *ht, void *key_addr)
{
	return jhash(key_addr, ht->p.key_size, 0);
}

static inline bool ubcore_jfs_need_advise(struct ubcore_jfs *jfs)
{
	return jfs->ub_dev->transport_type == UBCORE_TRANSPORT_IB &&
	       jfs->jfs_cfg.trans_mode == UBCORE_TP_RM;
}

static inline bool ubcore_jfs_tjfr_need_advise(struct ubcore_jfs *jfs,
					       struct ubcore_tjetty *tjfr)
{
	return jfs->ub_dev->transport_type == UBCORE_TRANSPORT_IB &&
	       jfs->jfs_cfg.trans_mode == UBCORE_TP_RM && tjfr->cfg.trans_mode == UBCORE_TP_RM;
}

static inline bool ubcore_jetty_need_advise(struct ubcore_jetty *jetty)
{
	return jetty->ub_dev->transport_type == UBCORE_TRANSPORT_IB &&
	       jetty->jetty_cfg.trans_mode == UBCORE_TP_RM;
}

static inline bool ubcore_jetty_tjetty_need_advise(struct ubcore_jetty *jetty,
						   struct ubcore_tjetty *tjetty)
{
	return jetty->ub_dev->transport_type == UBCORE_TRANSPORT_IB &&
	       jetty->jetty_cfg.trans_mode == UBCORE_TP_RM &&
	       tjetty->cfg.trans_mode == UBCORE_TP_RM;
}

static inline bool ubcore_jfr_need_advise(struct ubcore_jfr *jfr)
{
	return jfr->ub_dev->transport_type == UBCORE_TRANSPORT_IB &&
	       jfr->jfr_cfg.trans_mode == UBCORE_TP_RM;
}

#endif
