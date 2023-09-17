// SPDX-License-Identifier: GPL-2.0
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
 * Description: ubcore tp implementation
 * Author: Yan Fangfang
 * Create: 2022-08-25
 * Note:
 * History: 2022-08-25: Create file
 */

#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/random.h>
#include <linux/netdevice.h>
#include "ubcore_log.h"
#include "ubcore_netlink.h"
#include "ubcore_priv.h"
#include <urma/ubcore_uapi.h>
#include "ubcore_tp_table.h"
#include "ubcore_tp.h"

#define UB_PROTOCOL_HEAD_BYTES 313
#define UB_MTU_BITS_BASE_SHIFT 7

static inline void ubcore_set_net_addr_with_eid(struct ubcore_net_addr *net_addr,
						const union ubcore_eid *eid)
{
	memset(net_addr, 0, sizeof(struct ubcore_net_addr));
	(void)memcpy(net_addr, eid, UBCORE_EID_SIZE);
}

static inline int ubcore_mtu_enum_to_int(enum ubcore_mtu mtu)
{
	return 1 << ((int)mtu + UB_MTU_BITS_BASE_SHIFT);
}

enum ubcore_mtu ubcore_get_mtu(int mtu)
{
	mtu = mtu - UB_PROTOCOL_HEAD_BYTES;

	if (mtu >= ubcore_mtu_enum_to_int(UBCORE_MTU_8192))
		return UBCORE_MTU_8192;
	if (mtu >= ubcore_mtu_enum_to_int(UBCORE_MTU_4096))
		return UBCORE_MTU_4096;
	else if (mtu >= ubcore_mtu_enum_to_int(UBCORE_MTU_2048))
		return UBCORE_MTU_2048;
	else if (mtu >= ubcore_mtu_enum_to_int(UBCORE_MTU_1024))
		return UBCORE_MTU_1024;
	else if (mtu >= ubcore_mtu_enum_to_int(UBCORE_MTU_512))
		return UBCORE_MTU_512;
	else if (mtu >= ubcore_mtu_enum_to_int(UBCORE_MTU_256))
		return UBCORE_MTU_256;
	else
		return 0;
}
EXPORT_SYMBOL(ubcore_get_mtu);

static int ubcore_get_active_mtu(const struct ubcore_device *dev, uint8_t port_num,
				 enum ubcore_mtu *mtu)
{
	struct ubcore_device_status st = { 0 };

	if (port_num >= dev->attr.port_cnt || dev->ops->query_device_status == NULL) {
		ubcore_log_err("Invalid parameter");
		return -1;
	}
	if (dev->ops->query_device_status(dev, &st) != 0) {
		ubcore_log_err("Failed to query query_device_status for port %d", port_num);
		return -1;
	}
	if (st.port_status[port_num].state != UBCORE_PORT_ACTIVE) {
		ubcore_log_err("Port %d is not active", port_num);
		return -1;
	}
	*mtu = st.port_status[port_num].active_mtu;
	return 0;
}

static int ubcore_query_tp(struct ubcore_device *dev, const union ubcore_eid *remote_eid,
			   enum ubcore_transport_mode trans_mode,
			   struct ubcore_nl_query_tp_resp *query_tp_resp)
{
	int ret = 0;

	return ret;
}

int ubcore_destroy_tp(struct ubcore_tp *tp)
{
	if (!ubcore_have_tp_ops(tp->ub_dev)) {
		ubcore_log_err("TP ops is NULL");
		return -1;
	}

	if (tp->peer_ext.len > 0 && tp->peer_ext.addr != 0)
		kfree((void *)tp->peer_ext.addr);

	return tp->ub_dev->ops->destroy_tp(tp);
}
EXPORT_SYMBOL(ubcore_destroy_tp);

static struct ubcore_tp *ubcore_create_tp(struct ubcore_device *dev,
					  const struct ubcore_tp_cfg *cfg,
					  struct ubcore_udata *udata)
{
	struct ubcore_tp *tp = NULL;

	return tp;
}

static void ubcore_abort_tp(struct ubcore_tp *tp, struct ubcore_tp_meta *meta)
{
	struct ubcore_tp *target;

	if (tp == NULL)
		return;

	target = ubcore_find_remove_tp(meta->ht, meta->hash, &meta->key);
	if (target == NULL || target != tp) {
		ubcore_log_warn("TP is not found, already removed or under use\n");
		return;
	}

	(void)ubcore_destroy_tp(tp);
}

static void ubcore_set_multipath_tp_cfg(struct ubcore_tp_cfg *cfg,
					enum ubcore_transport_mode trans_mode,
					struct ubcore_nl_query_tp_resp *query_tp_resp)
{
	cfg->flag.bs.sr_en = query_tp_resp->cfg.flag.bs.sr_en;
	cfg->flag.bs.spray_en = query_tp_resp->cfg.flag.bs.spray_en;
	cfg->flag.bs.oor_en = query_tp_resp->cfg.flag.bs.oor_en;
	cfg->flag.bs.cc_en = query_tp_resp->cfg.flag.bs.cc_en;
	cfg->udp_range = query_tp_resp->cfg.tp_range;
	if (trans_mode == UBCORE_TP_RC) {
		cfg->data_udp_start = query_tp_resp->cfg.data_rctp_start;
		cfg->ack_udp_start = query_tp_resp->cfg.ack_rctp_start;
	} else if (trans_mode == UBCORE_TP_RM) {
		cfg->data_udp_start = query_tp_resp->cfg.data_rmtp_start;
		cfg->ack_udp_start = query_tp_resp->cfg.ack_rmtp_start;
	}
}

static int ubcore_set_initiator_tp_cfg(struct ubcore_tp_cfg *cfg, struct ubcore_device *dev,
				       enum ubcore_transport_mode trans_mode,
				       const union ubcore_eid *remote_eid,
				       struct ubcore_nl_query_tp_resp *query_tp_resp)
{
	cfg->flag.value = 0;
	cfg->flag.bs.target = 0;
	cfg->trans_mode = trans_mode;
	cfg->local_eid = dev->attr.eid;

	if (dev->attr.virtualization) {
		cfg->peer_eid = *remote_eid;
		ubcore_set_net_addr_with_eid(&cfg->local_net_addr, &dev->attr.eid);
		ubcore_set_net_addr_with_eid(&cfg->peer_net_addr, remote_eid);
	} else {
		if (dev->netdev == NULL)
			ubcore_log_warn("Could not find netdev.\n");

		cfg->peer_eid = query_tp_resp->dst_eid; /* set eid to be the remote underlay eid */
		cfg->local_net_addr = query_tp_resp->src_addr;
		if (dev->netdev != NULL && dev->netdev->dev_addr != NULL)
			(void)memcpy(cfg->local_net_addr.mac, dev->netdev->dev_addr,
				     dev->netdev->addr_len);
		if (dev->netdev != NULL)
			cfg->local_net_addr.vlan = (uint64_t)dev->netdev->vlan_features;
		cfg->peer_net_addr = query_tp_resp->dst_addr;
		ubcore_set_multipath_tp_cfg(cfg, trans_mode, query_tp_resp);
	}

	/* set mtu to active mtu temperately */
	if (ubcore_get_active_mtu(dev, 0, &cfg->mtu) != 0) {
		ubcore_log_err("Failed to get active mtu");
		return -1;
	}
	/* set psn to 0 temperately */
	cfg->rx_psn = 0;
	return 0;
}

static int ubcore_query_initiator_tp_cfg(struct ubcore_tp_cfg *cfg, struct ubcore_device *dev,
					 const union ubcore_eid *remote_eid,
					 enum ubcore_transport_mode trans_mode)
{
	struct ubcore_nl_query_tp_resp query_tp_resp;

	/* Do not query tp as TPS is not running on VM */
	if (dev->attr.virtualization)
		return ubcore_set_initiator_tp_cfg(cfg, dev, trans_mode, remote_eid, NULL);

	if (ubcore_query_tp(dev, remote_eid, trans_mode, &query_tp_resp) != 0) {
		ubcore_log_err("Failed to query tp");
		return -1;
	}
	return ubcore_set_initiator_tp_cfg(cfg, dev, trans_mode, NULL, &query_tp_resp);
}

static int ubcore_enable_tp(const struct ubcore_device *dev, struct ubcore_tp_node *tp_node,
			    struct ubcore_ta *ta, struct ubcore_udata *udata)
{
	return 0;
}

struct ubcore_tp *ubcore_create_vtp(struct ubcore_device *dev, const union ubcore_eid *remote_eid,
				    enum ubcore_transport_mode trans_mode,
				    struct ubcore_udata *udata)
{
	return NULL;
}
EXPORT_SYMBOL(ubcore_create_vtp);

int ubcore_destroy_vtp(struct ubcore_tp *vtp)
{
	return -1;
}
EXPORT_SYMBOL(ubcore_destroy_vtp);

static inline void ubcore_set_ta_for_tp_cfg(struct ubcore_device *dev, struct ubcore_ta *ta,
					    struct ubcore_tp_cfg *cfg)
{
	if (dev->transport_type == UBCORE_TRANSPORT_IB)
		cfg->ta = ta;
	else
		cfg->ta = NULL;
}

int ubcore_advise_tp(struct ubcore_device *dev, const union ubcore_eid *remote_eid,
		     struct ubcore_tp_advice *advice, struct ubcore_udata *udata)
{
	struct ubcore_tp_node *tp_node;
	struct ubcore_tp_cfg cfg = { 0 };
	struct ubcore_tp *new_tp;

	/* Must call driver->create_tp with udata if we are advising jetty */
	tp_node = ubcore_hash_table_lookup(advice->meta.ht, advice->meta.hash, &advice->meta.key);
	if (tp_node != NULL && !tp_node->tp->flag.bs.target) {
		atomic_inc(&tp_node->tp->use_cnt);
		return 0;
	}

	if (ubcore_query_initiator_tp_cfg(&cfg, dev, remote_eid, UBCORE_TP_RM) != 0) {
		ubcore_log_err("Failed to init tp cfg");
		return -1;
	}

	ubcore_set_ta_for_tp_cfg(dev, &advice->ta, &cfg);

	/* driver gurantee to return the same tp if we have created it as a target */
	new_tp = ubcore_create_tp(dev, &cfg, udata);
	if (new_tp == NULL) {
		ubcore_log_err("Failed to create tp");
		return -1;
	}

	tp_node = ubcore_add_tp_node(advice->meta.ht, advice->meta.hash, &advice->meta.key, new_tp,
				     &advice->ta);
	if (tp_node == NULL) {
		(void)ubcore_destroy_tp(new_tp);
		ubcore_log_err("Failed to find and add tp\n");
		return -1;
	} else if (tp_node != NULL && tp_node->tp != new_tp) {
		(void)ubcore_destroy_tp(new_tp);
		new_tp = NULL;
	}

	if (ubcore_enable_tp(dev, tp_node, &advice->ta, udata) != 0) {
		ubcore_abort_tp(new_tp, &advice->meta);
		ubcore_log_err("Failed to enable tp");
		return -1;
	}

	if (new_tp == NULL)
		atomic_inc(&tp_node->tp->use_cnt);

	return 0;
}
EXPORT_SYMBOL(ubcore_advise_tp);
