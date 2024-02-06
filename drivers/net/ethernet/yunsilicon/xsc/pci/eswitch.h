/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#ifndef ESWITCH_H
#define ESWITCH_H

#include <linux/if_ether.h>
#include <linux/if_link.h>
#include <linux/atomic.h>
#include <linux/if_vlan.h>
#include <linux/bitmap.h>
#include <net/devlink.h>
#include "common/xsc_core.h"
#include "common/vport.h"

struct xsc_vport_drop_stats {
	u64 rx_dropped;
	u64 tx_dropped;
};

int xsc_eswitch_init(struct xsc_core_device *dev);
void xsc_eswitch_cleanup(struct xsc_core_device *dev);
int xsc_eswitch_enable_locked(struct xsc_eswitch *esw, int mode, int num_vfs);
int xsc_eswitch_enable(struct xsc_eswitch *esw, int mode, int num_vfs);
void xsc_eswitch_disable_locked(struct xsc_eswitch *esw, bool clear_vf);
void xsc_eswitch_disable(struct xsc_eswitch *esw, bool clear_vf);

int xsc_devlink_eswitch_mode_set(struct devlink *devlink, u16 mod, struct netlink_ext_ack *extack);
int xsc_devlink_eswitch_mode_get(struct devlink *devlink, u16 *mode);

struct xsc_vport *__must_check
xsc_eswitch_get_vport(struct xsc_eswitch *esw, u16 vport_num);
int xsc_eswitch_get_vport_config(struct xsc_eswitch *esw,
				 u16 vport, struct ifla_vf_info *ivi);
int xsc_eswitch_set_vport_mac(struct xsc_eswitch *esw,
			      u16 vport, u8 mac[ETH_ALEN]);
int xsc_eswitch_get_vport_mac(struct xsc_eswitch *esw,
			      u16 vport, u8 *mac);
int xsc_eswitch_set_vport_vlan(struct xsc_eswitch *esw, int vport,
			       u16 vlan, u8 qos, __be16 vlan_proto);
int xsc_eswitch_set_vport_state(struct xsc_eswitch *esw,
				u16 vport, int link_state);
int xsc_eswitch_set_vport_spoofchk(struct xsc_eswitch *esw,
				   u16 vport, u8 spoofchk);
int xsc_eswitch_set_vport_trust(struct xsc_eswitch *esw,
				u16 vport_num, bool setting);
int xsc_eswitch_set_vport_rate(struct xsc_eswitch *esw, u16 vport,
			       u32 max_rate, u32 min_rate);
int xsc_eswitch_vport_update_group(struct xsc_eswitch *esw, int vport_num,
				   u32 group_id);
int xsc_eswitch_set_vgroup_rate(struct xsc_eswitch *esw, int group_id,
				u32 max_rate);
int xsc_eswitch_set_vgroup_max_rate(struct xsc_eswitch *esw, int group_id,
				    u32 max_rate);
int xsc_eswitch_set_vgroup_min_rate(struct xsc_eswitch *esw, int group_id,
				    u32 min_rate);
int xsc_eswitch_add_vport_trunk_range(struct xsc_eswitch *esw,
				      int vport, u16 start_vlan, u16 end_vlan);
int xsc_eswitch_del_vport_trunk_range(struct xsc_eswitch *esw,
				      int vport, u16 start_vlan, u16 end_vlan);
int xsc_eswitch_modify_esw_vport_context(struct xsc_eswitch *esw, u16 vport,
					 bool other_vport,
					 void *in, int inlen);
int xsc_eswitch_query_esw_vport_context(struct xsc_eswitch *esw, u16 vport,
					bool other_vport,
					void *out, int outlen);
int xsc_eswitch_get_vport_stats(struct xsc_eswitch *esw,
				u16 vport,
				struct ifla_vf_stats *vf_stats);
int xsc_eswitch_query_vport_drop_stats(struct xsc_core_device *dev,
				       struct xsc_vport *vport,
				       struct xsc_vport_drop_stats *stats);

#define xsc_esw_for_all_vports(esw, i, vport)  \
	for ((i) = XSC_VPORT_PF;            \
		(vport) = &(esw)->vports[(i)],  \
		(i) < (esw)->total_vports; (i)++)

#define xsc_esw_for_each_vf_vport(esw, i, vport, nvfs)  \
	for ((i) = XSC_VPORT_FIRST_VF;      \
		(vport) = &(esw)->vports[(i)],  \
		(i) <= (nvfs); (i)++)

static inline int xsc_eswitch_uplink_idx(struct xsc_eswitch *esw)
{
	/* Uplink always locate at the last element of the array.*/
	return esw->total_vports - 1;
}

static inline int xsc_eswitch_ecpf_idx(struct xsc_eswitch *esw)
{
	return esw->total_vports - 2;
}

static inline int xsc_eswitch_vport_num_to_index(struct xsc_eswitch *esw,
						 u16 vport_num)
{
	if (vport_num == XSC_VPORT_ECPF) {
		if (!xsc_ecpf_vport_exists(esw->dev) &&
		    !xsc_core_is_ecpf_esw_manager(esw->dev))
			xsc_core_warn(esw->dev, "ECPF vport doesn't exist!\n");
		return xsc_eswitch_ecpf_idx(esw);
	}

	if (vport_num == XSC_VPORT_UPLINK)
		return xsc_eswitch_uplink_idx(esw);

	/* PF and VF vports start from 0 to max_vfs */
	return vport_num;
}

static inline u16 xsc_eswitch_index_to_vport_num(struct xsc_eswitch *esw,
						 int index)
{
	if (index == xsc_eswitch_uplink_idx(esw))
		return XSC_VPORT_UPLINK;
	return index;
}

static inline u16 xsc_eswitch_manager_vport(struct xsc_core_device *dev)
{
	return xsc_core_is_ecpf_esw_manager(dev) ?
		XSC_VPORT_ECPF : XSC_VPORT_PF;
}

static inline u16 xsc_eswitch_first_host_vport_num(struct xsc_core_device *dev)
{
	return xsc_core_is_ecpf_esw_manager(dev) ?
		XSC_VPORT_PF : XSC_VPORT_FIRST_VF;
}

static inline u8 xsc_get_eswitch_mode(struct xsc_core_device *dev)
{
	struct xsc_eswitch *esw = dev->priv.eswitch;

	return ESW_ALLOWED(esw) ? esw->mode : XSC_ESWITCH_NONE;
}

static inline bool xsc_get_pp_bypass_res(struct xsc_core_device *dev)
{
	return (xsc_get_eswitch_mode(dev) == XSC_ESWITCH_OFFLOADS) ||
			(dev->device_id == XSC_MF_HOST_PF_DEV_ID);
}

#endif /* ESWITCH_H */

