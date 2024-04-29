/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#ifndef XSC_VPORT_H
#define XSC_VPORT_H

#include "common/xsc_core.h"
#include <rdma/ib_verbs.h>
#include "common/xsc_fs.h"

#define XSC_VPORT_PF_PLACEHOLDER		(1u)
#define XSC_VPORT_UPLINK_PLACEHOLDER		(1u)
#define XSC_VPORT_ECPF_PLACEHOLDER(dev)	(xsc_ecpf_vport_exists(dev) || \
					 xsc_core_is_ecpf_esw_manager(dev))

#define XSC_SPECIAL_VPORTS(dev) (XSC_VPORT_PF_PLACEHOLDER +		\
				   XSC_VPORT_UPLINK_PLACEHOLDER +	\
				   XSC_VPORT_ECPF_PLACEHOLDER(dev))

#define XSC_VPORT_MANAGER(dev)	(xsc_core_is_vport_manager(dev))

enum {
	XSC_CAP_INLINE_MODE_L2,
	XSC_CAP_INLINE_MODE_VPORT_CONTEXT,
	XSC_CAP_INLINE_MODE_NOT_REQUIRED,
};

/* Vport number for each function must keep unchanged */
enum {
	XSC_VPORT_PF			= 0x0,
	XSC_VPORT_FIRST_VF		= 0x1,
	XSC_VPORT_ECPF			= 0xfffe,
	XSC_VPORT_UPLINK		= 0xffff,
};

enum {
	XSC_VPORT_ADMIN_STATE_DOWN  = 0x0,
	XSC_VPORT_ADMIN_STATE_UP    = 0x1,
	XSC_VPORT_ADMIN_STATE_AUTO  = 0x2,
};

u8 xsc_query_vport_state(struct xsc_core_device *dev, u8 opmod, u16 vport);
int xsc_modify_vport_admin_state(struct xsc_core_device *dev, u8 opmod,
				 u16 vport, u8 other_vport, u8 state);
int xsc_query_nic_vport_mac_address(struct xsc_core_device *dev,
				    u16 vport, u8 *addr);
int xsc_query_other_nic_vport_mac_address(struct xsc_core_device *dev,
					  u16 vport, u8 *addr);
int xsc_query_nic_vport_min_inline(struct xsc_core_device *dev,
				   u16 vport, u8 *min_inline);
void xsc_query_min_inline(struct xsc_core_device *dev, u8 *min_inline);
int xsc_modify_nic_vport_min_inline(struct xsc_core_device *dev,
				    u16 vport, u8 min_inline);
int xsc_modify_nic_vport_mac_address(struct xsc_core_device *dev,
				     u16 vport, u8 *addr, bool perm_mac);
int xsc_modify_other_nic_vport_mac_address(struct xsc_core_device *dev,
					   u16 vport, u8 *addr, bool perm_mac);
int xsc_query_nic_vport_mtu(struct xsc_core_device *dev, u16 *mtu);
int xsc_modify_nic_vport_mtu(struct xsc_core_device *dev, u16 mtu);
int xsc_query_nic_vport_system_image_guid(struct xsc_core_device *dev,
					  u64 *system_image_guid);
int xsc_query_nic_vport_node_guid(struct xsc_core_device *dev, u32 vport,
				  u64 *node_guid);
int xsc_modify_nic_vport_node_guid(struct xsc_core_device *dev,
				   u16 vport, u64 node_guid);
int xsc_modify_other_nic_vport_node_guid(struct xsc_core_device *dev,
					 u16 vport, u64 node_guid);
int xsc_query_nic_vport_qkey_viol_cntr(struct xsc_core_device *dev,
				       u16 *qkey_viol_cntr);
int xsc_query_hca_vport_gid(struct xsc_core_device *dev, u8 other_vport,
			    u8 port_num, u16  vf_num, u16 gid_index,
			    union ib_gid *gid);
int xsc_query_hca_vport_pkey(struct xsc_core_device *dev, u8 other_vport,
			     u8 port_num, u16 vf_num, u16 pkey_index,
			     u16 *pkey);
int xsc_query_hca_vport_context(struct xsc_core_device *dev,
				u8 other_vport, u8 port_num,
				u16 vf_num,
				struct xsc_hca_vport_context *rep);
int xsc_query_hca_vport_node_guid(struct xsc_core_device *dev,
				  u64 *node_guid);
int xsc_query_nic_vport_mac_list(struct xsc_core_device *dev,
				 u16 vport,
				 enum xsc_list_type list_type,
				 u8 addr_list[][ETH_ALEN],
				 int *list_size);
int xsc_modify_nic_vport_mac_list(struct xsc_core_device *dev,
				  enum xsc_list_type list_type,
				  u8 addr_list[][ETH_ALEN],
				  int list_size);
int xsc_query_nic_vport_promisc(struct xsc_core_device *dev,
				u16 vport,
				int *promisc_uc,
				int *promisc_mc,
				int *promisc_all);
int xsc_modify_nic_vport_promisc(struct xsc_core_device *dev,
				 int promisc_uc,
				 int promisc_mc,
				 int promisc_all);
int xsc_query_nic_vport_vlans(struct xsc_core_device *dev, u32 vport,
			      unsigned long *vlans);
int xsc_modify_nic_vport_vlans(struct xsc_core_device *dev,
			       u16 vid, bool add);
int xsc_query_vport_down_stats(struct xsc_core_device *dev, u16 vport,
			       u8 other_vport, u64 *rx_discard_vport_down,
			       u64 *tx_discard_vport_down);
int xsc_query_vport_counter(struct xsc_core_device *dev, u8 other_vport,
			    int vf, u8 port_num, void *out,
			    size_t out_sz);
int xsc_modify_hca_vport_context(struct xsc_core_device *dev,
				 u8 other_vport, u8 port_num,
				 int vf,
				 struct xsc_hca_vport_context *req);
u16 xsc_eswitch_get_total_vports(const struct xsc_core_device *dev);
#endif /* XSC_VPORT_H */
