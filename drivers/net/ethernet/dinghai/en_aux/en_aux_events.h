/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#ifndef __EN_AUX_EVENTS_H__
#define __EN_AUX_EVENTS_H__
#include <linux/dinghai/driver.h>
#include <net/ip.h>
#include <net/vxlan.h>
#include <linux/ip.h>
#include "en_aux.h"
#include "../en_np/table/include/dpp_tbl_comm.h"

#define MULTI_FLAG (0x01)
#define IPV4_TYPE_FLAG (0x00)
#define GLOBAL_FLAG (0x5E)
#define BIT16 (16)
#define BIT8 (8)
#define BIT_23_L (0x7F)
#define BIT_15_L (0xFF)
#define BIT_7_L (0xFF)

enum {
	ZXDH_RDMA_HEALTH_EVENT = 1,
	ZXDH_RDMA_SRIOV_EVENT = 2,
};

struct zxdh_rdma_sriov_event_info {
	struct pci_dev *pdev;
	u64 bar0_virt_addr;
	u16 vport_id;
	u16 num_vfs;
};

s32 dh_aux_events_init(struct zxdh_en_priv *en_priv);
void dh_aux_events_uninit(struct zxdh_en_priv *en_priv);
s32 dh_aux_msg_recv_func_register(void);
void dh_aux_msg_recv_func_unregister(void);
s32 dh_aux_ipv6_notifier_init(struct zxdh_en_priv *en_priv);
s32 dh_aux_vxlan_netdev_notifier_init(struct zxdh_en_priv *en_priv);
s32 dh_ip_mac_init(struct zxdh_en_priv *en_priv);
s32 zxdh_rdma_events_call(struct net_device *netdev, u8 event_type, void *data);
void zxdh_cap_pkt_uninit(struct zxdh_en_device *en_dev, bool offload_mode);
void zxdh_aux_unload(struct zxdh_en_priv *en_priv);
s32 zxdh_aux_load(struct zxdh_en_priv *en_priv);
void zxdh_eth_config_show(struct net_device *netdev);
s32 zxdh_eth_config_recover(struct net_device *netdev);
void rx_mode_set_handler(struct work_struct *work);
#endif
