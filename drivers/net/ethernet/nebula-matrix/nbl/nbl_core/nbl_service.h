/* SPDX-License-Identifier: GPL-2.0*/
/*
 * Copyright (c) 2022 nebula-matrix Limited.
 * Author:
 */

#ifndef _NBL_SERVICE_H_
#define _NBL_SERVICE_H_

#include <linux/mm.h>
#include <linux/ptr_ring.h>
#include "nbl_core.h"

#define NBL_SERV_MGT_TO_COMMON(serv_mgt)	((serv_mgt)->common)
#define NBL_SERV_MGT_TO_DEV(serv_mgt)		NBL_COMMON_TO_DEV(NBL_SERV_MGT_TO_COMMON(serv_mgt))
#define NBL_SERV_MGT_TO_RING_MGT(serv_mgt)	(&(serv_mgt)->ring_mgt)
#define NBL_SERV_MGT_TO_REP_QUEUE_MGT(serv_mgt)	((serv_mgt)->rep_queue_mgt)
#define NBL_SERV_MGT_TO_FLOW_MGT(serv_mgt)	(&(serv_mgt)->flow_mgt)
#define NBL_SERV_MGT_TO_NET_RES_MGT(serv_mgt)	((serv_mgt)->net_resource_mgt)
#define NBL_SERV_MGT_TO_ST_MGT(serv_mgt)	((serv_mgt)->st_mgt)

#define NBL_SERV_MGT_TO_DISP_OPS_TBL(serv_mgt)	((serv_mgt)->disp_ops_tbl)
#define NBL_SERV_MGT_TO_DISP_OPS(serv_mgt)	(NBL_SERV_MGT_TO_DISP_OPS_TBL(serv_mgt)->ops)
#define NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt)	(NBL_SERV_MGT_TO_DISP_OPS_TBL(serv_mgt)->priv)

#define NBL_SERV_MGT_TO_CHAN_OPS_TBL(serv_mgt)	((serv_mgt)->chan_ops_tbl)
#define NBL_SERV_MGT_TO_CHAN_OPS(serv_mgt)	(NBL_SERV_MGT_TO_CHAN_OPS_TBL(serv_mgt)->ops)
#define NBL_SERV_MGT_TO_CHAN_PRIV(serv_mgt)	(NBL_SERV_MGT_TO_CHAN_OPS_TBL(serv_mgt)->priv)

#define NBL_DEFAULT_VLAN_ID				0

#define NBL_TX_TSO_MSS_MIN				(256)
#define NBL_TX_TSO_MSS_MAX				(16383)
#define NBL_TX_TSO_L2L3L4_HDR_LEN_MIN			(42)
#define NBL_TX_TSO_L2L3L4_HDR_LEN_MAX			(128)
#define NBL_TX_CHECKSUM_OFFLOAD_L2L3L4_HDR_LEN_MAX	(255)

#define NBL_FLAG_AQ_MODIFY_MAC_FILTER			BIT(0)
#define NBL_FLAG_AQ_CONFIGURE_PROMISC_MODE		BIT(1)

#define NBL_EEPROM_LENGTH				(0)

/* input set */
#define NBL_MAC_ADDR_LEN_U8				6

#define NBL_FLOW_IN_PORT_TYPE_ETH			0x0
#define NBL_FLOW_IN_PORT_TYPE_LAG			0x400
#define NBL_FLOW_IN_PORT_TYPE_VSI			0x800

#define NBL_FLOW_OUT_PORT_TYPE_VSI			0x0
#define NBL_FLOW_OUT_PORT_TYPE_ETH			0x10
#define NBL_FLOW_OUT_PORT_TYPE_LAG			0x20

#define SET_DPORT_TYPE_VSI_HOST				(0)
#define SET_DPORT_TYPE_VSI_ECPU				(1)
#define SET_DPORT_TYPE_ETH_LAG				(2)
#define SET_DPORT_TYPE_SP_PORT				(3)

#define NBL_VLAN_SHIFT					8

#define NBL_DEVLINK_INFO_FRIMWARE_VERSION_LEN		32
#define NBL_DEVLINK_FLASH_COMPONENT_CRC_SIZE		4

/* For customized P4 */
#define NBL_P4_ELF_IDENT				"\x7F\x45\x4C\x46\x01\x01\x01\x00"
#define NBL_P4_ELF_IDENT_LEN				8
#define NBL_P4_SECTION_LEN_MAX				2048
#define NBL_P4_VERIFY_CODE_LEN				9
#define NBL_P4_PRODUCT_INFO_SECTION_NAME		"product_info"

enum {
	NBL_MGT_SERV_MGT,
	NBL_MGT_SERV_RDMA,
};

enum {
	NBL_NET_SERV_NET,
	NBL_NET_SERV_RDMA,
};

struct nbl_serv_ring {
	dma_addr_t dma;
	u16 index;
	u16 local_queue_id;
	u16 global_queue_id;
	bool need_recovery;
	u32 tx_timeout_count;
};

struct nbl_serv_vector {
	char name[32];
	struct net_device *netdev;
	u32 irq_data;
	u8 *irq_enable_base;
	u16 local_vector_id;
	u16 global_vector_id;
	u16 intr_rate_usecs;
	u16 intr_suppress_level;
	struct napi_struct *napi;
	struct nbl_serv_ring *tx_ring;
	struct nbl_serv_ring *rx_ring;
};

struct nbl_serv_ring_vsi_info {
	u16 vsi_index;
	u16 vsi_id;
	u16 ring_offset;
	u16 ring_num;
	u16 active_ring_num;
	bool itr_dynamic;
	bool started;
};

struct nbl_serv_ring_mgt {
	struct nbl_serv_ring *tx_rings;
	struct nbl_serv_ring *rx_rings;
	struct nbl_serv_vector *vectors;
	struct nbl_serv_ring_vsi_info vsi_info[NBL_VSI_MAX];
	u16 tx_desc_num;
	u16 rx_desc_num;
	u16 tx_ring_num;
	u16 rx_ring_num;
	u16 active_ring_num;
	bool net_msix_mask_en;
};

struct nbl_serv_vlan_node {
	struct list_head node;
	u16 vid;
};

struct nbl_serv_submac_node {
	struct list_head node;
	u8 mac[ETH_ALEN];
};

struct nbl_serv_flow_mgt {
	u8 mac[ETH_ALEN];
	u8 eth;
	struct list_head vlan_list;
	struct list_head submac_list;
};

struct nbl_mac_filter {
	struct list_head list;
	u8 macaddr[ETH_ALEN];
};

enum nbl_adapter_flags {
	/* p4 flags must be at the start */
	NBL_FLAG_P4_DEFAULT,
	NBL_FLAG_LINK_DOWN_ON_CLOSE,
	NBL_FLAG_MINI_DRIVER,
	NBL_ADAPTER_FLAGS_MAX
};

struct nbl_serv_net_resource_mgt {
	struct nbl_service_mgt *serv_mgt;
	struct net_device *netdev;
	struct work_struct net_stats_update;
	struct work_struct rx_mode_async;
	struct work_struct tx_timeout;
	struct delayed_work watchdog_task;
	struct timer_list serv_timer;
	unsigned long serv_timer_period;

	/* spinlock_t for rx mode submac */
	spinlock_t mac_vlan_list_lock;
	/* spinlock_t for rx mode promisc */
	spinlock_t current_netdev_promisc_flags_lock;
	struct list_head mac_filter_list;
	struct list_head indr_dev_priv_list;
	u32 rxmode_set_required;
	u16 curr_promiscuout_mode;
	u16 num_net_msix;

	/* stats for netdev */
	u64 get_stats_jiffies;
	struct nbl_stats stats;
	struct nbl_priv_stats priv_stats;
	struct nbl_phy_state phy_state;
	struct nbl_phy_caps phy_caps;
	u32 configured_speed;
	u32 configured_fec;
};

#define IOCTL_TYPE 'n'
#define IOCTL_PASSTHROUGH	_IOWR(IOCTL_TYPE, 0x01, struct nbl_passthrough_fw_cmd_param)

#define NBL_RESTOOL_NAME_LEN	32
struct nbl_serv_st_mgt {
	void *serv_mgt;
	struct cdev cdev;
	int major;
	int minor;
	dev_t devno;
	int subdev_id;
};

struct nbl_service_mgt {
	struct nbl_common_info *common;
	struct nbl_dispatch_ops_tbl *disp_ops_tbl;
	struct nbl_channel_ops_tbl *chan_ops_tbl;
	struct nbl_serv_ring_mgt ring_mgt;
	struct nbl_serv_flow_mgt flow_mgt;
	struct nbl_serv_net_resource_mgt *net_resource_mgt;
	struct nbl_serv_st_mgt *st_mgt;
	DECLARE_BITMAP(flags, NBL_ADAPTER_FLAGS_MAX);
};

struct nbl_serv_update_fw_priv {
	struct pldmfw context;
	struct netlink_ext_ack *extack;
	struct nbl_service_mgt *serv_mgt;
};

struct nbl_serv_pldm_pci_record_id {
	u16 vendor;
	u16 device;
	u16 subsystem_vendor;
	u16 subsystem_device;
};

int nbl_serv_netdev_open(struct net_device *netdev);
int nbl_serv_netdev_stop(struct net_device *netdev);
int nbl_serv_vsi_open(void *priv, struct net_device *netdev, u16 vsi_index,
		      u16 real_qps, bool use_napi);
int nbl_serv_vsi_stop(void *priv, u16 vsi_index);

#endif
