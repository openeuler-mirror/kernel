/* SPDX-License-Identifier: GPL-2.0 */
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
#define NBL_SERV_MGT_TO_TC_MGT(serv_mgt)	(&(serv_mgt)->tc_mgt)
#define NBL_SERV_MGT_TO_ST_MGT(serv_mgt)	((serv_mgt)->st_mgt)

#define NBL_SERV_MGT_TO_DISP_OPS_TBL(serv_mgt)	((serv_mgt)->disp_ops_tbl)
#define NBL_SERV_MGT_TO_DISP_OPS(serv_mgt)	(NBL_SERV_MGT_TO_DISP_OPS_TBL(serv_mgt)->ops)
#define NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt)	(NBL_SERV_MGT_TO_DISP_OPS_TBL(serv_mgt)->priv)

#define NBL_SERV_MGT_TO_CHAN_OPS_TBL(serv_mgt)	((serv_mgt)->chan_ops_tbl)
#define NBL_SERV_MGT_TO_CHAN_OPS(serv_mgt)	(NBL_SERV_MGT_TO_CHAN_OPS_TBL(serv_mgt)->ops)
#define NBL_SERV_MGT_TO_CHAN_PRIV(serv_mgt)	(NBL_SERV_MGT_TO_CHAN_OPS_TBL(serv_mgt)->priv)

#define NBL_DEFAULT_VLAN_ID				0
#define NBL_HW_STATS_PERIOD_SECONDS			5
#define NBL_HW_STATS_RX_RATE_THRESHOLD			(1000) /* 1k pps */

#define NBL_REP_QUEUE_MGT_DESC_MAX			(32768)
#define NBL_REP_QUEUE_MGT_DESC_NUM			(2048)
#define NBL_REP_PER_VSI_QUEUE_NUM			(1)
#define NBL_DEFAULT_REP_TX_RETRY_NUM			2
#define NBL_DEFAULT_REP_TX_MAX_NUM			8192

#define NBL_MAX_QUEUE_TC_NUM				(8)
#define NBL_TC_WEIGHT_GRAVITY				(10)
#define NBL_TC_MBPS_DIVSIOR				(125000)

#define NBL_TX_TSO_MSS_MIN				(256)
#define NBL_TX_TSO_MSS_MAX				(16383)
#define NBL_TX_TSO_L2L3L4_HDR_LEN_MIN			(42)
#define NBL_TX_TSO_L2L3L4_HDR_LEN_MAX			(128)
#define NBL_TX_CHECKSUM_OFFLOAD_L2L3L4_HDR_LEN_MAX	(255)

#define NBL_FLAG_AQ_MODIFY_MAC_FILTER			BIT(0)
#define NBL_FLAG_AQ_CONFIGURE_PROMISC_MODE		BIT(1)
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

#define NBL_MAX_BURST					524287

/* primary vlan in vlan list */
#define NBL_NO_TRUST_MAX_VLAN				9
/* primary mac not in submac list */
#define NBL_NO_TRUST_MAX_MAC				12

#define NBL_DEVLINK_INFO_FRIMWARE_VERSION_LEN		32
#define NBL_DEVLINK_FLASH_COMPONENT_CRC_SIZE		4

/* For customized P4 */
#define NBL_P4_ELF_IDENT				"\x7F\x45\x4C\x46\x01\x01\x01\x00"
#define NBL_P4_ELF_IDENT_LEN				8
#define NBL_P4_VERIFY_CODE_LEN				9
#define NBL_P4_PRODUCT_INFO_SECTION_NAME		"product_info"
#define NBL_MD5SUM_LEN					16

enum {
	NBL_MGT_SERV_MGT,
	NBL_MGT_SERV_RDMA,
};

enum {
	NBL_NET_SERV_NET,
	NBL_NET_SERV_RDMA,
};

enum {
	NBL_TC_INVALID,
	NBL_TC_RUNNING,
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
	cpumask_t cpumask;
	struct net_device *netdev;
	struct nbl_napi_struct *nbl_napi;
	struct nbl_serv_ring *tx_ring;
	struct nbl_serv_ring *rx_ring;
	u8 __iomem *irq_enable_base;
	u32 irq_data;
	u32 irq_mask_data;
	u16 local_vector_id;
	u16 global_vector_id;
	u16 intr_rate_usecs;
	u16 intr_suppress_level;
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
	void *xdp_prog;
	struct nbl_serv_ring_vsi_info vsi_info[NBL_VSI_MAX];
	u32 *rss_indir_user;
	u16 tx_desc_num;
	u16 rx_desc_num;
	u16 tx_ring_num;
	u16 rx_ring_num;
	u16 xdp_ring_offset;
	u16 active_ring_num;
	bool net_msix_mask_en;
	u16 ethtool_rx_vlan_mode;
	u16 ethtool_rss_hash_mode;
	u16 half_offload_en;
};

struct nbl_serv_vlan_node {
	struct list_head node;
	u16 vid;
	// primary_mac_effective means base mac + vlan ok
	u16 primary_mac_effective;
	// sub_mac_effective means sub mac + vlan ok
	u16 sub_mac_effective;
	u16 ref_cnt;
};

struct nbl_serv_submac_node {
	struct list_head node;
	u8 mac[ETH_ALEN];
	// effective means this submac + allvlan flowrule effective
	u16 effective;
};

enum {
	NBL_PROMISC = 0,
	NBL_ALLMULTI = 1,
	NBL_USER_FLOW = 2,
	NBL_MIRROR = 3,
};

enum {
	NBL_SUBMAC_UNICAST = 0,
	NBL_SUBMAC_MULTI = 1,
	NBL_SUBMAC_MAX = 2
};

struct nbl_serv_flow_mgt {
	struct list_head vlan_list;
	struct list_head submac_list[NBL_SUBMAC_MAX];
	u16 vid;
	u8 mac[ETH_ALEN];
	u8 eth;
	bool trusted_en;
	bool trusted_update;
	u16 vlan_list_cnt;
	u16 active_submac_list;
	u16 submac_list_cnt;
	u16 unicast_mac_cnt;
	u16 multi_mac_cnt;
	u16 promisc;
	bool force_promisc;
	bool unicast_flow_enable;
	bool multicast_flow_enable;
	bool pending_async_work;
};

struct nbl_mac_filter {
	struct list_head list;
	u8 macaddr[ETH_ALEN];
};

struct nbl_serv_tc_mgt {
	int state;
	u16 orig_num_active_queues;
	u16 num_tc;
	u16 total_qps;
};

enum nbl_adapter_flags {
	/* p4 flags must be at the start */
	NBL_FLAG_P4_DEFAULT,
	NBL_FLAG_LINK_DOWN_ON_CLOSE,
	NBL_FLAG_NRZ_RS_FEC_544_SUPPORT,
	NBL_FLAG_HIGH_THROUGHPUT,
	NBL_FLAG_INTERLEAVE_SEG_DISABLE,
	NBL_FLAG_TX_PORT_FC_SEGREGATE,
	NBL_FLAG_RX_CSUM_DROP,
	NBL_FLAG_XDP_ENHANCE,
	NBL_FLAG_RXQ_LARGE_BUFF,
	NBL_FLAG_VLAN_FILTERING,
	NBL_ADAPTER_FLAGS_MAX
};

struct nbl_serv_lag_info {
	u16 lag_num;
	u8 lag_id;
};

struct nbl_serv_netdev_ops {
	const struct net_device_ops *pf_netdev_ops;
	const struct net_device_ops *rep_netdev_ops;
};

struct nbl_serv_rep_drop {
	struct u64_stats_sync rep_drop_syncp;
	u64 tx_dropped;
};

struct nbl_sysfs_vf_config_attr {
	struct kobj_attribute mac_attr;
	struct kobj_attribute rate_attr;
	struct kobj_attribute spoofchk_attr;
	struct kobj_attribute state_attr;
	void *priv;
	int vf_id;
};

struct nbl_serv_vf_info {
	struct kobject kobj;
	struct kobject meters_kobj;
	struct kobject rx_kobj;
	struct kobject tx_kobj;
	struct kobject rx_bps_kobj;
	struct kobject tx_bps_kobj;
	void *priv;
	u16 vf_id;

	int state;
	int spoof_check;
	int max_tx_rate;
	int meter_tx_rate;
	int meter_rx_rate;
	int meter_tx_burst;
	int meter_rx_burst;
	u8 mac[ETH_ALEN];
	u16 vlan;
	u16 vlan_proto;
	u8 vlan_qos;
	bool trusted;
};

#define NBL_DCB_NO_HW_CHG	1
#define NBL_DCB_HW_CHG		2

struct nbl_hw_stats {
	u64 *total_uvn_stat_pkt_drop;
	struct nbl_chan_param_drop_stats_resp start_drop_stats;
	bool update_ustore;
	u8 resv[3];
	u64 start_fake_drop;
};

struct nbl_serv_net_resource_mgt {
	struct nbl_service_mgt *serv_mgt;
	struct net_device *netdev;
	struct work_struct net_stats_update;
	struct work_struct rx_mode_async;
	struct work_struct tx_timeout;
	struct work_struct update_link_state;
	struct work_struct update_vlan;
	struct work_struct update_mirror_outputport;
	struct delayed_work watchdog_task;
	struct timer_list serv_timer;
	unsigned long serv_timer_period;

	struct list_head tmp_add_filter_list;
	struct list_head tmp_del_filter_list;
	struct list_head indr_dev_priv_list;
	struct nbl_serv_lag_info *lag_info;
	struct nbl_serv_netdev_ops netdev_ops;
	s64 last_st_time;
	u16 curr_promiscuout_mode;
	u16 num_net_msix;
	bool update_submac;
	int num_vfs;
	int total_vfs;

	/* stats for netdev */
	u64 get_stats_jiffies;
	struct nbl_stats stats;
	struct nbl_hw_stats hw_stats;
	unsigned long hw_stats_jiffies;
	unsigned long hw_stats_period;
	struct nbl_priv_stats priv_stats;
	struct nbl_phy_caps phy_caps;
	struct nbl_serv_rep_drop *rep_drop;
	struct nbl_serv_vf_info *vf_info;
	struct kobject *sriov_kobj;
	u32 configured_speed;
	u32 configured_fec;
	u32 user_configured_fec;
	u16 bridge_mode;
	int link_forced;

	u16 vlan_tci;
	u16 vlan_proto;
	int max_tx_rate;
	u32 dump_flag;
	u32 dump_perf_len;
	struct nbl_qos_info qos_info;

	struct nbl_port_state port_state;
	bool port_state_update;
};

struct nbl_serv_rep_queue_mgt {
	struct ptr_ring ring;
	struct net_device *netdev;

	/* spinlock_t for queue mgt */
	spinlock_t seq_lock;
	int size;
};

#define IOCTL_TYPE 'n'
#define IOCTL_PASSTHROUGH	_IOWR(IOCTL_TYPE, 0x01, struct nbl_passthrough_fw_cmd_param)
#define IOCTL_ST_INFO		_IOR(IOCTL_TYPE, 0x02, struct nbl_st_info_param)

#define IOCTL_ST_INFO_VERSION	0x10		/* 1.0 */

struct nbl_serv_st_mgt {
	void *serv_mgt;
	struct cdev cdev;
	int major;
	int minor;
	dev_t devno;
	int subdev_id;
	char st_name[NBL_RESTOOL_NAME_LEN];
	char real_st_name[NBL_RESTOOL_NAME_LEN];
	bool real_st_name_valid;
	u8 resv[3];
};

struct nbl_service_mgt {
	struct nbl_common_info *common;
	struct nbl_macsec_info *macsec;
	struct nbl_dispatch_ops_tbl *disp_ops_tbl;
	struct nbl_channel_ops_tbl *chan_ops_tbl;
	struct nbl_serv_ring_mgt ring_mgt;
	struct nbl_serv_rep_queue_mgt *rep_queue_mgt;
	struct nbl_serv_flow_mgt flow_mgt;
	struct nbl_serv_net_resource_mgt *net_resource_mgt;
	struct nbl_serv_tc_mgt tc_mgt;
	struct nbl_serv_st_mgt *st_mgt;
	unsigned long flags;
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

struct nbl_tc_flow_parse_pattern {
	u32 pattern_type;
	int (*parse_func)(const struct flow_rule *rule,
			  struct nbl_flow_pattern_conf *filter,
			  const struct nbl_common_info *common,
			  u16 flag);
};

struct nbl_tc_flow_action_driver_ops {
	int (*act_update)(struct nbl_rule_action *rule_act,
			  const struct flow_action_entry *act_entry,
			  enum flow_action_id type,
			  struct nbl_flow_pattern_conf *filterr,
			  struct nbl_tc_flow_param *param);
};

struct nbl_serv_notify_vlan_param {
	u16 vlan_tci;
	u16 vlan_proto;
};

int nbl_serv_netdev_open(struct net_device *netdev);
int nbl_serv_netdev_stop(struct net_device *netdev);
int nbl_serv_vsi_open(void *priv, struct net_device *netdev, u16 vsi_index,
		      u16 real_qps, bool use_napi);
int nbl_serv_vsi_stop(void *priv, u16 vsi_index);
void nbl_serv_get_rep_drop_stats(struct nbl_service_mgt *serv_mgt, u16 rep_vsi_id,
				 struct nbl_rep_stats *rep_stats);
u16 nbl_serv_get_vf_function_id(void *priv, int vf_id);
void nbl_serv_cpu_affinity_init(void *priv, u16 rings_num);

#endif
