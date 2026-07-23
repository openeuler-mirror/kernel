/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#ifndef __ZXDH_EN_AUX_H__
#define __ZXDH_EN_AUX_H__

#include "msg_common.h"
#include "zxdh_tools/zxdh_tools_ioctl.h"

#include <linux/dinghai/dh_cmd.h>
#include <linux/dinghai/driver.h>
#include <linux/dinghai/en_aux.h>
#include <linux/dinghai/eq.h>
#include <linux/compiler_types.h>
#include <linux/types.h>
#include "./en_aux/queue.h"
#include "./en_aux/en_aux_cmd.h"
#include "./en_pf.h"
#include "./en_aux/dcbnl/en_dcbnl.h"
#include "./en_np/driver/include/dpp_drv_hash.h"
#include "./en_pf/msg_func.h"
#include "./en_ethtool/ethtool.h"

#define MAX_VLAN_ID (4095)
#define MAX_QOS_ID (7)
#define VLAN_BITMAP_LENGTH (MAX_VLAN_ID + 1)
#define VLAN_BITMAP_BYTE_SIZE (512)
#define BIT_NUM_PER_BYTE (8)

#define PF_AC_MASK 0x800
#define FILTER_MAC 0xAA
#define UNFILTER_MAC 0xFF

#define AUX_INIT_INCOMPLETED 0
#define AUX_INIT_COMPLETED 1

#define IS_DELAY_STATISTICS_PKT 0
#define IS_NOT_DELAY_STATICTICS_PKT 1

#define ADD_IP6MAC 1
#define DEL_IP6MAC 2

#define WAKE_MAGIC (1 << 5)

/* IPv6 MAC work data structure */
struct zxdh_ip6mac_work_data {
	u32 addr6[4]; /* IPv6 address */
	u8 ip6mac[ETH_ALEN]; /* MAC address */
};

/* IPv6 MAC work item - each work item has its own data */
struct zxdh_ip6mac_work_item {
	struct work_struct work;
	struct zxdh_en_device *en_dev;
	struct zxdh_ip6mac_work_data data;
};

extern const u8 BOND_MCAST_ADDR[ETH_ALEN];

typedef int (*zxdh_feature_handler)(struct zxdh_en_device *en_dev, bool enable);

extern u32 max_pairs;

struct zxdh_rdma_if;
struct zxdh_en_if;
struct zxdh_sec_if;

struct zxdh_en_container {
	struct zxdh_auxiliary_device adev;
	struct zxdh_rdma_dev_info *rdma_infos;
	struct zxdh_rdma_if *rdma_ops;
	struct zxdh_en_if *ops;
	struct dh_core_dev *parent;
	s32 aux_id;
	struct zxdh_sec_if *sec_ops;
	void *auxiliary_ops[17]; //max support 20 auxiliary devices
};

struct zxdh_en_queue_stats {
	u64 q_rx_pkts;
	u64 q_tx_pkts;
	u64 q_rx_bytes;
	u64 q_tx_bytes;
	u64 q_tx_stopped;
	u64 q_tx_wake;
	u64 q_tx_dropped;
};

struct zxdh_en_netdev_stats {
	u64 rx_packets;
	u64 tx_packets;
	u64 rx_bytes;
	u64 tx_bytes;
	u64 tx_queue_wake;
	u64 tx_queue_stopped;
	u64 tx_queue_dropped;
	u64 rx_removed_vlan_packets;
	u64 tx_added_vlan_packets;
	u64 rx_csum_offload_good;
	u64 rx_csum_offload_error;
};

struct zxdh_en_vport_vqm_stats {
	u64 rx_vport_packets;
	u64 tx_vport_packets;
	u64 rx_vport_bytes;
	u64 tx_vport_bytes;
	u64 rx_vport_dropped;
};

struct zxdh_en_vport_dtp_stats {
	u64 rx_lro_packets;
	u64 rx_udp_csum_fail_packets;
	u64 tx_udp_csum_fail_packets;
	u64 rx_tcp_csum_fail_packets;
	u64 tx_tcp_csum_fail_packets;
	u64 rx_ipv4_csum_fail_packets;
	u64 tx_ipv4_csum_fail_packets;
};

struct zxdh_en_vport_stats {
	struct zxdh_en_vport_vqm_stats vqm_stats;
	struct zxdh_en_vport_np_stats np_stats;
	struct zxdh_en_vport_dtp_stats dtp_stats;
};

struct zxdh_en_phy_stats {
	u64 rx_packets_phy;
	u64 tx_packets_phy;
	u64 rx_bytes_phy;
	u64 tx_bytes_phy;
	u64 rx_error_phy;
	u64 tx_error_phy;
	u64 rx_drop_phy;
	u64 tx_drop_phy;
	u64 rx_good_bytes_phy;
	u64 tx_good_bytes_phy;
	u64 rx_unicast_phy;
	u64 tx_unicast_phy;
	u64 rx_multicast_phy;
	u64 tx_multicast_phy;
	u64 rx_broadcast_phy;
	u64 tx_broadcast_phy;
	u64 rx_under64_drop;
	u64 rx_undersize_phy;
	u64 rx_size_64_phy;
	u64 rx_size_65_127;
	u64 rx_size_128_255;
	u64 rx_size_256_511;
	u64 rx_size_512_1023;
	u64 rx_size_1024_1518;
	u64 rx_size_1519_mru;
	u64 rx_oversize_phy;
	u64 tx_undersize_phy;
	u64 tx_size_64_phy;
	u64 tx_size_65_127;
	u64 tx_size_128_255;
	u64 tx_size_256_511;
	u64 tx_size_512_1023;
	u64 tx_size_1024_1518;
	u64 tx_size_1519_mtu;
	u64 tx_oversize_phy;
	u64 rx_pause_phy;
	u64 tx_pause_phy;
	u64 rx_crc_errors;
	u64 tx_crc_errors;
	u64 rx_mac_control_phy;
	u64 tx_mac_control_phy;
	u64 rx_fragment_phy;
	u64 tx_fragment_phy;
	u64 rx_jabber_phy;
	u64 tx_jabber_phy;
	u64 rx_vlan_phy;
	u64 tx_vlan_phy;
	u64 rx_eee_phy;
	u64 tx_eee_phy;
} __packed;

struct zxdh_en_udp_phy_stats {
	u64 rx_arn_phy;
	u64 tx_psn_phy;
	u64 rx_psn_phy;
	u64 tx_psn_ack_phy;
	u64 rx_psn_ack_phy;
} __packed;

struct zxdh_en_spm_stats {
	u64 rx_total;
	u64 rx_pause;
	u64 rx_unicast;
	u64 rx_multicast;
	u64 rx_broadcast;
	u64 rx_vlan;
	u64 rx_size_64;
	u64 rx_size_65_127;
	u64 rx_size_128_255;
	u64 rx_size_256_511;
	u64 rx_size_512_1023;
	u64 rx_size_1024_1518;
	u64 rx_size_1519_mru;
	u64 rx_undersize;
	u64 rx_oversize;
	u64 rx_fragment;
	u64 rx_jabber;
	u64 rx_control;
	u64 rx_eee;

	u64 tx_total;
	u64 tx_pause;
	u64 tx_unicast;
	u64 tx_multicast;
	u64 tx_broadcast;
	u64 tx_vlan;
	u64 tx_size_64;
	u64 tx_size_65_127;
	u64 tx_size_128_255;
	u64 tx_size_256_511;
	u64 tx_size_512_1023;
	u64 tx_size_1024_1518;
	u64 tx_size_1519_mtu;
	u64 tx_undersize;
	u64 tx_oversize;
	u64 tx_fragment;
	u64 tx_jabber;
	u64 tx_control;
	u64 tx_eee;

	u64 rx_error;
	u64 rx_fcs_error;
	u64 rx_drop;

	u64 tx_error;
	u64 tx_fcs_error;
	u64 tx_drop;
} __packed;

struct zxdh_en_spm_bytes {
	u64 rx_total_bytes;
	u64 rx_good_bytes;

	u64 tx_total_bytes;
	u64 tx_good_bytes;
} __packed;

struct zxdh_en_hw_stats {
	struct zxdh_en_netdev_stats netdev_stats;
	struct zxdh_en_vport_stats vport_stats;
	struct zxdh_en_phy_stats phy_stats;
	struct zxdh_en_udp_phy_stats udp_stats;
	struct zxdh_en_queue_stats *q_stats;
};

struct zxdh_vlan_dev {
	u8 qos;
	u8 rsv;
	u16 protocol;
	u16 vlan_id;
};

/* drs sec */
struct zxdh_sec_pri {
	u64 SecVAddr;
	u64 SecPAddr;
	u32 SecMemSize;
};

struct zxdh_sec_info {
	dma_addr_t ring_dma_addr;
	dma_addr_t driver_event_dma_addr;
	dma_addr_t device_event_dma_addr;
	struct vring_packed_desc *desc;
	struct vring_packed_desc_event *driver;
	struct vring_packed_desc_event *device;
	size_t ring_size_in_bytes;
	size_t event_size_in_bytes;

	u16 desc_num;
	u8 queue_pairs;
	u32 phy_index;
	u64 notify_phy_addr;

	u64 bar0_phy_addr;
	u64 bar0_vir_addr;
	u64 bar0_size;
	u16 pcie_id;
	struct pci_dev *pdev;
};

struct zxdh_ethtool_table {
	struct ethtool_rx_flow_spec rfs;
	u32 loc;
	u32 index;
	bool is_used;
};

struct zxdh_flow_steering {
	struct zxdh_ethtool_table ethtool_fs[ETHTOOL_FD_MAX_NUM];
	u32 tot_num_rules;
};

struct en_device_config {
	u16 rx_queue_size;
	u16 tx_queue_size;
	u16 curr_combined;
	u32 hash_mode;
	u8 hash_func;
	u8 dev_addr[6];
	u32 queue_map[ZXDH_INDIR_RQT_SIZE];
	u8 vlan_trunk_bitmap[VLAN_BITMAP_BYTE_SIZE];
	struct recover_mac pf_recover_mac;
};

struct zxdh_pkt_file_info {
	u8 *pkt_addr_array;
	u32 pkt_buf_len;
};

struct zxdh_pkt_save_file {
	struct file *log_file;
	u8 enable_pkt_num_mode;
	u32 pkt_file_size;
	u32 pkt_set_count;
	u32 is_stop;
	u32 pkt_rbuf_idx;
	u32 ubuf_idx;
	u32 pkt_cur_num;
	char file_path[150];
	loff_t file_pos;
	size_t total_written_bytes;
};

struct zxdh_en_device {
	struct dh_core_dev *parent;
	struct net_device *netdev;
	struct device *dmadev;
	void *msgq_dev;
	struct zxdh_en_if *ops;
	struct zxdh_en_hw_stats hw_stats;
	struct zxdh_en_vport_stats pre_stats;
	struct zxdh_vlan_dev vlan_dev;

	u32 device_id;
	u32 vendor_id;

	u64 driver_feature;
	u64 device_feature;
	u64 guest_feature;

	struct list_head vqs_list;
	spinlock_t vqs_list_lock;
	u32 indir_rqt[ZXDH_INDIR_RQT_SIZE];

	s32 channels_num;
	struct zxdh_flow_steering fs;

	/* a list of queues so we can dispatch IRQs */
	spinlock_t lock;
	struct list_head virtqueues;
	/* array of all queues for house-keeping */
	struct zxdh_pci_vq_info **vqs;

	struct send_queue *sq;
	struct receive_queue *rq;
	u32 status;

	/* Max # of queue pairs supported by the device */
	u16 curr_queue_pairs;
	u16 max_queue_pairs; /* max_vq_pairs + msg_qpairs */
	u16 max_vq_pairs;
	u16 xdp_queue_pairs;

	u16 old_queue_pairs; /* for selq flow_map attrbuite group */

	bool xdp_enabled;

	enum zxdh_device_state device_state;
	bool need_msgq;
	/* Host can handle any s/g split between our header and packet data */
	bool any_header_sg;
	bool mergeable_rx_bufs;
	/* Packet custom queue header size */
	u8 hdr_len;
	u8 hdr_1588_len;
	/* Work struct for refilling if we run low on memory. */
	struct delayed_work refill;

	/* CPU hotplug instances for online & dead */
	struct hlist_node node;
	struct hlist_node node_dead;
	bool fast_unload;
	bool vqmb_port_ctl;

	bool dtp_drs_offload;

	u32 phy_index[ZXDH_MAX_QUEUES_NUM];

	u8 link_check_bit;
	u8 pannel_id;
	u8 rsv[2];

	u16 ep_bdf;
	u64 spec_sbdf;
	u16 pcie_id;
	/* vfunc_active */
	u16 slot_id;
	u16 vport;
	u8 phy_port;
	u8 panel_id;
	u8 hash_search_idx;

	u32 link_speed;
	bool link_up;
	u8 duplex;

	u32 speed;
	u32 curr_speed_modes;
	u32 autoneg_enable;
	u32 supported_speed_modes;
	u32 advertising_speed_modes;

	bool promisc_enabled;
	bool allmulti_enabled;
	u32 pflags;
	u8 clock_no;
	u32 msglevel;
	u32 wol_support;
	u32 wolopts;
	u8 fw_version[ETHTOOL_FWVERS_LEN];
	u8 fw_version_len;
	u32 vf_1588_call_np_num;
	u32 ptp_tc_enable_opt;
	u32 delay_statistics_enable;

	struct work_struct vf_link_info_update_work;
	struct work_struct link_info_irq_update_vf_work;
	struct work_struct link_info_irq_process_work;
	struct work_struct link_info_irq_update_np_work;
	struct work_struct rx_mode_set_work;
	struct work_struct plug_adev_work;
	struct work_struct unplug_adev_work;
	struct work_struct smart_nic_copy_work;

	u8 curr_unicast_num;
	u8 curr_multicast_num;
	struct work_struct pf_notify_vf_link_state_work;
	struct work_struct pf2vf_msg_proc_work;
	struct work_struct service_task;
	struct work_struct service_riscv_task;
	struct timer_list service_timer;
	struct timer_list service_riscv_timer;
	struct work_struct riscv2aux_msg_proc_work;
	struct work_struct capture_save_file_work;
	/* QoS DCB */
	struct zxdh_dcbnl_para dcb_para;
	struct zxdh_dcbnl_ets_switch_info ets_info;

	/* SEC */
	struct zxdh_sec_pri drs_sec_pri;
	struct zxdh_sec_info *sec_info;
	u32 sec_phy_index[256];
	resource_size_t notify_phy_addr;

#ifdef ZXDH_CONFIG_SPECIAL_SQ_EN
	DECLARE_HASHTABLE(flow_map_hash, ilog2(ZXDH_MAX_PAIRS_NUM));
#endif
	/* initialization completion flag */
	u8 init_comp_flag;

	struct notifier_block ipv6_notifier;
	struct notifier_block vxlan_notifier;

	/* just for hardware bond */
	bool is_hwbond;
	bool is_primary_port;
	bool is_rdma_aux_plug;
	struct zxdh_bond_device *hardware_bond;
	u64 last_tx_vport_ssvpc_packets;
	/* link-down-on-close */
	bool link_down_on_close;
	bool enable_1588;
#ifdef CONFIG_INET
	bool local_lb_enable;
#endif
	unsigned long state;
	u8 pkt_dev_flag;
	u8 pkt_cap_switch;
	u8 pkt_save_file_flag;
	u8 pkt_file_num;
	u8 pkt_addr_marked;
	u32 pkt_dev_speed;
	struct zxdh_pkt_file_info *pkt_file_info;
	struct zxdh_pkt_save_file pkt_save_file;
	struct workqueue_struct *pkt_wq;

	struct en_device_config eth_config;
	struct sockaddr last_np_mac_addr;

	u32 board_type;
	bool is_multi_ep;
	bool quick_remove;
	bool time_sync_done;
};

struct zxdh_en_priv {
	struct zxdh_en_device edev;
	struct mutex lock;
	struct dh_eq_table eq_table;
	struct dh_events *events;
};

struct MacAddress {
	u8 mac_addr[ETH_ALEN];
};

struct mac_config_info {
	u32 mac_num;
	u32 target_vf;
	union {
		u32 unicast_add_count;
		u32 unicast_del_count;
	};
	union {
		u32 multicast_add_count;
		u32 multicast_del_count;
	};
	struct MacAddress unicast_mac_array[128];
	struct MacAddress multicast_mac_array[32];
};

struct mac_transfer_info {
	u32 src_vf;
	u32 dst_vf;
};

struct dhtool_set_vf_mac_msg {
	enum { MAC_ADD, MAC_DEL, MAC_TRANSFER } action;
	union {
		struct mac_transfer_info mac_transfer;
		struct mac_config_info mac_config;
	};
};

enum VF_MAC_SET_RET {
	MAC_CONFIG_SUCCESS = 0,
	MAC_CONFIG_FAILED = 1,
	MAC_ALREADY_EXISTS_IN_OTHER_VF = 2,
	UNICAST_MAC_NUM_BEYOND_MAXNUM = 3,
	MULTICAST_MAC_NUM_BEYOND_MAXNUM = 4,
	UNICAST_MAC_NOT_EXISTS = 5,
	MULTICAST_MAC_NOT_EXISTS = 6,
	UNICAST_MAC_TRANSFER_FAILED = 7,
	MULTICAST_MAC_TRANSFER_FAILED = 8,
	VF_ERROR = 9,
};

struct padded_zxdh_net_hdr {
	struct zxdh_net_hdr_tx hdr;
	char padding[4];
};

#define DEV_UNICAST_MAX_NUM 128
#define DEV_MULTICAST_MAX_NUM 32
#define UNICAST_MAX_NUM (16 * 257)
#define MULTICAST_MAX_NUM (4 * 257)

#define EXTRACT_BUS(bdf) (((bdf) >> 8) & 0xff)
#define EXTRACT_DEVICE(bdf) (((bdf) >> 3) & 0x1f)
#define DEVICE_RANGE 31

struct mac_queue {
	u8 addr[DEV_MULTICAST_MAX_NUM][ETH_ALEN];
	u8 count;
};

s32 dh_aux_eq_table_init(struct zxdh_en_priv *en_priv);
void dh_aux_eq_table_cleanup(struct zxdh_en_priv *en_priv);
s32 zxdh_ip6mac_add(struct zxdh_en_device *en_dev, const u32 *addr6, const u8 *ip6mac);
s32 zxdh_ip6mac_del(struct zxdh_en_device *en_dev, const u32 *addr6, const u8 *ip6mac);
s32 zxdh_ip6mac_del_safe(struct zxdh_en_device *en_dev, const u32 *addr6, const u8 *ip6mac);
void zxdh_ip6mac_del_work_handler(struct work_struct *work);
s32 zxdh_ip6mac_add_safe(struct zxdh_en_device *en_dev, const u32 *addr6, const u8 *ip6mac);
void zxdh_ip6mac_add_work_handler(struct work_struct *work);
s32 zxdh_ip4mac_add(struct zxdh_en_device *en_dev, const u8 *ip4mac, u8 action);
s32 zxdh_ip4mac_del(struct zxdh_en_device *en_dev, const u8 *ip4mac, u8 action);
#ifdef HAVE_NDO_SELECT_QUEUE_FALLBACK_REMOVED
u16 zxdh_en_select_queue(struct net_device *netdev, struct sk_buff *skb, struct net_device *sb_dev);
#else
u16 zxdh_en_select_queue(struct net_device *netdev, struct sk_buff *skb, struct net_device *sb_dev,
			 select_queue_fallback_t fallback);
#endif
void zxdh_flow_map_cleanup(struct zxdh_en_priv *en_priv);
s32 zxdh_flow_map_init(struct zxdh_en_priv *en_priv);
s32 zxdh_flow_map_update_sysfs(struct net_device *netdev);
void zxdh_netdev_addr_set(struct net_device *dev, const u8 *addr);
void zxdh_netdev_features_over_dtp(struct net_device *netdev);
s32 set_feature_rxhash(struct zxdh_en_device *en_dev, bool enable);
s32 set_feature_ntuple(struct zxdh_en_device *en_dev, bool enable);
s32 zxdh_pf_add_vf_unicast_mac(struct zxdh_en_device *en_dev, struct dhtool_set_vf_mac_msg *msg);
s32 zxdh_pf_del_vf_unicast_mac(struct zxdh_en_device *en_dev, struct dhtool_set_vf_mac_msg *msg);
s32 zxdh_pf_add_vf_multicast_mac(struct zxdh_en_device *en_dev, struct dhtool_set_vf_mac_msg *msg);
s32 zxdh_pf_del_vf_multicast_mac(struct zxdh_en_device *en_dev, struct dhtool_set_vf_mac_msg *msg);
s32 zxdh_pf_transfer_vf_mac(struct zxdh_en_device *en_dev, u32 src_vf, u32 dst_vf);
s32 zxdh_pflags_update(struct net_device *netdev, u8 flag, bool enable);
s32 zxdh_port_enable(struct zxdh_en_device *en_dev, bool enable);
s32 zxdh_en_sync_features(struct zxdh_en_device *en_dev, netdev_features_t want_features);
s32 zxdh_en_config_mtu_to_np(struct net_device *netdev, s32 mtu_value);
s32 zxdh_vlan_trunk_recover(struct dpp_pf_info_t *pf_info, u8 *vlan_trunk_bitmap);

struct zxdh_rdma_if {
	void *(*get_rdma_netdev)(struct dh_core_dev *dh_dev);
};

struct zxdh_sec_if {
	void *(*get_sec_info)(struct dh_core_dev *dh_dev);
};

struct zxdh_en_if {
	u16 (*get_channels_num)(struct dh_core_dev *dh_dev);
	s32 (*create_vqs_channels)(struct dh_core_dev *dh_dev, void *data);
	void (*destroy_vqs_channels)(struct dh_core_dev *dh_dev);
	void (*switch_vqs_channel)(struct dh_core_dev *dh_dev, s32 channel, s32 op);
	s32 (*vqs_channel_bind_handler)(struct dh_core_dev *dh_dev, s32 vqs_channel_num,
					struct dh_vq_handler *handler);
	void (*vqs_channel_unbind_handler)(struct dh_core_dev *dh_dev, s32 vqs_channel_num);
	s32 (*vq_bind_channel)(struct dh_core_dev *dh_dev, s32 channel_num, s32 queue_index,
			       u16 vq_idx);
	void (*vq_unbind_channel)(struct dh_core_dev *dh_dev, s32 queue_index);
	s32 (*vqs_bind_eqs)(struct dh_core_dev *dh_dev, s32 vqs_channel_num,
			    struct list_head *vq_node);
	void (*vqs_unbind_eqs)(struct dh_core_dev *dh_dev, s32 vqs_channel_num);
	void __iomem *(*vp_modern_map_vq_notify)(struct dh_core_dev *dh_dev, u32 index,
						 resource_size_t *pa);
	void (*vp_modern_unmap_vq_notify)(struct dh_core_dev *dh_dev, void *priv);
	s32 (*get_vq_lock)(struct dh_core_dev *dh_dev);
	s32 (*find_valid_vqs)(struct dh_core_dev *dh_dev, u16 vqs_cnt, u32 vq_index[]);
	s32 (*write_vqs_bit)(struct dh_core_dev *dh_dev, u16 vqs_cnt, u32 vq_index[]);
	s32 (*write_queue_tlb)(struct dh_core_dev *dh_dev, u16 vqs_cnt, u32 vq_index[],
			       bool need_msgq);
	u16 (*get_fw_patch)(struct dh_core_dev *dh_dev);
	s32 (*release_vq_lock)(struct dh_core_dev *dh_dev);
	void (*activate_phy_vq)(struct dh_core_dev *dh_dev, u32 phy_index, s32 queue_size,
				u64 desc_addr, u64 driver_addr, u64 device_addr);
	void (*de_activate_phy_vq)(struct dh_core_dev *dh_dev, u32 phy_index);
	void (*set_status)(struct dh_core_dev *dh_dev, u8 status);
	u8 (*get_status)(struct dh_core_dev *dh_dev);
	u8 (*get_cfg_gen)(struct dh_core_dev *dh_dev);
	bool (*get_rp_link_status)(struct dh_core_dev *dh_dev);
	void (*set_vf_mac)(struct dh_core_dev *dh_dev, u8 *mac, s32 vf_id);
	void (*get_vf_mac)(struct dh_core_dev *dh_dev, u8 *mac, s32 vf_id);
	void (*set_mac)(struct dh_core_dev *dh_dev, u8 *mac);
	void (*get_mac)(struct dh_core_dev *dh_dev, u8 *mac);
	u64 (*get_features)(struct dh_core_dev *dh_dev);
	void (*set_features)(struct dh_core_dev *dh_dev, u64 features);
	u16 (*get_queue_num)(struct dh_core_dev *dh_dev);
	u16 (*get_queue_size)(struct dh_core_dev *dh_dev, u32 index);
	void (*set_queue_size)(struct dh_core_dev *dh_dev, u32 index, u16 size);
	void (*set_queue_enable)(struct dh_core_dev *dh_dev, u16 index, bool enable);
	u16 (*get_epbdf)(struct dh_core_dev *dh_dev);
	u64 (*get_spec_sbdf)(struct dh_core_dev *dh_dev);
	bool (*is_multi_ep)(struct dh_core_dev *dh_dev);
	u16 (*get_vport)(struct dh_core_dev *dh_dev);
	u16 (*get_pcie_id)(struct dh_core_dev *dh_dev);
	u16 (*get_slot_id)(struct dh_core_dev *dh_dev);
	bool (*is_bond)(struct dh_core_dev *dh_dev);
	bool (*is_upf)(struct dh_core_dev *dh_dev);
	enum dh_coredev_type (*get_coredev_type)(struct dh_core_dev *dh_dev);
	struct pci_dev *(*get_pdev)(struct dh_core_dev *dh_dev);
	u64 (*get_bar_virt_addr)(struct dh_core_dev *dh_dev, u8 bar_num);
	u64 (*get_bar_phy_addr)(struct dh_core_dev *dh_dev, u8 bar_num);
	u64 (*get_bar_size)(struct dh_core_dev *dh_dev, u8 bar_num);
	s32 (*msg_send_cmd)(struct dh_core_dev *dh_dev, u16 module_id, void *msg, void *ack,
			    struct zxdh_bar_extra_para *para);
	s32 (*async_eq_enable)(struct dh_core_dev *dh_dev, struct dh_eq_async *eq, const char *name,
			       bool attach);
	void (*aux_nh_attach)(struct dh_core_dev *dh_dev, struct dh_nb *nb, bool attach);
	struct zxdh_vf_item *(*get_vf_item)(struct dh_core_dev *dh_dev, u16 vf_idx);
	void (*set_pf_link_up)(struct dh_core_dev *dh_dev, bool link_up);
	bool (*get_pf_link_up)(struct dh_core_dev *dh_dev);
	void (*update_pf_link_info)(struct dh_core_dev *dh_dev,
				    struct link_info_struct *link_info_val);
	s32 (*get_pf_drv_msg)(struct dh_core_dev *dh_dev, u8 *drv_version, u8 *drv_version_len);
	void (*set_vepa)(struct dh_core_dev *dh_dev, bool setting);
	bool (*get_vepa)(struct dh_core_dev *dh_dev);
	void (*set_bond_num)(struct dh_core_dev *dh_dev, bool add);
	bool (*if_init)(struct dh_core_dev *dh_dev);
	s32 (*request_port)(struct dh_core_dev *dh_dev, void *data);
	s32 (*release_port)(struct dh_core_dev *dh_dev, u32 port_id);
	void (*get_link_info_from_vqm)(struct dh_core_dev *dh_dev, u8 *link_up);
	void (*set_vf_link_info)(struct dh_core_dev *dh_dev, u16 vf_idx, u8 link_up);
	bool (*get_vf_is_probe)(struct dh_core_dev *dh_dev, u16 vf_idx);
	void (*set_pf_phy_port)(struct dh_core_dev *dh_dev, u8 phy_port);
	void (*set_rdma_netdev)(struct dh_core_dev *dh_dev, void *data);
	u8 (*get_pf_phy_port)(struct dh_core_dev *dh_dev);
	void (*set_init_comp_flag)(struct dh_core_dev *dh_dev, u8 flag);
	struct zxdh_ipv6_mac_tbl *(*get_ip6mac_tbl)(struct dh_core_dev *dh_dev);
	struct device *(*get_dma_dev)(struct dh_core_dev *dh_dev);
	void (*unplug_adev)(struct dh_core_dev *dh_dev, enum AUX_DEVICE_TYPE adev_type);
	s32 (*plug_adev)(struct dh_core_dev *dh_dev, enum AUX_DEVICE_TYPE adev_type);
	bool (*is_nic)(struct dh_core_dev *dh_dev);
	bool (*is_special_bond)(struct dh_core_dev *dh_dev);
	u8 (*get_qpairs)(struct dh_core_dev *dh_dev);
	s32 (*eth_config_recover)(struct net_device *netdev);
	void (*eth_config_show)(struct net_device *netdev);
	s32 (*events_call_chain)(struct dh_core_dev *dh_dev, unsigned long type, void *data);
	s32 (*get_cpl_timeout_if_mask)(struct dh_core_dev *dh_dev);
	s32 (*set_cpl_timeout_mask)(struct dh_core_dev *dh_dev, u32 mask);
	s32 (*get_hp_irq_ctrl_status)(struct dh_core_dev *dh_dev);
	s32 (*set_hp_irq_ctrl_status)(struct dh_core_dev *dh_dev, u32 status);
	u32 (*get_dev_type)(struct dh_core_dev *dh_dev);
	bool (*if_suport_np_ext_stats)(struct dh_core_dev *dh_dev);
	struct zxdh_np_ext_stats *(*get_np_ext_stats)(struct dh_core_dev *dh_dev, u8 panel_id);
	void (*set_sec_info)(struct dh_core_dev *dh_dev, void *data);
	bool (*is_drs_sec_enable)(struct dh_core_dev *dh_dev);
	bool (*is_fw_feature_support)(struct dh_core_dev *dh_dev, u32 feature);
	bool (*is_pf_rate_enable)(struct dh_core_dev *dh_dev, u32 *pf_fc_val);
	u16 (*get_ovs_pf_vfid)(struct dh_core_dev *dh_dev);
	u8 (*get_board_type)(struct dh_core_dev *dh_dev);
	bool (*is_hwbond)(struct dh_core_dev *dh_dev, bool is_hwbond, bool update_pf);
	bool (*is_rdma_aux_plug)(struct dh_core_dev *dh_dev, bool is_rdma_aux_plug, bool update_pf);
	bool (*is_primary_port)(struct dh_core_dev *dh_dev, bool is_primary_port, bool update_pf);
	void (*optim_hardware_bond_time)(struct dh_core_dev *dh_dev, bool enable);
	s32 (*update_hb_file_val)(struct dh_core_dev *dh_dev, u64 spec_sbdf, const char *file_name,
				  bool flag);
	bool (*is_rdma_enable)(struct dh_core_dev *dh_dev);
};
extern s32 zxdh_get_ptp_clock_index(struct zxdh_en_device *en_dev, u32 *ptp_clock_idx);

#endif
