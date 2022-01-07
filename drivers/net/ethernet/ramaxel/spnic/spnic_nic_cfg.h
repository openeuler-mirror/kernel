/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2021 Ramaxel Memory Technology, Ltd */

#ifndef SPNIC_NIC_CFG_H
#define SPNIC_NIC_CFG_H

#include <linux/if_link.h>

#include "spnic_nic_cmd.h"
#include "spnic_mgmt_interface.h"
#include "spnic_mag_cmd.h"

#define OS_VF_ID_TO_HW(os_vf_id) ((os_vf_id) + 1)
#define HW_VF_ID_TO_OS(hw_vf_id) ((hw_vf_id) - 1)

#define SPNIC_VLAN_PRIORITY_SHIFT	13

#define SPNIC_RSS_KEY_RSV_NUM		2

#define SPNIC_MIN_MTU_SIZE		256
#define SPNIC_MAX_JUMBO_FRAME_SIZE	9600

#define SPNIC_PF_SET_VF_ALREADY		0x4
#define SPNIC_MGMT_STATUS_EXIST		0x6

#define SPNIC_LOWEST_LATENCY		1
#define SPNIC_MULTI_VM_LATENCY		32
#define SPNIC_MULTI_VM_PENDING_LIMIT	4
#define SPNIC_RX_RATE_LOW		400000
#define SPNIC_RX_COAL_TIME_LOW		16
#define SPNIC_RX_PENDING_LIMIT_LOW	2
#define SPNIC_RX_RATE_HIGH		1000000
#define SPNIC_RX_COAL_TIME_HIGH		225
#define SPNIC_RX_PENDING_LIMIT_HIGH	8
#define SPNIC_RX_RATE_THRESH		50000
#define SPNIC_TX_RATE_THRESH		50000
#define SPNIC_RX_RATE_LOW_VM		100000
#define SPNIC_RX_PENDING_LIMIT_HIGH_VM	87

enum spnic_valid_link_settings {
	HILINK_LINK_SET_SPEED = 0x1,
	HILINK_LINK_SET_AUTONEG = 0x2,
	HILINK_LINK_SET_FEC = 0x4,
};

struct spnic_link_ksettings {
	u32 valid_bitmap;
	u8 speed;   /* enum nic_speed_level */
	u8 autoneg; /* 0 - off; 1 - on */
	u8 fec;	    /* 0 - RSFEC; 1 - BASEFEC; 2 - NOFEC */
};

u64 spnic_get_feature_cap(void *hwdev);

#define SPNIC_SUPPORT_FEATURE(hwdev, feature)	(spnic_get_feature_cap(hwdev) & NIC_F_##feature)
#define SPNIC_SUPPORT_CSUM(hwdev)		SPNIC_SUPPORT_FEATURE(hwdev, CSUM)
#define SPNIC_SUPPORT_SCTP_CRC(hwdev)		SPNIC_SUPPORT_FEATURE(hwdev, SCTP_CRC)
#define SPNIC_SUPPORT_TSO(hwdev)		SPNIC_SUPPORT_FEATURE(hwdev, TSO)
#define SPNIC_SUPPORT_UFO(hwdev)		SPNIC_SUPPORT_FEATURE(hwdev, UFO)
#define SPNIC_SUPPORT_LRO(hwdev)		SPNIC_SUPPORT_FEATURE(hwdev, LRO)
#define SPNIC_SUPPORT_RSS(hwdev)		SPNIC_SUPPORT_FEATURE(hwdev, RSS)
#define SPNIC_SUPPORT_RXVLAN_FILTER(hwdev)	SPNIC_SUPPORT_FEATURE(hwdev, RX_VLAN_FILTER)
#define SPNIC_SUPPORT_VLAN_OFFLOAD(hwdev)	(SPNIC_SUPPORT_FEATURE(hwdev, RX_VLAN_STRIP) && \
						 SPNIC_SUPPORT_FEATURE(hwdev, TX_VLAN_INSERT))
#define SPNIC_SUPPORT_VXLAN_OFFLOAD(hwdev)	SPNIC_SUPPORT_FEATURE(hwdev, VXLAN_OFFLOAD)
#define SPNIC_SUPPORT_IPSEC_OFFLOAD(hwdev)	SPNIC_SUPPORT_FEATURE(hwdev, IPSEC_OFFLOAD)
#define SPNIC_SUPPORT_FDIR(hwdev)		SPNIC_SUPPORT_FEATURE(hwdev, FDIR)
#define SPNIC_SUPPORT_PROMISC(hwdev)		SPNIC_SUPPORT_FEATURE(hwdev, PROMISC)
#define SPNIC_SUPPORT_ALLMULTI(hwdev)		SPNIC_SUPPORT_FEATURE(hwdev, ALLMULTI)

struct nic_rss_type {
	u8 tcp_ipv6_ext;
	u8 ipv6_ext;
	u8 tcp_ipv6;
	u8 ipv6;
	u8 tcp_ipv4;
	u8 ipv4;
	u8 udp_ipv6;
	u8 udp_ipv4;
};

enum spnic_rss_hash_type {
	SPNIC_RSS_HASH_ENGINE_TYPE_XOR = 0,
	SPNIC_RSS_HASH_ENGINE_TYPE_TOEP,
	SPNIC_RSS_HASH_ENGINE_TYPE_MAX,
};

/* rss */
struct nic_rss_indirect_tbl {
	u32 rsvd[4]; /* Make sure that 16B beyond entry[] */
	u16 entry[SPNIC_RSS_INDIR_SIZE];
};

struct nic_rss_context_tbl {
	u32 rsvd[4];
	u32 ctx;
};

#define NIC_CONFIG_ALL_QUEUE_VLAN_CTX 0xFFFF
struct nic_vlan_ctx {
	u32 func_id;
	u32 qid; /* if qid = 0xFFFF, config current function all queue */
	u32 vlan_tag;
	u32 vlan_mode;
	u32 vlan_sel;
};

enum spnic_link_status {
	SPNIC_LINK_DOWN = 0,
	SPNIC_LINK_UP
};

struct nic_port_info {
	u8 port_type;
	u8 autoneg_cap;
	u8 autoneg_state;
	u8 duplex;
	u8 speed;
	u8 fec;
	u32 supported_mode;
	u32 advertised_mode;
};

struct nic_pause_config {
	u8 auto_neg;
	u8 rx_pause;
	u8 tx_pause;
};

#define MODULE_TYPE_SFP		0x3
#define MODULE_TYPE_QSFP28	0x11
#define MODULE_TYPE_QSFP	0x0C
#define MODULE_TYPE_QSFP_PLUS	0x0D

#define TCAM_IP_TYPE_MASK	0x1
#define TCAM_TUNNEL_TYPE_MASK	0xF
#define TCAM_FUNC_ID_MASK	0x7FFF

struct spnic_tcam_key_ipv4_mem {
	u32 rsvd1:4;
	u32 tunnel_type:4;
	u32 ip_proto:8;
	u32 rsvd0:16;
	u32 sipv4_h:16;
	u32 ip_type:1;
	u32 function_id:15;
	u32 dipv4_h:16;
	u32 sipv4_l:16;
	u32 rsvd2:16;
	u32 dipv4_l:16;
	u32 rsvd3;
	u32 dport:16;
	u32 rsvd4:16;
	u32 rsvd5:16;
	u32 sport:16;
	u32 outer_sipv4_h:16;
	u32 rsvd6:16;
	u32 outer_dipv4_h:16;
	u32 outer_sipv4_l:16;
	u32 vni_h:16;
	u32 outer_dipv4_l:16;
	u32 rsvd7:16;
	u32 vni_l:16;
};

struct spnic_tcam_key_ipv6_mem {
	u32 rsvd1:4;
	u32 tunnel_type:4;
	u32 ip_proto:8;
	u32 rsvd0:16;
	u32 sipv6_key0:16;
	u32 ip_type:1;
	u32 function_id:15;
	u32 sipv6_key2:16;
	u32 sipv6_key1:16;
	u32 sipv6_key4:16;
	u32 sipv6_key3:16;
	u32 sipv6_key6:16;
	u32 sipv6_key5:16;
	u32 dport:16;
	u32 sipv6_key7:16;
	u32 dipv6_key0:16;
	u32 sport:16;
	u32 dipv6_key2:16;
	u32 dipv6_key1:16;
	u32 dipv6_key4:16;
	u32 dipv6_key3:16;
	u32 dipv6_key6:16;
	u32 dipv6_key5:16;
	u32 rsvd2:16;
	u32 dipv6_key7:16;
};

struct tag_tcam_key {
	union {
		struct spnic_tcam_key_ipv4_mem key_info;
		struct spnic_tcam_key_ipv6_mem key_info_ipv6;
	};

	union {
		struct spnic_tcam_key_ipv4_mem key_mask;
		struct spnic_tcam_key_ipv6_mem key_mask_ipv6;
	};
};

int spnic_add_tcam_rule(void *hwdev, struct nic_tcam_cfg_rule *tcam_rule);
int spnic_del_tcam_rule(void *hwdev, u32 index);

int spnic_alloc_tcam_block(void *hwdev, u16 *index);
int spnic_free_tcam_block(void *hwdev, u16 *index);

int spnic_set_fdir_tcam_rule_filter(void *hwdev, bool enable);

int spnic_flush_tcam_rule(void *hwdev);

/* *
 * @brief spnic_update_mac - update mac address to hardware
 * @param hwdev: device pointer to hwdev
 * @param old_mac: old mac to delete
 * @param new_mac: new mac to update
 * @param vlan_id: vlan id
 * @param func_id: function index
 * @retval zero: success
 * @retval non-zero: failure
 */
int spnic_update_mac(void *hwdev, u8 *old_mac, u8 *new_mac, u16 vlan_id, u16 func_id);

/* *
 * @brief spnic_get_default_mac - get default mac address
 * @param hwdev: device pointer to hwdev
 * @param mac_addr: mac address from hardware
 * @retval zero: success
 * @retval non-zero: failure
 */
int spnic_get_default_mac(void *hwdev, u8 *mac_addr);

/* *
 * @brief spnic_set_port_mtu - set function mtu
 * @param hwdev: device pointer to hwdev
 * @param new_mtu: mtu
 * @retval zero: success
 * @retval non-zero: failure
 */
int spnic_set_port_mtu(void *hwdev, u16 new_mtu);

/* *
 * @brief spnic_get_link_state - get link state
 * @param hwdev: device pointer to hwdev
 * @param link_state: link state, 0-link down, 1-link up
 * @retval zero: success
 * @retval non-zero: failure
 */
int spnic_get_link_state(void *hwdev, u8 *link_state);

/* *
 * @brief spnic_get_vport_stats - get function stats
 * @param hwdev: device pointer to hwdev
 * @param stats: function stats
 * @retval zero: success
 * @retval non-zero: failure
 */
int spnic_get_vport_stats(void *hwdev, struct spnic_vport_stats *stats);

/* *
 * @brief spnic_notify_all_vfs_link_changed - notify to all vfs link changed
 * @param hwdev: device pointer to hwdev
 * @param link_status: link state, 0-link down, 1-link up
 */
void spnic_notify_all_vfs_link_changed(void *hwdev, u8 link_status);

/* *
 * @brief spnic_force_drop_tx_pkt - force drop tx packet
 * @param hwdev: device pointer to hwdev
 * @retval zero: success
 * @retval non-zero: failure
 */
int spnic_force_drop_tx_pkt(void *hwdev);

/* *
 * @brief spnic_set_rx_mode - set function rx mode
 * @param hwdev: device pointer to hwdev
 * @param enable: rx mode state
 * @retval zero: success
 * @retval non-zero: failure
 */
int spnic_set_rx_mode(void *hwdev, u32 enable);

/* *
 * @brief spnic_set_rx_vlan_offload - set function vlan offload valid state
 * @param hwdev: device pointer to hwdev
 * @param en: 0-disable, 1-enable
 * @retval zero: success
 * @retval non-zero: failure
 */
int spnic_set_rx_vlan_offload(void *hwdev, u8 en);

/* *
 * @brief spnic_set_rx_lro_state - set rx LRO configuration
 * @param hwdev: device pointer to hwdev
 * @param lro_en: 0-disable, 1-enable
 * @param lro_timer: LRO aggregation timeout
 * @param lro_max_pkt_len: LRO coalesce packet size(unit is 1K)
 * @retval zero: success
 * @retval non-zero: failure
 */
int spnic_set_rx_lro_state(void *hwdev, u8 lro_en, u32 lro_timer, u32 lro_max_pkt_len);

/* *
 * @brief spnic_set_vf_spoofchk - set vf spoofchk
 * @param hwdev: device pointer to hwdev
 * @param vf_id:  vf id
 * @param spoofchk: spoofchk
 * @retval zero: success
 * @retval non-zero: failure
 */
int spnic_set_vf_spoofchk(void *hwdev, u16 vf_id, bool spoofchk);

/* *
 * @brief spnic_vf_info_spoofchk - get vf spoofchk info
 * @param hwdev: device pointer to hwdev
 * @param vf_id: vf id
 * @retval spoofchk state
 */
bool spnic_vf_info_spoofchk(void *hwdev, int vf_id);

/* *
 * @brief spnic_add_vf_vlan - add vf vlan id
 * @param hwdev: device pointer to hwdev
 * @param vf_id: vf id
 * @param vlan: vlan id
 * @param qos: qos
 * @retval zero: success
 * @retval non-zero: failure
 */
int spnic_add_vf_vlan(void *hwdev, int vf_id, u16 vlan, u8 qos);

/* *
 * @brief spnic_kill_vf_vlan - kill vf vlan
 * @param hwdev: device pointer to hwdev
 * @param vf_id: vf id
 * @param vlan: vlan id
 * @retval zero: success
 * @retval non-zero: failure
 */
int spnic_kill_vf_vlan(void *hwdev, int vf_id);

/* *
 * @brief spnic_set_vf_mac - set vf mac
 * @param hwdev: device pointer to hwdev
 * @param vf_id: vf id
 * @param mac_addr: vf mac address
 * @retval zero: success
 * @retval non-zero: failure
 */
int spnic_set_vf_mac(void *hwdev, int vf_id, unsigned char *mac_addr);

/* *
 * @brief spnic_vf_info_vlanprio - get vf vlan priority
 * @param hwdev: device pointer to hwdev
 * @param vf_id: vf id
 * @retval zero: vlan priority
 */
u16 spnic_vf_info_vlanprio(void *hwdev, int vf_id);

/* *
 * @brief spnic_set_vf_tx_rate - set vf tx rate
 * @param hwdev: device pointer to hwdev
 * @param vf_id: vf id
 * @param max_rate: max rate
 * @param min_rate: min rate
 * @retval zero: success
 * @retval non-zero: failure
 */
int spnic_set_vf_tx_rate(void *hwdev, u16 vf_id, u32 max_rate, u32 min_rate);

/* *
 * @brief spnic_set_vf_tx_rate - set vf tx rate
 * @param hwdev: device pointer to hwdev
 * @param vf_id: vf id
 * @param ivi: vf info
 * @retval zero: success
 * @retval non-zero: failure
 */
void spnic_get_vf_config(void *hwdev, u16 vf_id, struct ifla_vf_info *ivi);

/* *
 * @brief spnic_set_vf_link_state - set vf link state
 * @param hwdev: device pointer to hwdev
 * @param vf_id: vf id
 * @param link: link state
 * @retval zero: success
 * @retval non-zero: failure
 */
int spnic_set_vf_link_state(void *hwdev, u16 vf_id, int link);

/* *
 * @brief spnic_get_port_info - set port info
 * @param hwdev: device pointer to hwdev
 * @param port_info: port info
 * @param channel: channel id
 * @retval zero: success
 * @retval non-zero: failure
 */
int spnic_get_port_info(void *hwdev, struct nic_port_info *port_info, u16 channel);

/* *
 * @brief spnic_set_rss_type - set rss type
 * @param hwdev: device pointer to hwdev
 * @param rss_type: rss type
 * @retval zero: success
 * @retval non-zero: failure
 */
int spnic_set_rss_type(void *hwdev, struct nic_rss_type rss_type);

/* *
 * @brief spnic_get_rss_type - get rss type
 * @param hwdev: device pointer to hwdev
 * @param rss_type: rss type
 * @retval zero: success
 * @retval non-zero: failure
 */
int spnic_get_rss_type(void *hwdev, struct nic_rss_type *rss_type);

/* *
 * @brief spnic_rss_get_hash_engine - get rss hash engine
 * @param hwdev: device pointer to hwdev
 * @param type: hash engine
 * @retval zero: success
 * @retval non-zero: failure
 */
int spnic_rss_get_hash_engine(void *hwdev, u8 *type);

/* *
 * @brief spnic_rss_set_hash_engine - set rss hash engine
 * @param hwdev: device pointer to hwdev
 * @param type: hash engine
 * @retval zero: success
 * @retval non-zero: failure
 */
int spnic_rss_set_hash_engine(void *hwdev, u8 type);

/* *
 * @brief spnic_rss_cfg - set rss configuration
 * @param hwdev: device pointer to hwdev
 * @param rss_en: enable rss flag
 * @param type: number of TC
 * @param prio_tc: priorityof TC
 * @param num_qps: number of queue
 * @retval zero: success
 * @retval non-zero: failure
 */
int spnic_rss_cfg(void *hwdev, u8 rss_en, u8 tc_num, u8 *prio_tc, u16 num_qps);

/* *
 * @brief spnic_rss_set_template_tbl - set template table
 * @param hwdev: device pointer to hwdev
 * @param key: rss key
 * @retval zero: success
 * @retval non-zero: failure
 */
int spnic_rss_set_hash_key(void *hwdev, const u8 *key);

/* *
 * @brief spnic_rss_get_template_tbl - get template table
 * @param hwdev: device pointer to hwdev
 * @param key: rss key
 * @retval zero: success
 * @retval non-zero: failure
 */
int spnic_rss_get_hash_key(void *hwdev, u8 *key);

/* *
 * @brief spnic_refresh_nic_cfg - refresh port cfg
 * @param hwdev: device pointer to hwdev
 * @param port_info: port information
 * @retval zero: success
 * @retval non-zero: failure
 */
int spnic_refresh_nic_cfg(void *hwdev, struct nic_port_info *port_info);

/* *
 * @brief spnic_add_vlan - add vlan
 * @param hwdev: device pointer to hwdev
 * @param vlan_id: vlan id
 * @param func_id: function id
 * @retval zero: success
 * @retval non-zero: failure
 */
int spnic_add_vlan(void *hwdev, u16 vlan_id, u16 func_id);

/* *
 * @brief spnic_del_vlan - delete vlan
 * @param hwdev: device pointer to hwdev
 * @param vlan_id: vlan id
 * @param func_id: function id
 * @retval zero: success
 * @retval non-zero: failure
 */
int spnic_del_vlan(void *hwdev, u16 vlan_id, u16 func_id);

/* *
 * @brief spnic_set_mac - set mac address
 * @param hwdev: device pointer to hwdev
 * @param mac_addr: mac address from hardware
 * @param vlan_id: vlan id
 * @param func_id: function index
 * @param channel: channel id
 * @retval zero: success
 * @retval non-zero: failure
 */
int spnic_set_mac(void *hwdev, const u8 *mac_addr, u16 vlan_id, u16 func_id, u16 channel);

/* *
 * @brief spnic_del_mac - delete mac address
 * @param hwdev: device pointer to hwdev
 * @param mac_addr: mac address from hardware
 * @param vlan_id: vlan id
 * @param func_id: function index
 * @param channel: channel id
 * @retval zero: success
 * @retval non-zero: failure
 */
int spnic_del_mac(void *hwdev, const u8 *mac_addr, u16 vlan_id, u16 func_id, u16 channel);

/* *
 * @brief spnic_set_vport_enable - set function valid status
 * @param hwdev: device pointer to hwdev
 * @param func_id: global function index
 * @param enable: 0-disable, 1-enable
 * @param channel: channel id
 * @retval zero: success
 * @retval non-zero: failure
 */
int spnic_set_vport_enable(void *hwdev, u16 func_id, bool enable, u16 channel);

/* *
 * @brief spnic_set_port_enable - set port status
 * @param hwdev: device pointer to hwdev
 * @param enable: 0-disable, 1-enable
 * @param channel: channel id
 * @retval zero: success
 * @retval non-zero: failure
 */
int spnic_set_port_enable(void *hwdev, bool enable, u16 channel);

/* *
 * @brief spnic_flush_qps_res - flush queue pairs resource in hardware
 * @param hwdev: device pointer to hwdev
 * @retval zero: success
 * @retval non-zero: failure
 */
int spnic_flush_qps_res(void *hwdev);

/* *
 * @brief spnic_init_nic_hwdev - init nic hwdev
 * @param hwdev: device pointer to hwdev
 * @param pcidev_hdl: pointer to pcidev or handler
 * @param dev_hdl: pointer to pcidev->dev or handler, for sdk_err() or
 * dma_alloc()
 * @param rx_buff_len: rx_buff_len is receive buffer length
 * @retval zero: success
 * @retval non-zero: failure
 */
int spnic_init_nic_hwdev(void *hwdev, void *pcidev_hdl, void *dev_hdl, u16 rx_buff_len);

/* *
 * @brief spnic_free_nic_hwdev - free nic hwdev
 * @param hwdev: device pointer to hwdev
 * @retval zero: success
 * @retval non-zero: failure
 */
void spnic_free_nic_hwdev(void *hwdev);

/* *
 * @brief spnic_get_speed - set link speed
 * @param hwdev: device pointer to hwdev
 * @param port_info: link speed
 * @param channel: channel id
 * @retval zero: success
 * @retval non-zero: failure
 */
int spnic_get_speed(void *hwdev, enum mag_cmd_port_speed *speed, u16 channel);

int spnic_get_dcb_state(void *hwdev, struct spnic_dcb_state *dcb_state);

int spnic_get_pf_dcb_state(void *hwdev, struct spnic_dcb_state *dcb_state);

/* *
 * @brief spnic_create_qps - create queue pairs
 * @param hwdev: device pointer to hwdev
 * @param num_qp: number of queue pairs
 * @param sq_depth: sq depth
 * @param rq_depth: rq depth
 * @param qps_msix_arry: msix info
 * @retval zero: success
 * @retval non-zero: failure
 */
int spnic_create_qps(void *hwdev, u16 num_qp, u32 sq_depth, u32 rq_depth,
		     struct irq_info *qps_msix_arry);

/* *
 * @brief spnic_destroy_qps - destroy queue pairs
 * @param hwdev: device pointer to hwdev
 */
void spnic_destroy_qps(void *hwdev);

enum spnic_queue_type {
	SPNIC_SQ,
	SPNIC_RQ,
	SPNIC_MAX_QUEUE_TYPE
};

/* *
 * @brief spnic_get_nic_queue - get nic queue
 * @param hwdev: device pointer to hwdev
 * @param q_id: queue index
 * @param q_type: queue type
 * @retval queue address
 */
void *spnic_get_nic_queue(void *hwdev, u16 q_id, enum spnic_queue_type q_type);

/* *
 * @brief spnic_init_qp_ctxts - init queue pair context
 * @param hwdev: device pointer to hwdev
 * @retval zero: success
 * @retval non-zero: failure
 */
int spnic_init_qp_ctxts(void *hwdev);

/* *
 * @brief spnic_free_qp_ctxts - free queue pairs
 * @param hwdev: device pointer to hwdev
 */
void spnic_free_qp_ctxts(void *hwdev);

/* *
 * @brief spnic_rss_set_indir_tbl - set rss indirect table
 * @param hwdev: device pointer to hwdev
 * @param indir_table: rss indirect table
 * @retval zero: success
 * @retval non-zero: failure
 */
int spnic_rss_set_indir_tbl(void *hwdev, const u32 *indir_table);

/* *
 * @brief spnic_rss_get_indir_tbl - get rss indirect table
 * @param hwdev: device pointer to hwdev
 * @param indir_table: rss indirect table
 * @retval zero: success
 * @retval non-zero: failure
 */
int spnic_rss_get_indir_tbl(void *hwdev, u32 *indir_table);

/* *
 * @brief spnic_get_phy_port_stats - get port stats
 * @param hwdev: device pointer to hwdev
 * @param stats: port stats
 * @retval zero: success
 * @retval non-zero: failure
 */
int spnic_get_phy_port_stats(void *hwdev, struct mag_cmd_port_stats *stats);

int spnic_set_port_funcs_state(void *hwdev, bool enable);

int spnic_reset_port_link_cfg(void *hwdev);

int spnic_force_port_relink(void *hwdev);

int spnic_set_dcb_state(void *hwdev, struct spnic_dcb_state *dcb_state);

int spnic_dcb_set_pfc(void *hwdev, u8 pfc_en, u8 pfc_bitmap);

int spnic_dcb_get_pfc(void *hwdev, u8 *pfc_en_bitmap);

int spnic_dcb_set_ets(void *hwdev, u8 *cos_tc, u8 *cos_bw, u8 *cos_prio, u8 *tc_bw, u8 *tc_prio);

int spnic_dcb_set_cos_up_map(void *hwdev, u8 cos_valid_bitmap, u8 *cos_up, u8 max_cos_num);

int spnic_get_pause_info(void *hwdev, struct nic_pause_config *nic_pause);

int spnic_set_pause_info(void *hwdev, struct nic_pause_config nic_pause);

int spnic_set_link_settings(void *hwdev, struct spnic_link_ksettings *settings);

int spnic_set_vlan_fliter(void *hwdev, u32 vlan_filter_ctrl);

void spnic_clear_vfs_info(void *hwdev);

int spnic_update_mac_vlan(void *hwdev, u16 old_vlan, u16 new_vlan, int vf_id);

int spnic_set_led_status(void *hwdev, enum mag_led_type type, enum mag_led_mode mode);

int spnic_set_func_capture_en(void *hwdev, u16 func_id, bool cap_en);

int spnic_set_loopback_mode(void *hwdev, u8 mode, u8 enable);
int spnic_get_loopback_mode(void *hwdev, u8 *mode, u8 *enable);

bool spnic_get_vf_trust(void *hwdev, int vf_id);
int spnic_set_vf_trust(void *hwdev, u16 vf_id, bool trust);

int spnic_set_autoneg(void *hwdev, bool enable);

int spnic_get_sfp_type(void *hwdev, u8 *sfp_type, u8 *sfp_type_ext);
int spnic_get_sfp_eeprom(void *hwdev, u8 *data, u32 len);

int spnic_set_nic_feature(void *hwdev, u64 *s_feature, u16 size);

#endif
