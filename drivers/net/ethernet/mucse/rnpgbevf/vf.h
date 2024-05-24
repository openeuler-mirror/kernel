/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2022 - 2024 Mucse Corporation. */

#ifndef __RNPGBE_VF_H__
#define __RNPGBE_VF_H__

#include <linux/pci.h>
#include <linux/delay.h>
#include <linux/interrupt.h>
#include <linux/if_ether.h>
#include <linux/netdevice.h>
#include <linux/aer.h>

#include "rnpgbevf_defines.h"
#include "rnpgbevf_regs.h"
#include "rnpgbevf_mbx.h"

struct rnpgbevf_hw;

/* iterator type for walking multicast address lists */
typedef u8 *(*rnp_mc_addr_itr)(struct rnpgbevf_hw *hw, u8 **mc_addr_ptr,
			       u32 *vmdq);
struct rnp_mac_operations {
	s32 (*init_hw)(struct rnpgbevf_hw *hw);
	s32 (*reset_hw)(struct rnpgbevf_hw *hw);
	s32 (*start_hw)(struct rnpgbevf_hw *hw);
	s32 (*clear_hw_cntrs)(struct rnpgbevf_hw *hw);
	enum rnp_media_type (*get_media_type)(struct rnpgbevf_hw *hw);
	u32 (*get_supported_physical_layer)(struct rnpgbevf_hw *hw);
	s32 (*get_mac_addr)(struct rnpgbevf_hw *hw, u8 *mac);
	s32 (*get_queues)(struct rnpgbevf_hw *hw);
	s32 (*stop_adapter)(struct rnpgbevf_hw *hw);
	s32 (*get_bus_info)(struct rnpgbevf_hw *hw);
	int (*read_eth_reg)(struct rnpgbevf_hw *hw, int reg, u32 *value);

	int (*get_mtu)(struct rnpgbevf_hw *hw);
	int (*set_mtu)(struct rnpgbevf_hw *hw, int mtu);
	int (*req_reset_pf)(struct rnpgbevf_hw *hw);

	/* Link */
	s32 (*setup_link)(struct rnpgbevf_hw *hw, rnp_link_speed speed,
			  bool autoneg, bool autoneg_wait_to_complete);
	s32 (*check_link)(struct rnpgbevf_hw *hw, rnp_link_speed *speed,
			  bool *link_up, bool autoneg_wait_to_complete);
	s32 (*get_link_capabilities)(struct rnpgbevf_hw *hw, rnp_link_speed *speed,
				     bool *autoneg_wait_to_complete);

	/* RAR, Multicast, VLAN */
	s32 (*set_rar)(struct rnpgbevf_hw *hw, u32 index, u8 *addr, u32 vmdq);
	s32 (*set_uc_addr)(struct rnpgbevf_hw *hw, u32 index, u8 *addr);
	s32 (*init_rx_addrs)(struct rnpgbevf_hw *hw);
	s32 (*update_mc_addr_list)(struct rnpgbevf_hw *hw, struct net_device *netdev);
	s32 (*enable_mc)(struct rnpgbevf_hw *hw);
	s32 (*disable_mc)(struct rnpgbevf_hw *hw);
	s32 (*clear_vfta)(struct rnpgbevf_hw *hw);
	s32 (*set_vfta)(struct rnpgbevf_hw *hw, u32 vlan, u32 vind, bool vlan_on);
	s32 (*set_vlan_strip)(struct rnpgbevf_hw *hw, bool vlan_on);
};

enum rnp_mac_type {
	rnp_mac_unknown = 0,
	rnp_mac_2port_10G,
	rnp_mac_2port_40G,
	rnp_mac_4port_10G,
	rnp_mac_8port_10G,
	rnp_num_macs
};

enum rnp_board_type {
	rnp_board_n10,
	rnp_board_n500,
	rnp_board_n210,
};

struct rnp_mac_info {
	struct rnp_mac_operations ops;
	u8 addr[6];
	u8 perm_addr[6];

	enum rnp_mac_type type;

	s32 mc_filter_type;
	u32 dma_version;

	bool get_link_status;
	u32 max_tx_queues;
	u32 max_rx_queues;
	u32 max_msix_vectors;
};

#define RNP_MAX_TRAFFIC_CLASS 4
enum rnp_fc_mode {
	rnp_fc_none = 0,
	rnp_fc_rx_pause,
	rnp_fc_tx_pause,
	rnp_fc_full,
	rnp_fc_default
};

struct rnp_fc_info {
	u32 high_water[RNP_MAX_TRAFFIC_CLASS]; /* Flow Control High-water */
	u32 low_water[RNP_MAX_TRAFFIC_CLASS]; /* Flow Control Low-water */
	u16 pause_time; /* Flow Control Pause timer */
	bool send_xon; /* Flow control send XON */
	bool strict_ieee; /* Strict IEEE mode */
	bool disable_fc_autoneg; /* Do not autonegotiate FC */
	bool fc_was_autonegged; /* Is current_mode the result of autonegging? */
	enum rnp_fc_mode current_mode; /* FC mode in effect */
	enum rnp_fc_mode requested_mode; /* FC mode requested by caller */
};

struct rnp_mbx_operations {
	s32 (*init_params)(struct rnpgbevf_hw *hw);
	s32 (*read)(struct rnpgbevf_hw *hw, u32 *msg, u16 size, bool to_cm3);
	s32 (*write)(struct rnpgbevf_hw *hw, u32 *msg, u16 size, bool to_cm3);
	s32 (*read_posted)(struct rnpgbevf_hw *hw, u32 *msg, u16 size, bool to_cm3);
	s32 (*write_posted)(struct rnpgbevf_hw *hw, u32 *msg, u16 size, bool to_cm3);
	s32 (*check_for_msg)(struct rnpgbevf_hw *hw, bool to_cm3);
	s32 (*check_for_ack)(struct rnpgbevf_hw *hw, bool to_cm3);
	s32 (*check_for_rst)(struct rnpgbevf_hw *hw, bool to_cm3);
	s32 (*configure)(struct rnpgbevf_hw *hw, int nr_vec, bool enable);
};

struct rnpgbevf_hw_operations {
	void (*set_veb_mac)(struct rnpgbevf_hw *hw, u8 *mac, u32 vf_num, u32 ring);
	void (*set_veb_vlan)(struct rnpgbevf_hw *hw, u16 vid, u32 vf_num);
};

struct rnp_mbx_stats {
	u32 msgs_tx;
	u32 msgs_rx;

	u32 acks;
	u32 reqs;
	u32 rsts;
};

struct rnp_mbx_info {
	struct rnp_mbx_operations ops;
	struct rnp_mbx_stats stats;
	u32 timeout;
	u32 udelay;
	u32 v2p_mailbox;
	u16 size;

	u16 pf_req;
	u16 pf_ack;
	u16 cpu_req;
	u16 cpu_ack;

	u32 vf_num_mask;
	// add reg define
	int mbx_size;

	int mbx_mem_size;
	// cm3 <-> pf mbx
	u32 cpu_pf_shm_base;
	u32 pf2cpu_mbox_ctrl;
	u32 pf2cpu_mbox_mask;
	u32 cpu_pf_mbox_mask;
	u32 cpu2pf_mbox_vec;
	// cm3 <-> vf mbx
	u32 cpu_vf_shm_base;
	u32 cpu2vf_mbox_vec_base;
	u32 cpu_vf_mbox_mask_lo_base;
	u32 cpu_vf_mbox_mask_hi_base;

	// pf <--> vf mbx
	u32 pf_vf_shm_base;
	u32 vf2cpu_mbox_ctrl_base;
	u32 pf2vf_mbox_ctrl_base;
	u32 pf_vf_mbox_mask_lo;
	u32 pf_vf_mbox_mask_hi;
	u32 pf2vf_mbox_vec_base;
	u32 vf2pf_mbox_vec_base;
	u32 vf2pf_mbox_ctrl_base;
};

struct rnpgbevf_hw_stats_own {
	u64 vlan_add_cnt;
	u64 vlan_strip_cnt;
	u64 csum_err;
	u64 csum_good;
};

struct rnpgbevf_hw_stats {
	u64 base_vfgprc;
	u64 base_vfgptc;
	u64 base_vfgorc;
	u64 base_vfgotc;
	u64 base_vfmprc;

	u64 last_vfgprc;
	u64 last_vfgptc;
	u64 last_vfgorc;
	u64 last_vfgotc;
	u64 last_vfmprc;

	u64 vfgprc;
	u64 vfgptc;
	u64 vfgorc;
	u64 vfgotc;
	u64 vfmprc;

	u64 saved_reset_vfgprc;
	u64 saved_reset_vfgptc;
	u64 saved_reset_vfgorc;
	u64 saved_reset_vfgotc;
	u64 saved_reset_vfmprc;
};

struct rnpgbevf_info {
	enum rnp_mac_type mac;
	enum rnp_board_type board_type;
	const struct rnp_mac_operations *mac_ops;
	s32 (*get_invariants)(struct rnpgbevf_hw *hw);
};

void rnpgbevf_rlpml_set_vf(struct rnpgbevf_hw *hw, u16 max_size);
//int rnpgbevf_negotiate_api_version(struct rnpgbevf_hw *hw, int api);
//int rnpgbevf_get_queues(struct rnpgbevf_hw *hw, unsigned int *num_tcs, unsigned int *default_tc);
#endif /* __RNP_VF_H__ */
