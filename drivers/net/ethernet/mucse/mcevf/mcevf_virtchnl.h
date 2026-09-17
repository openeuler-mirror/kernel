/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2020-2026 Mucse Corporation. */

#ifndef _MCEVF_VIRTCHNL_H_
#define _MCEVF_VIRTCHNL_H_
#include "mcevf.h"
#include "mcevf_mbx.h"

#define FLAG_VF_NONE_PROMISC (0x00000000)
#define FLAG_VF_UNICAST_PROMISC (0x00000001)
#define FLAG_VF_MULTICAST_PROMISC (0x00000002)

enum virtchnl_link_speed_shift {
	VIRTCHNL_LINK_SPEED_100MB_SFT = 0,
	VIRTCHNL_LINK_SPEED_1GB_SFT,
	VIRTCHNL_LINK_SPEED_10GB_SFT,
	VIRTCHNL_LINK_SPEED_25GB_SFT,
	VIRTCHNL_LINK_SPEED_40GB_SFT,
	VIRTCHNL_LINK_SPEED_100GB_SFT,
};

enum virtchnl_link_speed {
	VIRTCHNL_LINK_SPEED_UNKNOWN = 0,
	VIRTCHNL_LINK_SPEED_100MB = BIT(VIRTCHNL_LINK_SPEED_100MB_SFT),
	VIRTCHNL_LINK_SPEED_1GB = BIT(VIRTCHNL_LINK_SPEED_1GB_SFT),
	VIRTCHNL_LINK_SPEED_10GB = BIT(VIRTCHNL_LINK_SPEED_10GB_SFT),
	VIRTCHNL_LINK_SPEED_25GB = BIT(VIRTCHNL_LINK_SPEED_25GB_SFT),
	VIRTCHNL_LINK_SPEED_40GB = BIT(VIRTCHNL_LINK_SPEED_40GB_SFT),
	VIRTCHNL_LINK_SPEED_100GB = BIT(VIRTCHNL_LINK_SPEED_100GB_SFT),
};

struct mcevf_pf;

struct mcevf_virtchnl_operations {
	int (*set_init_done)(struct mcevf_hw *hw, bool en);
	int (*set_promisc_mode)(struct mcevf_hw *hw, bool en);
	int (*set_unicast_addr)(struct mcevf_hw *hw, u8 *addr);
	int (*set_ipv4_addr)(struct mcevf_hw *hw, __be32 ipv4_addr);
	int (*check_mbx_ipv4_addr_conflict)(struct mcevf_hw *hw, u32 ipv4_addr);
	int (*set_vlan_vfta)(struct mcevf_hw *hw, u32 vlan, u32 vind,
			     bool vlan_on);
	int (*set_add_uc_filter)(struct mcevf_hw *hw, const u8 *addr);
	int (*set_del_uc_filter)(struct mcevf_hw *hw, const u8 *addr);
	int (*set_notify_promisc_mode)(struct mcevf_hw *hw, u32 flags);
	int (*send_reset_msg)(struct mcevf_hw *hw);
	int (*get_qos_info)(struct mcevf_hw *hw);
	int (*notify_ring_cnt)(struct mcevf_hw *hw, int ring_cnt);
};

extern struct mcevf_virtchnl_operations virtchnl_ops;

void mcevf_mbx_pf_event_req_isr(struct mcevf_mbx_info *mbx, int event_id);
void mcevf_mbx_pf_req_isr(struct mcevf_mbx_info *mbx, struct mbx_req *req);
#endif /* _MCEVF_VIRTCHNL_H_ */
