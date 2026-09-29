/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2024-2026 Mucse Corporation. */

#ifndef _MCE_VF_LIB_H_
#define _MCE_VF_LIB_H_
#include <linux/netdevice.h>

struct mce_pf;

#define PFINFO_IDX (hw->max_vfs)
#define PF_MACVLAN_VF_MARKER (-2) /* PF MACVLAN sentinel, independent of SR-IOV */
#define PFVF_TOTAL_NUM(vfs) ((vfs) + 1)
#define PFINFO_NONE (0xff)
#define PFINFO_BCMC (0xfff)
#define PFINFO_DEFAULT_VLAN (0xfff)

#define MCE_MBOX_IRQ_NO_MSIX_BASE (0)
#define MCE_VF_NOT_FOUND (-100)
#define MCE_VF_INVALID (-101)
#define MCE_VF_UNUSED (-102)

#define MCE_LIMIT_VFS (128)

struct mce_hw;

/* VM RULE */
enum veb_policy_type {
	VEB_POLICY_TYPE_NONE,
	VEB_POLICY_TYPE_UC_ADD_MACADDR,
	VEB_POLICY_TYPE_UC_DEL_MACADDR,
	VEB_POLICY_TYPE_UC_ADD_MACADDR_WITH_ACT,
	VEB_POLICY_TYPE_UC_DEL_MACADDR_WITH_ACT,
	VEB_POLICY_TYPE_MACVLAN_ADD_MACADDR_WITH_ACT,
	VEB_POLICY_TYPE_MACVLAN_DEL_MACADDR_WITH_ACT,
	VEB_POLICY_TYPE_BCMC_ADD_MACADDR,
	VEB_POLICY_TYPE_BCMC_DEL_MACADDR,
	VEB_POLICY_TYPE_BCMC_ADD_MACADDR_WITH_ACT,
	VEB_POLICY_TYPE_BCMC_DEL_MACADDR_WITH_ACT,
	VEB_POLICY_TYPE_UC_ADD_VLAN,
	VEB_POLICY_TYPE_UC_DEL_VLAN,
	VEB_POLICY_TYPE_VEB_ADD_VLAN,
	VEB_POLICY_TYPE_VEB_DEL_VLAN,
	VEB_POLICY_TYPE_MAX,
};

enum mce_vf_veb_vlan_type {
	MCE_VF_VEB_VLAN_INVALID = 0,
	MCE_VF_VEB_VLAN_OUTER1,
	MCE_VF_VEB_VLAN_OUTER2,
	MCE_VF_VEB_VLAN_OUTER3,
};

enum mce_vf_post_ctrl {
	MCE_VF_POST_CTRL_NORMAL = 0,
	MCE_VF_POST_CTRL_FILTER_TX_TO_RX,
	MCE_VF_POST_CTRL_ALLIN_TO_RX,
	MCE_VF_POST_CTRL_ALLIN_TO_TXTRANS_AND_RX,
};

enum mce_vf_antivlan_ctrl {
	MCE_VF_ANTI_VLAN_CLEAR = 0,
	MCE_VF_ANTI_VLAN_SET,
	MCE_VF_ANTI_VLAN_HOLD,
};

struct vf_vlan {
	u16 vid;
	u16 qos;
	bool pf_used;
	bool vf_used;
};

struct mce_tcpsync {
	union {
		struct {
			u32 sync_tuple_pri : 1;
			u32 rsv0 : 19;
			u32 act_pri : 3;
			u32 rsv1 : 8;
			u32 enum_en : 1;
		} bits;
		u32 data;
	} acl;

	union {
		struct {
			u32 mark : 16;
			u32 rm_vlan_type : 2;
			u32 ring_num : 9;
			u32 pri_valid : 1;
			u32 mark_valid : 1;
			u32 vlan_valid : 1;
			u32 ring_valid : 1;
			u32 drop : 1;
		} bits;
		u32 data;
	} pri;
	bool valid;
};

enum mce_vf_flags {
	MCE_FLAG_VF_TX_MAXRATE_ENA,
	MCE_VF_FLAGS_NBITS /* must be last */
};

struct vf_info {
	unsigned char vf_mac_addr[ETH_ALEN];
	bool pf_set_mac;
	u16 pf_vlan; /* When set, guest VLAN config not allowed. */
	u16 pf_vlan_qos;
	u16 pf_vlan_proto;
#define MCE_MAX_VF_VLAN_WHITE_LISTS (16)
	struct vf_vlan vf_vlan[MCE_MAX_VF_VLAN_WHITE_LISTS];
	DECLARE_BITMAP(avail_vlan, MCE_MAX_VF_VLAN_WHITE_LISTS);
	int pf_vlan_entry; /* When set, guest VLAN config not allowed. */
	u16 tx_rate;
	int link_enable;
	int link_state;
	u8 spoofchk_enabled;
	u8 trusted;
	int xcast_mode;
	bool init_done;
	int ring_cnt;
	struct mce_tcpsync tcpsync;
	bool vf_true_promsic_en;
#define MCE_MAX_ETYPE_CNT 15
	DECLARE_BITMAP(avail_etype, MCE_MAX_ETYPE_CNT);
	u16 lan_vsi_idx;
#if IS_ENABLED(CONFIG_NET_DEVLINK)
	/* devlink port data */
	struct devlink_port devlink_port;
#endif /* CONFIG_NET_DEVLINK */
	struct mce_repr *repr;
	struct mce_pf *pf;
	DECLARE_BITMAP(flags, MCE_VF_FLAGS_NBITS);
	int fdir_active_fltr;
	__be32 vf_ipv4_addr; /* VF's IPv4 address (network byte order) */
};

/* Software flag types. */
enum mce_flag_type {
	MCE_F_HOLD = 0,
	MCE_F_SET,
	MCE_F_CLEAR,
};

enum vf_link_state {
	mce_link_state_on,
	mce_link_state_auto,
	mce_link_state_off,
};

struct vf_t_info {
	u16 vlanid;
	int entry;
	u8 macaddr[ETH_ALEN];
	int cnt;
	u32 index;
	enum mce_flag_type bcmc_bitmap;
};

struct mce_vf {
	struct mce_pf *pf;
	struct vf_t_info t_info;
	struct vf_info *vfinfo;
	DECLARE_BITMAP(avail_tunnel_bcmc, MCE_LIMIT_VFS);
};

struct mce_hw;
int _vfnum(struct mce_hw *hw, int vfid);
int mce_check_vf_mac_conflict(struct mce_pf *pf, int vf_id, u8 *mac,
			      u16 vlan_id);
int mce_vc_check_ipv4_conflict_with_vf(struct mce_pf *pf, int vfid,
				       __be32 ipv4_addr);
bool mce_vf_check_any_trust_setuped(struct mce_hw *hw);
int mce_vf_set_evb_vepa_mode(struct mce_hw *hw, bool on);
void mce_vf_cfg_txring_bw_lmt(struct mce_pf *pf, int vf_id, int max_tx_rate);
bool mce_check_vf_redir_filters_active(struct vf_info *vfinfo);
struct mce_vsi *mce_get_vf_vsi(struct mce_pf *pf, int vf_id);
int mce_vf_apply_spoofchk(struct mce_pf *pf, int vfid, bool enable);
int mce_vf_set_trusted(struct mce_pf *pf, int vfid, bool enable);
int mce_vf_resync_mc_list(struct mce_pf *pf, bool to_pfvf);
int mce_vf_resync_vlan_list(struct mce_pf *pf, bool to_pfvf);
int mce_vf_setup_flr_vlan(struct mce_pf *pf, int vf_id, u16 vlan_id);
int mce_vf_del_flr_vlan(struct mce_pf *pf, int vf_id, u16 vlan_id);
int mce_vf_del_all_vlan(struct mce_hw *hw, int vfid);
int mce_vf_setup_veb_vlan(struct mce_pf *pf, int vf_id, u16 vlan_id);
int mce_vf_del_veb_vlan(struct mce_pf *pf, int vf_id, u16 vlan_id);
int mce_vf_setup_true_promisc(struct mce_pf *pf);
int mce_vf_del_true_promisc(struct mce_pf *pf);
int mce_vf_setup_rqa_tcp_sync_en(struct mce_pf *pf, bool on);
int mce_check_vf_no_ready_for_cfg(struct vf_info *vfinfo);
void mce_vf_force_open_and_no_wait(struct mce_pf *pf);
int mce_vf_force_close_and_wait_done(struct mce_pf *pf);
int mce_vf_handle_flr_intr(struct mce_hw *hw, int vfid);
int mce_get_vf_max_supported_queue(struct mce_hw *hw, int *pf0_max_vf_queues,
				   int *pf1_max_vf_queues);
int mce_vf_clear_all_vlan_and_restore_pf_vlan(struct mce_hw *hw, int vfid);
int mce_add_pf_macvlan_fltr(struct mce_hw *hw, const u8 *mac, int ifindex);
int mce_del_pf_macvlan_fltr(struct mce_hw *hw, const u8 *mac);
void mce_del_pf_macvlan_by_ifindex(struct mce_hw *hw, int ifindex);
void mce_restore_pf_macvlan_fltr(struct mce_hw *hw);
void mce_cleanup_pf_macvlan_fltr(struct mce_hw *hw);
#endif /* _MCE_VF_LIB_H_ */
