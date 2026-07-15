/* SPDX-License-Identifier: GPL-2.0 */
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2_sriov.h
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#ifndef __SXE2_SRIOV_H__
#define __SXE2_SRIOV_H__

#include <linux/types.h>
#include <linux/hashtable.h>
#include <linux/mutex.h>
#include <linux/pci.h>

#include "sxe2_fnav.h"
#include "sxe2_switch.h"
#include "sxe2_vsi.h"
#include "sxe2_mbx_public.h"
#include "sxe2_drv_aux.h"
#include "sxe2_com_cdev.h"

struct sxe2_adapter;
struct sxe2_drv_vsi_caps;

enum sxe2_vf_caps {
	SXE2_VF_CAP_TRUSTED = 0,
	SXE2_VF_CAP_NBITS,

};

enum sxe2_vf_states {
	SXE2_VF_STATE_ACTIVE = 0,
	SXE2_VF_STATE_DIS,
	SXE2_VF_STATE_MC_PROMISC,
	SXE2_VF_STATE_UC_PROMISC,
	SXE2_VF_STATE_REPLAY_VC,
	SXE2_VF_STATES_NBITS
};

#define SXE2_VF_IDX_MASK 0xFF

#define SXE2_VF_IDX(vf_id) ((vf_id) & SXE2_VF_IDX_MASK)

#define SXE2_VF_EVENT_MSIX_NUM 1

#define SXE2_VF_CEQ_CTRL_MASK 0xBFFFFFFF

#define SXE2_VF_MACADDR_CNT_MAX 18
#define SXE2_VF_VLAN_CNT_MAX 8

#define SXE2_VF_64Q_MSIX_NUM (64 + SXE2_VF_EVENT_MSIX_NUM)
#define SXE2_VF_32Q_MSIX_NUM (32 + SXE2_VF_EVENT_MSIX_NUM)
#define SXE2_VF_16Q_MSIX_NUM (16 + SXE2_VF_EVENT_MSIX_NUM)
#define SXE2_VF_16Q_MSIX_NUM (16 + SXE2_VF_EVENT_MSIX_NUM)
#define SXE2_VF_4Q_MSIX_NUM (4 + SXE2_VF_EVENT_MSIX_NUM)
#define SXE2_VF_2Q_MSIX_NUM (2 + SXE2_VF_EVENT_MSIX_NUM)
#define SXE2_VF_1Q_MSIX_NUM (1 + SXE2_VF_EVENT_MSIX_NUM)

#define SXE2_VF_REFCNT_WAIT (3000)
#define SXE2_VF_REFCNT_WAIT_INTERNAL (1)

#define SXE2_VF_RESET_DONE_WAIT_COUNT (1000)
#define SXE2_VF_QUEUE_CNT_MIN (1)
#define SXE2_VF_QUEUE_CNT_MAX (SXE2_VF_ETH_Q_NUM + SXE2_VF_DPDK_Q_NUM)

#define SXE2_VF_ESW_CNT (2)

#define sxe2_for_each_vf(adapter, type)                                \
		for ((type) = 0; (type) < (adapter)->vf_ctxt.num_vfs;    \
		     (type)++)

#define SXE2_VF_NODE_LOCK(adapter, vf_id) \
	(&((adapter)->vf_ctxt.vf_node_e[(vf_id)].vf_lock))

#define SXE2_VF_NODE_E(adapter, vf_id) \
	(&((adapter)->vf_ctxt.vf_node_e[(vf_id)]))

#define SXE2_VF_NODE(adapter, vf_id) \
	((adapter)->vf_ctxt.vf_node_e[(vf_id)].vf_node)

enum sxe2_vf_type {
	SXE2_VF_TYPE_ETH = 0,
	SXE2_VF_TYPE_DPDK,
	SXE2_VF_TYPE_NR
};

struct sxe2_vf_node_e {
	struct sxe2_vf_node *vf_node;
	/* in order to protect the data */
	struct mutex vf_lock;
};

struct sxe2_vf_context {
	/* in order to protect the data */
	struct mutex vfs_lock;
	struct sxe2_adapter *adapter;
	u16 max_vfs;
	u16 num_vfs;
	u16 vfid_base;
	u16 q_cnt;
	u16 irq_cnt;
	u16 irq_base;
	struct sxe2_vf_node_e vf_node_e[SXE2_VF_NUM];
};

struct sxe2_vf_prop {
	u8 mac_from_pf : 1;
	u8 trusted : 1;
	u8 spoofchk : 1;
	u8 link_forced : 1;
	u8 link_up : 1;
	u32 min_tx_rate;
	u32 max_tx_rate;
};

enum sxe2_rst_type {
	SXE2_RST_TYPE_NO_RESET = 0,
	SXE2_RST_TYPE_VM_RESET,
	SXE2_RST_TYPE_VF_RESET,
};

struct sxe2_vf_ops {
	enum sxe2_rst_type reset_type;
	void (*free)(struct sxe2_vf_node *vf_node);
	void (*clear_mbx_reg)(struct sxe2_vf_node *vf_node);
	void (*trigger_reset_register)(struct sxe2_vf_node *vf_node, bool is_vflr);
	bool (*poll_reset_status)(struct sxe2_vf_node *vf_node);
	void (*clear_reset_trigger)(struct sxe2_vf_node *vf_node);
	int (*vsi_rebuild)(struct sxe2_vf_node *vf_node);
	void (*post_vsi_rebuild)(struct sxe2_vf_node *vf_node);
	void (*cfg_rdma_irq_map)(struct sxe2_vf_node *vf, struct aux_qv_info *qv_info);
	void (*clear_rdma_irq_map)(struct sxe2_vf_node *vf, struct aux_qv_info *qv_info);
};

struct sxe2_vf_vlaninfo {
	struct sxe2_vlan port_vlan;
	u8 port_vlan_exsit;
	u16 max_cnt;
	u16 vlan_cnt;
	struct sxe2_user_vlan_offload_cfg vlan_offload;
};

struct sxe2_vf_node {
	struct sxe2_adapter *adapter;
	struct sxe2_vsi *vsi;
	struct sxe2_vsi *dpdk_vf_vsi;
	u16 vsi_id[SXE2_VF_TYPE_NR];
	struct sxe2_vf_addr mac_addr;
	struct sxe2_vf_vlaninfo vlan_info;
	struct sxe2_mbx_msg_table *msg_table;
	const struct sxe2_vf_ops *vf_ops;
	struct sxe2_vf_prop prop;
	u16 irq_base_idx;
	u16 vf_idx;
	u32 mac_cnt;
	DECLARE_BITMAP(states, SXE2_VF_STATES_NBITS);
	DECLARE_BITMAP(caps, SXE2_VF_CAP_NBITS);
	struct sxe2_vf_repr *repr;
	struct sxe2_vf_ver_msg vf_ver;
	bool user_repr_valid;
	/* in order to protect the data */
	struct mutex repr_cfg_lock;
	enum sxe2_com_module mode;
};

static inline u16 sxe2_vf_port_vid_get(struct sxe2_vf_node *vf)
{
	return vf->vlan_info.port_vlan.vid;
}

static inline u8 sxe2_vf_port_vprio_get(struct sxe2_vf_node *vf)
{
	return vf->vlan_info.port_vlan.prio;
}

static inline u16 sxe2_vf_port_tpid_get(struct sxe2_vf_node *vf)
{
	return vf->vlan_info.port_vlan.tpid;
}

static inline bool sxe2_port_vlan_is_exist(struct sxe2_vf_node *vf)
{
	return (sxe2_vf_port_vid_get(vf) || sxe2_vf_port_vprio_get(vf));
}

struct sxe2_vf_node *sxe2_vf_node_get(struct sxe2_adapter *adapter, u16 vf_id);

bool sxe2_vf_is_trusted(struct sxe2_vf_node *vf);

bool sxe2_vf_set_mac_is_allow(struct sxe2_vf_node *vf);

int sxe2_sriov_configure(struct pci_dev *pdev, int num_vfs);

void sxe2_vf_init(struct sxe2_adapter *adapter);

void sxe2_vf_deinit(struct sxe2_adapter *adapter);

int sxe2_set_vf_port_vlan(struct net_device *netdev, int vf_idx, u16 vlan_id,
			  u8 qos, __be16 protocol);

int sxe2_set_vf_port_vlan_inner(struct sxe2_adapter *adapter, int vf_idx,
				u16 vlan_id, u8 qos, u16 protocol,
				bool need_vf_reset);

u32 sxe_calc_all_vfs_min_tx_rate(struct sxe2_adapter *adapter);

bool sxe2_min_tx_rate_oversubscribed(struct sxe2_adapter *adapter, s32 vf_idx, int min_tx_rate);

void sxe2_vf_queues_stop(struct sxe2_vf_node *vf_node);

void sxe2_vf_adv_cfg_clear(struct sxe2_vf_node *vf_node, bool is_vfr_vflr);

s32 sxe2_vf_rebuild(struct sxe2_vf_node *vf_node, bool is_vfr_vflr);

u16 sxe2_vf_num_get(struct sxe2_adapter *adapter);

s32 sxe2_vf_reset_notify(struct sxe2_adapter *adapter, struct sxe2_vf_node *vf_node);

s32 sxe2_vf_clean_and_rebuild(struct sxe2_vf_node *vf_node, bool is_vfr_vflr);

s32 sxe2_sriov_vsi_rebuild(struct sxe2_vsi *vsi, bool is_vfr_vflr);

s32 sxe2_vfs_disable(struct sxe2_adapter *adapter, bool is_remove);

bool sxe2_vf_is_exist(struct sxe2_adapter *adapter);

void sxe2_vfs_active(struct sxe2_adapter *adapter);

s32 sxe2_vf_id_check(struct sxe2_adapter *adapter, u16 vf_idx);

struct sxe2_vsi *sxe2_vf_vsi_get(struct sxe2_vf_node *vf_node, u16 vsi_id_in_dev);

void sxe2_vfs_vsi_id_get(struct sxe2_adapter *adapter, struct sxe2_drv_vsi_caps *repr_vf_id);

s32 sxe2_vf_base_l2_filter_setup(struct sxe2_vf_node *vf_node, struct sxe2_vsi *vsi);

void sxe2_vf_dpdk_cfg_clear(struct sxe2_vf_node *vf_node, bool is_vfr_vflr);

s32 sxe2_vf_vsi_type_get(struct sxe2_vf_node *vf_node, u16 vsi_id_in_dev, enum sxe2_vsi_type *type);

void sxe2_vf_vsi_destroy_by_id(struct sxe2_vf_node *vf_node, u16 vsi_id_in_dev);

s32 sxe2_vf_vsi_port_vlan_cfg(struct sxe2_vf_node *vf_node, struct sxe2_vsi *vsi);

void sxe2_vf_trust_cfg_restore(struct sxe2_vf_node *vf_node);

#endif
