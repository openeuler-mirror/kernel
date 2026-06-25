/* SPDX-License-Identifier: GPL-2.0 */
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2_drv_aux.h
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#ifndef _SXE2_DRV_AUX_H_
#define _SXE2_DRV_AUX_H_

#include <net/dcbnl.h>
#include <linux/device.h>
#include <linux/kernel.h>
#include "sxe2_compat.h"
#include "sxe2_cmd.h"

#ifdef NOT_SUPPORT_AUXILIARY_BUS
#include "auxiliary_bus.h"
#else
#include <linux/auxiliary_bus.h>
#endif

#define AUX_MAJOR_VER (1)
#define AUX_MINOR_VER (1)
#define SXE2_RDMA_INDEX (0x1)
#define AUX_RDMA_INVALID_PF_IDX (0xFF)
#define AUX_MAX_USER_PRIORITY (8)
#define AUX_MAX_APPS (64)
#define AUX_MAX_DSCP_MAPPING (64)
#define AUX_MAX_NUM_AUX (5)
#define SXE2_RDMA_VCHNL_Q_INVALID_IDX (0xFFFF)

#define SXE2_RDMA_INVALID_PF 0xFF
#define SXE2_RDMA_PF0 BIT(0)
#define SXE2_RDMA_PF1 BIT(1)
#define SXE2_RDMA_BOTH_PF 0x3

#define SXE2_DRV_VER_STR_LEN 32

enum aux_rdma_opcode {
	RDMA_MAC_RULE_ADD,
	RDMA_MAC_RULE_DELETE,
	RDMA_OPCODE_MAX
};

enum aux_reset_type {
	AUX_PFR,
	AUX_CORER,
	AUX_GLOBR,
};

enum aux_function_type {
	AUX_FUNCTION_TYPE_PF,
	AUX_FUNCTION_TYPE_VF,
};

enum aux_rdma_gen {
	AUX_RDMA_GEN_RESERVED = 0,
	AUX_RDMA_GEN_1 = 1,
	AUX_RDMA_GEN_2 = 2,
	AUX_RDMA_GEN_3 = 3,
};

struct aux_rdma_caps {
	u8 gen;
};

enum aux_event_type {
	SXE2_EVENT_MTU_CHANGED,
	SXE2_EVENT_NOTIFY_RESET,
	SXE2_EVENT_VF_RESET,
	SXE2_EVENT_AEQ_OVERFLOW,
	SXE2_EVENT_FAILOVER,
	SXE2_EVENT_TC_CHANGE,
	SXE2_EVENT_MAX
};

struct aux_ver_info {
	u16 major;
	u16 minor;
	u64 support;
};

struct aux_core_dev_info;

struct aux_rdma_qset_params {
	u16 teid;
	u16 qset_id;
	u16 vport_id;
	u8 tc[2];
	u8 user_pri;
	u8 qset_port;
};

struct aux_rdma_multi_qset_params {
	u16 teid[2];
	u16 qset_id[2];
	u8 qset_port[2];
	u16 vport_id;
	u8 tc[2];
	u8 num;
	u8 rdma_port[2];
	u8 active_ports;
	u8 user_pri;
};

struct aux_qos_info {
	u64 tc_ctx;
	u8 rel_bw;
	u8 prio_type;
	u8 egress_virt_up;
	u8 ingress_virt_up;
};

struct aux_dcb_app_info {
	u8 priority;
	u8 selector;
	u16 prot_id;
};

struct aux_qos_params {
	struct aux_qos_info tc_info[IEEE_8021QAZ_MAX_TCS];
	u8 up2tc[AUX_MAX_USER_PRIORITY];
	u8 vport_relative_bw;
	u8 vport_priority_type;
	u32 num_apps;
	u8 pfc_mode;
	struct aux_dcb_app_info apps[AUX_MAX_APPS];
	u8 dscp_map[AUX_MAX_DSCP_MAPPING];
	u8 num_tc;
};

struct aux_qv_info {
	u32 v_idx;
	u16 ceq_idx;
	u16 aeq_idx;
	u8 itr_idx;
};

struct aux_qvlist_info {
	u32 num_vectors;
	struct aux_qv_info qv_info[];
};

struct aux_vf_port_info {
	u16 vf_id;
	u16 vport_id;
	u16 port_vlan_id;
	u16 port_vlan_tpid;
};

struct sxe2_core_ops {
	int (*alloc_res)(struct aux_core_dev_info *cdev_info, struct aux_rdma_qset_params *qset);
	int (*free_res)(struct aux_core_dev_info *cdev_info, struct aux_rdma_qset_params *qset);
	int (*request_reset)(struct aux_core_dev_info *cdev_info,
			     enum aux_reset_type reset_type);
	int (*update_vport_filter)(struct aux_core_dev_info *cdev_info,
				   u16 vport_id, bool enable);
	int (*get_vf_info)(struct aux_core_dev_info *cdev_info,
			   u16 vf_id, struct aux_vf_port_info *vf_port_info);
	int (*vc_send)(struct aux_core_dev_info *cdev_info,
		       u16 vf_id, u8 *msg, u16 len, u64 session_id);
	int (*vc_send_sync)(struct aux_core_dev_info *cdev_info, u8 *msg,
			    u16 len, u8 *recv_msg, u16 recv_len);
	int (*rdma_send_cmd)(struct aux_core_dev_info *cdev_info,
			     enum sxe2_drv_cmd_opcode opcode, u8 *msg, u16 len,
			     u8 *recv_msg, u16 recv_len);
	int (*rdma_drv_config)(struct aux_core_dev_info *cdev_info, u8 opcode, u8 *msg);
	int (*vc_queue_vec_map_unmap)(struct aux_core_dev_info *cdev_info,
				      struct aux_qvlist_info *qvl_info, bool map);
	int (*alloc_multi_res)(struct aux_core_dev_info *cdev_info,
			       struct aux_rdma_multi_qset_params *qset);
	int (*free_multi_res)(struct aux_core_dev_info *cdev_info,
			      struct aux_rdma_multi_qset_params *qset);
	int (*dump_pcap_cmd)(struct aux_core_dev_info *cdev_info, u8 *mac, bool is_add);
	void (*notify_rdma_load)(struct aux_core_dev_info *cdev_info, bool loaded);
	u32 (*rdma_get_link_speed)(struct aux_core_dev_info *cdev_info);
};

struct sxe2_rdma_event_info {
	DECLARE_BITMAP(type, SXE2_EVENT_MAX);
	u16 vf_id;
	struct aux_qos_params port_qos;
};

struct aux_core_dev_info {
	struct pci_dev *pdev;
	struct auxiliary_device *adev;
	u8 __iomem *hw_addr;
	struct aux_ver_info ver;
	char drv_ver[SXE2_DRV_VER_STR_LEN];
	enum aux_function_type ftype;
	const struct sxe2_aux_ops *aux_ops;
	struct sxe2_core_ops *ops;
	int cdev_info_id;
	u8 pf_id;
	u8 pf_cnt;
	u16 vfid_base;
	u16 vport_id;
	struct aux_qos_params qos_info[2];
	struct net_device *netdev;
	struct msix_entry *msix_entries;
	u32 msix_count;
	struct aux_rdma_caps rdma_caps;
	struct sxe2_adapter *adapter;
	u8 bond_mode;
	u8 rdma_pf_bitmap;
	void *ext_ops;
	void *ext_info;
};

struct sxe2_aux_ops {
	void (*event_handler)(struct aux_core_dev_info *cdev_info,
			      struct sxe2_rdma_event_info *event);
	int (*vc_receive)(struct aux_core_dev_info *cdev_info,
			  u32 vf_id, u8 *msg, u16 len, u64 session_id);
};

struct sxe2_auxiliary_device {
	struct auxiliary_device adev;
	struct aux_core_dev_info *cdev_info;
};

struct sxe2_auxiliary_drv {
	struct auxiliary_driver adrv;
	struct sxe2_aux_ops aux_ops;
};

void sxe2_rdma_aux_adev_release(struct device *dev);

#endif
