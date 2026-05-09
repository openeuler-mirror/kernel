/* SPDX-License-Identifier: GPL-2.0 */
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2.h
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */
#ifndef __SXE2_H__
#define __SXE2_H__

#include <linux/kernel.h>
#include <linux/pci.h>
#include <linux/aer.h>
#include <linux/moduleparam.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <net/devlink.h>
#include <linux/if_vlan.h>
#include <linux/atomic.h>
#include <net/udp_tunnel.h>

#include "sxe2_compat.h"
#include "sxe2_version.h"
#include "sxe2_hw.h"
#include "sxe2_vsi.h"
#include "sxe2_cmd_channel.h"
#include "sxe2_switch.h"
#include "sxe2_monitor.h"
#include "sxe2_ptp.h"
#include "sxe2_msglevel.h"
#include "sxe2_host_cli.h"
#include "sxe2_dcb.h"
#include "sxe2_dev_ctrl.h"
#include "sxe2_log_export.h"
#include "sxe2_aux_driver.h"
#include "sxe2_macvlan.h"
#include "sxe2_flow.h"
#include "sxe2_fnav.h"
#include "sxe2_sriov.h"
#include "sxe2_rss.h"
#include "sxe2_txsched.h"
#include "sxe2_eswitch.h"
#include "sxe2_macsec.h"
#include "sxe2_ipsec.h"
#include "sxe2_arfs.h"
#include "sxe2_trace.h"
#include "sxe2_udp_tunnel.h"
#include "sxe2_com_cdev.h"
#include "sxe2_acl.h"
#include "sxe2_drv_cmd.h"

#define SXE2_CTXT_REG_VALUE(value, shift, width)                               \
	({ \
		typeof(shift) _shift = (shift); \
		(((value) << (_shift)) & (((1UL << (width)) - 1) << (_shift))); \
	})

#define SXE2_ETH_DEAD_LOAD  (ETH_HLEN + ETH_FCS_LEN + 2 * VLAN_HLEN)
#define SXE2_MAX_FRAME_SIZE 9832
#define SXE2_ETH_MAX_FRAME_SIZE (9728)
#define SXE2_MAX_MTU	    (SXE2_ETH_MAX_FRAME_SIZE - SXE2_ETH_DEAD_LOAD)

#define DEV_NAME_LEN	    (16)

#define SXE2_PCI_VENDOR_ID_1 0x1ff2
#define SXE2_PCI_DEVICE_ID_1 0x10b1

#define SXE2_PCI_VENDOR_ID_2 0x1d94
#define SXE2_PCI_DEVICE_ID_2 0x1260

#define SXE2_PCI_DEVICE_ID_10B3 0x10b3

#define SXE2_PCI_VENDOR_ID_206F 0x206f

#define SXE2_QUEUE_WAIT_RETRY_CNT (50)

#define SXE2_CLI_DEV_MGR_DATA_SIZE (128)
#define SXE2_CLI_DEV_MGR_DATA_STEP (1)
#define SXE2_CLI_DEV_MGR_DATA_CNT  (1)

enum sxe2_cli_dev_status {
	SXE2_CDEV_STATUS_NORMAL,
	SXE2_CDEV_STATUS_UNACCESS,
};

enum sxe2_adapter_flags {
	SXE2_FLAG_LEGACY_RX_ENABLE = 0,
	SXE2_FLAG_SKB_PRIO,
	SXE2_FLAG_LRO_CAPABLE,
	SXE2_FLAG_SRIOV_CAPABLE,
	SXE2_FLAG_SRIOV_VFS_DISABLED,
	SXE2_FLAG_ADV_MODE_ENABLE,
	SXE2_FLAG_DCB_CAPABLE,
	SXE2_FLAG_DCB_ENABLE,
	SXE2_FLAG_FW_DCBX_AGENT,
	SXE2_FLAG_FNAV_ENABLE,
	SXE2_FLAG_MTU_CHANGED,
	SXE2_FLAG_ADVANCE_MODE,
	SXE2_FLAG_FLTR_SYNC,
	SXE2_FLAG_SUSPEND,
	SXE2_FLAG_VFLR_PENDING,
	SXE2_FLAG_VMDQ_CAPABLE,
	SXE2_FLAG_MACVLAN_ENABLE,
	SXE2_FLAG_MDD_PENDING,
	SXE2_FLAG_MDD_TX_PENDING,
	SXE2_FLAG_MDD_RX_PENDING,
	SXE2_FLAG_MDD_AUTO_RESET_VF,
	SXE2_FLAG_RDMA_AEQ_OVERFLOW,
	SXE2_FLAG_LINK_CHECK,
	SXE2_FLAG_FNAV_TUNNEL_ENABLE,
	SXE2_FLAG_SWITCHDEV_CAPABLE,
	SXE2_FLAG_SWITCHDEV_ENABLE,
	SXE2_FLAG_VFSWSTATS_ENABLE,
	SXE2_FLAG_FW_DCBX_DIS_PENDING,
	SXE2_DATAPATH_LOG_ENABLE,
	SXE2_FLAG_LINK_DOWN_ON_CLOSE,
	SXE2_FLAG_RDMA_LOADED,
	SXE2_FLAG_ACL_CAPABLE,
	SXE2_PF_FLAGS_NBITS
};

struct sxe2_cli_dev_mgr_data {
	u16 id;
	atomic_t ref_count;
	struct sxe2_adapter *adapter;
	wait_queue_head_t waitq;
	enum sxe2_cli_dev_status status;
	struct sxe2_cdev_info cdev_info;
};

struct sxe2_cli_dev_mgr {
	DECLARE_BITMAP(map,
		       SXE2_CLI_DEV_MGR_DATA_SIZE);
	/* in order to protect the data */
	struct mutex lock;
	struct sxe2_cli_dev_mgr_data cdev_mgr[SXE2_CLI_DEV_MGR_DATA_SIZE];
};

struct sxe2_dcb_stats {
	struct sxe2_pause_stats curr_pause_stats;
	struct sxe2_pause_stats perv_pause_stats;
	bool prev_stat_loaded;
};

struct sxe2_caps_context {
	u16 max_rss_lut_size;
	u16 fnav_space_bsize;
	u16 fnav_space_gsize;
	u16 fnav_stat_base;
	u16 fnav_stat_num;
	u16 global_lut_base;
	u16 global_lut_num;
};

struct sxe2_rss_ctxt {
	struct sxe2_ppp_common_ctxt ppp;
	struct list_head rss_cfgs;
	/* in order to protect the data */
	struct mutex rss_cfgs_lock;
};

struct sxe2_pf_sw_stats {
	u64 fnav_prgm_err;
};

struct sxe2_pf_stats {
	struct sxe2_pf_hw_stats pf_hw_stats;
	struct sxe2_pf_hw_stats last_pf_hw_stats;
	struct sxe2_pf_hw_stats parse_pf_hw_stats;
	struct sxe2_pf_hw_stats parse_last_pf_hw_stats;
	u8 stat_prev_loaded : 1;
	struct sxe2_pf_sw_stats pf_sw_stats;

	struct sxe2_dcb_stats dcb_stats;
};

struct sxe2_fw_comp_ver {
	u16 major;
	u16 minor;
	u32 resv;
};

struct sxe2_udp_tunnel_context {
	/* in order to protect the data */
	struct mutex lock;
	DECLARE_BITMAP(vsi_map, SXE2_MAX_VSI_NUM);
};

struct sxe2_repr_vf_stats {
	struct rtnl_link_stats64 repr_link_stats64[SXE2_VF_NUM];
};

struct sxe2_adapter {
	char dev_name[DEV_NAME_LEN];
	u8 pf_idx;
	u8 port_idx;
	u8 pf_cnt;
	u8 pad;
	struct pci_dev *pdev;
	struct sxe2_hw hw;
	u32 tx_timeout_count;
	u32 tx_timeout_recovery_level;
	unsigned long tx_timeout_last_recovery;
	struct sxe2_irq_context irq_ctxt;
	struct sxe2_queue_context q_ctxt;
	struct sxe2_vsi_context vsi_ctxt;
	struct sxe2_txsched_context tx_sched_ctxt;
	struct sxe2_cmd_channel_context cmd_channel_ctxt;
	struct sxe2_monitor_context monitor_ctxt;
	struct sxe2_msglevel_context msglvl_ctxt;
	struct sxe2_pf_stats pf_stats;
	struct sxe2_repr_vf_stats repr_vf_stats;
	struct sxe2_vf_context vf_ctxt;
	struct sxe2_dcb_context dcb_ctxt;
	struct sxe2_dev_ctrl_context dev_ctrl_ctxt;
	struct sxe2_export_context export_ctxt;
	struct sxe2_ptp_context ptp_ctxt;
	struct sxe2_rdma_aux_context aux_ctxt;
	struct sxe2_cmd_link_context link_ctxt;
	struct sxe2_lfc_context lfc_ctxt;
	DECLARE_BITMAP(flags, SXE2_PF_FLAGS_NBITS);
	struct sxe2_switch_context switch_ctxt;
	struct sxe2_eswitch_context eswitch_ctxt;
	struct sxe2_caps_context caps_ctxt;
	struct sxe2_macvlan_context macvlan_ctxt;
	struct sxe2_fnav_context fnav_ctxt;
	struct sxe2_arfs_ctxt arfs_ctxt;
	struct sxe2_rss_ctxt rss_flow_ctxt;
#ifdef HAVE_MACSEC_SUPPORT
	struct sxe2_macsec_context macsec_ctxt;
#endif
	struct sxe2_ipsec_context ipsec_ctxt;
	struct sxe2_acl_context acl_ctxt;

	u8 serial_num[SXE2_SERIAL_NUM_LEN];
	struct sxe2_lag_context *lag_ctxt;

#if defined(CONFIG_DEBUG_FS) || defined(PCLINT)
	struct dentry *sxe2_debugfs_pf;
#endif
	struct sxe2_cli_dev_mgr_data *cdev_mgr;
	struct sxe2_user_context user_pf_ctxt;
	struct sxe2_fw_comp_ver fw_ver;
	struct sxe2_udp_tunnel_context udp_tunnel_ctxt;

	struct sxe2_com_context com_ctxt;
	struct sxe2_stats_map stats_map;
#ifdef HAVE_UDP_TUNNEL_NIC_INFO
#ifdef HAVE_UDP_TUNNEL_NIC_SHARED
	struct udp_tunnel_nic_shared udp_tunnel_shared;
#endif
	struct udp_tunnel_nic_info *udp_tunnel_nic;
#endif

	enum sxe2_com_module drv_mode;
};

void sxe2_fw_version_get(struct sxe2_adapter *adapter);

int sxe2_g_com_mode_get(void);

#endif
