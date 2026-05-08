/* SPDX-License-Identifier: GPL-2.0 */
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2vf.h
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#ifndef __SXE2VF_H__
#define __SXE2VF_H__

#include <linux/kernel.h>
#include <linux/pci.h>
#include <linux/aer.h>
#include <linux/moduleparam.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/if_vlan.h>

#include "sxe2_compat.h"
#include "sxe2vf_hw.h"
#include "sxe2vf_irq.h"
#include "sxe2vf_mbx_channel.h"
#include "sxe2vf_queue.h"
#include "sxe2vf_mbx_msg.h"
#include "sxe2vf_aux_drv.h"
#include "sxe2vf_l2_filter.h"
#include "sxe2_spec.h"
#include "sxe2vf_rxft.h"
#include "sxe2vf_ipsec.h"
#include "sxe2vf_trace.h"
#include "sxe2_com_cdev.h"

#define SXE2_VF_ETH_VSI_CNT 1
#define SXE2_VF_DPDK_VSI_CNT 1

#define SXE2VF_DFLT_NETIF_M (NETIF_MSG_DRV | NETIF_MSG_PROBE | NETIF_MSG_LINK)
#define SXE2VF_DBG_USER BIT_ULL(31)

#define DEV_NAME_LEN (16)
#define SXE2VF_WORKQUEUE_NAME_LEN (128)

#define SXE2VF_MSG_LEVEL_DEFAULT_SHT (3)
#define SXE2VF_DMA_BIT_WIDTH_64 (64)
#define SXE2VF_NO_ACTIVE_CNT (10)

#define SXE2VF_DEV_FUNC_MASK (0x7)
#define SXE2VF_WOKER_DELAY_5MS (5)
#define SXE2VF_WOKER_DELAY_10MS (10)
#define SXE2VF_WOKER_DELAY_20MS (20)
#define SXE2VF_WOKER_DELAY_30MS (30)

#define SXE2VF_WOKER_DELAY_1S (1 * HZ)
#define SXE2VF_WOKER_DELAY_2S (2 * HZ)
#define SXE2VF_WOKER_DELAY_5S (5 * HZ)

#define SXE2VF_RESET_DETEC_WAIT_COUNT (100)
#define SXE2VF_RESET_DONE_WAIT_COUNT (250)
#define SXE2VF_RESET_WAIT_MS (50)
#define SXE2VF_CORER_WAIT_DONE_COUNT (1000)
#define SXE2VF_WAIT_CONFIG_ACCESSIBLE_TIMEOUT_MS (60000)
#ifdef SXE2VF_TEST
#define SXE2VF_RESET_ROBACK_WAIT_COUNT (1)
#else
#define SXE2VF_RESET_ROBACK_WAIT_COUNT (18000)
#endif
#ifdef SXE2VF_TEST
#define SXE2VF_RESET_WAIT_COMPLETE_COUNT (1000)
#define SXE2VF_VFLR_DETEC_WAIT_COUNT (4000)
#else
#define SXE2VF_RESET_WAIT_COMPLETE_COUNT (150)
#define SXE2VF_VFLR_DETEC_WAIT_COUNT (300000)
#endif

#ifdef SXE2VF_TEST
#define SXE2VF_RESET_ACTIVE_WAIT_COUNT (5)
#define SXE2VF_RESET_COMPLETE_WAIT_COUNT (1)
#define SXE2VF_REMOVE_RESET_DETECT_COUNT (1)
#define SXE2VF_VFLR_ACTIVE_WAIT_COUNT (2)
#define SXE2VF_DEVSTATE_PROC_FAIL_CNT (10)
#else
#define SXE2VF_RESET_ACTIVE_WAIT_COUNT (1000)
#define SXE2VF_RESET_COMPLETE_WAIT_COUNT (1000)
#define SXE2VF_REMOVE_RESET_DETECT_COUNT (15000)
#define SXE2VF_VFLR_ACTIVE_WAIT_COUNT (5000)
#define SXE2VF_DEVSTATE_PROC_FAIL_CNT (3000)
#endif

#define SXE2VF_ACTIVE_WAIT_INTERVAL (2)
#define SXE2VF_RESET_WAIT_MIN (10)
#define SXE2VF_CORER_DONE_WAIT_INTERVAL (3)

#define SXE2VF_REQUEST_MSG_WAIT_TIME (50)
#define SXE2VF_MSG_REPLY_WAIT_TIMEOUT msecs_to_jiffies(2500)

#define SXE2VF_DOWN_WAIT_TIMEOUT msecs_to_jiffies(500)

#define SXE2VF_ADAPTER_TO_DEV(adapter) (&((adapter)->pdev->dev))

#define SXE2VF_DEV_TO_ADAPTER(pdev) (netdev_priv(pci_get_drvdata(pdev)))

#define sxe2vf_for_each_vsi_txq(vsi, i)                    \
	sxe2_for_each_array_element(i, 0, (vsi)->txqs.q_cnt)

#define sxe2vf_for_each_vsi_rxq(vsi, i)                    \
	sxe2_for_each_array_element(i, 0, (vsi)->rxqs.q_cnt)

#define sxe2vf_for_each_vsi_irq(vsi, i)                    \
	sxe2_for_each_array_element(i, 0, (vsi)->irqs.cnt)

enum sxe2vf_dev_state {
	SXE2VF_DEVSTATE_INITIAL = 0,
	SXE2VF_DEVSTATE_RESETTING,
	SXE2VF_DEVSTATE_STOPPED,
	SXE2VF_DEVSTATE_UNACTIVED,
	SXE2VF_DEVSTATE_ACTIVATED,
	SXE2VF_DEVSTATE_RUNNING,
	SXE2VF_DEVSTATE_VFR_REQUEST,
	SXE2VF_DEVSTATE_VFR_NOTIFY,
	SXE2VF_DEVSTATE_FAULT,
};

enum sxe2vf_reset_type {
	SXE2VF_RESET_NONE = 0,
	SXE2VF_RESET_CORER,
	SXE2VF_RESET_VFR,
	SXE2VF_RESET_MAX,
};

enum sxe2vf_probe_post_state {
	SXE2VF_PROBE_POST_INIT_UNSTART = 0,
	SXE2VF_PROBE_POST_INIT_STARTED = 1,
	SXE2VF_PROBE_POST_VER_MATCH = 2,
	SXE2VF_PROBE_POST_CAPS_INIT = 3,
	SXE2VF_PROBE_POST_IRQ_QUEUE_CFG = 4,
	SXE2VF_PROBE_POST_INIT_DONE = 5,
	SXE2VF_PROBE_POST_VER_CHK_FAIL = 6,

};

enum sxe2vf_wk_type {
	SXE2VF_WK_MONITOR,
	SXE2VF_WK_MONITOR_IM,
	SXE2VF_WK_MBX,
	SXE2VF_WK_NOTIFY_MSG,
	SXE2VF_WK_HEALTH,
};

enum sxe2vf_adapter_flags {
	SXE2VF_FLAG_LEGACY_RX_ENABLE = 0,
	SXE2VF_FLAG_LRO_ENABLE = 1,
	SXE2VF_FLAG_RXQ_DISABLED = 2,
	SXE2VF_FLAG_TXQ_DISABLED = 3,
	SXE2VF_FLAG_RESET_NOTIFY = 9,
	SXE2VF_FLAG_DRV_PROBE_DONE = 14,
	SXE2VF_FLAG_NETDEV_REGISTERED = 15,
	SXE2VF_FLAG_DRV_UP = 16,
	SXE2VF_FLAG_DCB_ENABLE = 17,
	SXE2VF_FLAG_FLTR_SYNC = 18,
	SXE2VF_FLAG_EVENT_IRQ_DISABLED = 19,
	SXE2VF_FLAG_SUSPEND = 20,
	SXE2VF_FLAG_FNAV_ENABLE = 21,
	SXE2VF_FLAG_UPDATE_NETDEV_FEATURES = 22,
	SXE2VF_FLAG_FLR_RUNNING = 23,
	SXE2VF_FLAG_FNAV_TUNNEL = 25,
	SXE2VF_FLAG_DRV_REMOVING = 26,
	SXE2VF_FLAG_MTU_CHANGED = 27,
	SXE2VF_FLAG_RXFCS_ENABLE = 28,
	SXE2VF_FLAGS_NBITS
};

enum { SXE2VF_VSI_CLOSE = 0,
	SXE2VF_VSI_DISABLE,
	SXE2VF_VSI_MAX,
};

#define SXE2VF_STATE_MASK (0xFFFF)

#define SXE2VF_STATE_INIT_INTERNAL_SHT (16)

struct sxe2vf_mac_filter {
	struct list_head mac_addr_list;
	struct list_head tmp_sync_list;
	struct list_head tmp_unsync_list;
	u8 def_mac_addr[ETH_ALEN];
	u8 cur_mac_addr[ETH_ALEN];
};

struct sxe2vf_filter_context {
	struct sxe2vf_mac_filter mac_filter;
	struct sxe2vf_vlan_info vlan_info;
	u32 cur_promisc_flags;
};

struct sxe2vf_switch_context {
	struct sxe2vf_filter_context filter_ctxt;
	struct sxe2vf_filter_context user_fltr_ctxt;
	/* in order to protect the data */
	struct mutex mac_addr_lock;
	/* in order to protect the data */
	struct mutex flag_lock;
};

struct sxe2vf_vsi_sw_stats {
	u64 rx_packets;
	u64 rx_bytes;
	u64 rx_csum_unnecessary;
	u64 rx_csum_none;
	u64 rx_csum_complete;
	u64 rx_csum_unnecessary_inner;
	u64 rx_lro_packets;
	u64 rx_lro_bytes;
	u64 rx_vlan_strip;
	u64 rx_pkts_sw_drop;
	u64 rx_buff_alloc_err;
	u64 rx_pg_alloc_fail;
	u64 rx_csum_err;
	u64 rx_lro_count;
	u64 rx_page_alloc;
	u64 rx_non_eop_descs;
	u64 rx_pa_err;

	u64 tx_packets;
	u64 tx_bytes;
	u64 tx_tso_packets;
	u64 tx_tso_bytes;
	u64 tx_vlan_insert;
	u64 tx_csum_none;
	u64 tx_csum_partial;
	u64 tx_csum_partial_inner;
	u64 tx_queue_dropped;
	u64 tx_xmit_more;
	u64 tx_linearize;
	u64 tx_busy;
	u64 tx_restart;
	u64 tx_tso_linearize_chk;
};

struct sxe2vf_vsi_stats {
	struct sxe2_vf_vsi_hw_stats vsi_hw_stats;
	struct sxe2_vf_vsi_hw_stats parse_vsi_hw_stats;
	struct sxe2vf_vsi_sw_stats vsi_sw_stats;
};

struct sxe2vf_vsi_qs_stats {
	struct sxe2vf_queue_stats *txqs_stats;
	struct sxe2vf_queue_stats *rxqs_stats;
};

struct sxe2vf_vsi {
	struct sxe2vf_adapter *adapter;
	struct net_device *netdev;
	u16 vsi_id;
	enum sxe2vf_vsi_type vsi_type;
	struct sxe2vf_vsi_irqs irqs;
	struct sxe2vf_vsi_queues txqs;
	struct sxe2vf_vsi_queues rxqs;
	u16 budget;
	DECLARE_BITMAP(state, SXE2VF_VSI_MAX);
	struct sxe2vf_vsi_stats vsi_stats;
	struct sxe2vf_vsi_qs_stats vsi_qs_stats;
};

struct sxe2vf_vsi_context {
	u16 vsi_cnt_max;
	/* in order to protect the data */
	struct mutex lock;
	struct sxe2vf_vsi *vf_vsi;
	struct sxe2vf_vsi *dpdk_vf_vsi;
	u16 vsi_ids[SXE2_VF_MAX_VSI_CNT];
};

enum { SXE2VF_VF_DISABLE = 0,
	SXE2VF_VF_MAX,
};

struct sxe2vf_dev_context {
	/* in order to protect the data */
	struct mutex vf_lock;
	bool remove;
	DECLARE_BITMAP(state, SXE2VF_VF_MAX);
};

enum { SXE2VF_MONITOR_WORK_DISABLED = 1,
	SXE2VF_MBX_WORK_DISABLED = 2,
	SXE2VF_HEALTH_WORK_DISABLED = 3,
};

struct sxe2vf_work_context {
	unsigned long period;
	unsigned long state;
	enum sxe2vf_probe_post_state post_state;
	enum sxe2vf_dev_state dev_state;
	enum sxe2vf_reset_type reset_type;

	/* in order to protect the data */
	spinlock_t state_lock;
	/* in order to protect the data */
	struct mutex monitor_lock;

	struct delayed_work monitor_wk;
	struct work_struct mbx_wk;
	struct work_struct msg_handle_wk;
	struct workqueue_struct *health_wq;
	struct delayed_work health_wk;
	/* in order to protect the data */
	struct mutex reset_detect_lock;

	u64 tx_timeout_cnt;
	u64 corer_cnt;
	u64 vfr_cnt;
	u8 failed_cnt;
	bool is_send;
	bool is_clear;
};

struct sxe2vf_log_level_context {
	u32 msg_enable;
	u64 debug_mask;
};

struct sxe2vf_msg_context {
	wait_queue_head_t reply_waitqueue;
};

struct sxe2vf_link_context {
	/* in order to protect the data */
	struct mutex link_lock;
	bool link_up;
	u32 speed;
};

struct sxe2vf_rss_cfg {
	struct list_head l_node;
	struct sxe2vf_rss_hash_cfg hash_cfg;
};

struct sxe2vf_rss_context {
	u16 rss_lut_type;
	u16 rss_key_size;
	u16 rss_lut_size;
	u8 *key;
	u8 *lut;
	struct list_head rss_cfgs;
	/* in order to protect the data */
	struct mutex rss_cfgs_lock;
	bool init;
};

struct sxe2vf_fnav_filter {
	struct list_head l_node;
	u32 filter_loc;
	u32 flow_id;
	enum sxe2_fnav_flow_type flow_type;
	u16 q_index;
	u8 act_type;
	u8 has_flex_filed;
	struct sxe2vf_fnav_filter_full_key full_key;
	struct sxe2_fnav_comm_full_msg full_msg;
};

struct sxe2vf_fnav_context {
	u16 space_bsize;
	u16 space_gsize;
	u32 filter_cnt;
	struct list_head filter_list;
	/* in order to protect the data */
	struct mutex filter_list_lock;
	bool init;
	u16 stat_idx;
	u64 fnav_match;
};

struct sxe2vf_adapter {
	char dev_name[DEV_NAME_LEN];
	struct pci_dev *pdev;
	struct net_device *netdev;
	struct sxe2vf_hw hw;
	u8 pf_id;
	u16 vf_id_in_dev;
	struct sxe2vf_irq_context irq_ctxt;
	struct sxe2vf_queue_context q_ctxt;
	struct sxe2vf_vsi_context vsi_ctxt;
	struct sxe2vf_dev_context dev_ctxt;
	struct sxe2vf_channel_context channel_ctxt;
	struct sxe2vf_msg_context msg_ctxt;
	struct sxe2vf_switch_context switch_ctxt;
	struct sxe2vf_work_context work_ctxt;
	struct sxe2vf_log_level_context log_level_ctxt;
	struct sxe2vf_link_context link_ctxt;
	struct sxe2vf_aux_context aux_ctxt;
	struct sxe2vf_rss_context rss_ctxt;
	struct sxe2vf_fnav_context fnav_ctxt;
	struct sxe2vf_ipsec_context ipsec_ctxt;
	struct work_struct com_work;
	struct sxe2_com_context com_ctxt;
	struct sxe2_vf_txsch_caps txsch_cap;

	DECLARE_BITMAP(flags, SXE2VF_FLAGS_NBITS);
#ifdef SXE2VF_TEST
	u32 work_count;
#endif
#if defined(CONFIG_DEBUG_FS) || defined(PCLINT)
	struct dentry *sxe2vf_debugfs_vf;
	struct dentry *sxe2vf_debugfs_vf_drv_mode;
#endif
	struct sxe2_vf_ver_msg pf_ver;
	enum sxe2_com_module drv_mode;
};

struct sxe2vf_res_caps {
	u16 vsi_id;
	u16 txq_base;
	u16 txq_cnt;
	u16 rxq_base;
	u16 rxq_cnt;
	u16 irq_base;
	u16 irq_cnt;
	u16 rss_lut_type;
	u16 rss_key_size;
	u16 rss_lut_size;
};

static inline bool sxe2vf_post_probe_is_done(struct sxe2vf_adapter *adapter)
{
	return (adapter->work_ctxt.post_state == SXE2VF_PROBE_POST_INIT_DONE);
}

static inline bool sxe2vf_post_probe_is_start(struct sxe2vf_adapter *adapter)
{
	return (adapter->work_ctxt.post_state > SXE2VF_PROBE_POST_INIT_UNSTART);
}

void sxe2vf_wkq_schedule(struct sxe2vf_adapter *adapter,
			 enum sxe2vf_wk_type type, const u32 delay);

void sxe2vf_post_state_update(struct sxe2vf_work_context *work_ctxt,
			      enum sxe2vf_probe_post_state post_state);

void sxe2vf_dev_state_set(struct sxe2vf_adapter *adapter, enum sxe2vf_dev_state new_state,
			  enum sxe2vf_reset_type new_reset_type);

void sxe2vf_dev_state_get(struct sxe2vf_adapter *adapter, enum sxe2vf_dev_state *state,
			  enum sxe2vf_reset_type *reset_type);

void sxe2vf_wkq_cancel(struct sxe2vf_adapter *adapter, enum sxe2vf_wk_type type);

s32 sxe2vf_reset_detect(struct sxe2vf_adapter *adapter);

s32 sxe2vf_dpdk_caps_get(struct sxe2vf_adapter *adapter, struct sxe2vf_res_caps *caps);

int sxe2vf_com_mode_get(void *adapter);

int sxe2vf_g_com_mode_get(void);

#endif
