/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hinic5_nic_dev.h
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   : NIC device header file
 */

#ifndef HINIC5_NIC_DEV_H
#define	HINIC5_NIC_DEV_H

#include <linux/netdevice.h>
#include <linux/semaphore.h>
#include <linux/types.h>
#include <linux/bitops.h>
#include <linux/ptp_clock_kernel.h>
#include <linux/net_tstamp.h>
#include <linux/rhashtable.h>

#include "ossl_knl.h"
#include "hinic5_lld.h"
#include "hinic5_nic_io.h"
#include "hinic5_nic_cfg.h"
#include "hinic5_tx.h"
#include "hinic5_rx.h"
#include "hinic5_dcb.h"
#include "hinic5_profile.h"
#include "hinic5_macsec_dev.h"
#include "hinic5_vram_common.h"

#define HINIC5_NIC_DRV_NAME	"hinic5"
#define HINIC5_NIC_DRV_VERSION	"100.0.1.100"

#define HINIC5_FUNC_IS_VF(hwdev)	(hinic5_func_type(hwdev) == TYPE_VF)

#define HINIC5_AVG_PKT_SMALL      256U
#define HINIC5_MODERATONE_DELAY   HZ

#define LP_PKT_CNT 64
#define LP_PKT_LEN 60

enum hinic5_flags {
	HINIC5_INTF_UP,
	HINIC5_MAC_FILTER_CHANGED,
	HINIC5_LP_TEST,
	HINIC5_RSS_ENABLE,
	HINIC5_DCB_ENABLE,
	HINIC5_SAME_RXTX,
	HINIC5_INTR_ADAPT,
	HINIC5_UPDATE_MAC_FILTER,
	HINIC5_CHANGE_RES_INVALID,
	HINIC5_FORCE_LINK_UP,
	HINIC5_BONDING_MASTER,
	HINIC5_AUTONEG_RESET,
	HINIC5_RXQ_RECOVERY,
	HINIC5_BONDING_BLOCK,
	HINIC5_PTP_CLOCK,
	HINIC5_DCB_UP_COS_SETTING,
};

#define HINIC5_CHANNEL_RES_VALID(nic_dev)	\
		((test_bit(HINIC5_INTF_UP, &(nic_dev)->flags) != 0) && \
		 (test_bit(HINIC5_CHANGE_RES_INVALID, &(nic_dev)->flags) == 0))

#define RX_BUFF_NUM_PER_PAGE	2

#define VLAN_BITMAP_BYTE_SIZE(nic_dev)	(sizeof(*(nic_dev)->vlan_bitmap))
#define VLAN_BITMAP_BITS_SIZE(nic_dev)	(VLAN_BITMAP_BYTE_SIZE(nic_dev) * 8)
#define VLAN_NUM_BITMAPS(nic_dev)	(VLAN_N_VID / \
					VLAN_BITMAP_BITS_SIZE(nic_dev))
#define VLAN_BITMAP_SIZE(nic_dev)	(VLAN_N_VID / \
					VLAN_BITMAP_BYTE_SIZE(nic_dev))
#define VID_LINE(nic_dev, vid)	((vid) / VLAN_BITMAP_BITS_SIZE(nic_dev))
#define VID_COL(nic_dev, vid)	((vid) & (VLAN_BITMAP_BITS_SIZE(nic_dev) - 1))

#define NIC_DRV_DEFAULT_FEATURE		NIC_F_ALL_MASK

enum hinic5_event_work_flags {
	EVENT_WORK_TX_TIMEOUT,
};

enum hinic5_rx_mode_state {
	HINIC5_HW_PROMISC_ON,
	HINIC5_HW_ALLMULTI_ON,
	HINIC5_PROMISC_FORCE_ON,
	HINIC5_ALLMULTI_FORCE_ON,
};

enum mac_filter_state {
	HINIC5_MAC_WAIT_HW_SYNC,
	HINIC5_MAC_HW_SYNCED,
	HINIC5_MAC_WAIT_HW_UNSYNC,
	HINIC5_MAC_HW_UNSYNCED,
};

struct hinic5_mac_filter {
	struct list_head list;
	u8 addr[ETH_ALEN];
	unsigned long state;
};

struct hinic5_irq {
	struct net_device *netdev;
	/* IRQ corresponding index number */
	u16 msix_entry_idx;
	u16 rsvd1;
	u32 irq_id;         /* The IRQ number from OS */

	char irq_name[IFNAMSIZ + 16];
	struct napi_struct napi;
	cpumask_t affinity_mask;
	struct hinic5_txq *txq;
	struct hinic5_rxq *rxq;
};

struct hinic5_dyna_txrxq_params {
	u16 num_qps;
	u8 num_cos;
	u8 rsvd1;
	u16 xdp_qps;
	u16 rsvd2;
	u32 sq_depth;
	u32 rq_depth;

	struct hinic5_dyna_txq_res *txqs_res;
	struct hinic5_dyna_rxq_res *rxqs_res;
	struct hinic5_irq *irq_cfg;
};

#define HINIC5_NIC_STATS_INC(nic_dev, field)			\
do {								\
	u64_stats_update_begin(&(nic_dev)->stats.syncp);	\
	(nic_dev)->stats.field++;				\
	u64_stats_update_end(&(nic_dev)->stats.syncp);		\
} while (0)

struct hinic5_nic_stats {
	u64 netdev_tx_timeout;

	/* Subdivision statistics show in private tool */
	u64 tx_carrier_off_drop;
	u64 tx_invalid_qid;
	u64 rsvd1;
	u64 rsvd2;
#ifdef HAVE_NDO_GET_STATS64
	struct u64_stats_sync syncp;
#else
	struct u64_stats_sync_empty syncp;
#endif
};

#define HINIC5_TCAM_DYNAMIC_BLOCK_SIZE 16
#define HINIC5_MAX_TCAM_FILTERS	1024

#define HINIC5_PKT_TCAM_DYNAMIC_INDEX_START(block_index)  \
		(HINIC5_TCAM_DYNAMIC_BLOCK_SIZE * (block_index))

struct hinic5_rx_flow_rule {
	struct list_head rules;
	int tot_num_rules;
};

struct hinic5_tcam_dynamic_block {
	struct list_head block_list;
	u16 dynamic_block_id;
	u16 dynamic_index_cnt;
	u8 dynamic_index_used[HINIC5_TCAM_DYNAMIC_BLOCK_SIZE];
};

struct hinic5_tcam_dynamic_block_info {
	struct list_head tcam_dynamic_list;
	u16 dynamic_block_cnt;
};

struct hinic5_tcam_filter {
	struct list_head tcam_filter_list;
	u16 dynamic_block_id;
	u16 index;
	struct tag_tcam_key tcam_key;
	u16 queue;
};

/* function level struct info */
struct hinic5_tcam_info {
	u16 tcam_rule_nums;
	struct list_head tcam_list;
	struct hinic5_tcam_dynamic_block_info tcam_dynamic_info;
};

struct hinic5_hinic5_vram {
	u32 hinic5_vram_mtu;
	u16 hinic5_vram_num_qps;
	unsigned long flags;

	/* dcb */
	u8	trust; /* pcp, dscp */
	u8	default_cos;
};

struct hinic5_ptp_ctrl {
	unsigned long flags;  /* PTP_TX_BUSY flag, ses enum hinic5_ptp_flags */
	void *hwdev;
	u32 inc_val;  /* rtc inc val per cycle */
	struct ptp_clock *ptp_clock;
	struct ptp_clock_info	ptp_info;
	spinlock_t		ptp_clock_lock;  /* lock for access ptp hw reg */
	struct sk_buff *tx_saved_skb;
	struct hwtstamp_config	config;
	unsigned long tx_start;  /* PTP tx send jiffies */
	int tx_enable;
	int rx_enable;
};

struct hinic5_timeout {
	u32 wait_flush_qp_res_timeout;
};

typedef u8 (*hinic5_nic_cqe_cb)(void *llddev, void *data);

struct hinic5_tx_rx_ops {
	void (*tx_set_wqe_offload)(struct hinic5_offload_info *offload_info,
				   struct hinic5_sq_wqe_combo *wqe_combo);
	void (*rx_get_cqe_info)(struct hinic5_rq_cqe *rx_cqe,
				struct hinic5_cqe_info *cqe_info, u8 cqe_mode, bool enable_pfe);
	bool (*rx_cqe_done)(struct hinic5_rxq *rxq, struct hinic5_rq_cqe **rx_cqe);
	hinic5_nic_cqe_cb cqe_cb[SERVICE_T_MAX];
	unsigned long     cqe_cb_state[SERVICE_T_MAX];
	unsigned long     cqe_cb_running[SERVICE_T_MAX];
};

struct hinic5_nic_dev {
	struct net_device *netdev;
	struct hinic5_lld_dev *lld_dev;
	void *hwdev;
	void *extend;	/* Product-specific custom data structure */

	/* Currently, 1 indicates is_in_kexec. */
	u32 state;

	int poll_weight;
	unsigned long *vlan_bitmap;

	u16 max_qps;
	u16 usr_qps_num;

	u8 flow_bifur_group_num;

	u32 msg_enable;
	unsigned long flags;

	u32 lro_replenish_thld;
	u32 dma_rx_buff_size;
	u16 rx_buff_len;
	u32 page_order;
	bool page_pool_enabled;

	/* Rss related varibles */
	u8 rss_hash_engine;
	struct nic_rss_type rss_type;
	u8 *rss_hkey;
	/* hkey in big endian */
	u32 *rss_hkey_be;
	u32 *rss_indir;

	u8 cos_config_num_max;
	u8 func_dft_cos_bitmap;
	u16 port_dft_cos_bitmap; /* used to tool validity check */

	struct hinic5_dcb_config hw_dcb_cfg;

	struct hinic5_hinic5_vram *nic_hinic5_vram;
	char nic_hinic5_vram_name[HINIC5_VRAM_NAME_MAX_LEN];

	int disable_port_cnt;

	struct hinic5_qp_coalesce_info *intr_coalesce;
	unsigned long last_moder_jiffies;
	u32 adaptive_rx_coal;
	u8 intr_coal_set_flag;

#ifndef HAVE_NETDEV_STATS_IN_NETDEV
	struct net_device_stats net_stats;
#endif

	struct hinic5_nic_stats	stats;

	/* lock for nic resource */
	struct mutex nic_mutex;
	bool force_port_disable;
	struct semaphore port_state_sem;
	u8 link_status;

	struct nic_service_cap nic_cap;

	struct hinic5_txq *txqs;
	struct hinic5_rxq *rxqs;
	struct hinic5_dyna_txrxq_params q_params;
	u8 cqe_mode; /* rx_cqe */
	bool support_htn;

	u16 num_qp_irq;
	struct irq_info *qps_irq_info;

	struct workqueue_struct *workq;

	struct work_struct rx_mode_work;
	struct delayed_work	moderation_task;

	struct list_head uc_filter_list;
	struct list_head mc_filter_list;
	unsigned long rx_mod_state;
	int netdev_uc_cnt;
	int	netdev_mc_cnt;

	int lb_test_rx_idx;
	int lb_pkt_len;
	u8 *lb_test_rx_buf;

	struct hinic5_tcam_info tcam;
	struct hinic5_rx_flow_rule rx_flow_rule;

#ifdef HAVE_XDP_SUPPORT
	struct bpf_prog *xdp_prog;
	bool remove_flag;
#endif

	struct delayed_work	periodic_work;
	/* reference to enum hinic5_event_work_flags */
	unsigned long event_flag;

	struct hinic5_nic_prof_attr *prof_attr;
	struct hinic5_prof_adapter *prof_adap;
	u64 rsvd8[7];
	u8 cos_mask_mode;
	u8 hw_default_cos_valid;
	u8 hw_default_cos;
	u8 tx_wqe_compact_task;
	u32 rxq_get_err_times;
	struct delayed_work	rxq_check_work;
	struct hinic5_ptp_ctrl ptp_ctrl;

	struct hinic5_tx_rx_ops tx_rx_ops;

	void *tc_info;

	struct hinic5_timeout timeout;

	struct macsec_resource *macsec_res;  // MACsec module uses resource
	struct work_struct arp_dual_work;
	struct sk_buff_head arp_queue;

	struct work_struct update_stats_work;
	struct hinic5_vport_stats vport_stats;
};

#define nicif_err(priv, type, dev, fmt, args...) \
	netif_level(err, priv, type, dev, "[NIC]" fmt, ##args)
#define nicif_warn(priv, type, dev, fmt, args...) \
	netif_level(warn, priv, type, dev, "[NIC]" fmt, ##args)
#define nicif_notice(priv, type, dev, fmt, args...) \
	netif_level(notice, priv, type, dev, "[NIC]" fmt, ##args)
#define nicif_info(priv, type, dev, fmt, args...) \
	netif_level(info, priv, type, dev, "[NIC]" fmt, ##args)
#define nicif_dbg(priv, type, dev, fmt, args...) \
	netif_level(dbg, priv, type, dev, "[NIC]" fmt, ##args)

#define hinic_msg(level, nic_dev, msglvl, format, arg...)	\
do {								\
	if ((nic_dev)->netdev && (nic_dev)->netdev->reg_state	\
	    == NETREG_REGISTERED)				\
		nicif_##level((nic_dev), msglvl, (nic_dev)->netdev,	\
			      format, ## arg);			\
	else							\
		nic_##level((nic_dev)->lld_dev->dev,		\
			    format, ## arg);			\
} while (0)

#define hinic5_info(nic_dev, msglvl, format, arg...)	\
	hinic_msg(info, nic_dev, msglvl, format, ## arg)

#define hinic5_warn(nic_dev, msglvl, format, arg...)	\
	hinic_msg(warn, nic_dev, msglvl, format, ## arg)

#define hinic5_err(nic_dev, msglvl, format, arg...)	\
	hinic_msg(err, nic_dev, msglvl, format, ## arg)

struct hinic5_uld_info *hinic5_get_nic_uld_info(void);

u32 hinic5_get_io_stats_size(const struct hinic5_nic_dev *nic_dev);

int hinic5_get_io_stats(const struct hinic5_nic_dev *nic_dev, void *stats);

int hinic5_open(struct net_device *netdev);

int hinic5_close(struct net_device *netdev);

int hinic5_flush_nic_dev(void *priv_data);

void hinic5_set_ethtool_ops(struct net_device *netdev);

void hinic5vf_set_ethtool_ops(struct net_device *netdev);

int hinic5_nic_ioctl(void *uld_dev, u32 cmd, const void *buf_in,
	      u32 in_size, void *buf_out, u32 *out_size);

void hinic5_update_num_qps(struct net_device *netdev);

void hinic5_set_netdev_ops(struct hinic5_nic_dev *nic_dev);

bool hinic5_is_netdev_ops_match(const struct net_device *netdev);

int hinic5_set_hw_features(struct hinic5_nic_dev *nic_dev);

void hinic5_set_rx_mode_work(struct work_struct *work);

void hinic5_clean_mac_list_filter(struct hinic5_nic_dev *nic_dev);

void hinic5_get_strings(struct net_device *netdev, u32 stringset, u8 *data);

void hinic5_get_ethtool_stats(struct net_device *netdev,
			      struct ethtool_stats *stats, u64 *data);

int hinic5_get_sset_count(struct net_device *netdev, int sset);

int hinic5_force_port_disable(struct hinic5_nic_dev *nic_dev);

int hinic5_force_set_port_state(struct hinic5_nic_dev *nic_dev, bool enable);

int hinic5_maybe_set_port_state(struct hinic5_nic_dev *nic_dev, bool enable);

#ifdef ETHTOOL_GLINKSETTINGS
#ifndef XENSERVER_HAVE_NEW_ETHTOOL_OPS
int hinic5_get_link_ksettings(struct net_device *netdev,
			      struct ethtool_link_ksettings *link_settings);
int hinic5_set_link_ksettings(struct net_device *netdev,
			      const struct ethtool_link_ksettings
			      *link_settings);
#endif
#endif

#ifndef HAVE_NEW_ETHTOOL_LINK_SETTINGS_ONLY
int hinic5_get_settings(struct net_device *netdev, struct ethtool_cmd *ep);
int hinic5_set_settings(struct net_device *netdev,
			struct ethtool_cmd *link_settings);
#endif

void hinic5_auto_moderation_work(struct work_struct *work);

typedef void (*hinic5_reopen_handler)(struct hinic5_nic_dev *nic_dev,
				      const void *priv_data);
int hinic5_change_channel_settings(struct hinic5_nic_dev *nic_dev,
				   struct hinic5_dyna_txrxq_params *trxq_params,
				   hinic5_reopen_handler reopen_handler,
				   const void *priv_data);

void hinic5_link_status_change(struct hinic5_nic_dev *nic_dev, bool status);

#ifdef HAVE_XDP_SUPPORT
bool hinic5_is_xdp_enable(struct hinic5_nic_dev *nic_dev);
int hinic5_xdp_max_mtu(struct hinic5_nic_dev *nic_dev);
int hinic5_safe_switch_channels(struct hinic5_nic_dev *nic_dev);
int hinic5_set_xdp_num(struct hinic5_nic_dev *nic_dev,
		       struct hinic5_dyna_txrxq_params *trxq_params);
#endif

#if defined(ETHTOOL_GFECPARAM) && defined(ETHTOOL_SFECPARAM)
int hinic5_get_fecparam(struct net_device *netdev, struct ethtool_fecparam *fecparam);
int hinic5_set_fecparam(struct net_device *netdev, struct ethtool_fecparam *fecparam);
#endif

#ifdef HAVE_UDP_TUNNEL_NIC_INFO
/* set vxlan dport */
int hinic5_udp_tunnel_set_port(struct net_device *netdev, unsigned int table,
			       unsigned int entry, struct udp_tunnel_info *ti);
int hinic5_udp_tunnel_unset_port(struct net_device *netdev, unsigned int table,
				 unsigned int entry, struct udp_tunnel_info *ti);
#endif /* HAVE_UDP_TUNNEL_NIC_INFO */

#endif

