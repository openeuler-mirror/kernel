/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2021 Ramaxel Memory Technology, Ltd */

#ifndef SPNIC_NIC_DEV_H
#define	SPNIC_NIC_DEV_H

#include <linux/netdevice.h>
#include <linux/semaphore.h>
#include <linux/types.h>
#include <linux/bitops.h>

#include "spnic_nic_io.h"
#include "spnic_nic_cfg.h"
#include "spnic_tx.h"
#include "spnic_rx.h"
#include "spnic_dcb.h"

#define SPNIC_NIC_DRV_NAME	"spnic"
#define SPNIC_DRV_VERSION	"B090"
#define SPNIC_DRV_DESC		"Ramaxel(R) Network Interface Card Driver"

#define SPNIC_FUNC_IS_VF(hwdev)	(sphw_func_type(hwdev) == TYPE_VF)

#define SPNIC_AVG_PKT_SMALL	256U
#define SPNIC_MODERATONE_DELAY	HZ

#define LP_PKT_CNT 64

enum spnic_flags {
	SPNIC_INTF_UP,
	SPNIC_MAC_FILTER_CHANGED,
	SPNIC_LP_TEST,
	SPNIC_RSS_ENABLE,
	SPNIC_DCB_ENABLE,
	SPNIC_SAME_RXTX,
	SPNIC_INTR_ADAPT,
	SPNIC_UPDATE_MAC_FILTER,
	SPNIC_CHANGE_RES_INVALID,
	SPNIC_RSS_DEFAULT_INDIR,
};

#define SPHW_CHANNEL_RES_VALID(nic_dev)	\
		(test_bit(SPNIC_INTF_UP, &(nic_dev)->flags) && \
		 !test_bit(SPNIC_CHANGE_RES_INVALID, &(nic_dev)->flags))

#define RX_BUFF_NUM_PER_PAGE	2

#define VLAN_BITMAP_BYTE_SIZE(nic_dev)	(sizeof(*(nic_dev)->vlan_bitmap))
#define VLAN_BITMAP_BITS_SIZE(nic_dev)	(VLAN_BITMAP_BYTE_SIZE(nic_dev) * 8)
#define VLAN_NUM_BITMAPS(nic_dev)	(VLAN_N_VID / \
					VLAN_BITMAP_BITS_SIZE(nic_dev))
#define VLAN_BITMAP_SIZE(nic_dev)	(VLAN_N_VID / \
					VLAN_BITMAP_BYTE_SIZE(nic_dev))
#define VID_LINE(nic_dev, vid)	((vid) / VLAN_BITMAP_BITS_SIZE(nic_dev))
#define VID_COL(nic_dev, vid)	((vid) & (VLAN_BITMAP_BITS_SIZE(nic_dev) - 1))

#define SPNIC_DRV_FEATURE	NIC_F_ALL_MASK

enum spnic_event_work_flags {
	EVENT_WORK_TX_TIMEOUT,
};

enum spnic_rx_mode_state {
	SPNIC_HW_PROMISC_ON,
	SPNIC_HW_ALLMULTI_ON,
	SPNIC_PROMISC_FORCE_ON,
	SPNIC_ALLMULTI_FORCE_ON,
};

enum mac_filter_state {
	SPNIC_MAC_WAIT_HW_SYNC,
	SPNIC_MAC_HW_SYNCED,
	SPNIC_MAC_WAIT_HW_UNSYNC,
	SPNIC_MAC_HW_UNSYNCED,
};

struct spnic_mac_filter {
	struct list_head list;
	u8 addr[ETH_ALEN];
	unsigned long state;
};

struct spnic_irq {
	struct net_device	*netdev;
	/* IRQ corresponding index number */
	u16			msix_entry_idx;
	u32			irq_id;         /* The IRQ number from OS */
	char			irq_name[IFNAMSIZ + 16];
	struct napi_struct	napi;
	cpumask_t		affinity_mask;
	struct spnic_txq	*txq;
	struct spnic_rxq	*rxq;
};

struct spnic_intr_coal_info {
	u8	pending_limt;
	u8	coalesce_timer_cfg;
	u8	resend_timer_cfg;

	u64	pkt_rate_low;
	u8	rx_usecs_low;
	u8	rx_pending_limt_low;
	u64	pkt_rate_high;
	u8	rx_usecs_high;
	u8	rx_pending_limt_high;

	u8	user_set_intr_coal_flag;
};

struct spnic_dyna_txrxq_params {
	u16	num_qps;
	u16	num_rss;
	u16	rss_limit;
	u8	num_tc;
	u8	rsvd1;
	u32	sq_depth;
	u32	rq_depth;

	struct spnic_dyna_txq_res	*txqs_res;
	struct spnic_dyna_rxq_res	*rxqs_res;
	struct spnic_irq		*irq_cfg;
};

#define SPNIC_NIC_STATS_INC(nic_dev, field)		\
do {							\
	u64_stats_update_begin(&(nic_dev)->stats.syncp);\
	(nic_dev)->stats.field++;			\
	u64_stats_update_end(&(nic_dev)->stats.syncp);	\
} while (0)

struct spnic_nic_stats {
	u64	netdev_tx_timeout;

	/* Subdivision statistics show in private tool */
	u64	tx_carrier_off_drop;
	u64	tx_invalid_qid;

	struct u64_stats_sync	syncp;
};

#define SPNIC_TCAM_DYNAMIC_BLOCK_SIZE 16
#define SPNIC_MAX_TCAM_FILTERS	512

#define SPNIC_PKT_TCAM_DYNAMIC_INDEX_START(block_index)  \
		(SPNIC_TCAM_DYNAMIC_BLOCK_SIZE * (block_index))

struct spnic_rx_flow_rule {
	struct list_head rules;
	int tot_num_rules;
};

struct spnic_tcam_dynamic_block {
	struct list_head block_list;
	u16 dynamic_block_id;
	u16 dynamic_index_cnt;
	u8 dynamic_index_used[SPNIC_TCAM_DYNAMIC_BLOCK_SIZE];
};

struct spnic_tcam_dynamic_block_info {
	struct list_head tcam_dynamic_list;
	u16 dynamic_block_cnt;
};

struct spnic_tcam_filter {
	struct list_head tcam_filter_list;
	u16 dynamic_block_id;
	u16 index;
	struct tag_tcam_key tcam_key;
	u16 queue;
};

/* function level struct info */
struct spnic_tcam_info {
	u16 tcam_rule_nums;
	struct list_head tcam_list;
	struct spnic_tcam_dynamic_block_info tcam_dynamic_info;
};

struct spnic_nic_dev {
	struct pci_dev		*pdev;
	struct net_device	*netdev;
	void			*hwdev;

	int			poll_weight;

	unsigned long		*vlan_bitmap;

	u16			max_qps;

	u32			msg_enable;
	unsigned long		flags;

	u32			lro_replenish_thld;
	u32			dma_rx_buff_size;
	u16			rx_buff_len;
	u32			page_order;

	/* Rss related varibles */
	u8			rss_hash_engine;
	struct nic_rss_type	rss_type;
	u8			*rss_hkey;
	/* hkey in big endian */
	u32			*rss_hkey_be;
	u32			*rss_indir;

	u32			dcb_changes;
	struct spnic_dcb_config hw_dcb_cfg;
	struct spnic_dcb_config wanted_dcb_cfg;
	unsigned long		dcb_flags;
	int			disable_port_cnt;
	/* lock for disable or enable traffic flow */
	struct semaphore	dcb_sem;

	struct spnic_intr_coal_info *intr_coalesce;
	unsigned long		last_moder_jiffies;
	u32			adaptive_rx_coal;
	u8			intr_coal_set_flag;

	struct spnic_nic_stats	stats;

	/* lock for nic resource */
	struct mutex		nic_mutex;
	bool			force_port_disable;
	struct semaphore	port_state_sem;
	u8			link_status;

	struct nic_service_cap	nic_cap;

	struct spnic_txq	*txqs;
	struct spnic_rxq	*rxqs;
	struct spnic_dyna_txrxq_params q_params;

	u16			num_qp_irq;
	struct irq_info		*qps_irq_info;

	struct workqueue_struct *workq;

	struct work_struct	rx_mode_work;
	struct delayed_work	moderation_task;

	struct list_head	uc_filter_list;
	struct list_head	mc_filter_list;
	unsigned long		rx_mod_state;
	int			netdev_uc_cnt;
	int			netdev_mc_cnt;

	int			lb_test_rx_idx;
	int			lb_pkt_len;
	u8			*lb_test_rx_buf;

	struct spnic_tcam_info tcam;
	struct spnic_rx_flow_rule rx_flow_rule;

	struct bpf_prog		*xdp_prog;

	struct delayed_work	periodic_work;
	/* reference to enum spnic_event_work_flags */
	unsigned long		event_flag;
};

#define IPSEC_CAP_IS_SUPPORT(nic_dev) ((nic_dev)->ipsec)

#define spnic_msg(level, nic_dev, msglvl, format, arg...)	\
do {								\
	if ((nic_dev)->netdev && (nic_dev)->netdev->reg_state	\
	    == NETREG_REGISTERED)				\
		nicif_##level((nic_dev), msglvl, (nic_dev)->netdev,	\
			      format, ## arg);			\
	else							\
		nic_##level(&(nic_dev)->pdev->dev,		\
			    format, ## arg);			\
} while (0)

#define spnic_info(nic_dev, msglvl, format, arg...)	\
	spnic_msg(info, nic_dev, msglvl, format, ## arg)

#define spnic_warn(nic_dev, msglvl, format, arg...)	\
	spnic_msg(warn, nic_dev, msglvl, format, ## arg)

#define spnic_err(nic_dev, msglvl, format, arg...)	\
	spnic_msg(err, nic_dev, msglvl, format, ## arg)

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

extern struct spnic_uld_info nic_uld_info;

u32 spnic_get_io_stats_size(struct spnic_nic_dev *nic_dev);

void spnic_get_io_stats(struct spnic_nic_dev *nic_dev, void *stats);

int spnic_open(struct net_device *netdev);

int spnic_close(struct net_device *netdev);

void spnic_set_ethtool_ops(struct net_device *netdev);

void spnicvf_set_ethtool_ops(struct net_device *netdev);

int nic_ioctl(void *uld_dev, u32 cmd, const void *buf_in,
	      u32 in_size, void *buf_out, u32 *out_size);

void spnic_update_num_qps(struct net_device *netdev);

int spnic_qps_irq_init(struct spnic_nic_dev *nic_dev);

void spnic_qps_irq_deinit(struct spnic_nic_dev *nic_dev);

void spnic_set_netdev_ops(struct spnic_nic_dev *nic_dev);

int spnic_set_hw_features(struct spnic_nic_dev *nic_dev);

void spnic_set_rx_mode_work(struct work_struct *work);

void spnic_clean_mac_list_filter(struct spnic_nic_dev *nic_dev);

void spnic_get_strings(struct net_device *netdev, u32 stringset, u8 *data);

void spnic_get_ethtool_stats(struct net_device *netdev, struct ethtool_stats *stats, u64 *data);

int spnic_get_sset_count(struct net_device *netdev, int sset);

int spnic_force_port_disable(struct spnic_nic_dev *nic_dev);

int spnic_force_set_port_state(struct spnic_nic_dev *nic_dev, bool enable);

int spnic_maybe_set_port_state(struct spnic_nic_dev *nic_dev, bool enable);

int spnic_get_link_ksettings(struct net_device *netdev,
			     struct ethtool_link_ksettings *link_settings);
int spnic_set_link_ksettings(struct net_device *netdev,
			     const struct ethtool_link_ksettings *link_settings);

void spnic_auto_moderation_work(struct work_struct *work);

typedef void (*spnic_reopen_handler)(struct spnic_nic_dev *nic_dev, const void *priv_data);
int spnic_change_channel_settings(struct spnic_nic_dev *nic_dev,
				  struct spnic_dyna_txrxq_params *trxq_params,
				  spnic_reopen_handler reopen_handler, const void *priv_data);

void spnic_link_status_change(struct spnic_nic_dev *nic_dev, bool status);

bool spnic_is_xdp_enable(struct spnic_nic_dev *nic_dev);
int spnic_xdp_max_mtu(struct spnic_nic_dev *nic_dev);

#endif
