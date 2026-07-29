/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2020-2026 Mucse Corporation. */

#ifndef _MCEVF_H_
#define _MCEVF_H_

#include <linux/types.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/firmware.h>
#include <linux/netdevice.h>
#include <linux/compiler.h>
#include <linux/etherdevice.h>
#include <linux/skbuff.h>
#include <linux/cpumask.h>
#include <linux/rtnetlink.h>
#include <linux/if_vlan.h>
#include <linux/if_macvlan.h>
#include <linux/dma-mapping.h>
#include <linux/pci.h>
#include <linux/workqueue.h>
#include <linux/wait.h>
#include <linux/aer.h>
#include <linux/interrupt.h>
#include <linux/ethtool.h>
#include <linux/timer.h>
#include <linux/delay.h>
#include <linux/bitmap.h>
#include <linux/bitfield.h>
#include <linux/hashtable.h>
#include <linux/log2.h>
#include <linux/ip.h>
#include <linux/sctp.h>
#include <linux/ipv6.h>
#include <linux/pkt_sched.h>
#include <linux/if_bridge.h>
#include <linux/string.h>
#include <linux/ctype.h>
#include <linux/sizes.h>
#include <linux/linkmode.h>
#include <linux/bpf.h>
#include <linux/filter.h>
#include <net/xdp_sock.h>
#include <net/ipv6.h>
#if IS_ENABLED(CONFIG_NET_DEVLINK)
#include <net/devlink.h>
#endif /* CONFIG_NET_DEVLINK */
#include <linux/dim.h>
#include <linux/gnss.h>
#include "mcevf_type.h"
#include "mcevf_txrx.h"

#include <linux/auxiliary_bus.h>
#if IS_ENABLED(CONFIG_VXLAN)
#include <net/vxlan.h>
#endif
#include <net/gre.h>
#if IS_ENABLED(CONFIG_GENEVE)
#include <net/geneve.h>
#endif
#include <net/gtp.h>
#include <net/udp_tunnel.h>
#ifdef NETIF_F_HW_TC
#include <net/pkt_cls.h>
#include <net/tc_act/tc_mirred.h>
#include <net/tc_act/tc_gact.h>
#endif /* NETIF_F_HW_TC */
#include <net/ip.h>
#include <linux/cpu_rmap.h>
#include <linux/atomic.h>
#include <linux/jiffies.h>
#include <net/inetpeer.h>

#define DRIVER_NAME "mcevf"

#define MCEVF_SET_USED(x) ((void)(x))

#define _vf_function(func) (func)
#define _vfnum(num) (num)
#define VF_T4_INDEX(num) ((num) - 4)

// #define MCEVF_DEBUG
#ifdef MCEVF_DEBUG
#define MCEVF_DBG(NIC, fmt, args...) \
	dev_info((NIC)->dev, "DEBUG: " fmt, ##args)
#else
#define MCEVF_DBG(NIC, fmt, args...) \
	do {                           \
	} while (0)
#endif

#define mcevf_pf_to_dev(pf) (&((pf)->pdev->dev))

#define mcevf_for_each_q_vector(vsi, i) \
	for ((i) = 0; (i) < (vsi)->num_q_vectors; (i)++)

/* iterator for handling rings in ring container */
#define mcevf_rc_for_each_ring(pos, head) \
	for (pos = (head).ring; pos; pos = pos->next)

/* iterator for handling rings in ring container */
#define mcevf_for_each_ring(pos, head) \
	for (pos = (head).ring; pos; pos = pos->next)

/* iterator for handling rings in ring container */
#define mcevf_rc_for_each_ring(pos, head) \
	for (pos = (head).ring; pos; pos = pos->next)

/* Macros for each Tx/Rx ring in a VSI */
#define mcevf_for_each_txq(vsi, i) \
	for ((i) = 0; (i) < (vsi)->num_txq; (i)++)

#define mcevf_for_each_rxq(vsi, i) \
	for ((i) = 0; (i) < (vsi)->num_rxq; (i)++)

/* Macro for each VSI in a PF */
#define mcevf_for_each_vsi(pf, i) \
	for ((i) = 0; (i) < (pf)->num_alloc_vsi; (i)++)

#define MCEVF_RXBUF_3072 (3072)
#define MCEVF_RXBUF_2048 (2048)
#define MCEVF_RXBUF_1536 (1536)

/* rx packets max/min len */
#define MCEVF_ETH_DFT_RXTRANS_MIN_LEN 33
// #define MCEVF_ETH_DFT_RXTRANS_MAX_LEN 16383
#define MCEVF_ETH_DFT_RXTRANS_MAX_LEN 9790
#define MCEVF_ETH_EDTUP_CMD_LEN 64
#define MCEVF_ETH_DFT_FRAME_MAX_LEN \
	(MCEVF_ETH_DFT_RXTRANS_MAX_LEN - MCEVF_ETH_EDTUP_CMD_LEN)
#define MCEVF_ETH_PKT_HDR_PAD (ETH_HLEN + ETH_FCS_LEN + (VLAN_HLEN * 2))
#define MCEVF_MAX_MTU (MCEVF_ETH_DFT_FRAME_MAX_LEN - MCEVF_ETH_PKT_HDR_PAD)

#define MCEVF_DMA_RING_RX_SCATTER_MAX_LEN 9728

#define MCEVF_INT_NAME_STR_LEN (IFNAMSIZ + 16)

#define MCEVF_DFLT_NETIF_M (NETIF_MSG_LINK | NETIF_MSG_IFUP | NETIF_MSG_IFDOWN)
#define MCEVF_SCHED_MAX_BW (100000000) /* in Kbps */
/* MSIX */
#define MCEVF_MIN_MSIX (1)

/* VSI */
#define MCEVF_NO_VSI (1)
#ifndef MAX_DEFAULT_VECTORS
#define MAX_DEFAULT_VECTORS (64)
#endif /* MAX_DEFAULT_VECTORS */
#define MIN_DEFAULT_VECTORS (8)

#define MCEVF_RES_VALID_BIT (0x8000)
#define MCEVF_INVAL_Q_INDEX (0xffff)
/* ring info */
#define MCEVF_MAX_NUM_DESC (1024)
#define MCEVF_MIN_NUM_DESC (64)
#define MCEVF_REQ_DESC_MULTIPLE (32)
#define MAX_RING_CNT (512)
#define MAX_Q_VECTORS (MAX_RING_CNT + 1)
#define MCEVF_MIN_PKT_LEN (60)
#define RNCEVF_MAX_FRAGS (16)

/* read or write reg*/
#define mcevf_rd_reg(reg) readl((reg))
#define mcevf_wr_reg(reg, val) writel((val), (reg))
#define rd32(rdev, off) mcevf_rd_reg((rdev)->eth_bar_base + (off))
#define wr32(rdev, off, val) mcevf_wr_reg((rdev)->eth_bar_base + (off), (val))
#define ring_rd32(ring, off) mcevf_rd_reg((ring)->ring_addr + (off))
#define ring_wr32(ring, off, val) mcevf_wr_reg((ring)->ring_addr + (off), (val))

#define SET_BIT(n, var) ((var) = ((var) | (1 << (n))))
#define CLR_BIT(n, var) ((var) = ((var) & ~(1 << (n))))
#define CHK_BIT(n, var) ((var) & (1 << (n)))

enum mcevf_boards {
	board_n20 = 0,
};

enum mcevf_pf_state {
	MCEVF_TESTING,
	MCEVF_DOWN,
	MCEVF_SERVICE_DIS,
	MCEVF_NEEDS_RESTART,
	MCEVF_SHUTTING_DOWN,
	MCEVF_SERVICE_SCHED,
	MCEVF_RESET_FAILED,
	MCEVF_MAILBOXQ_EVENT_PENDING,
	MCEVF_REMOVED,

	MCEVF_STATE_NBITS /* must be last */
};

enum mcevf_pf_flags {
	MCEVF_FLAG_FLTR_SYNC,
	MCEVF_FLAG_RSS_ENA,
	MCEVF_FLAG_SRIOV_ENA,
	MCEVF_FLAG_LEGACY_RX,
	MCEVF_FLAG_PF_SET_VLAN,
	MCEVF_FLAG_PF_UPDATE_VLAN,
	MCEVF_FLAG_PF_UPDATE_LINK,
	MCEVF_FLAG_PF_UPDATE_FCS,
	MCEVF_FLAG_VF_SET_DVLAN,
	MCEVF_FLAG_MTU_CHANGED,
	MCEVF_FLAG_HW_DIM_ENA,
	MCEVF_FLAG_SW_DIM_ENA,
	MCEVF_FLAG_RSS_MODE_ORDER,
	MCEVF_FLAG_RSS_MISC_TYPE_PTP,
	MCEVF_FLAG_RSS_MISC_TYPE_IPV4_SPI,
	MCEVF_FLAG_RSS_MISC_TYPE_IPV6_SPI,
	MCEVF_FLAG_RSS_MISC_TYPE_IPV4_TEID,
	MCEVF_FLAG_RSS_MISC_TYPE_IPV6_TEID,
	MCEVF_FLAG_FORCE_CLOSE,
	MCEVF_FLAG_FORCE_OPEN,
	MCEVF_FLAG_SPOOF_ON,
	MCEVF_FLAG_TRUST_ON,
	MCEVF_FLAG_TUNNEL_INNER_ENA,
	MCEVF_FLAG_NETDEV_STATE_FCS_ENA,
	MCEVF_FLAG_RSS_TBL_INITED,
	MCEVF_FLAG_DSCP_ENA,
	MCEVF_FLAG_PFC_ENA,
	MCEVF_FLAG_VF_NDO_OPENED,
	MCEVF_PF_FLAGS_NBITS /* must be last */
};

enum mcevf_vsi_state {
	MCEVF_VSI_DOWN,
	MCEVF_VSI_NEEDS_RESTART,
	MCEVF_VSI_NETDEV_ALLOCD,
	MCEVF_VSI_NETDEV_REGISTERED,
	MCEVF_VSI_UMAC_FLTR_CHANGED,
	MCEVF_VSI_MMAC_FLTR_CHANGED,
	MCEVF_CFG_BUSY,
	MCEVF_VSI_STATE_NBITS /* must be last */
};

enum pma_type {
	PHY_TYPE_NONE = 0,
	PHY_TYPE_1G_BASE_KX,
	PHY_TYPE_SGMII,
	PHY_TYPE_10G_BASE_KR,
	PHY_TYPE_25G_BASE_KR,
	PHY_TYPE_40G_BASE_KR4,
	PHY_TYPE_10G_BASE_SR,
	PHY_TYPE_40G_BASE_SR4,
	PHY_TYPE_40G_BASE_CR4,
	PHY_TYPE_40G_BASE_LR4,
	PHY_TYPE_10G_BASE_LR,
	PHY_TYPE_10G_BASE_ER,
};

struct mcevf_vsi;
struct mcevf_q_vector;
struct mcevf_vsi_stats {
	struct mcevf_ring_stats **tx_ring_stats; /* Tx ring stats array */
	struct mcevf_ring_stats **rx_ring_stats; /* Rx ring stats array */
};

struct mcevf_res_tracker {
	u16 num_entries;
	u16 end;
	u16 list[];
};

enum mcevf_dvlan_type {
	MCEVF_VLAN_TYPE_8100 = 0,
	MCEVF_VLAN_TYPE_88A8,
};

struct mcevf_vlan_hdr {
	u16 vid;
	enum mcevf_dvlan_type type;
} __packed;

struct mcevf_dvlan_ctrl {
	int en;
	struct mcevf_vlan_hdr outer_hdr;
	struct mcevf_vlan_hdr inner_hdr;
	int cnt;
} __packed;

/* ring debug information */
struct mcevf_d_ringinfo {
	u16 txring_start;
	u16 txring_end;
	u16 rxring_start;
	u16 rxring_end;
	bool txring_valid;
	bool rxring_valid;
} __packed;

/* desc debug information */
struct mcevf_d_descinfo {
	u16 txring_idx;
	u16 txdesc_idx;
	u16 rxring_idx;
	u16 rxdesc_idx;
} __packed;

enum mcevf_dcb_flags {
	MCEVF_DCB_EN = 0,
	MCEVF_ETS_EN,
	MCEVF_PFC_EN,
	MCEVF_DSCP_EN,
	MCEVF_FLAG_DCB_TOOLS,
	MCEVF_MQPRIO_CHANNEL,
	MCEVF_FLAG_RDMA_ENA,
	MCEVF_FLAG_DEVLINK_TEST,
	MCEVF_DCB_FLAG_NBITS
};

struct mcevf_tc_cfg {
	//u32 min_rate[MCE_MAX_QGS]; /* min rate, unit:Mb */
	//u32 max_rate[MCE_MAX_QGS]; /* max rate, unit:Mb */
	//u8 qg_qs[MCE_MAX_QGS]; /* ring num of QG[I], max is 4*/
	u8 tc_prios_bit[8]; /*  tc prio bitmap */
	u8 tc_prios_cnt[8]; /* prio cnts of this tc */
	u8 prio_tc[8]; /* prio[i] of tc */
	u8 etc_tc[8]; /* tc[i] used by ets map to actually used tc */
	u8 tc_qgs[8]; /* QG num of tc[i] */
	u8 tc_bw[8]; /* percent of tc[i] */
	u8 tc_cnt;
	u8 qg_cnt;

	u8 ntc_cnt;
	u8 prio_ntc[8]; /* prio i to tc in netdev */
	u16 ntc_txq_base[8]; /* tc[i] used first ring num */
	u16 ntc_txq_cunt[8]; /* tc[i] used ring cnts in netdev */
	u16 pfc_txq_base[8][8]; /* tc x prio i tx queue base */
	u16 pfc_txq_count[8][8]; /* tc x prio i tx queue count */
	u16 pfc_txq_base_temp[8]; /* prio i tx queue base */
	u16 pfc_txq_count_temp[8]; /* prio i tx queue count */
	int qg_base_off;
};

#define MCEVF_MAX_DSCP 64
#define MCEVF_MAX_VLAN 4096
#define MCE_MAX_PRIORITY 8
struct mcevf_dcb {
	struct mutex dcb_mutex; /* protects DCB configuration */
	struct mcevf_pf *back;
	/* when DSCP mapping defined by user set its bit to 1 */
	DECLARE_BITMAP(dscp_mapped, MCEVF_MAX_DSCP);
	/* array holding DSCP -> priority for DSCP L3 QoS mode */
	u8 dscp_map[MCEVF_MAX_DSCP];
	u8 vlan_to_q[MCEVF_MAX_VLAN];
	DECLARE_BITMAP(flags, MCEVF_DCB_FLAG_NBITS);

	//u16 dcbx_cap;
	struct mcevf_tc_cfg cur_tccfg;
	//struct mce_tc_cfg new_tccfg;
	//struct mce_ets_cfg cur_etscfg;
	//struct mce_ets_cfg new_etscfg;
	//struct mce_pfc_cfg cur_pfccfg;
	//struct mce_pfc_cfg new_pfccfg;
	//struct ieee_pfc pfc_os;
	//struct ieee_ets ets_os;
};

struct mcevf_pf {
	struct pci_dev *pdev;
	struct mcevf_hw hw;
	struct notifier_block nb;	/* notifier for IP address changes */

	u16 max_pf_txqs; /* Total Tx queues PF wide */
	u16 max_pf_rxqs; /* Total Rx queues PF wide */
	u16 num_msix_cnt; /* Total MSIX vectors */
	int num_avail_msix; /* remaining MSIX SW vectors left unclaimed */
	u16 qvec_irq_base; /* ring vectors base */
	u16 mbox_irq_base; /* mbox vectors base */
	u16 num_mbox_irqs; /* mbox irqs */
	u16 rdma_irq_base; /* rdma vectors base */
	u16 num_rdma_irqs; /* rdma irqs */

	u16 next_vsi; /* Next free slot in pf->vsi[] - 0-based! */
	u16 num_alloc_vsi;
	struct mcevf_vsi **vsi; /* VSIs created by the driver */
	struct mcevf_vsi_stats **vsi_stats;
	struct mcevf_dcb *dcb;
	struct msix_entry *msix_entries;
	struct mcevf_res_tracker *irq_tracker;

	struct mutex sw_mutex; /* lock for protecting VSI alloc flow */
	struct mutex avail_q_mutex; /* protects access to avail_[rx|tx]qs */

	unsigned long *avail_txqs; /* bitmap to track PF Tx queue usage */
	unsigned long *avail_rxqs; /* bitmap to track PF Rx queue usage */

	unsigned long serv_tmr_period;
	u32 serv_tmr_max_cnt;
	u32 serv_tmr_ticks;
	unsigned long serv_tmr_prev;
#define __MCEVF_SERV_TIMER_PERIODS_UNIT (HZ / 10 / (1000 / CONFIG_HZ))
#define __MCEVF_SERV_TIMER_PERIODS_CNT (10)
	struct timer_list serv_tmr;
	struct work_struct serv_task;
	char int_name[MCEVF_INT_NAME_STR_LEN];

	DECLARE_BITMAP(state, MCEVF_STATE_NBITS);
	DECLARE_BITMAP(flags, MCEVF_PF_FLAGS_NBITS);
	u32 msg_enable;
	u16 vf_vlan;
	u16 vf_vlan_qos;
	u16 vf_vlan_proto;
	u16 vlan_strip_cnt;
	bool drop_intr_timer_en;
	struct mcevf_dvlan_ctrl dvlan_ctrl;
	struct mcevf_d_ringinfo d_ringinfo;
	struct mcevf_d_descinfo d_descinfo;
	int valid_prio;

	/* RDMA */
	struct iidc_core_dev_info *cdev_infos;
	struct mutex adev_mutex; /* protects auxiliary device state */
	bool tun_inner;
	u32 cline_size; /* cpu cache line size */
	u32 ipv4_addr;
	bool ipv4_addr_conflict;
};

struct mcevf_q_vector {
	char name[MCEVF_INT_NAME_STR_LEN];
	struct mcevf_vsi *vsi;
	int v_idx;
	u8 num_ring_rx; /* total number of Rx rings in vector */
	u8 num_ring_tx; /* total number of Tx rings in vector */
	int cpu;
	int numa_node;
	u16 total_events;
	cpumask_t affinity_mask;
	struct irq_affinity_notify affinity_notify;
	struct mcevf_hw *rdev;
	struct napi_struct napi;
	struct mcevf_ring_container rx;
	struct mcevf_ring_container tx;
	u32 ticks;
	u32 old_ticks;
};

struct mcevf_port_info {
	struct mcevf_hw *hw; /* back pointer to HW instance */
	struct mcevf_mac_info mac;
	/* link info */
	bool link_up;
	u32 link_speed;
};

struct mcevf_vsi {
	u16 alloc_txq; /* Allocated Tx queues */
	u16 alloc_rxq; /* Allocated Rx queues */
	u16 num_txq; /* Used Tx queues */
	u16 num_rxq; /* Used Rx queues */
	u16 req_txq; /* User requested Tx queues */
	u16 req_rxq; /* User requested Rx queues */
	u16 num_tx_desc;
	u16 num_rx_desc;
	u16 *txq_map; /* index in pf->avail_txqs */
	u16 *rxq_map; /* index in pf->avail_rxqs */
	u16 num_q_vectors;
	u16 base_vector; /* IRQ base for OS reserved vectors */

	u16 max_frame;
	u16 rx_buf_len;

	u16 idx; /* software index in pf->vsi[] */

	struct net_device *netdev;
	struct mcevf_pf *back;
	struct mcevf_port_info *port_info; /* back pointer to port_info */

	struct mcevf_ring **rx_rings; /* Rx ring array */
	struct mcevf_ring **tx_rings; /* Tx ring array */
	struct mcevf_q_vector **q_vectors; /* q_vector array */

	irqreturn_t (*irq_handler)(int irq, void *data);

	DECLARE_BITMAP(state, MCEVF_VSI_STATE_NBITS);
	unsigned int current_netdev_flags;

	u32 tx_restart;
	u32 tx_busy;
	u32 rx_buf_failed;
	u32 rx_page_failed;
	u64 tx_linearize;
	/* VSI stats */
	spinlock_t stats_lock;
	struct rtnl_link_stats64 net_stats;
	struct rtnl_link_stats64 net_stats_prev;
	struct mcevf_ofld_stats ofld_stats;
	u8 irqs_ready;
	u8 rx_flags;
#define RX_FLAG_VLAN_STRIP BIT(0)
	netdev_features_t changed_flags;
} ____cacheline_internodealigned_in_smp;

struct mcevf_netdev_priv {
	struct mcevf_vsi *vsi;
};

static inline bool mcevf_is_xdp_ena_vsi(struct mcevf_vsi *vsi)
{
	return false;
}

/**
 * mcevf_get_main_vsi - Get the PF VSI
 * @pf: PF instance
 *
 * returns pf->vsi[0], which by definition is the PF VSI
 */
static inline struct mcevf_vsi *
mcevf_get_main_vsi(struct mcevf_pf *pf)
{
	return pf->vsi[0];
}

#define mcevf_hw_to_netdev(hw) \
	(mcevf_get_main_vsi(pci_get_drvdata((hw)->pdev))->netdev)

/* Attempt to maximize the headroom available for incoming frames. We use a 2K
 * buffer for MTUs <= 1500 and need 1536/1534 to store the data for the frame.
 * This leaves us with 512 bytes of room.  From that we need to deduct the
 * space needed for the shared info and the padding needed to IP align the
 * frame.
 *
 * Note: For cache line sizes 256 or larger this value is going to end
 *	 up negative.  In these cases we should fall back to the legacy
 *	 receive path.
 */
#if (PAGE_SIZE < 8192)
#define MCEVF_2K_TOO_SMALL_WITH_PADDING                   \
	((unsigned int)(NET_SKB_PAD + MCEVF_RXBUF_1536) > \
	 SKB_WITH_OVERHEAD(MCEVF_RXBUF_2048))
#else
#define MCEVF_2K_TOO_SMALL_WITH_PADDING false
#endif
/**
 * mcevf_compute_pad - compute the padding
 * @rx_buf_len: buffer length
 *
 * Figure out the size of half page based on given buffer length and
 * then subtract the skb_shared_info followed by subtraction of the
 * actual buffer length; this in turn results in the actual space that
 * is left for padding usage
 */
static inline int mcevf_compute_pad(int rx_buf_len)
{
	int half_page_size;

	half_page_size = ALIGN(rx_buf_len, PAGE_SIZE / 2);
	return SKB_WITH_OVERHEAD(half_page_size) - rx_buf_len;
}

#define MCEVF_SMP_CACHE_LINE_RESIZE 128

/**
 * mcevf_skb_pad - determine the padding that we can supply
 *
 * Figure out the right Rx buffer size and based on that calculate the
 * padding
 */
static inline int mcevf_skb_pad(struct mcevf_pf *pf)
{
#if (PAGE_SIZE < 8192)
	int rx_buf_len;

	/* If a 2K buffer cannot handle a standard Ethernet frame then
	 * optimize padding for a 3K buffer instead of a 1.5K buffer.
	 *
	 * For a 3K buffer we need to add enough padding to allow for
	 * tailroom due to NET_IP_ALIGN possibly shifting us out of
	 * cache-line alignment.
	 */
	if (MCEVF_2K_TOO_SMALL_WITH_PADDING) {
		if (pf->cline_size == MCEVF_SMP_CACHE_LINE_RESIZE)
			rx_buf_len = MCEVF_RXBUF_3072 +
				     ALIGN(NET_IP_ALIGN,
					   MCEVF_SMP_CACHE_LINE_RESIZE);
		else
			rx_buf_len =
				MCEVF_RXBUF_3072 + SKB_DATA_ALIGN(NET_IP_ALIGN);
	} else {
		if (pf->cline_size == MCEVF_SMP_CACHE_LINE_RESIZE)
			return MCEVF_SMP_CACHE_LINE_RESIZE;
		rx_buf_len = MCEVF_RXBUF_1536;
	}

	/* if needed make room for NET_IP_ALIGN */
	rx_buf_len -= NET_IP_ALIGN;

	return mcevf_compute_pad(rx_buf_len);
#else
	if (pf->cline_size != MCEVF_SMP_CACHE_LINE_RESIZE)
		return NET_SKB_PAD + NET_IP_ALIGN;
	return ALIGN(NET_SKB_PAD + NET_IP_ALIGN, MCEVF_SMP_CACHE_LINE_RESIZE);
#endif
}

#define MCEVF_SKB_PAD(pf) mcevf_skb_pad(pf)

struct device *mcevf_hw_to_dev(struct mcevf_hw *hw);

/* mcevf_hw_n20.c */
int mcevf_get_n20_caps(struct mcevf_hw *rdev);

/* mcevf_main.c */
void mcevf_service_task_schedule(struct mcevf_pf *pf);
u16 mcevf_get_avail_txq_count(struct mcevf_pf *pf);
u16 mcevf_get_avail_rxq_count(struct mcevf_pf *pf);
int mcevf_vsi_recfg_qs(struct mcevf_vsi *vsi, int new_rx, int new_tx,
		       bool force);

#ifdef CONFIG_SYSFS
void mcevf_sysfs_exit(struct mcevf_pf *pf);
int mcevf_sysfs_init(struct mcevf_pf *pf);
#else
static inline void mcevf_sysfs_exit(struct mcevf_pf *pf)
{
}

static inline int mcevf_sysfs_init(struct mcevf_pf *pf)
{
	return 0;
}
#endif

/* mcevf_ethtool.c */
void mcevf_set_ethtool_ops(struct net_device *netdev);

/* mcevf_idc.c */
int mcevf_plug_aux_devs(struct mcevf_pf *pf, const char *name);
void mcevf_unplug_aux_devs(struct mcevf_pf *pf);

/* mbx */
s32 mcevf_virtchnl_completion(struct mcevf_pf *pf, bool to_cm3);
int mcevf_init_hw(struct mcevf_hw *hw);
int mcevf_reset_hw(struct mcevf_hw *hw, bool set_mac);
void mcevf_set_promiscuous(struct mcevf_pf *pf);

extern unsigned int mcevf_loglevel;

enum MCEVF_NET_LOG {
	LOG_MBX_IN_REQ,
	LOG_MBX_REQ_OUT,
	LOG_VECTOR_ALLOC,
	LOG_MISC_IRQ,
	LOG_QUEUE_INFO,
	LOG_NET_MAX, /* must be last one */
};

#define TRACE() pr_debug("%s: %d\n", __func__, __LINE__)

#define logd(bit, fmt, args...)                  \
	do {                                     \
		if (BIT(bit) & mcevf_loglevel) { \
			pr_debug(fmt, ##args); \
		}                                \
	} while (0)

#define hw_logd(bit, fmt, args...)                      \
	do {                                            \
		if (BIT(bit) & mcevf_loglevel) {        \
			dev_info(hw->dev, fmt, ##args); \
		}                                       \
	} while (0)

#define pf_logd(bit, fmt, args...)                                  \
	do {                                                        \
		if (BIT(bit) & mcevf_loglevel) {                    \
			dev_info(mcevf_pf_to_dev(pf), fmt, ##args); \
		}                                                   \
	} while (0)

#define netdev_logd(bit, fmt, args...)                    \
	do {                                              \
		if (BIT(bit) & mcevf_loglevel) {          \
			netdev_info(netdev, fmt, ##args); \
		}                                         \
	} while (0)

#define mbx_logd(bit, fmt, args...)                          \
	do {                                                 \
		if (BIT(bit) & mcevf_loglevel) {             \
			dev_info(mbx->hw->dev, fmt, ##args); \
		}                                            \
	} while (0)

int speed_unzip(int speed_3bit);
int speed_zip_to_bit3(int speed);

#define __MCEVF_GET_RING_STATS_BY_HW 1

#endif /* _MCEVF_H_ */
