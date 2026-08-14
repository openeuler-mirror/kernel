/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2024-2026 Mucse Corporation. */

#ifndef _MCE_H_
#define _MCE_H_

#include <linux/types.h>
#include <linux/mutex.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/cdev.h>
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
#include <linux/bitops.h>
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
#include <net/devlink.h>
#include <linux/dim.h>
#if IS_ENABLED(CONFIG_GNSS)
#include <linux/gnss.h>
#endif
#include <linux/log2.h>
#include <linux/net_tstamp.h>
#include <linux/ptp_clock_kernel.h>
#include <net/dsfield.h>
#include <net/udp_tunnel.h>
#include "mce_type.h"
#include "mce_txrx.h"
#include <linux/auxiliary_bus.h>
#include "mce_ptp.h"

#include <net/pkt_cls.h>
#include <net/tc_act/tc_mirred.h>
#include <net/tc_act/tc_gact.h>
#include <net/ip.h>
#include <linux/cpu_rmap.h>
#include <linux/atomic.h>
#include <linux/jiffies.h>
#include "mce_fdir.h"
#include "mce_fdir_flow.h"
#include "mce_tc_lib.h"
#include "mce_sriov.h"
#include "./mucse_auxiliary/mce_idc.h"
#include "mce_repr.h"
#include "mce_arfs.h"

#define DRIVER_NAME "mcepf"

extern const struct file_operations mce_fops;
#define MCE_MAC_STATS_EN 1

#define MAX_MCE_DEVICES 256
#define MCE_GTPC_PORT 2123
#define mce_pf_to_dev(pf) (&((pf)->pdev->dev))
#define mce_hw_to_dev(hw) ((hw)->dev)

#define mce_for_each_q_vector(vsi, i) \
	for ((i) = 0; (i) < (vsi)->num_q_vectors; (i)++)

/* iterator for handling rings in ring container */
#define mce_rc_for_each_ring(pos, head) \
	for (pos = (head).ring; pos; pos = pos->next)

/* Macros for each Tx/Rx ring in a VSI */
#define mce_for_each_txq(vsi, i) for ((i) = 0; (i) < (vsi)->num_txq; (i)++)

/* scan all alloc_txq */
#define mce_for_each_txq_new(vsi, i) \
	for ((i) = 0; (i) < (vsi)->alloc_txq; (i)++)

#define mce_for_each_rxq_new(vsi, i) \
	for ((i) = 0; (i) < (vsi)->alloc_rxq; (i)++)

/* Macro for each VSI in a PF */
#define mce_for_each_vsi(pf, i) for ((i) = 0; (i) < (pf)->num_alloc_vsi; (i)++)

#define mce_for_each_vf_id(pf, i) for ((i) = 0; (i) < (pf)->num_vfs; (i)++)

#define mce_for_each_pf_vf_id(pf, i) for ((i) = 0; (i) <= (pf)->num_vfs; (i)++)

/* Macros for each misc irq */
#define mce_for_each_misc_irq(i) \
	for ((i) = MCE_MAC_MISC_IRQ_NONE; (i) < MCE_MAC_MISC_IRQ_MAX; (i)++)

#define MCE_RXBUF_3072 (3072)
#define MCE_RXBUF_2048 (2048)
#define MCE_RXBUF_1536 (1536)

/* rx packets max/min len */
#define MCE_ETH_DFT_RXTRANS_MIN_LEN 33
#define MCE_ETH_DFT_RXTRANS_MAX_LEN 16383
#define MCE_ETH_EDTUP_CMD_LEN 64
#define MCE_ETH_DFT_FRAME_MAX_LEN \
	(MCE_ETH_DFT_RXTRANS_MAX_LEN - MCE_ETH_EDTUP_CMD_LEN)
#define MCE_ETH_PKT_HDR_PAD (ETH_HLEN + ETH_FCS_LEN + (VLAN_HLEN * 2))
#define MCE_MAX_MTU (MCE_ETH_DFT_FRAME_MAX_LEN - MCE_ETH_PKT_HDR_PAD - 293)
#define NORMAL_MTU 9600

#define MCE_DMA_RING_RX_SCATTER_MAX_LEN 9728

#define MCE_INT_NAME_STR_LEN (IFNAMSIZ + 16)

#define MCE_DFLT_NETIF_M (NETIF_MSG_LINK | NETIF_MSG_IFUP | NETIF_MSG_IFDOWN)

#define MCE_SCHED_MAX_BW (100000000) /* in Kbps */

/* MSIX */
#define MCE_MIN_MSIX (1)

/* VSI */
#define MCE_NO_VSI (0xffff)
#define MIN_DEFAULT_VECTORS (1)

#define MCE_RES_VALID_BIT (0x8000)
#define MCE_INVAL_Q_INDEX (0xffff)
struct per_head {
	__be32 sip;
	__be32 dip;
	__be16 proto;
	__be16 resv;
};

struct per_head_v6 {
	struct in6_addr sip;
	struct in6_addr dip;
	__be16 proto;
	__be16 resv;
};

/* ring info */
#define MCE_MAX_NUM_DESC (8192)
#define MCE_MAX_NUM_DESC_DEFAULT (1024)
#define MCE_MIN_NUM_DESC (64)
#define MCE_REQ_DESC_MULTIPLE (32)
#define MAX_RING_CNT (512)
#define MAX_Q_VECTORS (MAX_RING_CNT + 1)
#define MCE_MIN_PKT_LEN (60)

#define MCE_MAX_TC_CNT (8)
#define MCE_QUEUE_FOR_TC (4)

/* MCE_MAX_TC_CNT * MCE_QUEUE_FOR_TC = max_queue */
#define MCE_MAX_TC_CNT_RDMA (8)
#define MCE_MAX_TC_CNT_NIC (8)
#define MCE_MAX_PRIORITY (8)
#define MAX_PFC_NO_TSO_MAX_SET (6)
#define MCE_MAX_DSCP (64)
#define MCE_MAX_QGS (128)
#define MCE_MAX_VLAN (4096)
#define MCE_MAX_XDP_QS (256)
#define MCE_XDP_QUEUE_OFFSET (256)

/* XDP return codes */
#define MCE_XDP_PASS     0
#define MCE_XDP_CONSUMED BIT(0)
#define MCE_XDP_TX       BIT(1)
#define MCE_XDP_REDIR    BIT(2)
/* each qg has 4 queues fixed */
#define MCE_MAX_QCNT_IN_QG (4)

#define rd32(rdev, off) readl((rdev)->eth_bar_base + (off))
#define wr32(rdev, off, val) writel((val), (rdev)->eth_bar_base + (off))

#define raw_rd32(addr) readl((addr))
#define raw_wr32(val, addr) writel((val), (addr))
#define rd64(rdev, off) readq((rdev)->eth_bar_base + (off))
#define wr64(rdev, off, val) writeq((val), (rdev)->eth_bar_base + (off))
#define ring_rd32(ring, off) readl((ring)->ring_addr + (off))
#define ring_wr32(ring, off, val) writel((val), (ring)->ring_addr + (off))
#define npu_rd(hw, off) ioread32((hw)->npu_bar_base + (off))
#define npu_wr(hw, off, val) iowrite32(val, (hw)->npu_bar_base + (off))
#define vector_rd(hw, off) ioread32((hw)->vector_bar_base + (off))
#define vector_wr(hw, off, val) iowrite32(val, (hw)->vector_bar_base + (off))

static inline unsigned int md32(struct mce_hw *hw, int reg, unsigned int mask,
				unsigned int new_value)
{
	unsigned int v = rd32(hw, reg);

	v = (v & ~mask) | (new_value & mask);

	wr32(hw, reg, v);

	return v;
}

#define rdma_rd32(rdev, off) mce_rdma_rd32(rdev, off)
#define rdma_wr32(rdev, off, val) mce_rdma_wr32(rdev, off, val)
#define rdma_rd64(rdev, off) mce_rdma_rd64(rdev, off)

#define SET_BIT(n, var) (var = (var | (1 << (n))))
#define CLR_BIT(n, var) (var = (var & (~(1 << (n)))))
#define CHK_BIT(n, var) ((var) & BIT(n))

#define mce_wait_status(hw, reg, cond, timeout_ms, err_str)               \
	({                                                                \
		int timeout_us = (timeout_ms) * 1000;                     \
		unsigned int _v;                                          \
		int ret = 0;                                              \
		while (1) {                                               \
			_v = rd32((hw), (reg));                           \
			if (_v == 0xffffffff) {                           \
				ret = -ENODEV;                                \
				break;                                        \
			}                                                 \
			if ((cond))                                       \
				break;                                    \
			if (timeout_us < 0) {                             \
				ret = -ETIMEDOUT;                         \
				if (err_str)                              \
					dev_err(mce_hw_to_dev((hw)),      \
						"%s: %s, status:0x%x\n",  \
						__func__, (err_str), _v); \
				break;                                    \
			}                                                 \
			if (!mce_context_can_sleep()) {                  \
				udelay(10);                               \
			} else {                                          \
				usleep_range(10, 20);                     \
			}                                                 \
			timeout_us -= 10;                                 \
		}                                                         \
		ret;                                                      \
	})

enum mce_boards {
	board_n20 = 0,
};

enum mce_aux_op {
	MCE_AUX_OP_NONE = 0,
	MCE_AUX_OP_PLUG,
	MCE_AUX_OP_UNPLUG,
};

enum mce_pf_state {
	MCE_TESTING,
	MCE_DOWN,
	MCE_SERVICE_DIS,
	MCE_NEEDS_RESTART,
	MCE_SHUTTING_DOWN,
	MCE_REMOVED,
	MCE_SERVICE_SCHED,
	MCE_RESET_FAILED,
	MCE_MAILBOXQ_EVENT_PENDING,
	MCE_VF_BW_INITED,
	MCE_PTP_TX_IN_PROGRESS,
	MCE_DCB_IN_PROGRESS,
	MCE_NO_LINK,
	MCE_STATE_NBITS /* must be last */
};

enum mce_pf_flags {
	MCE_FLAG_FLTR_SYNC,
	MCE_FLAG_SRIOV_ENA,
	MCE_FLAG_SRIOV_DOING,
	MCE_FLAG_USR_CHANGE_QNUM_ENA,
	MCE_FLAG_SRIOV_CAPABLE,
	MCE_FLAG_VFIO_VISIT,
	MCE_FLAG_PF_SET_VF_VLAN,
	MCE_FLAG_LEGACY_RX,
	MCE_FLAG_MTU_CHANGED,
	MCE_FLAG_VF_RECV_XMIT_BY_SELF,
	MCE_FLAG_VF_TRUE_PROMISC_ENA,
	MCE_FLAG_VF_RQA_TCPSYNC_ENA,
	MCE_FLAG_VF_INSERT_VLAN,
	MCE_FLAG_HW_DIM_ENA,
	MCE_FLAG_SW_DIM_ENA,
	MCE_FLAG_DSCP_ENA,
	MCE_FLAG_CAPTURE_RDMA_ENA,
	MCE_FLAG_DDP_EXTRA_ENA,
	MCE_FLAG_EVB_VEPA_ENA,
	MCE_FLAG_TUNNEL_INNER_ENA,
	MCE_FLAG_ESWITCH_CAPABLE,
	MCE_FLAG_FORCE_LINK_ENA,
	MCE_FLAG_RX_BUFFER_MANUALLY,
	MCE_FLAG_LLDP_TX_EN,
	MCE_FLAG_PF_ANTISPOOF,
	MCE_FLAG_PF_VLAN_Q_MAP,
	MCE_FLAG_PF_DCB_TOOLS,
	MCE_FLAG_PFC_RR_MODE,
	MCE_FLAG_IRQ_MSIX_CAPABLE,
	MCE_FLAG_IRQ_MSIX_ENA,
	MCE_FLAG_IRQ_MSI_CAPABLE,
	MCE_FLAG_IRQ_MSI_ENA,
	MCE_FLAG_IRQ_LEGACY_CAPABLE,
	MCE_FLAG_IRQ_LEGACY_ENA,
	/* misc irq flags */
	MCE_FLAG_MISC_IRQ_PCS_LINK_PENDING,
	MCE_FLAG_MISC_IRQ_PTP_PENDING,
	MCE_FLAG_MISC_IRQ_FLR_PENDING,
	MCE_FLAG_MBX_CTRL_ENA,
	MCE_FLAG_MBX_DATA_ENA,
	MCE_FLAG_MRDMA_CHANGED,
	MCE_FLAG_PF_RESET_ENA,
	MCE_FLAG_PF_UPDATE_LINK,
	MCE_FLAG_PF_FORCE_VF_LINK_DOWN,
	MCE_FLAG_PF_UC_HASH_SYNC_ENA,
	MCE_FLAG_PF_MC_HASH_SYNC_ENA,
	MCE_FLAG_PF_SET_VF_MAX_RING_PENDING,
	MCE_FLAG_PF_RSS_MODE_ORDER,
	MCE_FLAG_PF_RQA_TCPSYNC_ENA,
	MCE_FLAG_RSS_MISC_TYPE_PTP,
	MCE_FLAG_RSS_MISC_TYPE_IPV4_SPI,
	MCE_FLAG_RSS_MISC_TYPE_IPV6_SPI,
	MCE_FLAG_RSS_MISC_TYPE_IPV4_TEID,
	MCE_FLAG_RSS_MISC_TYPE_IPV6_TEID,
	MCE_FLAGS_SELF_TESTING,
	MCE_FLAGS_FDIR_FLOW_ENA,
	MCE_FLAG_RDMA_SCRIPT_DOING,
	MCE_FLAG_AUX_OP_PENDING,
	MCE_FLAG_AUX_REMOVED_FOR_SRIOV,
	MCE_PF_FLAGS_NBITS /* must be last */
};

enum mce_vsi_state {
	MCE_VSI_DOWN,
	MCE_VSI_NEEDS_RESTART,
	MCE_VSI_NETDEV_ALLOCD,
	MCE_VSI_NETDEV_REGISTERED,
	MCE_VSI_UMAC_FLTR_CHANGED,
	MCE_VSI_MMAC_FLTR_CHANGED,
	MCE_VSI_PROMISC_CHANGED,
	MCE_CFG_BUSY,
	MCE_VSI_DROP_TX,
	MCE_VSI_HOLD_VALID_MTU,
	MCE_VSI_STATE_NBITS /* must be last */
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
	PHY_TYPE_10G_TP
};

struct mce_vsi;
struct mce_q_vector;

struct mce_vsi_stats {
	struct mce_ring_stats **tx_ring_stats; /* Tx ring stats array */
	struct mce_ring_stats **rx_ring_stats; /* Rx ring stats array */
};

struct mce_res_tracker {
	u16 num_entries;
	u16 end;
	u16 list[];
};

enum mce_dvlan_type {
	MCE_VLAN_TYPE_8100 = 0,
	MCE_VLAN_TYPE_88A8,
};

struct mce_vlan_hdr {
	u16 vid;
	enum mce_dvlan_type type;
} __packed;

struct mce_dvlan_ctrl {
	int en;
	struct mce_vlan_hdr outer_hdr;
	struct mce_vlan_hdr inner_hdr;
	int cnt;
} __packed;

enum mce_fc_mode {
	MCE_FC_NONE = 0,
	MCE_FC_FULL,
	MCE_FC_RX_PAUSE,
	MCE_FC_TX_PAUSE,
};

enum mce_pause_state { /* autoneg state */
	MCE_PAUSE_UN = 0,
	MCE_PAUSE_EN = 1,
};

struct mce_flow_control {
	enum mce_fc_mode current_mode; /* FC mode in effect */
	enum mce_fc_mode req_mode; /* FC mode requested by caller */
	enum mce_fc_mode old_mode;
	u32 auto_pause;
};

/* CEE or IEEE 802.1Qaz ETS Configuration data */
struct mce_ets_cfg {
	u8 willing;
	u8 ets_cap;
	u8 curtcs;
	u8 prio_table[MCE_MAX_PRIORITY];
	u8 tcbwtable[MCE_MAX_PRIORITY];
	u8 tsatable[MCE_MAX_PRIORITY];
	DECLARE_BITMAP(etc_state, MCE_MAX_PRIORITY); /* this tc is used? */
};

/* CEE or IEEE 802.1Qaz PFC Configuration data */
struct mce_pfc_cfg {
	u8 willing;
	u8 mbc;
	u8 pfccap;
	u8 pfcena;
	u8 enacnt;
	int fifo_depth[MCE_MAX_PRIORITY];
	int fifo_head[MCE_MAX_PRIORITY];
	int fifo_tail[MCE_MAX_PRIORITY];
	u8 tx_pri2buf[MCE_MAX_PRIORITY];
	u8 rx_pri2buf[MCE_MAX_PRIORITY];
};

struct mce_pfc_cfg_v1 {
	u8 willing;
	u8 mbc;
	u8 pfccap;
	u8 pfcena;
	u8 enacnt;
};

struct mce_tc_cfg {
	u32 min_rate[MCE_MAX_QGS]; /* min rate, unit:Mb */
	u32 max_rate[MCE_MAX_QGS]; /* max rate, unit:Mb */
	u8 qg_qs[MCE_MAX_QGS]; /* ring num of QG[I], max is 4*/
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

enum mce_dcb_flags {
	MCE_DCB_EN = 0,
	MCE_ETS_EN,
	MCE_PFC_EN,
	MCE_DSCP_EN,
	MCE_FLAG_DCB_TOOLS,
	MCE_MQPRIO_CHANNEL,
	MCE_FLAG_RDMA_ENA,
	MCE_FLAG_DEVLINK_TEST,
	MCE_DCB_FLAG_NBITS
};

enum mce_prio_mode { MCE_DSCP_MODE, MCE_PCP_MODE };

struct mce_dcb {
	/* Protects DCB configuration state and hardware updates. */
	struct mutex dcb_mutex;
	struct mce_pf *back;
	/* when DSCP mapping defined by user set its bit to 1 */
	DECLARE_BITMAP(dscp_mapped, MCE_MAX_DSCP);
	/* array holding DSCP -> priority for DSCP L3 QoS mode */
	u8 dscp_map[MCE_MAX_DSCP];
	u8 vlan_to_q[MCE_MAX_VLAN];
	DECLARE_BITMAP(flags, MCE_DCB_FLAG_NBITS);
	int dcb_state_old;
	u16 dcbx_cap;
	struct mce_tc_cfg cur_tccfg;
	struct mce_tc_cfg new_tccfg;
	struct mce_ets_cfg cur_etscfg;
	struct mce_ets_cfg new_etscfg;
	struct mce_pfc_cfg cur_pfccfg;
	struct mce_pfc_cfg new_pfccfg;
	struct ieee_pfc pfc_os;
	struct ieee_ets ets_os;
	struct mce_pfc_cfg backup_pfccfg;
};

/* ring debug information */
struct mce_d_ringinfo {
	u16 txring_start;
	u16 txring_end;
	u16 rxring_start;
	u16 rxring_end;
	bool txring_valid;
	bool rxring_valid;
} __packed;

/* desc debug information */
struct mce_d_descinfo {
	u16 txring_idx;
	u16 txdesc_idx;
	u16 rxring_idx;
	u16 rxdesc_idx;
} __packed;

/* te queue debug information */
struct mce_d_tx_queue {
	u16 s_id;
	u16 e_id;
	bool en;
	bool permit;
	u16 r_id;
} __packed;

struct mce_priv_header {
	int en;
#define MCE_PRIV_HEADER_LEN 254
#define MCE_PRIV_HEADER_LEN_LINIT (MCE_PRIV_HEADER_LEN + 1)
	u8 priv_header[MCE_PRIV_HEADER_LEN_LINIT];
	u16 len;
};

enum mrdma_status { MRDMA_REMOVE, MRDMA_INSMOD };

struct mce_switchdev_info {
	struct mce_vsi *control_vsi;
	struct mce_vsi *uplink_vsi;
	bool is_running;
};

struct filp_node {
	struct list_head linkage;
	struct file *filp;
	struct pid *pid;
};

struct mce_pf {
	struct pci_dev *pdev;
	struct notifier_block nb;
	struct notifier_block inet_nb;

	/* bond membership state tracking */
	struct net_device *bond_upper;	/* current bond upper device, NULL if not in bond */
	bool bond_linked;		/* true if currently linked to bond_upper */

	/* async aux device operation (deferred from notifier to avoid rtnl_lock deadlock) */
	enum mce_aux_op aux_op_pending;	/* pending aux operation type */
	struct net_device *aux_op_upper;	/* upper device context for pending op */

#if IS_ENABLED(CONFIG_NET_DEVLINK)
	/* devlink port data */
	struct devlink_port devlink_port;
#endif /* CONFIG_NET_DEVLINK */
	unsigned int default_addend;
	int gmac4;
	u32 sub_second_inc;
	u32 systime_flags;
	bool rdma_rocv2_enabled;
	u16 bridge_mode;
	u32 tx_timeout_recovery_level;
	char name[32];
	/* add for cdev */
	struct cdev cdev;
	int index;
	/* Protects character-device DMA buffer access and lifetime. */
	struct mutex cdev_dma_lock;
	/* Serializes character-device operations with device removal. */
	struct mutex cdev_lock;
	/* Waits for open character-device files during removal. */
	wait_queue_head_t cdev_wait;
	int open_count;
	int open_exclusive;
	int open_inhibit;
	struct list_head filp_list;
	/* Protects character-device open state and file list updates. */
	spinlock_t spinlock_cdev;

	bool force;
	u16 max_pf_txqs; /* Total Tx queues PF wide */
	u16 max_pf_rxqs; /* Total Rx queues PF wide */
	u16 rss_tb_size; /* Total Rx queues PF wide */
	u16 num_msix_cnt; /* Total MSIX vectors */
	u16 num_avail_msix; /* remaining MSIX vectors left unclaimed */
	u16 qvec_irq_base;
	u16 mbox_irq_base;
	u16 num_mbox_irqs; /* mbox irqs */
	u16 rdma_irq_base;
	u16 num_rdma_irqs; /* rdma irqs */
	u16 num_max_tc; /* max tc supported */
	u16 num_q_for_tc; /* queue for each tc */

	u8 nr_pf;
	u8 bd_number;

	u16 next_vsi; /* Next free slot in pf->vsi[] - 0-based! */
	u16 num_alloc_vsi;
	struct mce_vsi **vsi; /* VSIs created by the driver */
	u16 eswitch_mode;
	struct mce_switchdev_info switchdev;
	struct mce_vsi_stats **vsi_stats;
	struct mce_dcb *dcb;
	int valid_mtu;
	enum mrdma_status m_status;
	enum mrdma_status m_status_req;

#ifdef CONFIG_DEBUG_FS
	struct dentry *mce_debugfs_hw;
	struct dentry *mce_debugfs_eth_symlink;
#endif /* CONFIG_DEBUG_FS */

	struct msix_entry *msix_entries;
	struct mce_res_tracker *irq_tracker;

	struct mutex sw_mutex; /* lock for protecting VSI alloc flow */
	struct mutex adev_mutex; /* lock to protect aux device access */

	struct mce_hw_stats stats;
	struct mce_hw_stats prev_stats;
	struct mce_mac_stats mac_stats;
	struct mce_hw hw;

#if IS_ENABLED(CONFIG_NET_CLS_FLOWER)
	/* TC flower filters and Flow Director flow-engine state. */
	u16 num_dmac_chnl_fltrs;
	struct hlist_head tc_flower_fltr_list;
	struct mce_flow_engine_module *flow_engine[MCE_FLOW_MAX];
	u32 fdir_mode;
#endif

	unsigned long serv_tmr_period;
	unsigned long serv_tmr_prev;
	struct timer_list serv_tmr;
	struct work_struct serv_task;

#define __MCE_SERV_TIMER_PERIODS_UNIT (HZ / 10 / (1000 / CONFIG_HZ))
#define __MCE_SERV_TIMER_PERIODS_CNT (10)
	bool drop_intr_timer_en;
	u32 serv_tmr_max_cnt;
	u32 serv_tmr_ticks;

	char int_name[MCE_INT_NAME_STR_LEN];

	struct iidc_core_dev_info *cdev_infos;

	DECLARE_BITMAP(state, MCE_STATE_NBITS);
	DECLARE_BITMAP(flags, MCE_PF_FLAGS_NBITS);

	DECLARE_BITMAP(nb_vlan_bitmap, VLAN_N_VID);
	DECLARE_BITMAP(vlan_bitmap, VLAN_N_VID);

	u32 msg_enable;

	struct mce_flow_control fc;

	/* sriov */
	int num_vfs;
	unsigned int max_vfs;
	struct mce_vf vf; /* VF associated with this VSI */
	s32 default_vport;
	s32 debug_tx;
	s32 tx_drop_en;
	u16 vlan_strip_cnt;
	struct mce_dvlan_ctrl dvlan_ctrl;

	/* add for ptp */
	struct delayed_work tx_hwtstamp_work;
	struct ptp_clock *ptp_clock;
	struct ptp_clock_info ptp_clock_ops;
	struct sk_buff *ptp_tx_skb;
	struct hwtstamp_config tstamp_config;
	spinlock_t ptp_lock; /* Used to protect the SYSTIME registers. */
	bool ptp_tx_en;
	bool ptp_rx_en;
	u32 flags2;
#define MCE_FLAG2_PTP_ENABLED ((u32)(1 << 10))
	u32 ptp_config_value;
	unsigned long tx_hwtstamp_start;
	unsigned long tx_timeout_factor;
	u64 tx_hwtstamp_timeouts;
	u32 ptp_default_int;
	u32 ptp_default_dec;

	u32 pcie_restore_cnt;
	struct mce_d_ringinfo d_ringinfo;
	struct mce_d_descinfo d_descinfo;
	struct mce_d_tx_queue d_txqueue;
	struct vf_info pfinfo;
	int pcie_irq_mode;
	u32 mac_misc_irq;
	bool mac_misc_irq_retry;
	bool xmit_check_intr_drop;
	bool poll_check_intr_drop;
	bool npu_capable;
	bool npu_en;
	/* ring mbx numbers */
	int mbx_ring_id;
	bool tun_inner;
	struct mce_priv_header priv_h;
	bool is_checksummed;
	u8 *cdev_dma_buf;
	dma_addr_t cdev_dma_phy;
	int cdev_dma_size;
	char *debugfs_buf;
	int debugfs_buf_bytes;
	int debugfs_buf_msg_size;
	int debugfs_queue_start;
	int debugfs_queue_end;
	int debugfs_queue_setted;
	bool debugfs_reg_rd_has_output;
	u32 cline_size; /* cpu cache line size */
	bool dis_irq_affinity;
	__be32 ipv4_addr;

};

enum mce_q_vector_state {
	MCE_Q_VECTOR_POLLING,
	MCE_Q_VECTOR_NBITS /* must be last */
};

struct mce_q_vector {
	char name[MCE_INT_NAME_STR_LEN];
	struct mce_vsi *vsi;
	int v_idx; /*0.. logic vector*/
	u8 wb_on_itr : 1; /* if true, WB on ITR is enabled */
	u8 num_ring_rx; /* total number of Rx rings in vector */
	u8 num_ring_tx; /* total number of Tx rings in vector */
	int cpu;
	int numa_node;
	u16 total_events;
	u16 total_events_old;
	cpumask_t affinity_mask;
	struct irq_affinity_notify affinity_notify;
	struct mce_hw *rdev;
	struct napi_struct napi;
	unsigned long check_jiffies;
	struct mce_ring_container rx;
	struct mce_ring_container tx;
	DECLARE_BITMAP(state, MCE_Q_VECTOR_NBITS);
	struct mce_repr *repr;
	u32 ticks;
	u32 old_ticks;
};

struct mce_port_info {
	/* mac addr*/
	u8 addr[ETH_ALEN];
	u8 perm_addr[ETH_ALEN];
	/* link info */
	bool link_up;
	int link_speed; /*SPEED_25000,SPEED_XXX*/
	int link_duplex;

	/* repr sw port */
	u8 lport;
	/* capability */
	u64 support_phy_type_list;
	u16 adv_speed_list; /* Advertised speed list */
	u16 sup_speed_list; /* Supported speed list */
	enum mce_media_type media_type;
	u32 adv_module_type; /* Advertised module type */
	u32 sup_module_type; /* Supported module type */
};

struct mce_vsi {
	u16 alloc_txq; /* Allocated Tx queues */
	u16 alloc_rxq; /* Allocated Rx queues */
	u16 num_txq; /* Used Tx queues */
	u16 num_txq_real; /* tx-queue to statck */
	u16 num_tc_offset;
	u16 num_rxq; /* Used Rx queues */
	u16 req_txq; /* User requested Tx queues */
	u16 req_rxq; /* User requested Rx queues */
	u16 num_tx_desc;
	u16 num_rx_desc;
	u16 num_q_vectors;
	u16 base_vector; /* IRQ base for OS reserved vectors */

	u16 max_frame;
	u16 rx_buf_len;

	u16 valid_prio;

	u16 idx; /* software index in pf->vsi[] */
	int vport_id;
	int bcmc_ref_cnf;
	enum mce_vsi_type type;

	struct net_device *netdev;
	struct mce_pf *back;
	struct mce_port_info *port_info; /* back pointer to port_info */

	struct mce_ring **rx_rings; /* Rx ring array */
	struct mce_ring **tx_rings; /* Tx ring array */
	struct mce_q_vector **q_vectors; /* q_vector array */
	struct task_struct *mce_poll_thread;
	bool quit_poll_thread;
	irqreturn_t (*irq_handler)(int irq, void *data);

	DECLARE_BITMAP(state, MCE_VSI_STATE_NBITS);
	unsigned int current_netdev_flags;

	u32 tx_restart;
	u32 tx_busy;
	u32 rx_buf_failed;
	u32 rx_page_failed;
	u64 rx_page_alloc_ok;
	u64 rx_page_reuse_ok;
	u64 rx_page_reuse_reserved;
	u64 rx_page_reuse_refcnt;
	u64 rx_page_reuse_offset;
	u64 tx_linearize;
	/* VSI stats */
	struct rtnl_link_stats64 net_stats;
	struct rtnl_link_stats64 net_stats_prev;
	spinlock_t stats_lock; /* protects net_stats and net_stats_prev */
	struct mce_ofld_stats ofld_stats;

	int link;
	u8 irqs_ready;
	u8 rx_flags;
#define RX_FLAG_VLAN_STRIP BIT(0)
	struct mce_vf *vf; /* VF associated with this VSI */

	/* aRFS members only allocated for the PF VSI */
#define MCE_MAX_RFS_FILTERS 0xFFFF
#define MCE_MAX_ARFS_LIST 1024
#define MCE_ARFS_LST_MASK (MCE_MAX_ARFS_LIST - 1)
	struct hlist_head *arfs_fltr_list;
	struct mce_arfs_active_fltr_cntrs *arfs_fltr_cntrs;
	spinlock_t arfs_lock; /* protects aRFS hash table and filter state */
	atomic_t *arfs_last_fltr_id;
} ____cacheline_internodealigned_in_smp;

struct mce_netdev_priv {
	struct mce_vsi *vsi;
	struct mce_repr *repr;
};

static inline bool mce_is_xdp_ena_vsi(struct mce_vsi *vsi)
{
	return false;
}

/**
 * mce_get_main_vsi - Get the PF VSI
 * @pf: PF instance
 *
 * returns pf->vsi[0], which by definition is the PF VSI
 */
static inline struct mce_vsi *mce_get_main_vsi(struct mce_pf *pf)
{
	return pf->vsi[0];
}

static inline struct net_device *mce_get_main_net_dev(struct mce_pf *pf)
{
	return pf->vsi[0]->netdev;
}

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
#define MCE_2K_TOO_SMALL_WITH_PADDING                   \
	((unsigned int)(NET_SKB_PAD + MCE_RXBUF_1536) > \
	 SKB_WITH_OVERHEAD(MCE_RXBUF_2048))
#else
#define MCE_2K_TOO_SMALL_WITH_PADDING false
#endif
/**
 * mce_compute_pad - compute the padding
 * @rx_buf_len: buffer length
 *
 * Figure out the size of half page based on given buffer length and
 * then subtract the skb_shared_info followed by subtraction of the
 * actual buffer length; this in turn results in the actual space that
 * is left for padding usage
 */
static inline int mce_compute_pad(int rx_buf_len)
{
	int half_page_size;

	half_page_size = ALIGN(rx_buf_len, PAGE_SIZE / 2);
	return SKB_WITH_OVERHEAD(half_page_size) - rx_buf_len;
}

#define MCE_SMP_CACHE_LINE_RESIZE 128

/**
 * mce_skb_pad - determine the padding that we can supply
 *
 * Figure out the right Rx buffer size and based on that calculate the
 * padding
 */
static inline int mce_skb_pad(struct mce_pf *pf)
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
	if (MCE_2K_TOO_SMALL_WITH_PADDING) {
		if (pf->cline_size == MCE_SMP_CACHE_LINE_RESIZE)
			rx_buf_len =
				MCE_RXBUF_3072 +
				ALIGN(NET_IP_ALIGN, MCE_SMP_CACHE_LINE_RESIZE);
		else
			rx_buf_len =
				MCE_RXBUF_3072 + SKB_DATA_ALIGN(NET_IP_ALIGN);
	} else {
		if (pf->cline_size == MCE_SMP_CACHE_LINE_RESIZE)
			return MCE_SMP_CACHE_LINE_RESIZE;
		rx_buf_len = MCE_RXBUF_1536;
	}

	/* if needed make room for NET_IP_ALIGN */
	rx_buf_len -= NET_IP_ALIGN;

	return mce_compute_pad(rx_buf_len);
#else
	if (pf->cline_size != MCE_SMP_CACHE_LINE_RESIZE)
		return NET_SKB_PAD + NET_IP_ALIGN;
	return ALIGN(NET_SKB_PAD + NET_IP_ALIGN, MCE_SMP_CACHE_LINE_RESIZE);
#endif
}

#define MCE_SKB_PAD(pf) mce_skb_pad(pf)

/* mce_hw_n20.c */
int mce_get_n20_caps(struct mce_hw *rdev);

/* mce_main.c */
void mce_service_task_schedule(struct mce_pf *pf);
void mce_set_pf_caps(struct mce_pf *pf);
void mce_get_port_phy_ability(struct mce_hw *hw);
irqreturn_t mce_misc_intr(int __always_unused irq, void *data);

/* mce_ethtool.c */
void mce_set_ethtool_ops(struct net_device *netdev);

/* mce_idc.c */
int mce_plug_aux_dev(struct mce_pf *pf);
void mce_unplug_aux_dev(struct mce_pf *pf);
bool mce_aux_dev_is_bound(struct mce_pf *pf);
bool mce_aux_dev_is_registered(struct mce_pf *pf);
void mce_send_event_to_auxs(struct mce_pf *pf, struct iidc_event *event);

#if IS_ENABLED(CONFIG_SYSFS)
void mce_sysfs_exit(struct mce_pf *pf);
int mce_sysfs_init(struct mce_pf *pf);
#endif

void mce_restore_hw(struct mce_hw *hw);
void mce_reset_hw(struct mce_hw *hw);
void mce_reset_prev_stats(struct mce_pf *pf);

#ifdef CONFIG_DEBUG_FS
void mce_debugfs_pf_init(struct mce_pf *pf);
void mce_debugfs_eth_link_rename(struct mce_pf *pf, const char *new_name);
void mce_debugfs_pf_exit(struct mce_pf *pf);
void mce_debugfs_init(void);
void mce_debugfs_exit(void);
#else
static inline void mce_debugfs_pf_init(struct mce_pf *pf)
{
}

static inline void mce_debugfs_pf_exit(struct mce_pf *pf)
{
}

static inline void mce_debugfs_init(void)
{
}

static inline void mce_debugfs_exit(void)
{
}
#endif /* CONFIG_DEBUG_FS */

void mce_set_ethtool_repr_ops(struct net_device *netdev);

enum REGION_IN {
	PART_FW = 0,
	PART_PXE,
	PART_MACSN,
};

#define __MCE_GET_RING_STATS_BY_HW (0)

#define N20_FW_MAGIC 0x4E323046
#define MAC_SN_MAGIC 0x87654321
int mce_flash_firmware(struct mce_pf *pf, enum REGION_IN region, const u8 *data,
		       int bytes);

#endif /* _MCE_H_ */
