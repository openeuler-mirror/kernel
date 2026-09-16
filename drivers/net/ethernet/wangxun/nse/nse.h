/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2018 - 2021 Beijing WangXun Technology Co., Ltd. */

#ifndef _NSE_H_
#define _NSE_H_

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
#include <linux/sysfs.h>
#include <linux/rhashtable.h>
#include <linux/rhashtable-types.h>
#include <linux/bpf.h>
#include <linux/filter.h>
#include <net/xdp.h>
#include <net/xdp_sock.h>
#include <net/ipv6.h>
#include <net/arp.h>
#include <net/vxlan.h>
#if IS_ENABLED(CONFIG_NET_DEVLINK)
#include <net/devlink.h>
#endif /* CONFIG_NET_DEVLINK */
#include <linux/dim.h>
#include "nse_devids.h"
#include "nse_type.h"
#include "nse_txrx.h"
#include "nse_dcb.h"
#include "nse_switch.h"
#include "nse_legacy_switch.h"
#include "nse_common.h"
#include "nse_flow.h"
#include "nse_sched.h"
#include <linux/auxiliary_bus.h>
#include <linux/idr.h>
#include "nse_idc_int.h"
#include "virtchnl.h"
#include "nse_sriov.h"
#include "nse_vf_mbx.h"
#include "nse_ptp.h"
#include "nse_fdir.h"
#include "nse_vdcm.h"
#include "nse_siov.h"
#include "nse_sriov_sysfs.h"
#include "nse_repr_sysfs.h"
#include "nse_repr_meter.h"
#include "nse_tc_ct.h"
#include "nse_xsk.h"
#include "nse_lag.h"
#include "nse_trace.h"
#include <net/vxlan.h>
#include <net/gre.h>
#include <net/geneve.h>
#include <net/udp_tunnel.h>
#include <net/pkt_cls.h>
#include <net/tc_act/tc_mirred.h>
#include <net/tc_act/tc_gact.h>
#include <net/ip.h>
#include <net/netevent.h>
#include <linux/cpu_rmap.h>
#include <linux/atomic.h>
#include <linux/jiffies.h>
#include "nse_arfs.h"
#include "nse_repr.h"
#include "nse_eswitch.h"
#include "nse_vsi_vlan_ops.h"

#include "nse_msgbox.h"

#define DRV_VERSION_MAJOR	1
#define DRV_VERSION_MINOR	0
#define DRV_VERSION_MINI	1
#define DRV_VERSION_PATCH	0
#define DRV_VERSION_BUILD	0

#define DRV_VERSION	"1.0.2.1oe"
#define DRV_SUMMARY	"WangXun(R) Ethernet Connection AM Series Linux Driver"
#ifdef NSE_ADD_PROBES
#define DRV_VERSION_EXTRA "_probes"
#else
#define DRV_VERSION_EXTRA ""
#endif /* NSE_ADD_PROBES */

extern const char nse_drv_ver[];

#define NSE_BAR0		0
#define NSE_BAR2		2

#define NSE_MAIN_VSI_MAX_QPS	256

#define NSE_REQ_DESC_MULTIPLE	32
#define NSE_MIN_NUM_DESC	64
#define NSE_MAX_NUM_DESC	8160

#define NSE_DFLT_NUM_RX_DESC	2048
#define NSE_DFLT_NUM_TX_DESC	2048

#define NSE_DFLT_NUM_CQ_DESC	(2048 * 128)		/* TX_DESC(2048) x N */

#define NSE_DFLT_TXQ_VMDQ_VSI	1
#define NSE_DFLT_RXQ_VMDQ_VSI	1
#define NSE_DFLT_VEC_VMDQ_VSI	1

#define NSE_MAX_MACVLANS	32
#define NSE_MAX_SCALABLE	100
#define NSE_DFLT_TRAFFIC_CLASS	BIT(0)
#define NSE_INT_NAME_STR_LEN	(IFNAMSIZ + 16)
#define NSE_ADMINQ_SQ_LEN	256
#define NSE_ADMINQ_RQ_LEN	512
#define NSE_MBQ_SQ_LEN		64
#define NSE_MBQ_RQ_LEN		768
#define NSE_UTILQ_SQ_LEN	512
#define NSE_MIN_LAN_MSIX	1
#define NSE_OICR_MSIX		1
#define NSE_RDMA_NUM_AEQ_MSIX	4
#define NSE_MIN_RDMA_MSIX	2
#define NSE_MIN_MSIX		(NSE_MIN_LAN_MSIX + NSE_OICR_MSIX)
#define NSE_NO_VSI		0xffff
#define NSE_VSI_MAP_CONTIG	0
#define NSE_VSI_MAP_SCATTER	1
#define NSE_MAX_SCATTER_TXQS	16
#define NSE_MAX_SCATTER_RXQS	16
#define NSE_Q_WAIT_RETRY_LIMIT	10
#define NSE_Q_WAIT_MAX_RETRY	(5 * NSE_Q_WAIT_RETRY_LIMIT)
#define NSE_MAX_LG_RSS_QS	256
#define NSE_MAX_MEDIUM_RSS_QS	64
#define NSE_MAX_SMALL_RSS_QS	16
#define NSE_RES_VALID_BIT	0x8000

enum nse_res_irq_id {
	NSE_RES_IRQ_ID_MISC				= 0x0,

	NSE_RES_IRQ_ID_RDMA				= 0x1,

	NSE_RES_IRQ_ID_NONVF_VSI_BASE	= 0x100,
};

enum nse_res_vsi_id {
	NSE_RES_VSI_ID_PF						= 0x0,

	NSE_RES_VSI_ID_OFFLOAD_MACVLAN_BASE		= 0x100,

	NSE_RES_VSI_ID_SWITCHDEV_CTRL			= 0x200,

	NSE_RES_VSI_ID_LB						= 0x201,

	NSE_RES_VSI_ID_ADI						= 0x300,

	NSE_RES_VSI_ID_VF_BASE					= 0x400,	/* max 256 per-PF */
};

enum nse_res_lan_rxq_id {
	NSE_RES_LAN_RXQ_ID_PF						= 0x0,

	NSE_RES_LAN_RXQ_ID_OFFLOAD_MACVLAN_BASE		= 0x100,

	NSE_RES_LAN_RXQ_ID_SWITCHDEV_CTRL			= 0x200,

	NSE_RES_LAN_RXQ_ID_LB						= 0x201,

	NSE_RES_LAN_RXQ_ID_FDIR_DROP_Q				= 0x202,

	NSE_RES_LAN_RXQ_ID_ADI_BASE					= 0x300,

	/* max 256 per-PF */
	NSE_RES_LAN_RXQ_ID_VF_BASE					= 0x400,
};

enum nse_res_lan_txq_id {
	/* ID used for PF VSI's regular-txq */
	NSE_RES_LAN_TXQ_ID_PF						= 0x0,
	/* ID used for PF VSI's xdp-txq */
	NSE_RES_LAN_TXQ_ID_PF_XDP					= 0x1,

	NSE_RES_LAN_TXQ_ID_OFFLOAD_MACVLAN_BASE		= 0x100,

	NSE_RES_LAN_TXQ_ID_SWITCHDEV_CTRL			= 0x200,

	NSE_RES_LAN_TXQ_ID_LB						= 0x201,

	NSE_RES_LAN_TXQ_ID_FDIR_DROP_Q				= 0x202,

	NSE_RES_LAN_TXQ_ID_ADI_BASE					= 0x300,

	/* max 256 per-PF */
	NSE_RES_LAN_TXQ_ID_VF_BASE					= 0x400,
};

enum nse_res_lan_txcq_id {
	NSE_RES_LAN_TXCQ_ID_NONVF_VSI_BASE	= 0x100,

	NSE_RES_LAN_TXCQ_ID_VF_BASE		= 0x200,
};

#define NSE_INVAL_IRQ_ID	0xFFFF

#define NSE_INVAL_Q_INDEX	0xffff
#define NSE_INVAL_Q_ID		NSE_INVAL_Q_INDEX

#define NSE_INVAL_VFID		256

#define NSE_MAX_RXQS_PER_TC		256	/* Used when setting VSI context per TC Rx queues */
#define NSE_MAX_TXQS_PER_TC		8
#define NSE_MAX_RDMA_QSET_PER_TC	1

#define NSE_MAX_RESET_WAIT		20

#define NSE_DFLT_NETIF_M (NETIF_MSG_DRV | NETIF_MSG_PROBE | NETIF_MSG_LINK)

#define NSE_MAX_MTU	(NSE_AQ_SET_MAC_FRAME_SIZE_MAX - NSE_ETH_PKT_HDR_PAD)

#define NSE_TX_DESC(R, i) (&(((struct nse_tx_desc *)((R)->desc))[i]))
#define NSE_RX_DESC(R, i) (&(((union nse_32b_rx_desc *)((R)->desc))[i]))
#define NSE_TX_CTX_DESC(R, i) (&(((struct nse_tx_ctx_desc *)((R)->desc))[i]))

#define NSE_TXCQ_DESC(R, i) (&(((struct nse_lan_txcq_desc *)((R)->desc))[i]))

/* Macro for each VSI in a PF */
#define nse_for_each_vsi(pf, i) \
	for ((i) = 0; (i) < (pf)->vsi_space_size; (i)++)

/* Macros for each Tx/Rx ring in a VSI */
#define nse_for_each_txq(vsi, i) \
	for ((i) = 0; (i) < (vsi)->num_txq; (i)++)

#define nse_for_each_xdp_txq(vsi, i) \
	for ((i) = 0; (i) < (vsi)->num_xdp_txq; (i)++)

#define nse_for_each_rxq(vsi, i) \
	for ((i) = 0; (i) < (vsi)->num_rxq; (i)++)

#define nse_for_each_lan_txcq(vsi, i) \
	for ((i) = 0; (i) < (vsi)->num_txcq; (i)++)

/* Macros for each allocated Tx/Rx ring whether used or not in a VSI */
#define nse_for_each_alloc_txq(vsi, i) \
	for ((i) = 0; (i) < (vsi)->alloc_txq; (i)++)

#define nse_for_each_alloc_rxq(vsi, i) \
	for ((i) = 0; (i) < (vsi)->alloc_rxq; (i)++)

#define nse_for_each_alloc_txcq(vsi, i) \
	for ((i) = 0; (i) < (vsi)->alloc_txcq; (i)++)

#define nse_for_each_q_vector(vsi, i) \
	for ((i) = 0; (i) < (vsi)->num_q_vectors; (i)++)

#define NSE_UCAST_PROMISC_BITS (NSE_PROMISC_UCAST_TX | NSE_PROMISC_UCAST_RX)

#define NSE_UCAST_VLAN_PROMISC_BITS (NSE_PROMISC_UCAST_TX | \
				     NSE_PROMISC_UCAST_RX | \
				     NSE_PROMISC_VLAN_TX  | \
				     NSE_PROMISC_VLAN_RX)

#define NSE_MCAST_PROMISC_BITS (NSE_PROMISC_MCAST_TX | NSE_PROMISC_MCAST_RX)

#define NSE_MCAST_VLAN_PROMISC_BITS (NSE_PROMISC_MCAST_TX | \
				     NSE_PROMISC_MCAST_RX | \
				     NSE_PROMISC_VLAN_TX  | \
				     NSE_PROMISC_VLAN_RX)

#define nse_pf_to_dev(pf) (&((pf)->pdev->dev))

enum nse_rate_limit_data_type {
	NSE_RATE_LIMIT_DATA_RATE,
	NSE_RATE_LIMIT_DATA_BURST,
	NSE_RATE_LIMIT_DATA_PACKETS_DROPPED,
	NSE_RATE_LIMIT_DATA_BYTES_DROPPED,
};

struct nse_txq_meta {
	u32 q_tnid;	/* Tx-scheduler element identifier */
	u16 q_abs_id;
	u16 q_handle;	/* Relative index of Tx queue within TC */
	u16 vsi_idx;	/* VSI index that Tx queue belongs to */
	u8 tc;		/* TC number that Tx queue belongs to */
};

struct nse_tc_info {
	u16 qoffset;
	u16 qcount_tx;
	u16 qcount_rx;
	u8 netdev_tc;
};

struct nse_tc_cfg {
	u8 numtc; /* Total number of enabled TCs */
	u16 ena_tc; /* Tx map */
	struct nse_tc_info tc_info[NSE_MAX_TRAFFIC_CLASS];
};

struct nse_res_tracker {
	u16 num_entries;
	u16 end;
	u16 list[];
};

struct nse_sw {
	struct nse_pf *pf;
	u16 sw_id;		/* switch ID for this switch */
	u16 bridge_mode;	/* VEB/VEPA/Port Virtualizer */
};

enum nse_pf_state {
	NSE_TESTING,
	NSE_DOWN,
	NSE_NEEDS_RESTART,
	NSE_PREPARED_FOR_RESET,	/* set by driver when prepared */
	NSE_RESET_OICR_RECV,		/* set by driver after rcv reset OICR */
	NSE_PFR_REQ,				/* set by driver and aux drivers */
	NSE_HIGH_RESET_CORER_REQ,	/* set by driver and aux drivers */
	NSE_HIGH_RESET_CORER_RECV,	/* set by OICR handler */

	NSE_SUSPENDED,		/* set on module remove path */
	NSE_RESET_FAILED,		/* set by reset/rebuild */

	/* When checking for the PF to be in a nominal operating state, the
	 * bits that are grouped at the beginning of the list need to be
	 * checked. Bits occurring before NSE_STATE_NOMINAL_CHECK_BITS will
	 * be checked. If you need to add a bit into consideration for nominal
	 * operating state, it must be added before
	 * NSE_STATE_NOMINAL_CHECK_BITS. Do not move this entry's position
	 * without appropriate consideration.
	 */
	NSE_STATE_NOMINAL_CHECK_BITS,
	NSE_ADMINQ_EVENT_PENDING,
	NSE_MDD_EVENT_PENDING,
	NSE_FLTR_OVERFLOW_PROMISC,
	NSE_VF_DIS,
	NSE_CFG_BUSY,
	NSE_SERVICE_SCHED,
	NSE_SERVICE_DIS,
	NSE_OICR_INTR_DIS,		/* Global OICR interrupt disabled */
	NSE_MDD_VF_PRINT_PENDING,	/* set when MDD event handle */
	NSE_VF_RESETS_DISABLED,	/* disable resets during remove */
	NSE_LINK_DEFAULT_OVERRIDE_PENDING,
	NSE_PHY_INIT_COMPLETE,
	NSE_LOGALL_INPROGRESS,
	NSE_RDMA_IS_RUNNING,
	NSE_STATE_NBITS		/* must be last */
};

struct nse_pf_sw_conf {
	/* fixed, only set at init time, not changed after */
	unsigned int lan_tx_use_cq;
	/* fixed, only set at init time, not changed after */
	unsigned int lan_tx_use_cq_for_vf;

	/* fixed (capable & enable), only set at init time, not changed after */
	unsigned int lan_rx_ena_rsc;

	unsigned int lan_txq_dflt_len;
	unsigned int lan_rxq_dflt_len;

	unsigned int fdir_ena;
	unsigned int fdir_ena_for_vf;
	unsigned int fdir_use_utilq;

	unsigned int ptp_fine_mode;	/* 0: coarse mode, 1: fine mode */

	unsigned int max_macvlans;	/* macvlan offload ( VDMq ) */

	unsigned int min_itr_no_intrl;
};

struct nse_vsi_sw_conf {
	unsigned int lan_tx_use_cq;		/* fixed, set from pf_sw_conf */

	unsigned int lan_rx_ena_rsc;	/* current status, changeable by NETIF_F_LRO */

	unsigned int fdir_ena;
	unsigned int fdir_use_utilq;

	unsigned int fdir_max_num_pfilter_vsi;
	unsigned int fdir_max_num_sfilter_vsi;
};

enum nse_vsi_state {
	NSE_VSI_DOWN,
	NSE_VSI_NEEDS_RESTART,
	NSE_VSI_NETDEV_ALLOCD,
	NSE_VSI_NETDEV_REGISTERED,
	NSE_VSI_UMAC_FLTR_CHANGED,
	NSE_VSI_MMAC_FLTR_CHANGED,
	NSE_VSI_VLAN_FLTR_CHANGED,
	NSE_VSI_PROMISC_CHANGED,
	NSE_VSI_STATE_NBITS		/* must be last */
};

/* struct that defines a VSI, associated with a dev */
struct nse_vsi {
	struct net_device *netdev;
	struct nse_sw *vsw;		 /* switch this VSI is on */
	struct nse_pf *back;		 /* back pointer to PF */
	struct nse_port_info *port_info; /* back pointer to port_info */
	struct nse_ring **rx_rings;	 /* Rx ring array */
	struct nse_ring **tx_rings;	 /* Tx ring array */
	struct nse_txcq_ring **txcq_rings;	/* CQ ring array */
	/* Initial VSI tx_rings array when L2 offload is off */
	struct nse_ring **base_tx_rings;
	struct nse_q_vector **q_vectors; /* q_vector array */

	irqreturn_t (*irq_handler)(int irq, void *data);

	DECLARE_BITMAP(state, NSE_VSI_STATE_NBITS);

	struct nse_vsi_sw_conf sw_conf;

	unsigned int current_netdev_flags;

	u16 num_q_vectors;

	u16 base_vector;		/* IRQ base for OS reserved vectors */
	enum nse_vsi_type type;
	enum nse_vsi_mode vsi_mode;

	u16 vsi_abs_num;		/* HW (absolute) index of this VSI */
	u16 vsi_rel_num;		/* relative index of this VSI, inside PF VSI space */
	/*  software index in pf->vsi[] --- Note: idx is NOT relative ID in PF VSI space, idx !=
	 * vsi_rel_num
	 */
	u16 idx;
	u16 nonvf_vsi_res_owner_id;	/* from nse_nonvf_vsi_owner_id(), only for nonVF VSI */

	struct nse_vf *vf;		/* VF associated with this VSI */

	u16 rss_lut_start;
	u16 rss_lut_size;
	u16 rss_lut_size_log2;
	u16 rss_lut_size_aligned;	/* 1 << log2 */
	u16 *rss_lut_user;		/* User configured lookup table entries */
	u8 *rss_hkey_user;		/* User configured hash keys */
#define NSE_RSS_KEY_SIZE     40  /* size of RSS Hash Key in bytes */

	u32 rss_ctl;
	u32 rss_ctl_user_req_alg;
#define NSE_VSI_RSS_CTL_EN_S			0
#define NSE_VSI_RSS_CTL_EN_M			BIT(0)

#define NSE_VSI_RSS_CTL_TCBIT_S			1
#define NSE_VSI_RSS_CTL_TCBIT_M			NSE_M(0x3, 1)

#define NSE_VSI_RSS_CTL_RSSBIT_S		4
#define NSE_VSI_RSS_CTL_RSSBIT_M		NSE_M(0xF, 4)

#define NSE_VSI_RSS_CTL_FIRST_LUT_S		8
#define NSE_VSI_RSS_CTL_FIRST_LUT_M		NSE_M(0xFFF, 8)

#define NSE_VSI_RSS_CTL_ALG_S			24
#define NSE_VSI_RSS_CTL_ALG_M			NSE_M(0xFF, 24)

	#define NSE_VSI_RSS_CTL_ALG_IPV4_TCP		BIT(24)
	#define NSE_VSI_RSS_CTL_ALG_IPV4			BIT(25)
	#define NSE_VSI_RSS_CTL_ALG_IPV4_SCTP		BIT(26)
	#define NSE_VSI_RSS_CTL_ALG_IPV6_SCTP		BIT(27)
	#define NSE_VSI_RSS_CTL_ALG_IPV6			BIT(28)
	#define NSE_VSI_RSS_CTL_ALG_IPV6_TCP		BIT(29)
	#define NSE_VSI_RSS_CTL_ALG_IPV4_UDP		BIT(30)
	#define NSE_VSI_RSS_CTL_ALG_IPV6_UDP		BIT(31)

	u16 max_frame;
	u16 rx_buf_len;

	struct nse_aqc_vsi_props info;	 /* VSI properties */

	u32 rxdid;

	/* VSI stats */
	struct rtnl_link_stats64 net_stats;

	struct nse_vsi_hw_stats			hw_stats;
	struct nse_vsi_hw_stats			hw_stats_prev;
	struct nse_vsi_hw_stats			hw_stats_new;
	struct nse_vsi_hw_stats_raw	hw_stats_raw;
	bool hw_stats_prev_loaded;

	struct nse_vsi_sw_stats		sw_stats;
	struct nse_vsi_sw_stats		sw_stats_prev;
	struct nse_vsi_sw_stats			sw_stats_new;
	bool sw_stats_prev_loaded;

	bool wd_subtask_update_vsi_stats_now;

	struct list_head tmp_sync_list;		/* MAC filters to be synced */
	struct list_head tmp_unsync_list;	/* MAC filters to be unsynced */

	u8 irqs_ready:1;
	u8 current_isup:1;		 /* Sync 'link up' logging */

	struct nse_vsi_vlan_ops inner_vlan_ops;
	struct nse_vsi_vlan_ops outer_vlan_ops;
	u16 num_vlan;

	/* queue information */
	u16 vsi_rxq_space_start;	/* relative ID in PF rxq/txq space */
	u16 vsi_txq_space_start;
	u16 alloc_txq;			 /* Allocated Tx queues */
	u16 num_txq;			 /* Used Tx queues */
	u16 alloc_rxq;			 /* Allocated Rx queues */
	u16 num_rxq;			 /* Used Rx queues */
	u16 req_txq;			 /* User requested Tx queues */
	u16 req_rxq;			 /* User requested Rx queues */
	u16 num_rx_desc;
	u16 num_tx_desc;

	u16 vsi_txcq_space_start;	/* rel ID in PF space */
	u16 alloc_txcq;				/* num_txcq == */
	u16 num_txcq;
	u32 num_txcq_desc;

	u16 qset_handle[NSE_MAX_TRAFFIC_CLASS];
	struct nse_tc_cfg tc_cfg;
	struct bpf_prog *xdp_prog;
	struct nse_ring **xdp_rings;	 /* XDP ring array */
	/*  Only make sense for PF-main-VSI, != vsi_txq_space_start, but also relative ID in PF txq
	 * space
	 */
	u16 vsi_xdp_txq_start;
	u16 xdp_txq_owner_id;	/* MUST be NSE_RES_LAN_TXQ_ID_PF_XDP */
	u16 num_xdp_txq;		 /* Used XDP queues */
	unsigned long *af_xdp_zc_qps;    /* tracks AF_XDP ZC enabled qps */
	int af_xdp_zc_qps_bitmap_size;

	struct net_device **target_netdevs;
	u16 target_netdevs_len;

#ifdef CONFIG_DEBUG_FS
	struct dentry *vsi_dbgfs_dir;
	struct dentry *vsi_netdev_symlink;
#endif

#if defined(NSE_DEBUG_EXT)
	struct work_struct hack_send_magic_pkt_task;
	unsigned int hack_send_magic_pkt_task_cancelling;
	unsigned int hack_send_magic_pkt_size;
	unsigned int hack_send_magic_pkt_cnt;
	unsigned int hack_send_magic_pkt_interval;
	unsigned int hack_send_magic_pkt_per_round_budget;
#endif

#if defined(NSE_DEBUG_EXT)
	/* Only work for VSI used in PF driver.
	 *
	 * while VF-VSI is controlled in VF driver, with nsevf_adapter->debug_lan_no_xmit
	 */
	unsigned int debug_lan_no_xmit;
#endif

	spinlock_t	*tx_rings_locks;
} ____cacheline_internodealigned_in_smp;

/* struct that defines an interrupt vector */
struct nse_q_vector {
	struct nse_vsi *vsi;

	u16 v_idx;			/* index in the vsi->q_vector array. */
	u16 reg_idx;
	u8 num_ring_rx;			/* total number of Rx rings in vector */
	u8 num_ring_tx;			/* total number of Tx rings in vector */
	u8 wb_on_itr:1;			/* if true, WB on ITR is enabled */
	/* in usecs, need to use nse_intrl_to_usecs_reg() before writing this
	 * value to the device
	 */
	u8 intrl;

	struct dim dim;		/* data for net_dim algorithm */
	/* this matches the maximum number of ITR bits, but in usec
	 * values, so it is shifted left one bit (bit zero is ignored)
	 */
	union {
		struct {
			/*  HW register is 12 bit field in 2 us unit, here itr_setting are 1 us
			 * unit, so it is 13 bit
			 */
			u16 itr_setting:13;
			u16 itr_reserved:2;
			u16 itr_mode:1;
		};
		u16 itr_settings;
	};

	u16 dyn_itr_val;
	bool dyn_itr_refresh;

	struct napi_struct napi;

	struct nse_ring_container rx;
	struct nse_ring_container tx;
	struct nse_txcq_ring *txcq;

	cpumask_t affinity_mask;
	struct irq_affinity_notify affinity_notify;

	char name[NSE_INT_NAME_STR_LEN];

	u16 total_events;	/* net_dim(): number of interrupts processed */

#if defined(NSE_DEBUG_EXT)
	struct {
		unsigned long hardirq_total_cnt;
		unsigned long napi_poll_total_cnt;

		u64 napi_poll_last_ns;

		unsigned long napi_poll_txq_clean_done_cnt;
		unsigned long napi_poll_txq_clean_not_done_cnt;
		unsigned long napi_poll_txcq_clean_done_cnt;
		unsigned long napi_poll_txcq_clean_not_done_cnt;
		unsigned long napi_poll_rxq_clean_done_cnt;
		unsigned long napi_poll_rxq_clean_not_done_cnt;

		unsigned long napi_poll_budeget_less_0_cnt;
		unsigned long napi_poll_budeget_less_0_last_poll_cnt;
		u64 napi_poll_budeget_less_0_last_ns;

		unsigned long napi_poll_cpu_change_cnt;
		unsigned long napi_poll_cpu_change_last_poll_cnt;
		u64 napi_poll_cpu_change_last_ns;

		unsigned long napi_poll_clean_done_cnt;
		unsigned long napi_poll_clean_not_done_cnt;

		unsigned long napi_poll_clean_done_unmask_irq_cnt;
		unsigned long napi_poll_clean_done_keep_wb_on_itr_cnt;

		unsigned long napi_poll_last_ret_event;
	} dbg_stats;
#endif
} ____cacheline_internodealigned_in_smp;

enum nse_pf_flags {
	NSE_FLAG_FLTR_SYNC,
	NSE_FLAG_VMDQ_ENA,
	NSE_FLAG_MACVLAN_ENA,
	NSE_FLAG_ROCE_ENA,

	NSE_FLAG_RSS_CAPABLE,

	NSE_FLAG_SRIOV_ENA,
	NSE_FLAG_SRIOV_CAPABLE,
	NSE_FLAG_SIOV_ENA,
	NSE_FLAG_SIOV_CAPABLE,
	NSE_FLAG_DCB_CAPABLE,
	NSE_FLAG_DCB_ENA,
	NSE_FLAG_PTP_SUPPORTED,		/* NVM PTP support */
	NSE_FLAG_PTP,				/* PTP successfully initialized */
	NSE_FLAG_AUX_ENA,
	NSE_FLAG_PLUG_AUX_DEV,
	NSE_FLAG_UNPLUG_AUX_DEV,
	NSE_FLAG_MTU_CHANGED,
	NSE_FLAG_CLS_FLOWER,		/* support cls flower filters */
	NSE_FLAG_LINK_DOWN_ON_CLOSE_ENA,
	NSE_FLAG_TOTAL_PORT_SHUTDOWN_ENA,
	NSE_FLAG_FW_LLDP_AGENT_DFLT_ENA,	/* FW-LLDP-agent default running from NVM setting */
	NSE_FLAG_FW_LLDP_AGENT_ENA,			/* FW-LLDP-agent currently running */
	NSE_FLAG_FW_LLDP_DCBX_SUBAGENT_ENA,	/* FW-LLDP-DCBx-subagent currently running */
	NSE_FLAG_ETHTOOL_CTXT,		/* set when ethtool holds RTNL lock */
	NSE_FLAG_LEGACY_RX,
	NSE_FLAG_VF_TRUE_PROMISC_ENA,
	NSE_FLAG_MDD_AUTO_RESET_VF,
	NSE_FLAG_VF_VLAN_PRUNING,
	NSE_FLAG_ESWITCH_CAPABLE,
	NSE_FLAG_ALLOW_FEC_DIS_AUTO,

	NSE_PF_FLAGS_NBITS		/* must be last */
};

struct nse_macvlan {
	struct list_head list;
	int id;
	struct net_device *vdev;
	struct nse_vsi *parent_vsi;
	struct nse_vsi *vsi;
	u8 mac[ETH_ALEN];
};

struct nse_neigh_info {
	struct list_head	neigh_list_head;
	spinlock_t		neigh_tbl_lock; /*protect neigh_list*/
	struct notifier_block   netevent_nb;

	struct workqueue_struct *wq;
};

struct nse_switchdev_info {
	struct nse_vsi *control_vsi;
	struct nse_vsi *uplink_vsi;
	struct nse_neigh_info neigh_info; /*global neigh info*/
	struct nse_rep_sysfs uplink_sysfs;
	struct nse_rep_meter uplink_meter;
	struct nse_tc_ct_priv ct_priv;
	bool is_running;
	bool pf_roce_en;
};

struct nse_ip_route_addr {
	union {
		__be32	v4;
		struct in6_addr v6;
	} dst_ip;
	int family;
	int prefix_len;
	bool is_w_dmac;
	u8 dst_mac[ETH_ALEN];
};

struct nse_pf {
	struct pci_dev *pdev;

	bool force_reset_vf;

#if IS_ENABLED(CONFIG_NET_DEVLINK)
	struct devlink_region *func_caps_region;
	/* devlink port data */
	struct devlink_port devlink_port;
#endif /* CONFIG_NET_DEVLINK */

	u16 vsi_space_start;
	u16 vsi_space_size;
	struct nse_res_tracker *vsi_tracker;
	struct mutex vsi_tracker_mutex;
	u16 next_nonvf_vsi;	/* Next free slot in pf->vsi[], for non-VF VSI - 0-based */
	struct nse_vsi **vsi;		/* VSIs created by the driver */
	u16 nonvf_vsi_region_size;	/* = nse_vfs->vf_vsialloc_firstvsi, rename for clearness. */

	u16 lan_rxq_space_start;
	u16 lan_rxq_space_size;
	u16 lan_txq_space_start;
	u16 lan_txq_space_size;
	u16 lan_txcq_space_start;
	u16 lan_txcq_space_size;
	u16 lan_txcq_space_valid;
	struct nse_res_tracker *lan_rxq_tracker;
	struct nse_res_tracker *lan_txq_tracker;
	struct nse_res_tracker *lan_txcq_tracker;
	struct mutex lan_rxq_tracker_mutex;
	struct mutex lan_txq_tracker_mutex;
	struct mutex lan_txcq_tracker_mutex;

	u16 rdma_qset_space_start;
	u16 rdma_qset_space_size;
	u16 rdma_qset_space_valid;

	u16 irq_space_start;
	u16 irq_space_size;

	struct nse_res_tracker *irq_tracker_self_region;
	/* OS reserved IRQ details */
	struct msix_entry *msix_entries;
	/* First MSIX vector used by SR-IOV VFs. Calculated by subtracting the
	 * number of MSIX vectors needed for all SR-IOV VFs from the number of
	 * MSIX vectors allowed on this PF.
	 */
	u16 sriov_base_vector;

	bool sriov_res_planned;		/* SRIOV VF resources already planned ? */

#define NSE_RXQ_RSS_LUT_SCALE	4
	struct nse_res_tracker *rss_lut_tracker;
	u16 rss_lut_start;
	u16 rss_lut_size;
	struct mutex rss_lut_tracker_mutex;

	struct page *tso_hsb_pages;
	dma_addr_t tso_hsb_daddr;

	bool tso_hsb_usable;

	struct nse_sw *first_sw;	/* first switch created by firmware */
	u16 eswitch_mode;		/* current mode of eswitch */

	struct nse_vfs vfs;

	DECLARE_BITMAP(state, NSE_STATE_NBITS);
	DECLARE_BITMAP(flags, NSE_PF_FLAGS_NBITS);

	unsigned long serv_tmr_period;
	unsigned long serv_tmr_prev;
	struct timer_list serv_tmr;
	struct work_struct serv_task;
	struct tasklet_struct serv_bh;	/* Only used if nse_aq_rq_rx_method = 1 */

	struct timer_list polling_tmr;

	unsigned int wd_subtask_flags;
#define WD_SUBTASK_FLAG_UPDATE_PF_STATS_NOW			BIT(0)
#define WD_SUBTASK_FLAG_UPDATE_VSI_STATS_NOW		BIT(1)

#define WD_SUBTASK_FLAG_RUN_NOW						BIT(16)	/* as separator */
#define WD_SUBTASK_FLAG_OICR_OVERHEAT_RECV			BIT(16)

	/* check temperature in watchdog_task */
	unsigned long wd_subtask_check_temp_prev;
	unsigned long wd_subtask_check_temp_period;
#define WD_SUBTASK_CHECK_TEMP_PERIOD		(60 * HZ)
	bool in_high_temp;
#define WD_SUBTASK_CHECK_TEMP_CHIP_HIGH_THRES	90
#define WD_SUBTASK_CHECK_TEMP_CHIP_LOW_THRES	80
#define WD_SUBTASK_CHECK_TEMP_EPHY_HIGH_THRES	90
#define WD_SUBTASK_CHECK_TEMP_EPHY_LOW_THRES	80

	bool check_temp_force_cancel_rl_after_reset;

	unsigned long check_temp_run_cnt;
	unsigned long check_temp_high_cnt;
	unsigned long check_temp_low_cnt;

	unsigned long misc_intr_run_cnt;
	unsigned long serv_tmr_run_cnt;
	unsigned long serv_task_run_cnt;
	unsigned long serv_task_resched_imm_cnt;	/* resched immediately */
	unsigned long serv_bh_run_cnt;

	struct mutex sw_mutex;		/* lock for protecting VSI alloc flow */
	struct mutex tc_mutex;		/* lock to protect TC changes */
	struct mutex adev_mutex;	/* lock to protect aux device access */
	u32 msg_enable;
	struct nse_ptp ptp;
	u16 num_rdma_msix;	/* Total MSIX vectors for RDMA driver */
	u16 rdma_base_vector;
	/* MACVLAN specific variables */
	unsigned long *avail_macvlan;
	struct list_head macvlan_list;
	u16 num_macvlan;
	u16 max_num_macvlan;

	/* spinlock to protect the AdminQ wait list */
	spinlock_t aq_wait_lock;
	struct hlist_head aq_wait_list;
	wait_queue_head_t aq_wait_queue;
	bool fw_emp_reset_disabled;

	wait_queue_head_t reset_wait_queue;

	u16 misc_irq_idx;

	u32 oicr_ena;

	u32 oicr_hi_int_cnt;
	u32 oicr_me_int_cnt;
	u32 oicr_lo_int_cnt;
	u32 oicr_sw_int_cnt;

	u32 oicr_sw_int_tmp_poll;
	struct timer_list oicr_sw_int_tmp_poll_timer;
	unsigned long oicr_sw_int_tmp_poll_timer_run_cnt;

	u16 num_avail_sw_msix;	/* remaining MSIX SW vectors left unclaimed */
	u16 num_lan_msix;	/* Total MSIX vectors for base driver */
	u16 num_lan_tx;		/* num LAN Tx queues setup */
	u16 num_lan_rx;		/* num LAN Rx queues setup */

	u16 bypass_switch_vsi_abs_id;

	u16 pf_reset_count;		/* PF reset count (including both PFR and PFLR) */
	u16 pfr_count;			/* PFR count */
	u16 pflr_count;			/* PFLR count */
	u16 high_reset_count;	/* high_reset count */
	u16 high_reset_oicr_swint_count;
	u16 high_reset_oicr_corer_count;

	u8 wol_ena : 1;		/* software state of WoL */
	u32 wakeup_reason;	/* last wakeup reason */

	struct nse_hw_port_stats stats;
	struct nse_hw_port_stats stats_prev;
	struct nse_hw_port_stats stats_new;
	struct nse_hw_port_stats_raw stats_raw;
	bool stat_prev_loaded; /* has previous stats been loaded */

	struct nse_hw hw;
#ifdef NSE_ADD_PROBES
	u64 tcp_segs;
	u64 udp_segs;
	u64 tx_tcp_cso;
	u64 tx_udp_cso;
	u64 tx_sctp_cso;
	u64 tx_ip4_cso;
	u64 tx_l3_cso_err;
	u64 tx_l4_cso_err;
	u64 rx_tcp_cso;
	u64 rx_udp_cso;
	u64 rx_sctp_cso;
	u64 rx_ip4_cso;
	u64 rx_ip4_cso_err;
	u64 rx_tcp_cso_err;
	u64 rx_udp_cso_err;
	u64 rx_sctp_cso_err;
	u64 tx_q_vlano;
	u64 rx_q_vlano;
	u64 tx_ad_vlano;
	u64 rx_ad_vlano;
#endif
	u16 dcbx_cap;
	u32 tx_timeout_count;
	unsigned long tx_timeout_last_recovery;
	u32 tx_timeout_recovery_level;
	char int_name[NSE_INT_NAME_STR_LEN];
	struct iidc_core_dev_info **cdev_infos;
	int aux_idx;

	struct hlist_head tc_flower_fltr_list;
	struct mutex tc_flower_mutex;		/* lock to protect tc_flower_fltr_list */

	u64 supported_rxdids; /* bitmap for supported RXDID */
	struct nse_lag *lag; /* Link Aggregation information */

	__be16 vxlan_port;
	__be16 vxlan_gpe_port;
	__be16 geneve_port;
	u32 udp_tnl_flags;
	spinlock_t udp_tnl_lock;	/* protect udp_tnl_flags and the tunnel ports */
#define UDP_TNL_FLAG_SYNC_VXLAN_PORT		BIT(0)
#define UDP_TNL_FLAG_SYNC_VXLAN_GPE_PORT	BIT(1)
#define UDP_TNL_FLAG_SYNC_GENEVE_PORT		BIT(2)

	struct nse_switchdev_info switchdev;

	struct nse_msgbox_cb msgbox_cb;

#ifdef CONFIG_DEBUG_FS
	struct dentry *pf_dbgfs_dir;
#endif /* CONFIG_DEBUG_FS */

	u16 main_vsi_lan_qps_dflt;	/* RXQ/TXQ pairs */
	u16 main_vsi_lan_rxqs_max;
	u16 main_vsi_lan_txqs_max;

	struct nse_pf_sw_conf sw_conf;

#if defined(NSE_DEBUG_EXT)
	unsigned int test_rss;

	unsigned int test_fdir;

	unsigned int test_rcsum;
	u16 test_rcsum_dport;

	unsigned int test_rvlan;
	u16 test_rvlan_dport;

	unsigned int test_tvlan;

	unsigned int test_tcsum;
	unsigned int test_tcsum_pktcnt_interval;

	unsigned int test_tso;
	unsigned int test_tso_pktcnt_interval;

	unsigned int test_tdm_desc_err;	/* 0 for not in test, non-0 for in test and test type */
	int test_tdm_desc_err_cntdown;
#endif

	dma_addr_t bitmap_dma; /* for logall debug */
	atomic_t *bitmap_addr; /* for logall debug */

	const struct firmware *ddp;
};

extern struct workqueue_struct *nse_wq;

struct nse_netdev_priv {
	struct nse_vsi *vsi;
	/* indirect block callbacks on registered higher level devices
	 * (e.g. tunnel devices)
	 *
	 * tc_indr_block_cb_priv_list is used to lookup indirect callback
	 * private data
	 *
	 * netdevice_nb is the netdev events notifier - used to register
	 * tunnel devices for block events
	 *
	 */
	struct list_head tc_indr_block_priv_list;
	struct nse_repr *repr;
};

struct nse_cb {
	u16	append_cnt;		/* number of skb's appended */
};

#define NSE_CB(skb) ((struct nse_cb *)(skb)->cb)

void
nse_irq_dynamic_ena(struct nse_hw *hw, struct nse_vsi *vsi,
		    struct nse_q_vector *q_vector);

/**
 * nse_netdev_to_pf - Retrieve the PF struct associated with a netdev
 * @netdev: pointer to the netdev struct
 */
static inline struct nse_pf *nse_netdev_to_pf(struct net_device *netdev)
{
	struct nse_netdev_priv *np = netdev_priv(netdev);

	return np->vsi->back;
}

static inline bool nse_is_xdp_ena_vsi(struct nse_vsi *vsi)
{
	return !!vsi->xdp_prog;
}

static inline void nse_set_ring_xdp(struct nse_ring *ring)
{
	ring->flags |= NSE_TX_FLAGS_RING_XDP;
}

static inline bool nse_vsi_is_any_xdp_enabled(struct nse_vsi *vsi)
{
	if (vsi->xdp_prog)	//regular xdp_prog installed
		return true;

	if (vsi->af_xdp_zc_qps &&	//XSK mem installed
		(bitmap_weight(vsi->af_xdp_zc_qps, vsi->af_xdp_zc_qps_bitmap_size) > 0))
		return true;

	return false;
}

/**
 * nse_xsk_umem - get XDP UMEM bound to a ring
 * @ring: ring to use
 *
 * Returns a pointer to xdp_umem structure if there is an UMEM present,
 * NULL otherwise.
 */
static inline struct xsk_buff_pool *nse_xsk_umem(struct nse_ring *ring)
{
	struct nse_vsi *vsi = ring->vsi;
	u16 qid = ring->q_index;

	if (nse_ring_is_xdp(ring))
		qid -= vsi->num_xdp_txq;

	if (!nse_is_xdp_ena_vsi(vsi) || !test_bit(qid, vsi->af_xdp_zc_qps))
		return NULL;

	return xsk_get_pool_from_qid(vsi->netdev, qid);
}

/**
 * nse_get_main_vsi - Get the PF VSI
 * @pf: PF instance
 *
 * returns pf->vsi[0], which by definition is the PF VSI
 */
static inline struct nse_vsi *nse_get_main_vsi(struct nse_pf *pf)
{
	return pf->vsi[0];
}

/**
 * nse_get_netdev_priv_vsi - return VSI associated with netdev priv.
 * @np: private netdev structure
 */
static inline struct nse_vsi *nse_get_netdev_priv_vsi(struct nse_netdev_priv *np)
{
	/* In case of port representor return source port VSI. */
	if (np->repr)
		return np->repr->src_vsi;
	else
		return np->vsi;
}

/**
 * nse_find_vsi - Find the VSI from VSI ID
 * @pf: The PF pointer to search in
 * @vsi_num: The VSI ID to search for
 */
static inline struct nse_vsi *nse_find_vsi_by_abs_id(struct nse_pf *pf, u16 vsi_abs_id)
{
	int i;

	nse_for_each_vsi(pf, i)
		if (pf->vsi[i] && pf->vsi[i]->vsi_abs_num == vsi_abs_id)
			return  pf->vsi[i];
	return NULL;
}

/**
 * nse_find_vsi - Find the VSI from VSI ID
 * @pf: The PF pointer to search in
 * @vsi_num: The VSI ID to search for
 */
static inline struct nse_vsi *nse_find_vsi_by_rel_id(struct nse_pf *pf, u16 vsi_rel_id)
{
	int i;

	nse_for_each_vsi(pf, i)
		if (pf->vsi[i] && pf->vsi[i]->vsi_rel_num == vsi_rel_id)
			return  pf->vsi[i];
	return NULL;
}

#if IS_ENABLED(CONFIG_NET_DEVLINK)
/**
 * nse_is_switchdev_running - check if switchdev is configured
 * @pf: pointer to PF structure
 *
 * Returns true if eswitch mode is set to DEVLINK_ESWITCH_MODE_SWITCHDEV
 * and switchdev is configured, false otherwise.
 */
static inline bool nse_is_switchdev_running(struct nse_pf *pf)
{
	return pf->switchdev.is_running;
}

#else
static inline bool
nse_is_switchdev_running(struct nse_pf __always_unused *pf)
{
	return false;
}
#endif /* IS_ENABLED(CONFIG_NET_DEVLINK) */

static inline bool nse_is_offloaded_macvlan_ena(struct nse_pf *pf)
{
	return test_bit(NSE_FLAG_MACVLAN_ENA, pf->flags);
}

#ifdef CONFIG_DEBUG_FS
void nse_debugfs_vsi_init(struct nse_vsi *vsi);
void nse_debugfs_vsi_exit(struct nse_vsi *vsi);
void nse_debugfs_vf_init(struct nse_vf *vf);
void nse_debugfs_vf_exit(struct nse_vf *vf);
void nse_debugfs_pf_init(struct nse_pf *pf);
void nse_debugfs_pf_exit(struct nse_pf *pf);
void nse_debugfs_init(void);
void nse_debugfs_exit(void);
#else
static inline void nse_debugfs_vsi_init(struct nse_vsi *vsi) { }
static inline void nse_debugfs_vsi_exit(struct nse_vsi *vsi) { }
static inline void nse_debugfs_vf_init(struct nse_vf *vf) { }
static inline void nse_debugfs_vf_exit(struct nse_vf *vf) { }
static inline void nse_debugfs_pf_init(struct nse_pf *pf) { }
static inline void nse_debugfs_pf_exit(struct nse_pf *pf) { }
static inline void nse_debugfs_init(void) { }
static inline void nse_debugfs_exit(void) { }
#endif /* CONFIG_DEBUG_FS */

bool netif_is_nse(struct net_device *dev);

int nse_vsi_setup_tx_rings(struct nse_vsi *vsi);
int nse_vsi_setup_rx_rings(struct nse_vsi *vsi);
int nse_vsi_setup_lan_tx_cq_rings(struct nse_vsi *vsi);

int nse_vsi_open_ctrl(struct nse_vsi *vsi);
int nse_vsi_open(struct nse_vsi *vsi);
void nse_set_ethtool_repr_ops(struct net_device *netdev);
void nse_set_ethtool_ops(struct net_device *netdev);
void nse_set_ethtool_recovery_ops(struct net_device *netdev);
void nse_set_ethtool_safe_mode_ops(struct net_device *netdev);

u16 nse_get_avail_rxq_count(struct nse_pf *pf);
u16 nse_get_avail_txq_count(struct nse_pf *pf);
u16 nse_get_avail_rxq_count_max_contig(struct nse_pf *pf);
u16 nse_get_avail_txq_count_max_contig(struct nse_pf *pf);
/* Note, not max */
u16 nse_get_avail_rxq_count_contig_from_offset(struct nse_pf *pf, u16 offset);
/* Note, not max */
u16 nse_get_avail_txq_count_contig_from_offset(struct nse_pf *pf, u16 offset);
/* Note, not max */
u16 nse_get_avail_rxq_count_contig_before_offset(struct nse_pf *pf, u16 offset);
/* Note, not max */
u16 nse_get_avail_txq_count_contig_before_offset(struct nse_pf *pf, u16 offset);
u16 nse_get_avail_txcq_count(struct nse_pf *pf);
u16 nse_get_avail_txcq_count_max_contig(struct nse_pf *pf);

int nse_vsi_recfg_qs(struct nse_vsi *vsi, int new_rx, int new_tx);
void nse_update_pf_stats(struct nse_pf *pf);
void nse_dump_pf_stats(struct nse_pf *pf, struct nse_hw_port_stats *stats);
void nse_update_vsi_stats(struct nse_vsi *vsi);
int nse_up(struct nse_vsi *vsi);
void nse_fetch_u64_stats_per_ring(struct nse_ring *ring, u64 *pkts, u64 *bytes);
int nse_down(struct nse_vsi *vsi);
int nse_vsi_cfg(struct nse_vsi *vsi);
struct nse_vsi *nse_lb_vsi_setup(struct nse_pf *pf, struct nse_port_info *pi);
int nse_vsi_cfg_netdev_tc0(struct nse_vsi *vsi);
int nse_prepare_xdp_rings(struct nse_vsi *vsi, struct bpf_prog *prog);
int nse_destroy_xdp_rings(struct nse_vsi *vsi);
int
nse_xdp_xmit(struct net_device *dev, int n, struct xdp_frame **frames,
	     u32 flags);
int nse_set_rss_lut(struct nse_vsi *vsi, u16 *lut, u16 lut_size);
int nse_get_rss_lut(struct nse_vsi *vsi, u16 *lut, u16 lut_size);
int nse_set_rss_key(struct nse_vsi *vsi, u8 *seed);
int nse_get_rss_key(struct nse_vsi *vsi, u8 *seed);
void nse_fill_rss_lut(u16 *lut, u16 rss_table_size, u16 rss_size);

void nse_prepare_for_reset(struct nse_pf *pf, enum nse_reset_req reset_type, bool initiate_by_me);
int nse_schedule_reset(struct nse_pf *pf, enum nse_reset_req reset);

int nse_plug_aux_dev(struct iidc_core_dev_info *cdev_info, const char *name);
void nse_unplug_aux_dev(struct iidc_core_dev_info *cdev_info, unsigned int unplug_preset_reset);
int nse_plug_aux_devs(struct nse_pf *pf);
void nse_unplug_aux_devs(struct nse_pf *pf, unsigned int unplug_preset_reset,
			 unsigned int force_preset_reset);
int nse_init_aux_devices(struct nse_pf *pf);
int
nse_aux_iterate(struct nse_pf *pf, void *data,
		int (*fn)(struct iidc_core_dev_info *, void *));
#ifdef CONFIG_PM
void nse_cdev_info_refresh_msix(struct nse_pf *pf);
#endif /* CONFIG_PM */

/** nse_chk_rdma_cap - check the status of RDMA if PF flags
 * @pf: PF struct
 */
static inline bool nse_chk_rdma_cap(struct nse_pf *pf)
{
	return test_bit(NSE_FLAG_ROCE_ENA, pf->flags);
}

const char *nse_stat_str(enum nse_status stat_err);
const char *nse_aq_str(enum nse_aq_err aq_err);

const char *nse_pf_flag_str(unsigned int f);
const char *nse_pf_state_str(unsigned int s);

bool nse_is_wol_supported(struct nse_hw *hw);

int nse_open(struct net_device *netdev);
int nse_open_internal(struct net_device *netdev);
int nse_stop(struct net_device *netdev);
void nse_service_task_schedule(struct nse_pf *pf);

int nse_lan_init_tso_hsb(struct nse_pf *pf);
void nse_lan_deinit_tso_hsb(struct nse_pf *pf);
void nse_lan_reinstall_tso_hsb(struct nse_pf *pf);

void nse_udp_tunnels_rebuild(struct nse_pf *pf);

#define nse_printk(fmt, args...) pr_alert("[%s, %d] " fmt, __func__, __LINE__, ##args)

extern unsigned int nse_aq_cmd_timeout_tick;
extern unsigned int nse_aq_cmd_timeout;
extern unsigned int nse_aq_cmd_check_dd;
extern unsigned int nse_aq_cmd_wait_method;
extern unsigned int nse_aq_rq_rx_method;

extern unsigned int nse_main_vsi_max_lanq_num;
extern unsigned int nse_main_vsi_max_lanirq_num;
extern unsigned int nse_vf_vsi_max_lanq_num;
extern unsigned int nse_vf_vsi_max_lanirq_num;

extern unsigned int nse_sriov_vf_res_alloc_from_tail;

extern unsigned int nse_lan_tx_select_q_dport;
extern unsigned int nse_lan_tx_select_q_default;

extern unsigned int nse_bypass_sched;
extern unsigned int nse_bypass_switch;
extern unsigned int nse_tcam_less;
extern unsigned int nse_palladium_debug;
extern unsigned int nse_no_reset;
extern unsigned int nse_no_irq;
extern unsigned int nse_polling_mod;

extern unsigned int nse_timeout_scale;

#define NSE_RESET_WAIT_TICK				1			/* 1ms */

/* the native scale between these base are: 200 : 100 : 5 */
#define NSE_HIGH_RESET_WAIT_TIMEOUT_BASE	20000		/* 20000 x 1 ms = 20 s */
#define NSE_PF_RESET_WAIT_TIMEOUT_BASE		10000		/* 10000 x 1 ms = 10 s */
#define NSE_VF_RESET_WAIT_TIMEOUT_BASE		500			/* 500 x 1 ms = 0.5 s */

#define NSE_RESET_WAIT_FLAG_WAIT_FRTRIG		0x1
#define NSE_RESET_WAIT_FLAG_WAIT_FWMNG		0x2
#define NSE_RESET_WAIT_FLAG_WAIT_ST_MNG		0x4
#define NSE_RESET_WAIT_FLAG_WAIT_ST_PEC		0x8

extern unsigned int nse_bypass_qos_db_flush_disable;

#define NSE_LOOPBACK_MODE_SWITCH	1
#define NSE_LOOPBACK_MODE_LMAC		2
#define NSE_LOOPBACK_MODE_PHY		3
#define NSE_LOOPBACK_MODE_HW_JTAG	4
extern unsigned int nse_loopback_mode;

extern unsigned int nse_lan_tx_no_bql;

extern unsigned int nse_lan_tx_not_use_ctx_desc;

extern unsigned int nse_lan_txcq_initial_hw_gen;
extern unsigned int nse_lan_tcsum_force_l3;
extern unsigned int nse_lan_tdm_check_desc_err;

#define NSE_LAN_DESC_CACHE_TX	0x1
#define NSE_LAN_DESC_CACHE_RX	0x2
extern unsigned int nse_lan_desc_cache;

extern unsigned int nse_lan_tx_rs_optimize;

extern unsigned int nse_lan_no_xmit;
extern unsigned int nse_lan_disable_q_before_cfg;

extern unsigned int nse_lan_vlan_pvid_inner_strip;

extern unsigned int nse_lan_bulk_ena_dis;

extern unsigned int nse_lan_no_irqll;

extern unsigned int nse_sch_use_cir_transfer;

extern unsigned int nse_ptp_fine_mode;

extern unsigned int nse_qos_db_use_share;

#if defined(NSE_DEBUG_EXT)
extern unsigned int nse_qos_db_test_fc_tx;

/*	high thres: 1280 B (0x500 - 0101 0000 0000)
 *	low thres:	1024 B (0x400 - 0100 0000 0000)
 */
#define NSE_QOS_DB_RPB_SMALL_HTHRES		0x500
#define NSE_QOS_DB_RPB_SMALL_LTHRES		0x400

extern unsigned int nse_lan_vlan_force_up;

#endif

extern unsigned int nse_fw_lldp;

#if defined(NSE_DEBUG_EXT)
extern unsigned int nse_lan_rx_force_rxdid;
#endif

#if defined(NSE_DEBUG_EXT)
#define NSE_LAN_DEBUG_HW_QSTAT_TDM_CNT 16

extern unsigned int nse_lan_debug_hw_qstat;
#endif

extern unsigned int nse_rdma_ena;

extern unsigned int nse_chip_dbg_mode;

extern unsigned int nse_dbg_force_mac_ss;

extern unsigned int nse_misc_check_temp;

extern unsigned int nse_lmac_phy_ephy_ftype;

#define be16_to_le(x)	cpu_to_le16(be16_to_cpu(x))
#define be32_to_le(x)	cpu_to_le32(be32_to_cpu(x))
#define le16_to_be(x)	cpu_to_be16(le16_to_cpu(x))
#define le32_to_be(x)	cpu_to_be32(le32_to_cpu(x))

static inline bool nse_is_regval_reset_magic(u32 regval)
{
	return (regval == NSE_REG_VALUE_RESET_MAGIC_1 ||
			regval == NSE_REG_VALUE_RESET_MAGIC_2 ||
			regval == NSE_REG_VALUE_RESET_MAGIC_3);
}

#define BAR0_RNOC_BASE		0x200000
#define FW_RNOC_BASE		0x70000000

#endif /* _NSE_H_ */

