/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (c) 2018 - 2021 Beijing WangXun Technology Co., Ltd. */

#ifndef _NSEVF_H_
#define _NSEVF_H_

#include <linux/dim.h>

#include <linux/module.h>
#include <linux/pci.h>
#include <linux/aer.h>
#include <linux/netdevice.h>
#include <linux/vmalloc.h>
#include <linux/interrupt.h>
#include <linux/ethtool.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/sctp.h>
#include <linux/ipv6.h>
#include <linux/kernel.h>
#include <linux/bitops.h>
#include <linux/timer.h>
#include <linux/workqueue.h>
#include <linux/wait.h>
#include <linux/delay.h>
#include <linux/gfp.h>
#include <linux/skbuff.h>
#include <linux/dma-mapping.h>
#include <linux/etherdevice.h>
#include <linux/socket.h>
#include <linux/jiffies.h>
#include <net/ipv6.h>
#include <net/ip6_checksum.h>
#include <net/udp.h>
#include <linux/sctp.h>
#include <net/pkt_cls.h>
#include <net/tc_act/tc_gact.h>
#include <net/tc_act/tc_mirred.h>

#include "nsevf_type.h"
#include "virtchnl.h"
#include "nsevf_txrx.h"
#include <linux/bitmap.h>
#include "siov_regs.h"

#include "nsevf_msgbox.h"

extern unsigned int nsevf_use_msgbox;
extern unsigned int nsevf_polling_mod;

#define DEFAULT_DEBUG_LEVEL_SHIFT 3
#define PFX "nsevf: "

int nsevf_status_to_errno(enum nsevf_status status);
int virtchnl_status_to_errno(enum virtchnl_status_code v_status);

/* VSI state flags shared with common code */
enum nsevf_vsi_state_t {
	__NSEVF_VSI_DOWN,
	/* This must be last as it determines the size of the BITMAP */
	__NSEVF_VSI_STATE_SIZE__,
};

/* dummy struct to make common code less painful */
struct nsevf_vsi {
	struct nsevf_adapter *back;
	struct net_device *netdev;
	unsigned long active_cvlans[BITS_TO_LONGS(VLAN_N_VID)];
	unsigned long active_svlans[BITS_TO_LONGS(VLAN_N_VID)];

	/* dummy pointer - VF plans to add this functionality in the future */
	struct nsevf_ring **xdp_rings;
	u16 seid;
	u16 vsi_abs_id;
	u16 vsi_rel_id;
	DECLARE_BITMAP(state, __NSEVF_VSI_STATE_SIZE__);
	int base_vector;
	u16 qs_handle;
	/* stats counted by SW end */
};

enum nse_hw_platform {
	NSE_HW_PLATFORM_ASIC,
	NSE_HW_PLATFORM_FPGA,

	NSE_HW_PLATFORM_MAX,
};

#define NSEVF_INVAL_Q_INDEX 0xffff

/* How many Rx Buffers do we bundle into one write to the hardware ? */
#define NSEVF_RX_BUFFER_WRITE 16 /* Must be power of 2 */
#define NSEVF_DEFAULT_TXD 512
#define NSEVF_DEFAULT_RXD 512
#define NSEVF_MAX_TXD 4096
#define NSEVF_MIN_TXD 64
#define NSEVF_MAX_RXD 4096
#define NSEVF_MIN_RXD 64
#define NSEVF_REQ_DESCRIPTOR_MULTIPLE 32

#define NSE_DFLT_NUM_CQ_DESC (2048 * 128)

#define NSEVF_MAX_AQ_BUF_SIZE 4096
#define NSEVF_AQ_LEN 32
#define NSEVF_AQ_MAX_ERR 20 /* times to try before resetting AQ */

#define NSEVF_UTILQ_SQ_LEN 512

#define MAXIMUM_ETHERNET_VLAN_SIZE (VLAN_ETH_FRAME_LEN + ETH_FCS_LEN)

#define NSEVF_RX_DESC(R, i) (&(((union nsevf_rx_desc *)((R)->desc))[i]))
#define NSEVF_TX_DESC(R, i) (&(((struct nsevf_tx_desc *)((R)->desc))[i]))
#define NSEVF_TX_CTXTDESC(R, i) (&(((struct nse_tx_ctx_desc *)((R)->desc))[i]))

#define NSEVF_TXCQ_DESC(R, i) (&(((struct nse_lan_txcq_desc *)((R)->desc))[i]))

#define NSEVF_MAX_REQ_QUEUES 16

#define NSEVF_START_CHNL_TC 1

#define NSEVF_MBPS_DIVISOR 125000 /* divisor to convert to Mbps */
#define NSEVF_MBPS_QUANTA 50

#define NSEVF_NETIF_F_HW_VLAN_BITS
#define NSEVF_NETIF_F_HW_VLAN_CTAG_RX NETIF_F_HW_VLAN_CTAG_RX

#define NSEVF_NETIF_F_HW_VLAN_CTAG_TX NETIF_F_HW_VLAN_CTAG_TX

#define NSEVF_NETIF_F_HW_VLAN_CTAG_FILTER NETIF_F_HW_VLAN_CTAG_FILTER

enum nse_dynamic_itr { ITR_STATIC = 0, ITR_DYNAMIC = 1 };

#define ITR_IS_DYNAMIC(qvec) ((qvec)->itr_mode == ITR_DYNAMIC)
#define NSE_ITR_GRAN_S		1	/* ITR granularity is always 2us */
#define NSE_ITR_GRAN_US		BIT(NSE_ITR_GRAN_S)
#define NSE_ITR_MASK		0x1FFE	/* ITR register value alignment mask */
#define ITR_REG_ALIGN(setting)	((setting) & NSE_ITR_MASK)

/* MAX_MSIX_Q_VECTORS of these are allocated,
 * but we only use one per queue-specific vector.
 */
struct nsevf_q_vector {
	struct nsevf_adapter *adapter;
	struct nsevf_vsi *vsi;
	struct napi_struct napi;
	struct nsevf_ring_container rx;
	struct nsevf_ring_container tx;
	u32 ring_mask;

	struct nsevf_txcq_ring *txcq;

	u8 num_ringpairs; /* total number of ring pairs in vector */
	u16 v_idx; /* index in the vsi->q_vector array. */
	u16 reg_idx; /* register index of the interrupt */
	char name[IFNAMSIZ + 15];

	cpumask_t affinity_mask;
	struct irq_affinity_notify affinity_notify;

	int best_local_cpu_id;
	cpumask_t best_affinity_mask;	/* affinity_mask would change, define a non-change one */

	u8 wb_on_itr : 1; /* if true, WB on ITR is enabled */
	/* in usecs, need to use nse_intrl_to_usecs_reg() before writing this
	 * value to the device
	 */
	u8 intrl;

	struct dim dim; /* data for net_dim algorithm */
	/* this matches the maximum number of ITR bits, but in usec
	 * values, so it is shifted left one bit (bit zero is ignored)
	 */
	union {
		struct {
			/* The 12-bit HW field uses 2-us units; SW uses 1-us units. */
			u16 itr_setting : 13;
			u16 itr_reserved : 2;
			u16 itr_mode : 1;
		};
		u16 itr_settings;
	};

	u32 dyn_itr_val;
	bool dyn_itr_refresh;

	u16 total_events; /* net_dim(): number of interrupts processed */

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
};

/* Helper macros to switch between ints/sec and what the register uses.
 * And yes, it's the same math going both ways.  The lowest value
 * supported by all of the nsevf hardware is 8.
 */
#define EITR_INTS_PER_SEC_TO_REG(_eitr) \
	((_eitr) ? (1000000000 / ((_eitr) * 256)) : 8)
#define EITR_REG_TO_INTS_PER_SEC EITR_INTS_PER_SEC_TO_REG

#define NSEVF_DESC_UNUSED(R)                                          \
	((((R)->next_to_clean > (R)->next_to_use) ? 0 : (R)->count) + \
	 (R)->next_to_clean - (R)->next_to_use - 1)

#define OTHER_VECTOR 1
#define NONQ_VECS (OTHER_VECTOR)

#define MIN_MSIX_Q_VECTORS 1
#define MIN_MSIX_COUNT (MIN_MSIX_Q_VECTORS + NONQ_VECS)

#define NSEVF_QUEUE_END_OF_LIST 0x7FF
#define NSEVF_FREE_VECTOR 0x7FFF
struct nsevf_mac_filter {
	struct list_head list;
	u8 macaddr[ETH_ALEN];
	struct {
		u8 is_new_mac : 1; /* filter is new, wait for PF decision */
		u8 remove : 1; /* filter needs to be removed */
		u8 add : 1; /* filter needs to be added */
		u8 is_primary : 1; /* filter is a default VF MAC */
		/* Received response from PF for filter add. */
		u8 add_handled : 1;
		u8 padding : 3;
	};
};

#define NSEVF_VLAN(vid, tpid) ((struct nsevf_vlan){ vid, tpid })
struct nsevf_vlan {
	u16 vid;
	u16 tpid;
};

struct nsevf_vlan_filter {
	struct list_head list;
	struct nsevf_vlan vlan;
	struct {
		u8 is_new_vlan : 1; /* filter is new, wait for PF answer */
		u8 remove : 1; /* filter needs to be removed */
		u8 add : 1; /* filter needs to be added */
		u8 padding : 5;
	};
};

/* Driver state. The order of these is important! */
enum nsevf_state_t {
	__NSEVF_STARTUP, /* driver loaded, probe complete */
	__NSEVF_REMOVE, /* driver is being unloaded */
	__NSEVF_INIT_VERSION_CHECK, /* aq msg sent, awaiting reply */
	__NSEVF_INIT_GET_RESOURCES, /* aq msg sent, awaiting reply */
	__NSEVF_INIT_EXTENDED_CAPS, /* process extended caps which require aq msg exchange */
	__NSEVF_INIT_CONFIG_ADAPTER,
	__NSEVF_INIT_SW, /* got resources, setting up structs */
	__NSEVF_INIT_FAILED, /* init failed, restarting procedure */
	__NSEVF_RESETTING, /* in reset */
	__NSEVF_COMM_FAILED, /* communication with PF failed */
	__NSEVF_STATE_UP_AFTER_RESET, /* adapter failed reset, while running, up it again */
	/* Below here, watchdog is running */
	__NSEVF_DOWN, /* ready, can be opened */
	__NSEVF_DOWN_PENDING, /* descending, waiting for watchdog */
	__NSEVF_TESTING, /* in ethtool self-test */
	__NSEVF_RUNNING /* opened, working */
};

enum nsevf_critical_section_t {
	__NSEVF_IN_CRITICAL_TASK, /* cannot be interrupted */
	__NSEVF_IN_REMOVE_TASK, /* device being removed */
	__NSEVF_TX_TSTAMP_IN_PROGRESS, /* PTP Tx timestamp request in progress */
};

/* structure used for the virtchnl message queue */
struct nsevf_vc_msg {
	struct list_head list;
	enum virtchnl_ops v_opcode;
	u16 msglen;
	u8 msg[];
};

struct nsevf_vc_msg_queue {
	struct list_head msgs;
	/* Lock protecting access to the virtchnl message queue */
	struct mutex lock; /* protects Flow Director filter state */
};

enum nsevf_rdma_vc_op_state {
	NSEVF_RDMA_VC_OP_NO_WORK = 0,
	NSEVF_RDMA_VC_OP_PENDING,
	NSEVF_RDMA_VC_OP_COMPLETE,
	NSEVF_RDMA_VC_OP_FAILED,
};

struct nsevf_rdma {
	struct iidc_core_dev_info *cdev_info;
	int aux_idx;
	u16 num_msix;
	u16 recv_sync_msg_size;
	u8 recv_sync_msg[NSEVF_MAX_AQ_BUF_SIZE];
	wait_queue_head_t vc_op_waitqueue;
	enum nsevf_rdma_vc_op_state vc_op_state;
	struct nsevf_adapter *back;
	struct delayed_work init_task;
};

struct nsevf_fdir_ntuple_userdef {
	u16 flex_fltr; /* 0 for FALSE, 1 for TRUE */

	u16 flex_base;
	u16 flex_offset;
	u16 flex_word;
};

struct nsevf_fdir_input_stream {
	u8 pad0;
	u8 vsi;
	__le16 flex_bytes;
	__le16 dst_port;
	__le16 src_port;
	__le32 dst_ip[4];
	__le32 src_ip[4];
	u8 ptype;
	u8 pad1;
} __packed;

struct nsevf_fdir_utilq_config_payload {
	__le32 ip6_sa1;
	__le32 ip6_sa2;
	__le32 ip6_sa3;
	__le32 sa0;

	__le32 da;
	__le32 port;

	__le32 flex;
	__le32 hash;

	__le32 cmd;

	__le32 rsv;
} __packed;

struct nsevf_fdir_filter {
	struct hlist_node hnode;

	struct nsevf_fdir_input_stream input_stream;

	u16 bkt_hash; /* Lookup Table HASH */
	u16 sig_hash; /* Signature HASH, only used in signature mode */

	u16 sw_idx;

	u16 is_action_drop;

	u16 action_rxq_abs_id;

	/* save fsp input for quick GET */
	u64 fsp_ring_cookie;
	u32 fsp_flow_type;
	__be32 fsp_h_ext_data[2];
	__be32 fsp_m_ext_data[2];
};

struct nsevf_fdir_cb {
	u32 fdir_mode;
	u16 fdir_drp_rxq_abs_id;
	u8 pad[2];

	__le32 fdir_hkey;
	__le32 fdir_skey;

	u32 fdir_max_num_pfilter;
	u32 fdir_max_num_sfilter;

	struct hlist_head filter_list;
	unsigned int filter_count;

	struct nsevf_fdir_input_stream input_stream_mask;
	struct nsevf_fdir_ntuple_userdef flex_setting;

	u32 hw_ptype_mask; //set into FDIR_MASK_IDX_OTHER

	struct mutex lock; /* protects Flow Director filter state */
};

struct nsevf_sw_conf { /* like pf-linux-driver nse_pf_sw_conf and nse_vsi_sw_conf */

	unsigned int lan_tx_use_cq; /* must use CQ */

	/* Set at probe; it may later be disabled but cannot be re-enabled. */
	unsigned int lan_rx_ena_rsc;

	/* Unused; NSEVF_FLAG_FDIR_CAPABLE describes VF capability. */
	unsigned int fdir_ena;
};

/* board specific private data structure */
struct nsevf_adapter {
	struct workqueue_struct *wq;
	struct work_struct adminq_task;
	struct delayed_work watchdog_task;
	wait_queue_head_t down_waitqueue;
	wait_queue_head_t reset_waitqueue;
	wait_queue_head_t vc_waitqueue;

	struct timer_list vf_polling_tmr;

	struct nsevf_sw_conf sw_conf;

	struct nsevf_q_vector *q_vectors;
	struct list_head vlan_filter_list;
	struct list_head mac_filter_list;
	/* Lock to protect accesses to MAC and VLAN lists */
	spinlock_t mac_vlan_list_lock;
	char misc_vector_name[IFNAMSIZ + 9];
	u8 rxdid;
	int num_active_queues;
	int num_req_queues;

	/* TX */
	struct nsevf_ring *tx_rings;
	u32 tx_timeout_count;
	u32 tx_desc_count;

	/* RX */
	struct nsevf_ring *rx_rings;
	u32 rx_desc_count;
	int num_msix_vectors;
	struct msix_entry *msix_entries;

	/* TX-CQ */
	struct nsevf_txcq_ring *txcq_rings;
	u32 txcq_desc_count;

	u32 flags;
#define NSEVF_FLAG_RX_CSUM_ENABLED BIT(0)
#define NSEVF_FLAG_PF_COMMS_FAILED BIT(3)
#define NSEVF_FLAG_RESET_PENDING BIT(4)
#define NSEVF_FLAG_RESET_NEEDED BIT(5)
#define NSEVF_FLAG_WB_ON_ITR_CAPABLE BIT(6)
#define NSEVF_FLAG_BYPASS_SWITCH BIT(7)

/* also used as FDIR_ENA in VF driver */
#define NSEVF_FLAG_FDIR_CAPABLE BIT(8)

#define NSEVF_FLAG_LEGACY_RX BIT(15)

#define NSEVF_FLAG_REINIT_ITR_NEEDED BIT(16)
#define NSEVF_FLAG_QUEUES_ENABLED BIT(17)
#define NSEVF_FLAG_QUEUES_DISABLED BIT(18)
#define NSEVF_FLAG_REINIT_MSIX_NEEDED BIT(20)

#define NSEVF_FLAG_RESET_DETECTED BIT(22)
#define NSEVF_FLAG_INITIAL_MAC_SET BIT(23)
#define NSEVF_FLAG_SUSPEND_RUNNING BIT(24)
#define NSEVF_FLAG_UPDATE_NETDEV_FEATURES BIT(25)
#define NSEVF_FLAG_RESET_FAILED_DEV_UP BIT(26)

	/* flags for admin queue service task */
	u64 aq_required;
#define NSEVF_FLAG_AQ_ENABLE_QUEUES BIT(0)
#define NSEVF_FLAG_AQ_DISABLE_QUEUES BIT(1)
#define NSEVF_FLAG_AQ_ADD_MAC_FILTER BIT(2)
#define NSEVF_FLAG_AQ_ADD_VLAN_FILTER BIT(3)
#define NSEVF_FLAG_AQ_DEL_MAC_FILTER BIT(4)
#define NSEVF_FLAG_AQ_DEL_VLAN_FILTER BIT(5)
#define NSEVF_FLAG_AQ_CONFIGURE_QUEUES BIT(6)
#define NSEVF_FLAG_AQ_MAP_VECTORS BIT(7)
#define NSEVF_FLAG_AQ_HANDLE_RESET BIT(8)
#define NSEVF_FLAG_AQ_GET_CONFIG BIT(10)

#define NSEVF_FLAG_AQ_SET_RSS_ALG BIT(12)
#define NSEVF_FLAG_AQ_SET_RSS_KEY BIT(13)
#define NSEVF_FLAG_AQ_SET_RSS_LUT BIT(14)
#define NSEVF_FLAG_AQ_CONFIGURE_PROMISC_MODE BIT(15)

#define NSEVF_FLAG_AQ_SET_FDIR_INPUT_MASK BIT(16)

#define NSEVF_FLAG_AQ_REQUEST_STATS BIT(25)
#define NSEVF_FLAG_AQ_GET_OFFLOAD_VLAN_V2_CAPS BIT(26)
#define NSEVF_FLAG_AQ_ENABLE_CTAG_VLAN_STRIPPING BIT(27)
#define NSEVF_FLAG_AQ_DISABLE_CTAG_VLAN_STRIPPING BIT(28)
#define NSEVF_FLAG_AQ_ENABLE_STAG_VLAN_STRIPPING BIT(29)
#define NSEVF_FLAG_AQ_DISABLE_STAG_VLAN_STRIPPING BIT(30)
#define NSEVF_FLAG_AQ_ENABLE_CTAG_VLAN_INSERTION BIT(31)
#define NSEVF_FLAG_AQ_DISABLE_CTAG_VLAN_INSERTION BIT_ULL(32)
#define NSEVF_FLAG_AQ_ENABLE_STAG_VLAN_INSERTION BIT_ULL(33)
#define NSEVF_FLAG_AQ_DISABLE_STAG_VLAN_INSERTION BIT_ULL(34)
#define NSEVF_FLAG_AQ_GET_SUPPORTED_RXDIDS BIT_ULL(35)
#define NSEVF_FLAG_AQ_MSG_QUEUE_PENDING BIT_ULL(37)

	/* AQ messages that must be sent after NSEVF_FLAG_AQ_GET_CONFIG, in
	 * order to negotiated extended capabilities.
	 */
#define NSEVF_FLAG_AQ_EXTENDED_CAPS               \
	(NSEVF_FLAG_AQ_GET_OFFLOAD_VLAN_V2_CAPS | \
	 NSEVF_FLAG_AQ_GET_SUPPORTED_RXDIDS)

	/* flags for processing extended capability messages during
	 * __NSEVF_INIT_EXTENDED_CAPS. Each capability exchange requires
	 * both a SEND and a RECV step, which must be processed in sequence.
	 *
	 * During the __NSEVF_INIT_EXTENDED_CAPS state, the driver will
	 * process one flag at a time during each state loop.
	 */
	u64 extended_caps;
#define NSEVF_EXTENDED_CAP_SEND_VLAN_V2 BIT(0)
#define NSEVF_EXTENDED_CAP_RECV_VLAN_V2 BIT(1)
#define NSEVF_EXTENDED_CAP_SEND_RXDID BIT(2)
#define NSEVF_EXTENDED_CAP_RECV_RXDID BIT(3)

#define NSEVF_EXTENDED_CAPS                                                  \
	(NSEVF_EXTENDED_CAP_SEND_VLAN_V2 | NSEVF_EXTENDED_CAP_RECV_VLAN_V2 | \
	 NSEVF_EXTENDED_CAP_SEND_RXDID | NSEVF_EXTENDED_CAP_RECV_RXDID)

	/* Lock to prevent possible clobbering of
	 * current_netdev_promisc_flags
	 */
	spinlock_t current_netdev_promisc_flags_lock;
	netdev_features_t current_netdev_promisc_flags;

	/* OS defined structs */
	struct net_device *netdev;
	struct pci_dev *pdev;

	struct net_device_stats net_stats;

	struct nsevf_vsi_sw_stats sw_stats;
	struct nsevf_vsi_sw_stats sw_stats_prev;
	struct nsevf_vsi_sw_stats sw_stats_new;
	bool sw_stats_prev_loaded;

	struct nsevf_vsi_hw_stats hw_stats;
	unsigned long hw_stats_last_update_time;
	unsigned long hw_stats_update_period;

	struct nsevf_hw hw; /* defined in nsevf_type.h */

	enum nsevf_state_t state;
	enum nsevf_state_t last_state;
	unsigned long crit_section;

	/* protect some following fields */
	struct mutex misc_mutex;
	bool about_os_reset;
	bool in_os_reset;
	bool napi_enabled;
	bool sw_shutdown_mq_imm; /* SW should shutdown mq itself immediately */

	u8 external_reset_type;
#define NSEVF_EXTERNAL_RESET_TYPE_VF_RESET 0
#define NSEVF_EXTERNAL_RESET_TYPE_PF_RESET 1
#define NSEVF_EXTERNAL_RESET_TYPE_HIGH_RESET 2

	bool netdev_registered;
	bool link_up;
	enum virtchnl_link_speed link_speed;
	/* This is only populated if the VIRTCHNL_VF_CAP_ADV_LINK_SPEED is set
	 * in vf_res->vf_cap_flags. Use ADV_LINK_SUPPORT macro to determine if
	 * this field is valid. This field should be used going forward and the
	 * enum virtchnl_link_speed above should be considered the legacy way of
	 * storing/communicating link speeds.
	 */
	u32 link_speed_mbps;

	enum virtchnl_ops current_op;
	struct nsevf_vc_msg_queue vc_msg_queue;

#define RDMA_ALLOWED(_a) ((_a)->vf_res->vf_cap_flags & VIRTCHNL_VF_CAP_RDMA)
/* RSS by the PF should be preferred over RSS via other methods. */
#define RSS_PF(_a) ((_a)->vf_res->vf_cap_flags & VIRTCHNL_VF_OFFLOAD_RSS_PF)
#define VLAN_V2_ALLOWED(_a) \
	((_a)->vf_res->vf_cap_flags & VIRTCHNL_VF_OFFLOAD_VLAN_V2)
#define VLAN_V2_FILTERING_ALLOWED(_a)                             \
	(VLAN_V2_ALLOWED((_a)) &&                                 \
	 ((_a)->vlan_v2_caps.filtering.filtering_support.outer || \
	  (_a)->vlan_v2_caps.filtering.filtering_support.inner))
#define VLAN_FILTERING_ALLOWED(_a) (VLAN_V2_FILTERING_ALLOWED((_a)))
#define ADV_LINK_SUPPORT(_a) \
	((_a)->vf_res->vf_cap_flags & VIRTCHNL_VF_CAP_ADV_LINK_SPEED)

#define RXDID_ALLOWED(_a) \
	((_a)->vf_res->vf_cap_flags & VIRTCHNL_VF_OFFLOAD_RX_FLEX_DESC)

	struct virtchnl_vf_resource *vf_res; /* incl. all VSIs */
	struct virtchnl_vsi_resource *vsi_res; /* our LAN VSI */
	struct virtchnl_version_info pf_version;
	struct virtchnl_vlan_caps vlan_v2_caps;
	struct virtchnl_supported_rxdids supported_rxdids;

	u16 msg_enable;

	struct nsevf_vsi vsi;
	u32 aq_wait_count;

	/* RSS stuff */
	u16 rss_key_size;
	u16 rss_lut_size;
	u8 *rss_key;
	u16 *rss_lut;

	u32 rss_ctl_alg;
#define NSE_VSI_RSS_CTL_ALG_IPV4_TCP BIT(24)
#define NSE_VSI_RSS_CTL_ALG_IPV4 BIT(25)
#define NSE_VSI_RSS_CTL_ALG_IPV4_SCTP BIT(26)
#define NSE_VSI_RSS_CTL_ALG_IPV6_SCTP BIT(27)
#define NSE_VSI_RSS_CTL_ALG_IPV6 BIT(28)
#define NSE_VSI_RSS_CTL_ALG_IPV6_TCP BIT(29)
#define NSE_VSI_RSS_CTL_ALG_IPV4_UDP BIT(30)
#define NSE_VSI_RSS_CTL_ALG_IPV6_UDP BIT(31)

	u32 rss_hash_alg; /* not used for now */

	struct nsevf_rdma rdma;

	struct nsevf_msgbox_cb msgbox_cb;

	unsigned int probed_id;

	unsigned int wq_low_interval;
	unsigned int wq_low_mid_interval;
	unsigned int wq_mid_interval;
	unsigned int wq_mid_high_interval;
	unsigned int wq_high_interval;

	struct nsevf_fdir_cb fdir_cb;

	unsigned int debug_lan_no_xmit;

#ifdef CONFIG_DEBUG_FS
	struct dentry *vf_dbgfs_dir;
#endif
};

struct nsevf_cb {
	u16 append_cnt; /* number of skb's appended */
};

#define NSEVF_CB(skb) ((struct nsevf_cb *)(skb)->cb)

#define nsevf_adapter_to_dev(_adpater) (&((_adpater)->pdev->dev))

static inline struct device *nsevf_hw_to_dev(struct nsevf_hw *hw)
{
	struct nsevf_adapter *pf = container_of(hw, struct nsevf_adapter, hw);

	return &pf->pdev->dev;
}

/* Ethtool Private Flags */

/* needed by nsevf_ethtool.c */
extern char nsevf_driver_name[];
extern const char nsevf_driver_version[];

static inline const char *nsevf_state_str(enum nsevf_state_t state)
{
	switch (state) {
	case __NSEVF_STARTUP:
		return "__NSEVF_STARTUP";
	case __NSEVF_REMOVE:
		return "__NSEVF_REMOVE";
	case __NSEVF_INIT_VERSION_CHECK:
		return "__NSEVF_INIT_VERSION_CHECK";
	case __NSEVF_INIT_GET_RESOURCES:
		return "__NSEVF_INIT_GET_RESOURCES";
	case __NSEVF_INIT_EXTENDED_CAPS:
		return "__NSEVF_INIT_EXTENDED_CAPS";
	case __NSEVF_INIT_CONFIG_ADAPTER:
		return "__NSEVF_INIT_CONFIG_ADAPTER";
	case __NSEVF_INIT_SW:
		return "__NSEVF_INIT_SW";
	case __NSEVF_INIT_FAILED:
		return "__NSEVF_INIT_FAILED";
	case __NSEVF_RESETTING:
		return "__NSEVF_RESETTING";
	case __NSEVF_COMM_FAILED:
		return "__NSEVF_COMM_FAILED";
	case __NSEVF_DOWN:
		return "__NSEVF_DOWN";
	case __NSEVF_DOWN_PENDING:
		return "__NSEVF_DOWN_PENDING";
	case __NSEVF_TESTING:
		return "__NSEVF_TESTING";
	case __NSEVF_RUNNING:
		return "__NSEVF_RUNNING";
	case __NSEVF_STATE_UP_AFTER_RESET:
		return "__NSEVF_STATE_UP_AFTER_RESET";
	default:
		return "__NSEVF_UNKNOWN_STATE";
	}
}

static inline void nsevf_change_state(struct nsevf_adapter *adapter,
				      enum nsevf_state_t state)
{
	struct nsevf_hw *hw = &adapter->hw;

	if (adapter->state != state) {
		adapter->last_state = adapter->state;
		adapter->state = state;

		nsevf_debug(hw, NSEVF_DBG_SYS,
			    "state transition from:%s to:%s\n",
			    nsevf_state_str(adapter->last_state),
			    nsevf_state_str(adapter->state));
	}
}

bool nsevf_is_reset(struct nsevf_hw *hw);
int nsevf_check_reset_complete(struct nsevf_hw *hw, bool check_frtrig,
			       bool check_arqbal);

/**
 * nsevf_force_wb - Issue SW Interrupt so HW does a wb
 * @vsi: the VSI we care about
 * @q_vector: the vector  on which to force writeback
 *
 **/
static inline void nsevf_force_wb(struct nsevf_vsi *vsi,
				  struct nsevf_q_vector *q_vector)
{
	struct nsevf_hw *hw;
	u32 val;

	hw = &vsi->back->hw;

	val = (NSEVF_REG_INT_DYN_CTLN_SWINT_TRIG_M |
	       NSEVF_REG_INT_DYN_CTLN_INTMSK_VLD_M);

	wr32(hw, INT_DYN_CTLN(hw, q_vector->reg_idx), val);
}

struct nsevf_adapter *nsevf_pdev_to_adapter(struct pci_dev *pdev);
int nsevf_up(struct nsevf_adapter *adapter);
void nsevf_up_complete(struct nsevf_adapter *adapter);
void nsevf_down(struct nsevf_adapter *adapter);
int nsevf_process_config(struct nsevf_adapter *adapter);
int nsevf_parse_vf_resource_msg(struct nsevf_adapter *adapter);
void nsevf_schedule_reset(struct nsevf_adapter *adapter, u64 flags);
void nsevf_schedule_aq_request(struct nsevf_adapter *adapter, u64 flags);
void nsevf_reset(struct nsevf_adapter *adapter);
bool nsevf_is_reset_in_progress(struct nsevf_adapter *adapter);
bool nsevf_is_remove_in_progress(struct nsevf_adapter *adapter);
void nsevf_set_ethtool_ops(struct net_device *netdev);
void nsevf_update_sw_stats(struct nsevf_adapter *adapter);
void nsevf_sync_net_stats(struct nsevf_adapter *adapter);
void nsevf_reset_stats(struct nsevf_adapter *adapter);
void nsevf_reset_interrupt_capability(struct nsevf_adapter *adapter);
int nsevf_init_interrupt_scheme(struct nsevf_adapter *adapter);
void nsevf_irq_enable_queues(struct nsevf_adapter *adapter, u32 mask);
void nsevf_free_all_tx_resources(struct nsevf_adapter *adapter);
void nsevf_free_all_rx_resources(struct nsevf_adapter *adapter);
void nsevf_free_all_txcq_resources(struct nsevf_adapter *adapter);

void nsevf_napi_add_all(struct nsevf_adapter *adapter);
void nsevf_napi_del_all(struct nsevf_adapter *adapter);

int nsevf_send_api_ver(struct nsevf_adapter *adapter);
int nsevf_verify_api_ver(struct nsevf_adapter *adapter);
int nsevf_send_vf_config_msg(struct nsevf_adapter *adapter);
int nsevf_get_vf_config(struct nsevf_adapter *adapter);
int nsevf_get_vf_vlan_v2_caps(struct nsevf_adapter *adapter);
int nsevf_send_vf_offload_vlan_v2_msg(struct nsevf_adapter *adapter);
int nsevf_send_vf_supported_rxdids_msg(struct nsevf_adapter *adapter);
int nsevf_get_vf_supported_rxdids(struct nsevf_adapter *adapter);
void nsevf_set_queue_vlan_tag_loc(struct nsevf_adapter *adapter);
u16 nsevf_get_num_vlans_added(struct nsevf_adapter *adapter);
void nsevf_irq_enable(struct nsevf_adapter *adapter, bool flush);
void nsevf_configure_queues(struct nsevf_adapter *adapter);
void nsevf_deconfigure_queues(struct nsevf_adapter *adapter);
void nsevf_enable_queues(struct nsevf_adapter *adapter);
void nsevf_disable_queues(struct nsevf_adapter *adapter);
void nsevf_map_queues(struct nsevf_adapter *adapter);
int nsevf_request_queues(struct nsevf_adapter *adapter, int num);
void nsevf_add_ether_addrs(struct nsevf_adapter *adapter);
void nsevf_del_ether_addrs(struct nsevf_adapter *adapter);
void nsevf_add_vlans(struct nsevf_adapter *adapter);
void nsevf_del_vlans(struct nsevf_adapter *adapter);
void nsevf_set_promiscuous(struct nsevf_adapter *adapter);
bool nsevf_promiscuous_mode_changed(struct nsevf_adapter *adapter);
void nsevf_request_stats(struct nsevf_adapter *adapter);
int nsevf_request_reset(struct nsevf_adapter *adapter);
int nsevf_request_reset_rdma(struct nsevf_adapter *adapter);
void nsevf_force_reset_trig(struct nsevf_hw *hw);
void nsevf_set_rss_alg(struct nsevf_adapter *adapter);
void nsevf_set_rss_key(struct nsevf_adapter *adapter);
void nsevf_set_rss_lut(struct nsevf_adapter *adapter);
void nsevf_set_fdir_input_mask(struct nsevf_adapter *adapter);
void nsevf_enable_vlan_stripping(struct nsevf_adapter *adapter);
void nsevf_disable_vlan_stripping(struct nsevf_adapter *adapter);
void nsevf_virtchnl_completion(struct nsevf_adapter *adapter,
			       enum virtchnl_ops v_opcode,
			       enum virtchnl_status_code v_retval, u8 *msg,
			       u16 msglen);

#define NSEVF_CONFIG_RSS_FLAG_ALG 0x1
#define NSEVF_CONFIG_RSS_FLAG_KEY 0x2
#define NSEVF_CONFIG_RSS_FLAG_LUT 0x4
#define NSEVF_CONFIG_RSS_FLAG_ALL 0xFFFF
int nsevf_config_rss(struct nsevf_adapter *adapter, unsigned int flags);

void nsevf_enable_vlan_stripping_v2(struct nsevf_adapter *adapter, u16 tpid);
void nsevf_disable_vlan_stripping_v2(struct nsevf_adapter *adapter, u16 tpid);
void nsevf_enable_vlan_insertion_v2(struct nsevf_adapter *adapter, u16 tpid);
void nsevf_disable_vlan_insertion_v2(struct nsevf_adapter *adapter, u16 tpid);
int nsevf_replace_primary_mac(struct nsevf_adapter *adapter, const u8 *new_mac);

void nsevf_dump_vlan_filters(struct nsevf_adapter *adapter);
void nsevf_dump_mac_filters(struct nsevf_adapter *adapter);

void nsevf_send_vc_msg(struct nsevf_adapter *adapter);
struct nsevf_vc_msg *nsevf_alloc_vc_msg(enum virtchnl_ops v_opcode, u16 msglen);
void nsevf_queue_vc_msg(struct nsevf_adapter *adapter,
			struct nsevf_vc_msg *msg);
void nsevf_flush_vc_msg_queue(struct nsevf_adapter *adapter,
			      bool (*op_match)(enum virtchnl_ops pending_op));

void nsevf_set_vlan_offload_features(struct nsevf_adapter *adapter,
				     netdev_features_t prev_features,
				     netdev_features_t features);

#ifdef CONFIG_DEBUG_FS
void nsevf_debugfs_vf_init(struct nsevf_adapter *adapter);
void nsevf_debugfs_vf_exit(struct nsevf_adapter *adapter);
void nsevf_debugfs_init(void);
void nsevf_debugfs_exit(void);
#else
static inline void nsevf_debugfs_vf_init(struct nsevf_adapter *adapter)
{
}

static inline void nsevf_debugfs_vf_exit(struct nsevf_adapter *adapter)
{
}

static inline void nsevf_debugfs_init(void)
{
}

static inline void nsevf_debugfs_exit(void)
{
}
#endif /* CONFIG_DEBUG_FS*/

/* max VF number probed by 1 VF driver instance */
#define NSE_MAX_VF_CNT 256

#define NSE_ITR_INTERVAL_MIN_USEC 2
#define NSE_ITR_INTERVAL_MIN_IN_2_USEC 1
#define NSE_ITR_INTERVAL_MAX_USEC 8190
#define NSE_ITR_INTERVAL_MAX_IN_2_USEC 4095
#define NSE_ITR_INTERVAL_8K 124
#define NSE_ITR_INTERVAL_20K 50
#define NSE_ITR_INTERVAL_DEFAULT NSE_ITR_INTERVAL_20K

#define NSE_INTRL_INTERVAL_NO_USEC 0
#define NSE_INTRL_INTERVAL_MIN_USEC 4
#define NSE_INTRL_INTERVAL_MAX_USEC 252

int nsevf_set_itr_interval(struct nsevf_hw *hw, u16 irq, u32 interval_in_us);
int nsevf_write_itr(struct nsevf_q_vector *qvec, u32 interval_in_us);
void nsevf_set_q_vector_intrl(struct nsevf_q_vector *q_vector);

int nsevf_set_intrl_interval(struct nsevf_hw *hw, u16 irq, u32 interval_in_us);
void nsevf_write_intrl(struct nsevf_q_vector *q_vector, u8 intrl);
void nsevf_set_q_vector_intrl(struct nsevf_q_vector *q_vector);

void nsevf_set_vf_virtio_mode(struct nsevf_hw *hw, bool ena);

#define nsevf_for_each_txq(_adapter, _i) \
	for ((_i) = 0; (_i) < (_adapter)->num_active_queues; (_i)++)

#define nsevf_for_each_rxq(_adapter, _i) \
	for ((_i) = 0; (i) < (_adapter)->num_active_queues; (_i)++)

#define nsevf_for_each_q_vector(_adapter, _i)                             \
	for ((_i) = 0; (_i) < ((_adapter)->num_msix_vectors - NONQ_VECS); \
	     (_i)++)

#define nsevf_for_each_txcq(_adapter, _i) \
	for ((_i) = 0; (i) < (_adapter)->vf_res->lan_txcq_num; (_i)++)

int nsevf_msgbox_init(struct nsevf_adapter *adapter);
void nsevf_msgbox_exit(struct nsevf_adapter *adapter);

void nsevf_msgbox_debugfs_init(struct nsevf_adapter *adapter);

enum nsevf_status nsevf_msgbox_v2p_send_msg(struct nsevf_adapter *adapter,
					    char *msg, unsigned int msg_len);
enum nsevf_status
nse_msgbox_v2p_send_msg_to_pf(struct nsevf_hw *hw, enum virtchnl_ops v_opcode,
			      enum virtchnl_status_code v_retval, u8 *msg,
			      u16 msglen);

void dump_vf_res(struct nsevf_adapter *adapter,
		 struct virtchnl_vf_resource *vf_res);

extern unsigned int nse_aq_cmd_check_dd;
extern unsigned int nse_aq_cmd_wait_method;

extern unsigned int nse_lan_tx_no_bql;

extern unsigned int nsevf_lan_tx_rs_optimize;

extern unsigned int nsevf_lan_min_itr_no_intrl;

extern unsigned int nse_timeout_scale;

#define NSEVF_RESET_WAIT_TICK 10
#define NSEVF_RESET_WAIT_DETECT_TIMEOUT_BASE 500
#define NSEVF_RESET_WAIT_COMPLETE_TIMEOUT_BASE 3000

extern unsigned int nsevf_fdir_ena;
extern unsigned int nsevf_lan_tx_use_cq;

#define be16_to_le(x) cpu_to_le16(be16_to_cpu(x))
#define be32_to_le(x) cpu_to_le32(be32_to_cpu(x))
#define le16_to_be(x) cpu_to_be16(le16_to_cpu(x))
#define le32_to_be(x) cpu_to_be32(le32_to_cpu(x))

static inline bool nsevf_is_regval_reset_magic(u32 regval)
{
	return (regval == NSEVF_REG_VALUE_RESET_MAGIC_1 ||
		regval == NSEVF_REG_VALUE_RESET_MAGIC_2 ||
		regval == NSEVF_REG_VALUE_RESET_MAGIC_3);
}

#endif /* _NSEVF_H_ */
