/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2022 nebula-matrix Limited.
 * Author:
 */

#ifndef _NBL_RESOURCE_H_
#define _NBL_RESOURCE_H_

#include "nbl_core.h"
#include "nbl_hw.h"
#include "nbl_include.h"

#define NBL_RES_MGT_TO_COMMON(res_mgt)		((res_mgt)->common)
#define NBL_RES_MGT_TO_COMMON_OPS(res_mgt)	(&((res_mgt)->common_ops))
#define NBL_RES_MGT_TO_DEV(res_mgt)		NBL_COMMON_TO_DEV(NBL_RES_MGT_TO_COMMON(res_mgt))
#define NBL_RES_MGT_TO_DMA_DEV(res_mgt)		\
	NBL_COMMON_TO_DMA_DEV(NBL_RES_MGT_TO_COMMON(res_mgt))
#define NBL_RES_MGT_TO_INTR_MGT(res_mgt)	((res_mgt)->intr_mgt)
#define NBL_RES_MGT_TO_ACCEL_MGT(res_mgt)	((res_mgt)->accel_mgt)
#define NBL_RES_MGT_TO_QUEUE_MGT(res_mgt)	((res_mgt)->queue_mgt)
#define NBL_RES_MGT_TO_TXRX_MGT(res_mgt)	((res_mgt)->txrx_mgt)
#define NBL_RES_MGT_TO_FLOW_MGT(res_mgt)	((res_mgt)->flow_mgt)
#define NBL_RES_MGT_TO_TC_FLOW_MGT(res_mgt)	((res_mgt)->tc_flow_mgt)
#define NBL_RES_MGT_TO_COUNTER_MGT(res_mgt)	(((res_mgt)->tc_flow_mgt)->fc_mgt)
#define NBL_RES_MGT_TO_VSI_MGT(res_mgt)		((res_mgt)->vsi_mgt)
#define NBL_RES_MGT_TO_PORT_MGT(res_mgt)	((res_mgt)->port_mgt)
#define NBL_RES_MGT_TO_ADMINQ_MGT(res_mgt)	((res_mgt)->adminq_mgt)
#define NBL_RES_MGT_TO_INTR_MGT(res_mgt)	((res_mgt)->intr_mgt)
#define NBL_RES_MGT_TO_FD_MGT(res_mgt)		((res_mgt)->fd_mgt)
#define NBL_RES_MGT_TO_PROD_OPS(res_mgt)	((res_mgt)->product_ops)
#define NBL_RES_MGT_TO_RES_INFO(res_mgt)	((res_mgt)->resource_info)
#define NBL_RES_MGT_TO_SRIOV_INFO(res_mgt)	(NBL_RES_MGT_TO_RES_INFO(res_mgt)->sriov_info)
#define NBL_RES_MGT_TO_ESWITCH_INFO(res_mgt)	(NBL_RES_MGT_TO_RES_INFO(res_mgt)->eswitch_info)
#define NBL_RES_MGT_TO_ETH_INFO(res_mgt)	(NBL_RES_MGT_TO_RES_INFO(res_mgt)->eth_info)
#define NBL_RES_MGT_TO_QINFO_CFG(res_mgt)	(NBL_RES_MGT_TO_RES_INFO(res_mgt)->qinfo)
#define NBL_RES_MGT_TO_VSI_INFO(res_mgt)	(NBL_RES_MGT_TO_RES_INFO(res_mgt)->vsi_info)
#define NBL_RES_MGT_TO_ETH_BOND_INFO(res_mgt)	(NBL_RES_MGT_TO_RES_INFO(res_mgt)->eth_bond_info)
#define NBL_RES_MGT_TO_PF_NUM(res_mgt)		(NBL_RES_MGT_TO_RES_INFO(res_mgt)->max_pf)
#define NBL_RES_MGT_TO_OWNED_PF_BITMAP(res_mgt)	(NBL_RES_MGT_TO_RES_INFO(res_mgt)->owned_pf_bitmap)
#define NBL_RES_MGT_TO_VDPA_VF_STATS(res_mgt)	(NBL_RES_MGT_TO_RES_INFO(res_mgt)->vdpa.vf_stats)
#define NBL_RES_MGT_TO_DROP_STATS(res_mgt)	(NBL_RES_MGT_TO_RES_INFO(res_mgt)->drop_stats)
#define NBL_RES_MGT_TO_FAKE_STATS(res_mgt)	(NBL_RES_MGT_TO_RES_INFO(res_mgt)->fake_drop)
#define NBL_RES_MGT_TO_PRE_FAKE_STATS(res_mgt)	(NBL_RES_MGT_TO_RES_INFO(res_mgt)->pre_fake_drop)
#define NBL_RES_MGT_TO_PHY_OPS_TBL(res_mgt)	((res_mgt)->phy_ops_tbl)
#define NBL_RES_MGT_TO_PHY_OPS(res_mgt)		(NBL_RES_MGT_TO_PHY_OPS_TBL(res_mgt)->ops)
#define NBL_RES_MGT_TO_PHY_PRIV(res_mgt)	(NBL_RES_MGT_TO_PHY_OPS_TBL(res_mgt)->priv)
#define NBL_RES_MGT_TO_CHAN_OPS_TBL(res_mgt)	((res_mgt)->chan_ops_tbl)
#define NBL_RES_MGT_TO_CHAN_OPS(res_mgt)	(NBL_RES_MGT_TO_CHAN_OPS_TBL(res_mgt)->ops)
#define NBL_RES_MGT_TO_CHAN_PRIV(res_mgt)	(NBL_RES_MGT_TO_CHAN_OPS_TBL(res_mgt)->priv)
#define NBL_RES_MGT_TO_TX_RING(res_mgt, index)	\
	(NBL_RES_MGT_TO_TXRX_MGT(res_mgt)->tx_rings[(index)])
#define NBL_RES_MGT_TO_RX_RING(res_mgt, index)	\
	(NBL_RES_MGT_TO_TXRX_MGT(res_mgt)->rx_rings[(index)])
#define NBL_RES_MGT_TO_VECTOR(res_mgt, index)	\
	(NBL_RES_MGT_TO_TXRX_MGT(res_mgt)->vectors[(index)])

#define NBL_RES_BASE_QID(res_mgt)		NBL_RES_MGT_TO_RES_INFO(res_mgt)->base_qid
#define NBL_RES_NOFITY_QID(res_mgt, local_qid)	(NBL_RES_BASE_QID(res_mgt) * 2 + (local_qid))

#define NBL_MAX_NET_ID				NBL_MAX_FUNC
#define NBL_MAX_JUMBO_FRAME_SIZE		(9600)
#define NBL_4K_FRAME_SIZE			(4096)
#define NBL_PKT_HDR_PAD				(ETH_HLEN + (VLAN_HLEN * 2))

#define NBL_TPID_PORT_NUM			(1031)
#define NBL_VLAN_TPYE				(0)
#define NBL_QINQ_TPYE				(1)

/* --------- QUEUE ---------- */
#define NBL_MAX_TXRX_QUEUE			(2048)
#define NBL_DEFAULT_DESC_NUM			(1024)
#define NBL_MAX_TXRX_QUEUE_FUNC_LEONIS		(256)
#define NBL_MAX_TXRX_QUEUE_VSI_LEONIS		(256)

#define NBL_DEFAULT_DRACO_REP_HW_QUEUE_NUM	(16)
#define NBL_DEFAULT_REP_HW_QUEUE_NUM		(16)
#define NBL_DEFAULT_PF_HW_QUEUE_NUM		(16)
#define NBL_DEFAULT_USER_HW_QUEUE_NUM		(16)
#define NBL_DEFAULT_VF_HW_QUEUE_NUM		(2)
#define NBL_VSI_PF_LEGACY_QUEUE_NUM_MAX		(240)

/* Intf localq->globalq pf max is 128*3; but rss max 128. */
#define NBL_MAX_TXRX_QUEUE_FUNC_PF_DRACO	(128 * 3)
/* This macro only for nblconfig check */
#define NBL_MAX_TXRX_QUEUE_FUNC_PF_DRACO_CHK	(128 + NBL_DEFAULT_REP_HW_QUEUE_NUM)
#define NBL_MAX_TXRX_QUEUE_FUNC_VF_DRACO	(32)
#define NBL_MAX_TXRX_QUEUE_VSI_PF_DRACO		(128)
#define NBL_MAX_TXRX_QUEUE_VSI_VF_DRACO		(32)

#define NBL_AUX_NET_ID_OFFSET_LEONIS		(4)
#define NBL_AUX_NET_ID_OFFSET_DRACO		(264)
#define NBL_MAX_BATCH_DESC			(64)

#define NBL_VDPA_ITR_BATCH_CNT			(64)

#define FIELD_LOC(pos, off, vld) (((pos) << 8) + ((off) << 1) + (vld))
#define FIELD_POS(f) ((f) >> 8)
#define FIELD_OFFSET(f) (((f) >> 1) & 0x3f)
#define FIELD_VLD(f) ((f) & 0x1)

#define HDR_CFG(ptr, pos, off, vld, val) ((ptr)[(pos)] |= (((val) << (off)) & -(vld)))
#define HDR_CLR(ptr, pos, off, vld, mask) ((ptr)[(pos)] &= ~((((mask)) << (off)) & -(vld)))

#define NBL_FW_HEARTBEAT_SEQ_BASE		(0X100)

enum nbl_qid_map_table_type {
	NBL_MASTER_QID_MAP_TABLE,
	NBL_SLAVE_QID_MAP_TABLE,
	NBL_QID_MAP_TABLE_MAX
};

struct nbl_queue_vsi_info {
	enum nbl_vsi_type vsi_index;	/* save the vsi type define as enum nbl_vsi_type */
	u32 curr_qps;
	u16 curr_qps_static;		/* This will not be reset when netdev down */
	u16 vsi_id;
	u16 rss_ret_base;
	u16 rss_entry_size_unit;
	u16 rss_entry_size;
	u16 net_id;
	u16 queue_offset;
	u16 queue_num;
	u16 high_pri_queue;
	bool rss_vld;
	bool vld;
};

struct nbl_queue_info {
	struct nbl_queue_vsi_info vsi_info[NBL_VSI_MAX];
	u64 notify_addr;
	u16 num_txrx_queues;
	u16 rss_ret_base;
	u16 *txrx_queues;
	u64 *queues_context;
	u32 *uvn_stat_pkt_drop;
	u16 rss_entry_size;
	u32 curr_qps;
	u16 split;
	u16 queue_size;
	u16 is_dpdk;
	u16 dpdk_vsi;
	u16 extra_vsi_rss_ret_base;
};

struct nbl_adapt_desc_gother {
	u64 get_desc_stats_jiffies;
	u32 uvn_desc_rd_entry;
	u16 level;
	bool is_dpdk;
};

struct nbl_dvn_desc_req_info {
	bool desc_req_need; /*  draco has tail point, no need cfg dvn_desc_req */
	bool is_desc_req_cfg; /* is the desc req val is cfg by user, no eq default  */
	u8 resv[2];
};

struct nbl_queue_mgt {
	DECLARE_BITMAP(txrx_queue_bitmap, NBL_MAX_TXRX_QUEUE);
	DECLARE_BITMAP(rss_ret_bitmap, NBL_EPRO_RSS_RET_TBL_DEPTH);
	struct nbl_qid_map_table qid_map_table[NBL_QID_MAP_TABLE_ENTRIES];
	struct nbl_queue_info queue_info[NBL_MAX_FUNC];
	u16 net_id_ref_vsinum[NBL_MAX_NET_ID];
	struct nbl_adapt_desc_gother adapt_desc_gother;
	int qid_map_select;
	u32 total_qid_map_entries;
	u32 queue_base_idx;
	u32 max_queue;
	u32 qid_map_tail[NBL_QID_MAP_TABLE_MAX];
	u16 aux_netid_offset;
	u16 avail_queue_num;
	bool check_allpf_qp;
	u16 rss_key_range_oft;
	u16 rss_key_range_size;
	u16 dsch_dport_id;
	u16 group_id;
	u16 class_id;
	u16 user_group_id;
	u16 user_class_id;
	u16 rss_exclude_queue_num;
	u8 need_cfg_g2p;
	u8 need_clear_g2p;
	u8 need_cfg_n2g;
	bool rss_replace; /* leonis only one rss, so need replay it */
	u16 dpdk_cnt;
	u16 pf_func_max_qp;
	u16 pf_func_max_qp_chk;
	u16 vf_func_max_qp;
	u16 pf_vsi_max_qp;
	u16 vf_vsi_max_qp;
	u16 pf_coexist_vsi_max_qp; /* data && user vsi max qp_num */
	struct nbl_dvn_desc_req_info dvn_desc_req;
	u16 desc_gother_level0_timeout;
	u16 desc_gother_level1_timeout;
};

/* --------- INTERRUPT ---------- */
#define NBL_MAX_OTHER_INTERRUPT			4096
#define NBL_MAX_NET_INTERRUPT			1024

struct nbl_msix_map {
	u16 valid:1;
	u16 global_msix_index:13;
	u16 rsv:2;
};

struct nbl_msix_map_table {
	struct nbl_msix_map *base_addr;
	dma_addr_t dma;
	size_t size;
};

struct nbl_func_interrupt_resource_mng {
	u16 num_interrupts;
	u16 num_net_interrupts;
	u16 msix_base;
	u16 *interrupts;
	u16 max_net_interrupt;
	u16 max_other_interrupt;
	u16 rdma_intr_num;
	struct nbl_msix_map_table msix_map_table;
};

struct nbl_interrupt_mgt {
	DECLARE_BITMAP(interrupt_net_bitmap, NBL_MAX_NET_INTERRUPT);
	DECLARE_BITMAP(interrupt_others_bitmap, NBL_MAX_OTHER_INTERRUPT);
	struct nbl_func_interrupt_resource_mng func_intr_res[NBL_MAX_FUNC];
	u32 msix_table_range_oft;
	u32 msix_table_range_size;
	u16 msix_map_table_max_entries;
	u16 max_net_interrupt;
	u16 max_other_interrupt;
};

enum nbl_rx_los_lol_irq_state {
	NBL_RX_LOS_LOL_IRQ_STATE_OFF = 1,
	NBL_RX_LOS_LOL_IRQ_STATE_ON = 2,
};

struct nbl_port_mgt {
	bool need_check_rx_los_loc_irq;
	enum nbl_rx_los_lol_irq_state last_rx_los_lol_irq_state;
	struct mutex eth_lock; /* To lock module eeprom */
};

/* --------- TXRX ---------- */
struct nbl_txrx_vsi_info {
	u16 ring_offset;
	u16 ring_num;
};

struct nbl_ring_desc {
	/* buffer address */
	__le64 addr;
	/* buffer length */
	__le32 len;
	/* buffer ID */
	__le16 id;
	/* the flags depending on descriptor type */
	__le16 flags;
};

struct nbl_tx_buffer {
	struct nbl_ring_desc *next_to_watch;
	u8 *tls_pkthdr;
	union {
		struct sk_buff *skb;
		void *raw_buff; /* for xdp */
	};
	dma_addr_t dma;
	u32 len;

	unsigned int bytecount;
	unsigned short gso_segs;
	bool page;
	u8 hlen;
};

struct nbl_dma_info {
	dma_addr_t addr;
	struct page *page;
	u32 size;
	u16 pagecnt_bias;
};

struct nbl_page_cache {
	struct nbl_dma_info *page_cache;
	u32 head;
	u32 tail;
	u32 size;
};

struct nbl_rx_buffer {
	struct nbl_dma_info *di;
	u16 offset;
	u16 rx_pad;
	u16 size;
	bool last_in_page;
	bool first_in_page;
};

struct nbl_res_vector {
	struct nbl_napi_struct nbl_napi;
	struct nbl_res_tx_ring *tx_ring;
	struct nbl_res_rx_ring *rx_ring;
	struct nbl_res_tx_ring *xdp_ring;
	u8 *irq_enable_base;
	u32 irq_data;
	bool started;
	bool net_msix_mask_en;
};

enum nbl_vlan_offload_type {
	NBL_VLAN_NOT_SUPPORT_OFFLOAD,
	NBL_VLAN_SW_OFFLOAD,
	NBL_VLAN_HW_OFFLOAD,
};

enum nbl_tx_hdr_key {
	NBL_FWD,
	NBL_DPORT,
	NBL_DPORT_ID,
	NBL_MSS,
	NBL_CSUM,
	NBL_TLS_IDX,
	NBL_TLS_FLAG,
	NBL_TX_MAX,
};

struct nbl_res_tx_ring {
	/*data path*/
	struct nbl_ring_desc *desc;
	struct nbl_tx_buffer *tx_bufs;
	struct device *dma_dev;
	struct net_device *netdev;
	u8 __iomem *notify_addr;
	struct nbl_queue_stats stats;
	struct nbl_tx_queue_stats tx_stats;
	u16 cfg_offset[NBL_TX_MAX];
	//draco hdr max, 16 bytes
	u8 default_hdr[sizeof(struct nbl_tx_extend_head_draco)];

	u16 queue_index;
	u16 desc_num;
	u16 notify_qid;
	u16 avail_used_flags;
	u16 max_payload_size;
	u16 next_to_use;
	u16 next_to_clean;
	u16 vlan_tci;
	u16 vlan_proto;
	/* device ring wrap counter */
	bool used_wrap_counter;
	u8 vsi_type;
	u8 extheader_tx_len;
	u8 ktls_inithdr_len;
	u8 ktls_synchdr_len;
	u8 interleave_seg_disable;
	u8 dport_id2;
	u8 bond;
	u8 simple_fwd;
	u8 eth_id;
	u8 support_ptr;
	/* control path */
	// dma for desc[]
	dma_addr_t dma;
	// size for desc[]
	unsigned int size;
	bool valid;

	void *xdp_prog;
	spinlock_t xmit_lock; /* use for xdp tx_act; because XDP queue'num may less then core num */

	/* for ktls payload fill */
	void (*fill_ktls_init_payload)(void *init_payload,
				       struct nbl_ktls_offload_context_tx *priv_tx);
} ____cacheline_internodealigned_in_smp;

enum nbl_rq_flags {
	NBL_RQ_FLAGS_XDP_XMIT,
	NBL_RQ_FLAGS_XDP_REDIRECT,
};

struct nbl_res_rx_ring {
	/* data path */
	struct nbl_ring_desc *desc;
	struct nbl_rx_buffer *rx_bufs;
	struct nbl_dma_info *di;
	struct device *dma_dev;
	struct net_device *netdev;
	struct page_pool *page_pool;
	struct nbl_queue_stats stats;
	struct nbl_rx_queue_stats rx_stats;
	struct nbl_page_cache page_cache;
	DECLARE_BITMAP(flags, 8);

	u32 buf_len;
	u16 avail_used_flags;
	u16 next_to_use;
	u16 next_to_clean;
	u16 next_to_free;
	u16 vq_free_cnt;
	u16 desc_num;
	u16 queue_index;
	u16 vlan_tci;
	u16 vlan_proto;
	u8 vsi_type;
	u8 nid;
	bool used_wrap_counter;
	bool linear_skb;
	bool xdp_enhance;
	bool rxq_large_buf;

	struct nbl_common_info *common;
	void *txrx_mgt;
	void *xdp_prog;
	struct xdp_rxq_info xdp_rxq;
	// dma for desc[]
	dma_addr_t dma;
	// size for desc[]
	unsigned int size;
	bool valid;
	u8 extheader_rx_len;
	u16 notify_qid;
	u16 frags_num_per_page;
	u16 max_pkt_len;
	/* for rx packet header parse */
	u16 (*parse_rx_extend_header)(struct nbl_res_rx_ring *ring, void *hdr, struct sk_buff *skb);
} ____cacheline_internodealigned_in_smp;

struct nbl_txrx_bond_info {
	u16 eth_id[NBL_LAG_MAX_PORTS];
	u16 lag_id;
	bool bond_enable;
};

struct nbl_txrx_mgt {
	struct nbl_res_vector **vectors;
	struct nbl_res_tx_ring **tx_rings;
	struct nbl_res_rx_ring **rx_rings;
	struct nbl_txrx_bond_info bond_info;
	struct nbl_txrx_vsi_info vsi_info[NBL_VSI_MAX];
	enum nbl_vlan_offload_type offload_type;
	u16 tx_ring_num;
	u16 rx_ring_num;
	u16 xdp_ring_offset;
	u16 xdp_ring_num;
	u16 need_check_mtu;
	u8 extheader_tx_len;
	u8 extheader_rx_len;
	u8 ktls_inithdr_len;
	u8 ktls_synchdr_len;
	/* novirtual means not consider virtualization, such as df200/rnic400.
	 * fwd filed initial value is cpu_fwd.
	 * conversely, initial value is normal_fwd, such as df200 virtio/leonis/draco.
	 * leonis vxlan toe use virtio hdr directly, not care the field.
	 */
	u8 novirtual;
	/* simple_fwd means ext hdr always keep same.
	 * such as df200 virtio/leonis vxlan toe.
	 * that is not have arp dual send, lldp/lacp cpu_fwd send, eswitch offload.
	 */
	u8 simple_fwd;
	u8 support_ptr;

};

struct nbl_vsi_mgt {
};

struct nbl_emp_version {
	char app_version[16];
	char kernel_version[16];
	char build_version[16];
};

struct nbl_eth_stats_info;

struct nbl_adminq_mgt {
	struct nbl_emp_version emp_verion;
	u32 fw_last_hb_seq;
	unsigned long fw_last_hb_time;

	struct work_struct eth_task;
	struct nbl_resource_mgt *res_mgt;
	u8 speed_changed[NBL_MAX_ETHERNET];
	u8 module_inplace_changed[NBL_MAX_ETHERNET];
	u8 link_state_changed[NBL_MAX_ETHERNET];

	struct mutex eth_lock; /* To prevent link_state_changed mismodified. */
	void *cmd_filter;

	char firmware_version[NBL_FRIMWARE_VERSION_LEN];
	char firmware_magic[8];
	struct nbl_devcomm_comp_dev *comp_dev; /* for nblconfig cfg notify */
	struct nbl_eth_stats_info *eth_stats_info;
	u32 eth_stats_array_size;
	const struct ethtool_rmon_hist_range *rmon_ranges;
	u16 *eth_stats_offset;
	u32 eth_stats_struct_size;
	u32 wol_reg_offset;
	bool eth_task_init;
	u8 rsv[2];
};

/* --------- FLOW ---------- */
#define NBL_FEM_HT_PP0_LEN				(2 * 1024)

#define NBL_MACVLAN_TABLE_LEN				(4096 * 2)

enum nbl_next_stg_id_e {
	NBL_NEXT_STG_PA		= 1,
	NBL_NEXT_STG_IPRO	= 2,
	NBL_NEXT_STG_PP0_S0	= 3,
	NBL_NEXT_STG_PP0_S1	= 4,
	NBL_NEXT_STG_PP1_S0	= 5,
	NBL_NEXT_STG_PP1_S1	= 6,
	NBL_NEXT_STG_PP2_S0	= 7,
	NBL_NEXT_STG_PP2_S1	= 8,
	NBL_NEXT_STG_MCC	= 9,
	NBL_NEXT_STG_ACL_S0	= 10,
	NBL_NEXT_STG_ACL_S1	= 11,
	NBL_NEXT_STG_EPRO	= 12,
	NBL_NEXT_STG_BYPASS	= 0xf,
};

enum {
	NBL_FLOW_UP_TNL,
	NBL_FLOW_UP,
	NBL_FLOW_DOWN,
	NBL_FLOW_MACVLAN_MAX,
	NBL_FLOW_LLDP_LACP_UP = NBL_FLOW_MACVLAN_MAX,
	NBL_FLOW_PMD_ND_UPCALL,
	NBL_FLOW_L2_UP_MULTI_MCAST,
	NBL_FLOW_L3_UP_MULTI_MCAST,
	NBL_FLOW_UP_MULTI_MCAST_END,
	NBL_FLOW_L2_DOWN_MULTI_MCAST = NBL_FLOW_UP_MULTI_MCAST_END,
	NBL_FLOW_L3_DOWN_MULTI_MCAST,
	NBL_FLOW_DOWN_MULTI_MCAST_END,
	NBL_FLOW_ACCEL_BEGIN = NBL_FLOW_DOWN_MULTI_MCAST_END,
	NBL_FLOW_TLS_UP	= NBL_FLOW_ACCEL_BEGIN,
	NBL_FLOW_IPSEC_DOWN,
	NBL_FLOW_ACCEL_END,
	NBL_FLOW_TYPE_MAX = NBL_FLOW_ACCEL_END,
	NBL_FLOW_ECN_COUNT,
};

struct nbl_flow_ht_key {
	u16 vid;
	u16 ht_other_index;
	u32 kt_index;
};

struct nbl_flow_ht_tbl {
	struct nbl_flow_ht_key key[4];
	u32 ref_cnt;
};

struct nbl_flow_ht_mng {
	struct nbl_flow_ht_tbl *hash_map[NBL_FEM_HT_PP0_LEN];
};

struct nbl_flow_fem_entry {
	s32 type;
	u32 kt_idx;
	u16 sec_idx;
	u16 flow_id;
	u16 ht0_hash;
	u16 ht1_hash;
	u16 hash_table;
	u16 ht_index;
	u16 hash_bucket;
	u16 tcam_index;
	u8 tcam_flag;
	u8 flow_type;
	u8 tcam_table;
	u8 kt_type;
	u8 key[40];
};

struct nbl_flow_mcc_node {
	struct list_head node;
	u16 data;
	u16 mcc_id;
	u16 mcc_action;
	bool mcc_head;
	u8 type;
};

/* draco flow */
enum {
	NBL_PHY_FLOW_MACVLAN,
	NBL_PHY_FLOW_DIPSEC,
	NBL_PHY_FLOW_UTLS,
	NBL_PHY_FLOW_ACCEL_MAX,
};

struct nbl_flow_mcc_group {
	struct list_head group_node;
	/* list_head for mcc_node_list */
	struct list_head mcc_node;
	struct list_head mcc_head;
	unsigned long *vsi_bitmap;
	u32 nbits;
	u32 vsi_base;
	u32 vsi_num;
	u32 ref_cnt;
	u16 up_mcc_id;
	u16 down_mcc_id;
	u16 mcc_id;
	bool multi;
};

struct nbl_flow_switch_res {
	void *mac_hash_tbl;
	unsigned long *vf_bitmap;
	unsigned long *mcc_id_bitmap;
	struct list_head allmulti_head;
	struct list_head allmulti_list;
	struct list_head mcc_group_head;
	struct nbl_flow_fem_entry allmulti_up[2];
	struct nbl_flow_fem_entry allmulti_down[2];
	unsigned long *allmulti_vsi_bitmap;
	u16 num_vsi_allmulti_active;
	u16 vld;
	u16 network_status;
	u16 pfc_mode;
	u16 bp_mode;
	u16 allmulti_first_mcc;
	u16 num_vfs;
	u16 active_vfs;
	u16 allmulti_mcc_id;
	u8 ether_id;
};

struct nbl_flow_lacp_rule {
	struct nbl_flow_fem_entry entry;
	struct list_head node;
	u16 vsi;
};

struct nbl_flow_lldp_rule {
	struct nbl_flow_fem_entry entry;
	struct list_head node;
	u16 vsi;
};

struct nbl_flow_ecn_rule {
	struct nbl_flow_fem_entry entry;
	struct list_head node;
	u16 eth;
};

struct nbl_flow_ul4s_rule {
	struct nbl_flow_fem_entry ul4s_entry;
	struct list_head node;
	u16 vsi;
	u32 index;
};

struct nbl_flow_dipsec_rule {
	struct nbl_flow_fem_entry dipsec_entry;
	struct list_head node;
	u16 vsi;
	u32 index;
};

#define NBL_FLOW_PMD_ND_UPCALL_NA (0)
#define NBL_FLOW_PMD_ND_UPCALL_NS (1)
#define NBL_FLOW_PMD_ND_UPCALL_FLOW_NUM (2)

struct nbl_flow_nd_upcall_rule {
	struct nbl_flow_fem_entry entry[NBL_FLOW_PMD_ND_UPCALL_FLOW_NUM];
	struct list_head node;
};

struct nbl_event_mirror_outputport_data {
	u16 func_id;
	bool opcode; /* true: add; false: del */
};

struct nbl_flow_mgt {
	unsigned long *flow_id_bitmap;
	unsigned long *mcc_id_bitmap;
	DECLARE_BITMAP(tcam_id, NBL_TCAM_TABLE_LEN);
	u32 pp_tcam_count;
	u32 unicast_mac_threshold;
	u32 accel_flow_count;
	u32 start_flow_idx;
	struct nbl_flow_ht_mng pp0_ht0_mng;
	struct nbl_flow_ht_mng pp0_ht1_mng;
	struct nbl_flow_switch_res switch_res[NBL_MAX_ETHERNET];
	void *mac_hash_tbl[NBL_MAX_ETHERNET];
	struct list_head lldp_list;
	struct list_head ecn_list;
	struct list_head lacp_list;
	struct list_head ul4s_head;
	struct list_head dprbac_head;
	void *mcc_tbl_priv;
	struct list_head nd_upcall_list;	// note: works only for offload network
	u32 flow_id_cnt;
	u16 vsi_max_per_switch;
#define NBL_MIRROR_OUTPUTPORT_MAX_FUNC			8
	u16 mirror_outputport_func[NBL_MIRROR_OUTPUTPORT_MAX_FUNC];
#define NBL_FLOW_OFFLOAD				1
#define NBL_FLOW_NON_OFFLOAD				0
	bool offload_status;
	u32 max_flow_idx;
};

#define NBL_FLOW_INIT_BIT				BIT(1)
#define NBL_FLOW_AVAILABLE_BIT				BIT(2)
#define NBL_ALL_PROFILE_NUM				(64)
#define NBL_ASSOC_PROFILE_GRAPH_NUM			(32)
#define NBL_ASSOC_PROFILE_NUM				(16)
#define NBL_FLOW_ASSOC_PROFILE_GRAPH_NUM		(32)
#define NBL_PROFILE_KEY_MAX_NUM				(32)
#define NBL_FLOW_KEY_NAME_SIZE				(32)
#define NBL_FLOW_INDEX_LEN				131072
#define NBL_FLOW_TABLE_NUM				(64 * 1024)
#define NBL_FEM_TCAM_MAX_NUM				(64)
#define NBL_AT_MAX_NUM					8
#define NBL_MAX_ACTION_NUM				16
#define NBL_ACT_BYTE_LEN				32

enum nbl_flow_key_type {
	NBL_FLOW_KEY_TYPE_PID,		// profile id
	NBL_FLOW_KEY_TYPE_ACTION,	// AT action data, in 22 bits
	NBL_FLOW_KEY_TYPE_PHV,		// keys: PHV fields, inport, tab_index
					// and other extracted 16 bits actions
	NBL_FLOW_KEY_TYPE_MASK,		// mask 4 bits
	NBL_FLOW_KEY_TYPE_BTS		// bit setter
};

	#define NBL_PP0_KT_NUM					(0)
	#define NBL_PP1_KT_NUM					(24 * 1024)
	#define NBL_PP2_KT_NUM					(96 * 1024)
	#define NBL_PP0_KT_OFFSET				(120 * 1024)
	#define NBL_PP1_KT_OFFSET				(96 * 1024)

	#define NBL_FEM_HT_PP0_LEN				(2 * 1024)
	#define NBL_FEM_HT_PP1_LEN				(6 * 1024)
	#define NBL_FEM_HT_PP2_LEN				(16 * 1024)
	#define NBL_FEM_HT_PP0_DEPTH				(2 * 1024)
	#define NBL_FEM_HT_PP1_DEPTH				(6 * 1024)
	#define NBL_FEM_HT_PP2_DEPTH				(0)  /* 16K, treat as zero */
	#define NBL_FEM_AT_PP1_LEN				(12 * 1024)
	#define NBL_FEM_AT2_PP1_LEN				(4  * 1024)
	#define NBL_FEM_AT_PP2_LEN				(64 * 1024)
	#define NBL_FEM_AT2_PP2_LEN				(16 * 1024)

#define NBL_TC_MCC_TBL_DEPTH					(4096)
#define NBL_TC_ENCAP_TBL_DEPTH					(4 * 1024)

struct nbl_flow_key_info {
	bool valid;
	enum nbl_flow_key_type key_type;
	u16 offset;
	u16 length;
	u8 key_id;
	char name[NBL_FLOW_KEY_NAME_SIZE];
};

struct nbl_profile_msg {
	bool valid;
	// pp loopback or not
	bool pp_mode;
	bool key_full;
	bool pt_cmd;
	bool from_start;
	bool to_end;
	bool need_upcall;

	// id in range of 0 to 2
	u8 pp_id;

	// id in range of 0 to 15
	u8 profile_id;

	// id in range of 0 to 47
	u8 g_profile_id;

	/* for draco */
	u8 lkp_id;

	// count of valid profile keys in the flow_keys list
	u8 key_count;
	u16 key_len;
	u64 key_flag;
	u8 act_count;
	u8 pre_assoc_profile_id[NBL_ASSOC_PROFILE_NUM];
	u8 next_assoc_profile_id[NBL_ASSOC_PROFILE_NUM];
	// store all profile key info
	struct nbl_flow_key_info flow_keys[NBL_PROFILE_KEY_MAX_NUM];
};

struct nbl_flow_tab_hash_info {
	void *flow_tab_hash;
	s32 tab_cnt;
};

struct nbl_profile_assoc_graph {
	u64 key_flag;
	u8 profile_count;
	u8 profile_id[NBL_ASSOC_PROFILE_STAGE_NUM];
};

/* pp ht hash-list struct  */
struct nbl_flow_pp_ht_key {
	u16 vid;
	u16 ht_other_index;
	u32 kt_index;
};

struct nbl_flow_pp_ht_tbl {
	struct nbl_flow_pp_ht_key	key[4];
	u32 ref_cnt;
};

struct nbl_flow_pp_ht_mng {
	struct nbl_flow_pp_ht_tbl	**hash_map;
};

/* at hash-list struct  */
struct nbl_flow_pp_at_key {
	union {
		u32 act[NBL_AT_MAX_NUM];
		u8 act_data[NBL_ACT_BYTE_LEN];
	};
};

struct nbl_flow_at_tbl {
	u32 ref_cnt;
};

struct nbl_flow_at_mng {
	void *at_tbl[NBL_PP_TYPE_MAX][NBL_AT_TYPE_MAX];
};

struct nbl_tc_ht_item {
	u16 ht_entry;
	u16 ht0_hash;
	u16 ht1_hash;
	u16 hash_bucket;
	u32 tbl_id;
};

union nbl_tc_common_data_u {
	struct nbl_tc_common_data {
		u32 rsv[10];
	} __packed info;
#define NBL_TC_COMMON_DATA_TAB_WIDTH (sizeof(struct nbl_tc_common_data) \
		/ sizeof(u32))
	u32 data[NBL_TC_COMMON_DATA_TAB_WIDTH];
	u8 hash_key[sizeof(struct nbl_tc_common_data)];
};

struct nbl_tc_kt_item {
	union nbl_tc_common_data_u kt_data;
	u8 pp_type;
	u8 key_type;
};

struct nbl_act_collect {
	u32 act_vld;
	u32 act2_vld;
	u32 act_offset;
	u32 act2_offset;
	u32 act_hw_index;
	u32 act2_hw_index;
	struct nbl_flow_pp_at_key act_key[2];
};

struct nbl_tc_at_item {
	u32 act_buf[NBL_AT_MAX_NUM];
	u32 act_num;
	u32 act1_buf[NBL_AT_MAX_NUM];
	u32 act1_num;
	u32 act2_buf[NBL_AT_MAX_NUM];
	u32 act2_num;
	struct nbl_act_collect act_collect;
};

struct nbl_flow_tcam_key_item {
	u8 key[NBL_KT_BYTE_HALF_LEN];
	u8 key_mode;
	struct nbl_tc_ht_item ht_item;
	struct nbl_tc_kt_item kt_item;
	struct nbl_tc_at_item at_item;
	u32 sw_hash_id;
	u8 profile_id;
};

struct nbl_flow_tcam_key_mng {
	struct nbl_flow_tcam_key_item item;
	u32 ref_cnt;
};

struct nbl_flow_tcam_ad_item {
	u32 action[NBL_MAX_ACTION_NUM];
};

struct nbl_flow_tcam_ad_mng {
	struct nbl_flow_tcam_ad_item item;
};

struct nbl_count_mng {
	u32 pp1_tcam_count;
	u32 pp2_tcam_count;
};

/* --------- tc flow stats ---------- */
struct nbl_flow_counter_cache {
	u64 packets;
	u64 bytes;
};

#define INVALID_CAR_ID	(0xffff)

struct nbl_flow_counter {
	struct list_head entries;
	u64 lastpackets;
	u64 lastbytes;
	u64 lastuse;
	struct nbl_flow_counter_cache cache;
	unsigned long cookie;
	u32 counter_id;
	u16 bind_car_id;
};

struct nbl_flow_update_counter {
	u32 counter_id;
	unsigned long cookie;
};

struct nbl_flow_query_counter {
	u32 counter_id[NBL_FLOW_COUNT_NUM];
	unsigned long cookie[NBL_FLOW_COUNT_NUM];
};

struct nbl_fc_mgt;
struct nbl_fc_product_ops {
	void (*get_spec_stat_sz)(u16 *hit_sz, u16 *bytes_sz);
	void (*get_flow_stat_sz)(struct nbl_fc_mgt *mgt, u16 *hit_sz, u16 *bytes_sz);
	void (*get_spec_stats)(struct nbl_flow_counter *counter, u64 *pkts, u64 *bytes);
	void (*get_flow_stats)(struct nbl_fc_mgt *mgt, struct nbl_flow_counter *counter,
			       u64 *pkts, u64 *bytes);
	int (*update_stats)(struct nbl_fc_mgt *mgt, struct nbl_flow_query_counter *counter_array,
			    u32 flow_num, u32 clear, bool is_spec_id);
	int (*init_resp_data)(struct nbl_fc_mgt *mgt);
	void (*free_resp_data)(struct nbl_fc_mgt *mgt);
};

struct nbl_fc_mgt {
	spinlock_t counter_lock; /* protect the counter */
	void *cls_cookie_tbl[NBL_FC_TYPE_MAX];
	struct workqueue_struct *counter_wq;
	struct nbl_common_info *common;
	struct nbl_resource_mgt *res_mgt;
	struct delayed_work counter_work;
	struct list_head counter_hash_list;
	struct list_head spec_counter_hash_list;
	/* for draco update stats */
	spinlock_t resp_lock;
	struct nbl_flow_update_counter *counter_update_list;
	struct nbl_draco_flow_stat_width_72_cmd_resp *flow_resp_72;
	struct nbl_draco_flow_stat_width_144_cmd_resp *flow_resp_144;
	struct nbl_draco_spec_stat_cmd_resp *spec_resp;
	struct nbl_cmd_hdr cmd_hdr[NBL_CMDQ_MAX_OP_CODE];
	unsigned long query_interval;
	unsigned long next_query;
	struct nbl_fc_product_ops fc_ops;
	enum nbl_product_type type;

	//only for draco
	bool select_flow_stat_width72;
};

struct nbl_tc_mcc_mgt {
	DECLARE_BITMAP(mcc_pool, NBL_TC_MCC_TBL_DEPTH);
	struct nbl_common_info *common;
	struct list_head mcc_list;
	u16 mcc_offload_cnt;
};

struct nbl_tc_pedit_res_info {
#define NBL_TC_MAX_PED_IDX 2048
	/* common pedit resource */
	DECLARE_BITMAP(pedit_pool, NBL_TC_MAX_PED_IDX);
	void *pedit_tbl;
	u32 pedit_num:16;
	u32 pedit_cnt:16;
	u32 pedit_key_len;
	u32 pedit_data_len;

	/* special use for leonis-ipv6, ipv6 need 2 addrs */
	DECLARE_BITMAP(pedit_pool_h, NBL_TC_MAX_PED_H_IDX);
	void *pedit_tbl_h;
	/* normal could store in _h */
	u32 pedit_num_h:16;
	u32 pedit_cnt_h:16;

	u32 pedit_base_id;
};

struct nbl_tc_pedit_mgt {
	struct nbl_tc_pedit_res_info pedit_res[NBL_FLOW_PED_RES_MAX];
	struct nbl_common_info *common;
	struct mutex pedit_lock;	/* protect the pedit */
};

struct nbl_tc_flow_mgt {
	struct mutex flow_lock;  /* used to lock flow resource */
	struct nbl_flow_prf_upcall_info prf_info;
	u8 profile_graph_count;
	struct nbl_profile_msg profile_msg[NBL_ALL_PROFILE_NUM];
	struct nbl_profile_assoc_graph profile_graph[NBL_ASSOC_PROFILE_GRAPH_NUM];
	void *flow_idx_tbl;

	struct nbl_flow_tab_hash_info flow_tab_hash[NBL_ALL_PROFILE_NUM];

	DECLARE_BITMAP(assoc_table_bmp, NBL_FLOW_TABLE_NUM);
	DECLARE_BITMAP(pp1_kt_bmp, NBL_PP1_KT_NUM);
	DECLARE_BITMAP(pp2_kt_bmp, NBL_PP2_KT_NUM);

	u8 init_status;
	atomic64_t destroy_num;
	atomic64_t create_num;
	atomic64_t ref_cnt;

	struct nbl_flow_pp_ht_mng pp0_ht0_mng;
	struct nbl_flow_pp_ht_mng pp0_ht1_mng;
	struct nbl_flow_pp_ht_mng pp1_ht0_mng;
	struct nbl_flow_pp_ht_mng pp1_ht1_mng;
	struct nbl_flow_pp_ht_mng pp2_ht0_mng;
	struct nbl_flow_pp_ht_mng pp2_ht1_mng;
	struct nbl_flow_at_mng at_mng;

	struct nbl_flow_tcam_key_mng tcam_pp0_key_mng[NBL_FEM_TCAM_MAX_NUM];
	struct nbl_flow_tcam_ad_mng tcam_pp0_ad_mng[NBL_FEM_TCAM_MAX_NUM];
	struct nbl_flow_tcam_key_mng tcam_pp1_key_mng[NBL_FEM_TCAM_MAX_NUM];
	struct nbl_flow_tcam_ad_mng tcam_pp1_ad_mng[NBL_FEM_TCAM_MAX_NUM];
	struct nbl_flow_tcam_key_mng tcam_pp2_key_mng[NBL_FEM_TCAM_MAX_NUM];
	struct nbl_flow_tcam_ad_mng tcam_pp2_ad_mng[NBL_FEM_TCAM_MAX_NUM];

	struct nbl_count_mng count_mng;
	struct nbl_fc_mgt *fc_mgt;
	struct nbl_resource_mgt *res_mgt;
	u8 pf_set_tc_count;
	struct nbl_tc_mcc_mgt tc_mcc_mgt;
	u16 port_tpid_type[NBL_TPID_PORT_NUM];

	/* encap and decap info */
	struct mutex encap_tbl_lock; /* used to lock encap resource */
	struct nbl_flow_tab_hash_info encap_tbl;
	DECLARE_BITMAP(encap_tbl_bmp, NBL_TC_ENCAP_TBL_DEPTH);

	/* pedit info */
	struct nbl_tc_pedit_mgt pedit_mgt;

	/* special process some key and mask */
	struct nbl_tc_parse_info *parse_info;

	/* product private resource */
	void *priv_flow_mgt;
};

/* --------- ACCEL ---------- */
#define NBL_MAX_KTLS_SESSION			(1024)
#define NBL_MAX_IPSEC_SESSION			(2048)
#define NBL_MAX_IPSEC_TCAM			(32)
#define NBL_IPSEC_HT_LEN			(1 * 512)
#define NBL_MAX_MACSEC_SC			(8)
#define NBL_MAX_MACSEC_SA			(32)
#define NBL_IPSEC_IDX_BLK_LEN			(16)

struct nbl_ipsec_ht_mng {
	struct nbl_flow_ht_tbl *hash_map[NBL_IPSEC_HT_LEN];
};

struct nbl_accel_uipsec_rule {
	struct nbl_flow_fem_entry uipsec_entry;
	struct list_head node;
	u16 vsi;
	u32 index;
};

struct nbl_tls_cfg_info {
	u16 vld;
	u16 vsi;
};

struct nbl_ipsec_idx_blk {
	DECLARE_BITMAP(blk_bitmap, NBL_IPSEC_IDX_BLK_LEN);
	u16 start_index;
};

struct nbl_accel_mgt {
	DECLARE_BITMAP(tx_ktls_bitmap, NBL_MAX_KTLS_SESSION);
	DECLARE_BITMAP(rx_ktls_bitmap, NBL_MAX_KTLS_SESSION);
	struct nbl_tls_cfg_info dtls_cfg_info[NBL_MAX_KTLS_SESSION];
	struct nbl_tls_cfg_info utls_cfg_info[NBL_MAX_KTLS_SESSION];

	DECLARE_BITMAP(tx_ipsec_bitmap, NBL_MAX_IPSEC_SESSION);
	DECLARE_BITMAP(rx_ipsec_bitmap, NBL_MAX_IPSEC_SESSION);
	struct nbl_ipsec_cfg_info tx_cfg_info[NBL_MAX_IPSEC_SESSION];
	struct nbl_ipsec_cfg_info rx_cfg_info[NBL_MAX_IPSEC_SESSION];
	u16 start_ipsec_idx[64];
	u16 available_ipsec_idx[64];

	DECLARE_BITMAP(ipsec_tcam_id, NBL_MAX_IPSEC_TCAM);
	struct nbl_ipsec_ht_mng ipsec_ht0_mng;
	struct nbl_ipsec_ht_mng ipsec_ht1_mng;
	struct list_head uprbac_head;

	DECLARE_BITMAP(tx_macsec_sc_bitmap, NBL_MAX_MACSEC_SC);
	DECLARE_BITMAP(rx_macsec_sc_bitmap, NBL_MAX_MACSEC_SC);
	DECLARE_BITMAP(tx_macsec_sa_bitmap, NBL_MAX_MACSEC_SA);
	DECLARE_BITMAP(rx_macsec_sa_bitmap, NBL_MAX_MACSEC_SA);
};

/* --------- INFO ---------- */
#define NBL_MAX_PF					8
#define NBL_RES_RDMA_MAX				(63)
#define NBL_RES_RDMA_INTR_NUM				(3)
#define NBL_MAX_VF					(NBL_MAX_FUNC - NBL_MAX_PF)
#define NBL_RES_RDMA_MAX_DRACO				(64)

#define FIRMWARE_MAGIC_LEONIS		"M181FWV0"
#define FIRMWARE_MAGIC_DRACO		"M183FWV0"

struct nbl_sriov_info {
	unsigned int bdf;
	unsigned int num_vfs;
	unsigned int start_vf_func_id;
	unsigned short offset;
	unsigned short stride;
	unsigned short active_vf_num;
	u64 vf_bar_start;
	u64 vf_bar_len;
	u64 pf_bar_start;
};

struct nbl_eswitch_info {
	struct nbl_rep_data *rep_data;
	int num_vfs;
	u16 mode;
	u16 vf_base_vsi_id;
};

struct nbl_eth_info {
	DECLARE_BITMAP(eth_bitmap, NBL_MAX_ETHERNET);
	u64 port_caps[NBL_MAX_ETHERNET];
	u64 port_advertising[NBL_MAX_ETHERNET];
	u64 port_lp_advertising[NBL_MAX_ETHERNET];
	u32 link_speed[NBL_MAX_ETHERNET];  /* in Mbps units */
	u8 active_fc[NBL_MAX_ETHERNET];
	u8 active_fec[NBL_MAX_ETHERNET];
	u8 link_state[NBL_MAX_ETHERNET];
	u8 module_inplace[NBL_MAX_ETHERNET];
	u8 port_type[NBL_MAX_ETHERNET]; /* enum nbl_port_type */
	u8 port_max_rate[NBL_MAX_ETHERNET]; /* enum nbl_port_max_rate */
	u8 module_repluged[NBL_MAX_ETHERNET];

	u8 pf_bitmap[NBL_MAX_ETHERNET];
	u8 eth_num;
	u8 resv[3];
	u8 eth_id[NBL_MAX_PF];
	u8 logic_eth_id[NBL_MAX_PF];
	u64 link_down_count[NBL_MAX_ETHERNET];
	struct mutex eth_lock; /* To lock emp resource */
};

enum nbl_table_range_addr_type {
	NBL_ADDR_MSIX,
	NBL_ADDR_QUEUE,
	NBL_ADDR_RSV,
	NBL_ADDR_MAX
};

enum nbl_vsi_serv_type {
	NBL_VSI_SERV_PF_DATA_TYPE,
	NBL_VSI_SERV_PF_CTLR_TYPE,
	NBL_VSI_SERV_PF_USER_TYPE,
	NBL_VSI_SERV_PF_XDP_TYPE,
	NBL_VSI_SERV_VF_DATA_TYPE,
	/* use for pf_num > eth_num, the extra pf belong pf0's switch */
	NBL_VSI_SERV_PF_EXTRA_TYPE,
	NBL_VSI_SERV_MAX_TYPE,
};

struct nbl_vsi_serv_info {
	u16 base_id;
	u16 num;
};

struct nbl_vsi_mac_info {
	u16 vlan_proto;
	u16 vlan_tci;
	int rate;
	u8 mac[ETH_ALEN];
	bool trusted;
};

struct nbl_vsi_info {
	u16 num;
	struct nbl_vsi_serv_info serv_info[NBL_MAX_ETHERNET][NBL_VSI_SERV_MAX_TYPE];
	struct nbl_vsi_mac_info mac_info[NBL_MAX_FUNC];
};

#define NBL_RDMA_BOND_KEY_MAGIC			0x1000

struct nbl_rdma_id_info {
	u16 id;
	u16 grc_id;
	bool id_vaild;
	bool grc_id_vaild;
	u8 resv;
};

struct nbl_rdma_info {
	DECLARE_BITMAP(func_cap, NBL_MAX_FUNC);
	struct nbl_rdma_id_info rdma_id_info[NBL_MAX_FUNC];
	struct ida *adev_ida;
	struct ida *grc_adev_ida;
	struct mutex *lock; /* avoid idx change when multi ctrl dev concurrent op */
	u32 mem_type;
	u16 pf_msix_num;
	u16 vf_msix_num;
	u16 rdma_max_func_num;
};

#define NBL_ETH_BOND_VALID_PORT(x)		((x) < NBL_LAG_MAX_PORTS)
struct nbl_eth_bond_entry {
	u8 eth_id[NBL_LAG_MAX_PORTS];
	u16 vsi_id[NBL_LAG_MAX_PORTS];
	u16 lag_id;
	u16 lag_num;
};

struct nbl_eth_bond_info {
	struct nbl_eth_bond_entry entry[NBL_LAG_MAX_NUM];
};

struct nbl_net_ring_num_info {
	u16 pf_def_max_net_qp_num;
	u16 vf_def_max_net_qp_num;
	u16 net_max_qp_num[NBL_MAX_FUNC];
};

struct nbl_pfc_info {
	/* 0: 802.1p, 1: dscp */
	u16 pfc_mode;
	/* 0: port, 1: pfc */
	u16 bp_mode;
};

struct nbl_rdma_cap_info {
	u32 valid;
	u8 rdma_func_bitmaps[65];
	u8 rsv[7];
};

struct nbl_rdma_mem_type_info {
	u32 mem_type;
};

struct nbl_internal_cfg_info {
	u32 cfg;
};

/* Host Board Configuration */
/* 256 Byte */
struct nbl_host_board_config {
	/* dw0/1 */
	u8 version;
	char magic[7];

	/* dw2 */
	u8 board_id;
	u8 def_tlv_index;
	u8 spi_flash_type;
	u8 dw2_rsv_zero;		// 0x00

	/* dw3 -bits */
	u32 port_type: 1;		// 0: optical, 1: electrical
	u32 port_number: 7;
	u32 port_speed: 2;
	u32 port_module_type: 3;	// 0: SFP, 1: QSFP, 2: PHY
	u32 upper_config: 1;	// 0: lower, 1: upper
	u32 dw3_bits_rsv1: 1;
	u32 i2c_mdio: 1;		// 0: i2c, 1: mdio
	u32 mdio_pin: 1;		// 0: N to N, 1: 1 to N
	u32 pam4_supported: 1;	// 0: no, 1: yes
	u32 dual_bc_supported: 1;	// 0: no, 1: yes
	u32 bc_index: 1;
	u32 disable_crypto: 1;	// 0: no, 1: yes
	u32 ocp_card: 1;		// 0: no, 1: yes
	u32 oem: 1;		// 0: no, 1: yes
	u32 dw3_bits_rsv2: 9;	// 0

	/* dw4 - bits */
	u32 dw4_bits_rsv;		// 0

	/* dw5 */
	u8 pcie_pf_mask;		// bitmap
	u8 pcie_vpd_mask;		// bitmap
	u8 pcie_lanes;		// valid value: 1/2/4/8/16
	u8 pcie_speed;		// valid value: 1/2/3/4

	/* dw6 */
	u8 eth_lane_mask;		// bitmap
	u8 eth_mac_mask;		// bitmap
	u8 phy_type;
	u8 board_version;

	/* dw7 */
	u8 ncsi_package_id;
	u8 fru_eeprom_i2c_addr;
	u8 ext_gpio_i2c_addr0;
	u8 ext_gpio_i2c_addr1;

	/* dw8 */
	u8 phy_mdio_addr[4];

	/* dw9~12 */
	u16 pcie_vendor_id;	// 0x1F0F
	u16 pcie_device_id;
	u32 pcie_class_rev;	// 0x02000000
	u16 pcie_sub_vendor_id;	// 0x1F0F
	u16 pcie_sub_device_id;	// 0x0001
	u16 pcie_vf_device_id;	// 0x340D
	u16 pcie_vf_sub_device_id;	// 0x0001

	/* dw13 */
	u16 pf_max_vfs;
	u16 device_max_qps;	// 2048

	/* dw14 */
	u16 smbus_addr0;
	u16 smbus_addr1;

	/* dw15 */
	u32 temp_i2c_addr: 8;	// onboard temperature sensor
	u32 temp_type: 5;
	u32 temp_port_index: 3;
	u32 voltage_i2c_addr: 8;	// onboard voltage sensor
	u32 voltage_type: 5;
	u32 voltage_port_index: 3;

	/* dw16~44 */
	u64 port_capability[2];	// dw16~19
	u8 port_gpio[4][16];	// dw20~35
	u8 misc_gpio[16];		// dw36~39

	/* dw40~49 */
	char controller_part_no[8];	// dw40/41
	char board_pn[12];		// dw42~44
	char product_name[20];		// dw45~49

	/* dw50~59 */
	u32 reserved_zero0;	// 0x00
	u32 reserved_zero1;
	u32 reserved_zero2;
	u32 reserved_zero3;
	u32 reserved_zero4;
	u32 reserved_zero5;
	u32 reserved_zero6;
	u32 reserved_zero7;
	u32 reserved_zero8;
	u32 reserved_zero9;

	/* dw60~63 */
	u32 reserved_one0;		// 0xFF
	u32 reserved_one1;
	u32 reserved_one2;
	u32 reserved_one3;
};

struct nbl_serial_number_info {
	u8 len;
	char sn[128];
};

struct nbl_vdpa_status {
	struct nbl_vf_stats init_stats;
	struct nbl_vf_stats prev_stats;
	unsigned long timestamp;
	u16 itr_level;
};

struct nbl_vdpa_info {
	DECLARE_BITMAP(vdpa_func_bitmap, NBL_MAX_FUNC);
	struct nbl_vdpa_status *vf_stats[NBL_MAX_FUNC];
	u32 start;
};

struct nbl_qinfo_cfg_table {
	dma_addr_t dma_addr;
	u32 size_bwind;
};

struct nbl_resource_info {
	/* ctrl-dev owned pfs */
	DECLARE_BITMAP(owned_pf_bitmap, NBL_MAX_PF);
	DECLARE_BITMAP(func_bitmap, NBL_MAX_FUNC);
	struct nbl_vdpa_info vdpa;
	struct nbl_sriov_info *sriov_info;
	struct nbl_eswitch_info *eswitch_info;
	struct nbl_eth_info *eth_info;
	struct nbl_qinfo_cfg_table *qinfo;
	struct nbl_vsi_info *vsi_info;
	struct nbl_pfc_info pfc_info;
	struct nbl_eth_bond_info *eth_bond_info;
	u32 base_qid;
	u32 max_vf_num;
	u32 max_vf_bypf_num;

	struct nbl_rdma_info rdma_info;
	struct nbl_net_ring_num_info net_ring_num_info;

	/* for af use */
	int p4_used;
	u16 eth_mode;
	u16 init_acl_refcnt;
	u8 max_pf;
	u16 nd_upcall_refnt;
	u16 bdf;
	struct nbl_board_port_info board_info;
	/* store all pf names for vf/rep device name use */
	char pf_name_list[NBL_MAX_PF][IFNAMSIZ];

	u8 link_forced_info[NBL_MAX_FUNC];
	struct nbl_mtu_entry mtu_list[NBL_MAX_MTU];

	struct nbl_chan_param_drop_stats_resp *drop_stats;
	u64 fake_drop;
	u32 pre_fake_drop;
	u32 start_uvn_drop_queue_disable;
	u8 uvn_drop_queue_disable_init;
	u8 rsv[3];
	u32 internal_cfg;
};

enum {
	NBL_FD_MODE_DEFAULT = 0,/* Support src_mac & dst_mac, ipv4 + other in total 512 rules */
	NBL_FD_MODE_FULL,	/* Unsupport src_mac & dst_mac, ipv4 + other each 512 rules */
	NBL_FD_MODE_LITE,	/* Only support ipv4, 1536 rules */
	NBL_FD_MODE_MAX,
};

union nbl_fd_compo_info {
	u8 src_mac[ETH_ALEN];
	u8 dst_mac[ETH_ALEN];
	u16 ethertype;
	u32 src_ipv4;
	u32 dst_ipv4;
	u32 src_ipv6[NBL_IPV6_U32LEN];
	u32 dst_ipv6[NBL_IPV6_U32LEN];
	u8 ipproto;
	u16 l4_sport;
	u16 l4_dport;
	struct nbl_fd_compo_udf {
		u32 offset;
		u32 data;
	} udf;
};

struct nbl_flow_direct_entry {
	struct list_head node;
	u16 action_index;
	u16 depth_index;
	u16 slot_index;
	u8 pid;
	bool udf;
	bool slot_index_valid;
	struct nbl_chan_param_fdir_replace param;
};

struct nbl_flow_direct_info {
	struct list_head list[NBL_CHAN_FDIR_RULE_MAX];
	u16 state[NBL_CHAN_FDIR_RULE_MAX];
	u16 cnt[NBL_CHAN_FDIR_RULE_MAX];
};

struct nbl_fd_component_ops {
	int (*validate)(struct ethtool_rx_flow_spec *fs);
	int (*form)(struct nbl_flow_direct_entry *entry, struct ethtool_rx_flow_spec *fs);
	u16 layer;
};

struct nbl_extra_vsi_slot_info {
	u16 global_queue_id;
	u16 ref_cnt;
};

struct nbl_udf_cfg {
	u32 udf_cnt;
	u32 udf_offset;
	u16 udf_layer;
	u8 pf_id;
};

struct nbl_flow_direct_mgt {
	struct nbl_flow_direct_info info[NBL_MAX_PF];
#define NBL_EXTRA_VSI_SLOT_NUM			(32)
	struct nbl_extra_vsi_slot_info extra_vsi_slot_info[NBL_EXTRA_VSI_SLOT_NUM];
	struct nbl_devcomm_comp_dev *comp_dev;
	struct nbl_udf_cfg other_udf_cfg[NBL_MAX_PF];
	u32 max_spec;
	u32 udf_offset;
	u32 udf_cnt;
	u16 udf_layer;
	u16 cnt[NBL_FD_PROFILE_MAX];
	u16 start_depth_index;
	u16 extra_vsi_id;
	u8 mode;
	u8 state;
};

struct nbl_tx_resync_info {
	u64 rec_num;
	u32 resync_len;
	u32 nr_frags;
	skb_frag_t frags[MAX_SKB_FRAGS];
};

/* --------- PMD status ---------- */
struct nbl_upcall_port_info {
	u8 upcall_port_active:1;
	u8 has_upcall:1;
	u16 func_id;
};

struct nbl_rep_offload_status {
#define NBL_OFFLOAD_STATUS_MAX_VSI		(1024)
#define NBL_OFFLOAD_STATUS_MAX_ETH		(4)
	DECLARE_BITMAP(rep_vsi_bitmap, NBL_OFFLOAD_STATUS_MAX_VSI);
	DECLARE_BITMAP(rep_eth_bitmap, NBL_OFFLOAD_STATUS_MAX_ETH);
	bool status[NBL_MAX_ETHERNET];
	bool pmd_debug;
	unsigned long timestamp;
};

struct nbl_pmd_status {
	struct nbl_upcall_port_info upcall_port_info;
	struct nbl_rep_offload_status rep_status;
	struct nbl_devcomm_comp_dev *comp_dev;
	bool other_pmd_cfg[NBL_MAX_ETHERNET]; /* only for draco ovs-dpdk bond */
};

struct nbl_resource_common_ops {
	u16 (*vsi_id_to_func_id)(void *res_mgt, u16 vsi_id);
	int (*vsi_id_to_pf_id)(void *res_mgt, u16 vsi_id);
	u16 (*vsi_id_to_vf_id)(void *res_mgt, u16 vsi_id);
	u16 (*pfvfid_to_func_id)(void *res_mgt, int pfid, int vfid);
	u16 (*pfvfid_to_vsi_id)(void *res_mgt, int pfid, int vfid, u16 type);
	u16 (*func_id_to_vsi_id)(void *res_mgt, u16 func_id, u16 type);
	int (*func_id_to_pfvfid)(void *res_mgt, u16 func_id, int *pfid, int *vfid);
	int (*func_id_to_bdf)(void *res_mgt, u16 func_id, u8 *bus, u8 *dev, u8 *function);
	u64 (*get_func_bar_base_addr)(void *res_mgt, u16 func_id);
	u8 (*vsi_id_to_eth_id)(void *res_mgt, u16 vsi_id);
	u8 (*eth_id_to_pf_id)(void *res_mgt, u8 eth_id);
	u8 (*pf_id_to_eth_id)(void *res_mgt, u8 pf_id);
	u8 (*eth_id_to_lag_id)(void *res_mgt, u8 eth_id);
	u16 (*vfid_to_vsi_id)(void *p, u16 vf_id);
	bool (*check_func_active_by_queue)(void *res_mgt, u16 func_id);
	int (*get_queue_num)(void *res_mgt, u16 func_id, u16 *tx_queue_num, u16 *rx_queue_num);
};

struct nbl_res_product_ops {
	/* for queue */
	int (*queue_mgt_init)(struct nbl_resource_mgt *res_mgt);
	int (*flow_mgt_init)(struct nbl_resource_mgt *res_mgt);
	int (*setup_qid_map_table)(struct nbl_resource_mgt *res_mgt, u16 func_id, u64 notify_addr);
	void (*remove_qid_map_table)(struct nbl_resource_mgt *res_mgt, u16 func_id);
	int (*init_qid_map_table)(struct nbl_resource_mgt *res_mgt,
				  struct nbl_queue_mgt *queue_mgt, struct nbl_phy_ops *phy_ops);
	int (*init_epro_vpt_extra)(struct nbl_resource_mgt *res_mgt, u16 vsi_id);
	int (*get_rss_ret_base_and_size)(struct nbl_resource_mgt *res_mgt,
					 u16 vsi_id, u16 queue_num,
					 struct nbl_queue_vsi_info *vsi_info);
	void (*get_rxfh_indir)(void *priv, u16 vsi_id, u32 *indir);
	int (*get_hash_fields)(void *priv, u16 vsi_id, int flow_type, u64 *hash_fields);
	int (*set_hash_fields)(void *priv, u16 vsi_id, int flow_type, u64 hash_fields);

	/* for intr */
	void (*intr_mgt_init)(struct nbl_resource_mgt *res_mgt);

	/* for txrx */
	int (*txrx_mgt_init)(struct nbl_resource_mgt *res_mgt);
	u16 (*parse_rx_extend_header)(struct nbl_res_rx_ring *ring, void *hdr, struct sk_buff *skb);
	netdev_features_t (*features_check)(struct sk_buff *skb, struct net_device *dev,
					    netdev_features_t features);
	/* for flow director */
	int (*config_key)(struct nbl_resource_mgt *res_mgt, struct nbl_flow_direct_entry *entry,
			  struct nbl_acl_tcam_param *data, struct nbl_acl_tcam_param *mask,
			  u32 *action, u16 vsi_id);
	int (*handle_queue_update)(u16 type, void *event_data, void *callback_data);

	/* for ktls */
	void (*fill_ktls_init_payload)(void *init_payload,
				       struct nbl_ktls_offload_context_tx *priv_tx);
	bool (*ktls_send_resync_packet)(struct nbl_resource_mgt *res_mgt,
					struct nbl_res_tx_ring *tx_ring,
					struct nbl_ktls_offload_context_tx *priv_tx,
					struct nbl_tx_resync_info *info);
	void (*adminq_mgt_init)(struct nbl_resource_mgt *res_mgt);
	void (*port_mgt_init)(struct nbl_resource_mgt *res_mgt);
	u16 *tx_exthdr_offset;
};

struct nbl_resource_mgt {
	struct nbl_resource_common_ops common_ops;
	struct nbl_common_info *common;
	struct nbl_resource_info *resource_info;
	struct nbl_channel_ops_tbl *chan_ops_tbl;
	struct nbl_phy_ops_tbl *phy_ops_tbl;
	struct nbl_queue_mgt *queue_mgt;
	struct nbl_interrupt_mgt *intr_mgt;
	struct nbl_txrx_mgt *txrx_mgt;
	struct nbl_flow_mgt *flow_mgt;
	struct nbl_tc_flow_mgt *tc_flow_mgt;
	struct nbl_vsi_mgt *vsi_mgt;
	struct nbl_adminq_mgt *adminq_mgt;
	struct nbl_accel_mgt *accel_mgt;
	struct nbl_port_mgt *port_mgt;
	struct nbl_flow_direct_mgt *fd_mgt;
	struct nbl_res_product_ops *product_ops;
	DECLARE_BITMAP(flex_capability, NBL_FLEX_CAP_NBITS);
	DECLARE_BITMAP(fix_capability, NBL_FIX_CAP_NBITS);
	struct nbl_pmd_status pmd_status;
};

#define NBL_RES_FW_CMD_FILTER_MAX		8
struct nbl_res_fw_cmd_filter {
	int (*in)(struct nbl_resource_mgt *res_mgt, void *in, u16 in_len);
	int (*out)(struct nbl_resource_mgt *res_mgt, void *in, u16 in_len, void *out, u16 out_len);
};

u16 nbl_res_vsi_id_to_func_id(struct nbl_resource_mgt *res_mgt, u16 vsi_id);
int nbl_res_vsi_id_to_pf_id(struct nbl_resource_mgt *res_mgt, u16 vsi_id);
u16 nbl_res_pfvfid_to_func_id(struct nbl_resource_mgt *res_mgt, int pfid, int vfid);
u16 nbl_res_pfvfid_to_vsi_id(struct nbl_resource_mgt *res_mgt, int pfid, int vfid, u16 type);
u16 nbl_res_func_id_to_vsi_id(struct nbl_resource_mgt *res_mgt, u16 func_id, u16 type);
int nbl_res_func_id_to_pfvfid(struct nbl_resource_mgt *res_mgt, u16 func_id, int *pfid, int *vfid);
u8 nbl_res_eth_id_to_pf_id(struct nbl_resource_mgt *res_mgt, u8 eth_id);
u8 nbl_res_pf_id_to_eth_id(struct nbl_resource_mgt *res_mgt, u16 pf_id);
u8 nbl_res_eth_id_to_lag_id(struct nbl_resource_mgt *res_mgt, u8 eth_id);
int nbl_res_func_id_to_bdf(struct nbl_resource_mgt *res_mgt, u16 func_id, u8 *bus,
			   u8 *dev, u8 *function);
u64 nbl_res_get_func_bar_base_addr(struct nbl_resource_mgt *res_mgt, u16 func_id);
u8 nbl_res_vsi_id_to_eth_id(struct nbl_resource_mgt *res_mgt, u16 vsi_id);
u16 nbl_res_vfid_to_vsi_id(struct nbl_resource_mgt *res_mgt, u16 vf_id);
void nbl_res_dump_func_info(void *priv, struct seq_file *m);
bool nbl_res_check_func_active_by_queue(struct nbl_resource_mgt *res_mgt, u16 func_id);

int nbl_adminq_mgt_start(struct nbl_resource_mgt *res_mgt, char *firmware_magic, bool is_ctrl);
void nbl_adminq_mgt_stop(struct nbl_resource_mgt *res_mgt);
int nbl_adminq_setup_ops(struct nbl_resource_ops *resource_ops);

int nbl_intr_mgt_start(struct nbl_resource_mgt *res_mgt);
void nbl_intr_mgt_stop(struct nbl_resource_mgt *res_mgt);
int nbl_intr_setup_ops(struct nbl_resource_ops *resource_ops);
void nbl_intr_remove_ops(struct nbl_resource_ops *resource_ops);

int nbl_queue_mgt_start(struct nbl_resource_mgt *res_mgt);
void nbl_queue_mgt_stop(struct nbl_resource_mgt *res_mgt);
struct nbl_queue_vsi_info *nbl_res_queue_get_vsi_info(struct nbl_resource_mgt *res_mgt, u16 vsi_id);
int nbl_res_queue_setup_rss(void *priv, u16 vsi_id);
int nbl_res_queue_set_epro_rss_ret(void *priv, u16 slot_index, u16 global_queue_id);

int nbl_txrx_mgt_start(struct nbl_resource_mgt *res_mgt);
void nbl_txrx_mgt_stop(struct nbl_resource_mgt *res_mgt);
int nbl_txrx_setup_ops(struct nbl_resource_ops *resource_ops);
void nbl_txrx_remove_ops(struct nbl_resource_ops *resource_ops);

int nbl_vsi_mgt_start(struct nbl_resource_mgt *res_mgt);
void nbl_vsi_mgt_stop(struct nbl_resource_mgt *res_mgt);
int nbl_vsi_setup_ops(struct nbl_resource_ops *resource_ops);
void nbl_vsi_remove_ops(struct nbl_resource_ops *resource_ops);

int nbl_accel_setup_ops(struct nbl_resource_ops *res_ops, bool is_draco);
int nbl_accel_mgt_start(struct nbl_resource_mgt *res_mgt);
void nbl_accel_mgt_stop(struct nbl_resource_mgt *res_mgt);

int nbl_fd_mgt_start(struct nbl_resource_mgt *res_mgt);
void nbl_fd_mgt_stop(struct nbl_resource_mgt *res_mgt);
int nbl_fd_setup_ops(struct nbl_resource_ops *resource_ops);
void nbl_fd_remove_ops(struct nbl_resource_ops *resource_ops);

int nbl_queue_setup_ops(struct nbl_resource_ops *res_ops);
void nbl_queue_remove_ops(struct nbl_resource_ops *res_ops);
bool nbl_res_get_flex_capability(void *priv, enum nbl_flex_cap_type *cap_type);
bool nbl_res_get_fix_capability(void *priv, enum nbl_fix_cap_type *cap_type);
void nbl_res_set_flex_capability(struct nbl_resource_mgt *res_mgt, enum nbl_flex_cap_type cap_type);
void nbl_res_set_fix_capability(struct nbl_resource_mgt *res_mgt, enum nbl_fix_cap_type cap_type);

int nbl_res_open_sfp(struct nbl_resource_mgt *res_mgt, u8 eth_id);
int nbl_res_get_eth_mac(struct nbl_resource_mgt *res_mgt, u8 *mac, u8 eth_id);
void nbl_res_pf_dev_vsi_type_to_hw_vsi_type(u16 src_type, enum nbl_vsi_serv_type *dst_type);
int nbl_res_get_rep_idx(struct nbl_eswitch_info *eswitch_info, u16 rep_vsi_id);
bool nbl_res_vf_is_active(void *priv, u16 func_id);
void nbl_res_set_hw_status(void *priv, enum nbl_hw_status hw_status);
void nbl_res_check_hw_status(void *priv);
enum nbl_hw_status nbl_res_get_hw_status(void *priv);
int nbl_res_get_pf_vf_num(void *priv, u16 pf_id);

u16 nbl_res_intr_get_suppress_level(void *priv,
				    struct nbl_get_intr_suppress_level_param *prm);
int nbl_res_intr_set_intr_suppress_level(void *priv,
					 struct nbl_ch_prm_set_intr_suppress_level *prm);
void nbl_res_setup_rdma_id(void *priv, struct ida *adev_ida,
			   struct ida *grc_adev_ida, struct mutex *lock);
void nbl_res_remove_rdma_id(void *priv, struct ida *adev_ida,
			    struct ida *grc_adev_ida, struct mutex *lock);
int nbl_res_register_rdma_grc_id(void *priv, u16 *vsi_id, int *grc_id);
int nbl_res_unregister_rdma_grc_id(void *priv, u16 *vsi_id);
int nbl_res_register_rdma(void *priv, u16 *vsi_id, struct nbl_rdma_register_param *param);
int nbl_res_unregister_rdma(void *priv, u16 *vsi_id);
u32 nbl_res_get_pfvf_queue_num(struct nbl_resource_mgt *res_mgt, int pfid, int vfid);
int nbl_res_get_user_queue_info(void *priv, u16 *vsi_id, struct nbl_ch_prm_get_queue_info *output);
int nbl_res_get_xdp_queue_info(void *priv, u16 *vsi_id,
			       struct nbl_ch_prm_get_queue_info *output);
int nbl_res_update_offload_status(struct nbl_resource_mgt *res_mgt);
int nbl_res_set_phy_flow(struct nbl_resource_mgt *res_mgt, u8 eth_id, bool status);
int nbl_res_set_dport_fc_th_vld(void *priv,
				struct nbl_ch_prm_set_func_vld *param);
int nbl_res_set_shaping_dport_vld(void *priv,
				  struct nbl_ch_prm_set_func_vld *param);
int nbl_res_cfg_eth_bond_info(void *priv, struct nbl_lag_member_list_param *param);
void nbl_adminq_mgt_init_leonis(struct nbl_resource_mgt *res_mgt);
void nbl_adminq_mgt_init_draco(struct nbl_resource_mgt *res_mgt);
int nbl_res_prepare_vf_chan(struct nbl_resource_mgt *res_mgt, u16 func_id);
int nbl_res_update_active_vf_num(struct nbl_resource_mgt *res_mgt, u16 func_id, bool add_flag);
u32 nbl_res_check_active_vf(void *priv, u16 *func_id);
int nbl_res_configure_qos(void *priv, struct nbl_ch_prm_configure_qos *param);
int nbl_res_adminq_set_eth_pfc(void *priv, u8 eth_id, u8 *pfc);
int nbl_res_set_pfc_buffer_size(void *priv, struct nbl_ch_prm_set_pfc_buffer_size *param);
int nbl_res_get_pfc_buffer_size(void *priv, struct nbl_ch_prm_get_pfc_buffer_size *param,
				struct nbl_ch_prm_get_pfc_buffer_size_resp *output);
int nbl_res_configure_rdma_bw(void *priv, struct nbl_ch_prm_configure_rdma_bw *param);
int nbl_res_set_rate_limit(void *priv, struct nbl_ch_prm_set_rate_limit *param);
int nbl_res_get_my_pf(void *priv, u16 *sfid, u8 *my_pf);
int nbl_res_check_fw_working(struct nbl_resource_mgt *res_mgt);
int nbl_res_get_chip_temperature(void *priv, struct nbl_ch_prm_get_hwmon *param);
int nbl_res_intr_get_abnormal_irq_num(void *priv);
int nbl_res_unregister_net(void *priv, u16 *func_id);
int nbl_res_configure_mirror(void *priv, struct nbl_ch_prm_mirror *param);
int nbl_res_get_mirror_table_id(void *priv, struct nbl_ch_prm_get_mirror_table_id *param,
				struct nbl_ch_prm_get_mirror_table_id *output);
int nbl_res_get_dev_name(void *priv, struct nbl_ch_prm_pf_name *param,
			 struct nbl_ch_prm_pf_name *output);
int nbl_res_register_dev_name(void *priv, struct nbl_ch_prm_pf_name *param);
bool nbl_res_check_lag_nosupport(void *priv);
#endif
