/* SPDX-License-Identifier: GPL-2.0*/
/*
 * Copyright (c) 2022 nebula-matrix Limited.
 * Author:
 */

#ifndef _NBL_RESOURCE_H_
#define _NBL_RESOURCE_H_

#include "nbl_core.h"
#include "nbl_hw.h"

#define NBL_RES_MGT_TO_COMMON(res_mgt)		((res_mgt)->common)
#define NBL_RES_MGT_TO_COMMON_OPS(res_mgt)	(&((res_mgt)->common_ops))
#define NBL_RES_MGT_TO_DEV(res_mgt)		NBL_COMMON_TO_DEV(NBL_RES_MGT_TO_COMMON(res_mgt))
#define NBL_RES_MGT_TO_DMA_DEV(res_mgt)		\
	NBL_COMMON_TO_DMA_DEV(NBL_RES_MGT_TO_COMMON(res_mgt))
#define NBL_RES_MGT_TO_INTR_MGT(res_mgt)	((res_mgt)->intr_mgt)
#define NBL_RES_MGT_TO_QUEUE_MGT(res_mgt)	((res_mgt)->queue_mgt)
#define NBL_RES_MGT_TO_TXRX_MGT(res_mgt)	((res_mgt)->txrx_mgt)
#define NBL_RES_MGT_TO_FLOW_MGT(res_mgt)	((res_mgt)->flow_mgt)
#define NBL_RES_MGT_TO_VSI_MGT(res_mgt)		((res_mgt)->vsi_mgt)
#define NBL_RES_MGT_TO_PORT_MGT(res_mgt)	((res_mgt)->port_mgt)
#define NBL_RES_MGT_TO_ADMINQ_MGT(res_mgt)	((res_mgt)->adminq_mgt)
#define NBL_RES_MGT_TO_RES_INFO(res_mgt)	((res_mgt)->resource_info)
#define NBL_RES_MGT_TO_PROD_OPS(res_mgt)	((res_mgt)->product_ops)
#define NBL_RES_MGT_TO_SRIOV_INFO(res_mgt)	(NBL_RES_MGT_TO_RES_INFO(res_mgt)->sriov_info)
#define NBL_RES_MGT_TO_ETH_INFO(res_mgt)	(NBL_RES_MGT_TO_RES_INFO(res_mgt)->eth_info)
#define NBL_RES_MGT_TO_VSI_INFO(res_mgt)	(NBL_RES_MGT_TO_RES_INFO(res_mgt)->vsi_info)
#define NBL_RES_MGT_TO_PF_NUM(res_mgt)		(NBL_RES_MGT_TO_RES_INFO(res_mgt)->max_pf)

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

#define NBL_MAX_FUNC				(520)
#define NBL_MAX_JUMBO_FRAME_SIZE		(9600)
#define NBL_PKT_HDR_PAD				(ETH_HLEN + ETH_FCS_LEN + (VLAN_HLEN * 2))

/* temperature threshold1 */
#define NBL_LEONIS_TEMP_MAX			(100)
/* temperature threshold2 */
#define NBL_LEONIS_TEMP_CRIT			(115)

/* --------- QUEUE ---------- */
#define NBL_MAX_TXRX_QUEUE			(2048)
#define NBL_DEFAULT_DESC_NUM			(1024)
#define NBL_MAX_TXRX_QUEUE_PER_FUNC		(256)

#define NBL_DEFAULT_REP_HW_QUEUE_NUM		(16)
#define NBL_DEFAULT_PF_HW_QUEUE_NUM		(16)
#define NBL_DEFAULT_USER_HW_QUEUE_NUM		(16)
#define NBL_DEFAULT_VF_HW_QUEUE_NUM		(2)

#define NBL_SPECIFIC_VSI_NET_ID_OFFSET		(4)
#define NBL_MAX_CACHE_SIZE			(256)
#define NBL_MAX_BATCH_DESC			(64)

enum nbl_qid_map_table_type {
	NBL_MASTER_QID_MAP_TABLE,
	NBL_SLAVE_QID_MAP_TABLE,
	NBL_QID_MAP_TABLE_MAX
};

struct nbl_queue_vsi_info {
	u32 curr_qps;
	u16 curr_qps_static;		/* This will not be reset when netdev down */
	u16 vsi_index;
	u16 vsi_id;
	u16 rss_ret_base;
	u16 rss_entry_size;
	u16 net_id;
	u16 queue_offset;
	u16 queue_num;
	bool rss_vld;
	bool vld;
};

struct nbl_queue_info {
	struct nbl_queue_vsi_info vsi_info[NBL_VSI_MAX];
	u64 notify_addr;
	u32 qid_map_index;
	u16 num_txrx_queues;
	u16 *txrx_queues;
	u16 *queues_context;
	u16 rss_ret_base;
	u16 rss_entry_size;
	u32 curr_qps;
	u16 split;
	u16 queue_size;
};

struct nbl_adapt_desc_gother {
	u16 level;
	u32 uvn_desc_rd_entry;
	u64 get_desc_stats_jiffies;
};

struct nbl_queue_mgt {
	DECLARE_BITMAP(txrx_queue_bitmap, NBL_MAX_TXRX_QUEUE);
	DECLARE_BITMAP(rss_ret_bitmap, NBL_EPRO_RSS_RET_TBL_DEPTH);
	struct nbl_qid_map_table qid_map_table[NBL_QID_MAP_TABLE_ENTRIES];
	struct nbl_queue_info queue_info[NBL_MAX_FUNC];
	u32 total_qid_map_entries;
	int qid_map_select;
	bool qid_map_ready;
	u32 qid_map_tail[NBL_QID_MAP_TABLE_MAX];
	struct nbl_adapt_desc_gother adapt_desc_gother;
};

/* --------- INTERRUPT ---------- */
#define NBL_MAX_OTHER_INTERRUPT			1024
#define NBL_MAX_NET_INTERRUPT			4096

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
	u16 msix_base;
	u16 msix_max;
	u16 *interrupts;
	struct nbl_msix_map_table msix_map_table;
};

struct nbl_interrupt_mgt {
	DECLARE_BITMAP(interrupt_net_bitmap, NBL_MAX_NET_INTERRUPT);
	DECLARE_BITMAP(interrupt_others_bitmap, NBL_MAX_OTHER_INTERRUPT);
	struct nbl_func_interrupt_resource_mng func_intr_res[NBL_MAX_FUNC];
};

struct nbl_port_mgt {
};

/* --------- TXRX ---------- */
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
	struct sk_buff *skb;
	dma_addr_t dma;
	u32 len;

	unsigned int bytecount;
	unsigned short gso_segs;
	bool page;
	u32 tx_flags;
};

struct nbl_dma_info {
	dma_addr_t addr;
	struct page *page;
};

struct nbl_page_cache {
	u32 head;
	u32 tail;
	struct nbl_dma_info page_cache[NBL_MAX_CACHE_SIZE];
};

struct nbl_rx_buffer {
	struct nbl_dma_info *di;
	u32 offset;
	bool last_in_page;
};

struct nbl_res_vector {
	struct napi_struct napi;
	struct nbl_res_tx_ring *tx_ring;
	struct nbl_res_rx_ring *rx_ring;
	u8 *irq_enable_base;
	u32 irq_data;
	bool started;
	bool net_msix_mask_en;
};

struct nbl_res_tx_ring {
	/*data path*/
	struct nbl_ring_desc *desc;
	struct nbl_tx_buffer *tx_bufs;
	struct device *dma_dev;
	struct net_device *netdev;
	u8 __iomem *notify_addr;

	enum nbl_product_type product_type;
	u16 queue_index;
	u16 desc_num;
	u16 notify_qid;
	u16 avail_used_flags;
	/* device ring wrap counter */
	bool used_wrap_counter;
	u16 next_to_use;
	u16 next_to_clean;
	u16 tail_ptr;
	u16 mode;
	u8 eth_id;
	u8 extheader_tx_len;

	struct nbl_queue_stats stats;
	struct u64_stats_sync syncp;
	struct nbl_tx_queue_stats tx_stats;

	/* control path */
	// dma for desc[]
	dma_addr_t dma;
	// size for desc[]
	unsigned int size;
	bool valid;
} ____cacheline_internodealigned_in_smp;

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
	struct u64_stats_sync syncp;
	struct nbl_page_cache page_cache;

	enum nbl_product_type product_type;
	u32 buf_len;
	u16 avail_used_flags;
	bool used_wrap_counter;
	u16 next_to_use;
	u16 next_to_clean;
	u16 tail_ptr;
	u16 mode;
	u16 desc_num;
	u16 queue_index;

	/* control path */
	struct nbl_common_info *common;
	void *txrx_mgt;
	// dma for desc[]
	dma_addr_t dma;
	// size for desc[]
	unsigned int size;
	bool valid;
	u16 notify_qid;
} ____cacheline_internodealigned_in_smp;

struct nbl_txrx_vsi_info {
	u16 ring_offset;
	u16 ring_num;
};

struct nbl_txrx_mgt {
	struct nbl_res_vector **vectors;
	struct nbl_res_tx_ring **tx_rings;
	struct nbl_res_rx_ring **rx_rings;
	struct nbl_txrx_vsi_info vsi_info[NBL_VSI_MAX];
	u16 tx_ring_num;
	u16 rx_ring_num;
};

struct nbl_vsi_mgt {
};

struct nbl_emp_version {
	char app_version[16];
	char kernel_version[16];
	char build_version[16];
};

struct nbl_adminq_mgt {
	struct nbl_emp_version emp_verion;
	u32 fw_last_hb_seq;
	unsigned long fw_last_hb_time;

	struct work_struct eth_task;
	struct nbl_resource_mgt *res_mgt;
	u8 module_inplace_changed[NBL_MAX_ETHERNET];
	u8 link_state_changed[NBL_MAX_ETHERNET];

	bool fw_resetting;
	struct wait_queue_head wait_queue;

	struct mutex eth_lock; /* To prevent link_state_changed mismodified. */

	void *cmd_filter;
};

/* --------- FLOW ---------- */
#define NBL_FEM_HT_PP0_LEN				(1 * 1024)
#define NBL_MACVLAN_TABLE_LEN				(4096)

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
	NBL_FLOW_L2_UP = NBL_FLOW_MACVLAN_MAX,
	NBL_FLOW_L2_DOWN,
	NBL_FLOW_L3_UP,
	NBL_FLOW_L3_DOWN,
	NBL_FLOW_TYPE_MAX,
	NBL_FLOW_LLDP_LACP_UP,
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
	u16 flow_id;
	u16 ht0_hash;
	u16 ht1_hash;
	u16 hash_table;
	u16 hash_bucket;
	u16 tcam_index;
	u8 tcam_flag;
	u8 flow_type;
};

struct nbl_flow_mcc_node {
	struct list_head node;
	u16 mcc_id;
};

struct nbl_flow_multi_group {
	struct list_head mcc_list;
	struct nbl_flow_fem_entry entry[NBL_FLOW_TYPE_MAX - NBL_FLOW_MACVLAN_MAX];
	u8 ether_id;
	u16 mcc_id;
	u16 network_status;
	u16 pfc_mode;
	u16 bp_mode;
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

struct nbl_flow_UL4S_rule {
	struct nbl_flow_fem_entry UL4S_entry;
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

struct nbl_flow_mgt {
	DECLARE_BITMAP(flow_id, NBL_MACVLAN_TABLE_LEN);
	DECLARE_BITMAP(tcam_id, NBL_TCAM_TABLE_LEN);
	u32 pp_tcam_count;
	u32 unicast_mac_threshold;
	struct nbl_flow_ht_mng pp0_ht0_mng;
	struct nbl_flow_ht_mng pp0_ht1_mng;
	struct nbl_flow_multi_group multi_flow[NBL_MAX_ETHERNET];
	void *mac_hash_tbl[NBL_MAX_ETHERNET];
	struct list_head lldp_list;
	struct list_head lacp_list;
	void *mcc_tbl_priv;
};

#define NBL_FLOW_INIT_BIT				BIT(1)
#define NBL_FLOW_AVAILABLE_BIT				BIT(2)
#define NBL_ALL_PROFILE_NUM				(64)
#define NBL_ASSOC_PROFILE_GRAPH_NUM			(32)
#define NBL_ASSOC_PROFILE_NUM				(16)
#define NBL_ASSOC_PROFILE_STAGE_NUM			(8)
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
#define NBL_PP1_KT_NUM					(12 * 1024)
#define NBL_PP2_KT_NUM					(112 * 1024)
#define NBL_PP0_KT_OFFSET				(124 * 1024)
#define NBL_PP1_KT_OFFSET				(112 * 1024)
#define NBL_FEM_HT_PP0_LEN				(1 * 1024)
#define NBL_FEM_HT_PP1_LEN				(3 * 1024)
#define NBL_FEM_HT_PP2_LEN				(16 * 1024)
#define NBL_FEM_HT_PP0_DEPTH				(1 * 1024)
#define NBL_FEM_HT_PP1_DEPTH				(3 * 1024)
#define NBL_FEM_HT_PP2_DEPTH				(0)
#define NBL_FEM_AT_PP1_LEN				(6 * 1024)
#define NBL_FEM_AT2_PP1_LEN				(2 * 1024)
#define NBL_FEM_AT_PP2_LEN				(72 * 1024)
#define NBL_FEM_AT2_PP2_LEN				(16 * 1024)

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
	struct hlist_head *flow_tab_head;
	s32 tab_cnt;
};

struct nbl_flow_index_mng {
	struct hlist_head flow_index_head[NBL_FLOW_INDEX_LEN];
	DECLARE_BITMAP(flow_index_bmp, NBL_FLOW_INDEX_LEN);
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
	struct hlist_node node;
	struct nbl_flow_pp_at_key	key;
	u32 at_bitmap_index;
	u32 ref_cnt;
};

/* --------- INFO ---------- */
#define NBL_RES_RDMA_MAX				(63)
#define NBL_RES_RDMA_INTR_NUM				(3)
#define NBL_MAX_VF					(NBL_MAX_FUNC - NBL_MAX_PF)

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

	u8 pf_bitmap[NBL_MAX_ETHERNET];
	u8 eth_num;
	u8 resv[3];
	u8 eth_id[NBL_MAX_PF];
	u8 logic_eth_id[NBL_MAX_PF];
};

enum nbl_vsi_serv_type {
	NBL_VSI_SERV_PF_DATA_TYPE,
	NBL_VSI_SERV_PF_CTLR_TYPE,
	NBL_VSI_SERV_PF_USER_TYPE,
	NBL_VSI_SERV_VF_DATA_TYPE,
	/* use for pf_num > eth_num, the extra pf belong pf0's switch */
	NBL_VSI_SERV_PF_EXTRA_TYPE,
	NBL_VSI_SERV_MAX_TYPE,
};

struct nbl_vsi_serv_info {
	u16 base_id;
	u16 num;
};

struct nbl_vsi_info {
	u16 num;
	struct nbl_vsi_serv_info serv_info[NBL_MAX_ETHERNET][NBL_VSI_SERV_MAX_TYPE];
};

struct nbl_net_ring_num_info {
	u16 pf_def_max_net_qp_num;
	u16 vf_def_max_net_qp_num;
	u16 net_max_qp_num[NBL_MAX_FUNC];
};

struct nbl_resource_info {
	/* ctrl-dev owned pfs */
	DECLARE_BITMAP(func_bitmap, NBL_MAX_FUNC);
	struct nbl_sriov_info *sriov_info;
	struct nbl_eth_info *eth_info;
	struct nbl_vsi_info *vsi_info;
	u32 base_qid;

	struct nbl_net_ring_num_info net_ring_num_info;

	/* for af use */
	int p4_used;
	u16 eth_mode;
	u16 init_acl_refcnt;
	u8 max_pf;
	u16 nd_upcall_refnt;
	struct nbl_board_port_info board_info;
};

struct nbl_upcall_port_info {
	bool upcall_port_active;
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

struct nbl_resource_common_ops {
	u16 (*vsi_id_to_func_id)(void *res_mgt, u16 vsi_id);
	int (*vsi_id_to_pf_id)(void *res_mgt, u16 vsi_id);
	u16 (*pfvfid_to_func_id)(void *res_mgt, int pfid, int vfid);
	u16 (*pfvfid_to_vsi_id)(void *res_mgt, int pfid, int vfid, u16 type);
	u16 (*func_id_to_vsi_id)(void *res_mgt, u16 func_id, u16 type);
	int (*func_id_to_pfvfid)(void *res_mgt, u16 func_id, int *pfid, int *vfid);
	int (*func_id_to_bdf)(void *res_mgt, u16 func_id, u8 *bus, u8 *dev, u8 *function);
	u64 (*get_func_bar_base_addr)(void *res_mgt, u16 func_id);
	u16 (*get_particular_queue_id)(void *res_mgt, u16 vsi_id);
	u8 (*vsi_id_to_eth_id)(void *res_mgt, u16 vsi_id);
	u8 (*eth_id_to_pf_id)(void *res_mgt, u8 eth_id);
};

struct nbl_res_product_ops {
	/* for queue */
	void (*queue_mgt_init)(struct nbl_queue_mgt *queue_mgt);
	int (*setup_qid_map_table)(struct nbl_resource_mgt *res_mgt, u16 func_id, u64 notify_addr);
	void (*remove_qid_map_table)(struct nbl_resource_mgt *res_mgt, u16 func_id);
	int (*init_qid_map_table)(struct nbl_resource_mgt *res_mgt,
				  struct nbl_queue_mgt *queue_mgt, struct nbl_phy_ops *phy_ops);

	/* for intr */
	void (*nbl_intr_mgt_init)(struct nbl_resource_mgt *res_mgt);
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
	struct nbl_vsi_mgt *vsi_mgt;
	struct nbl_adminq_mgt *adminq_mgt;
	struct nbl_accel_mgt *accel_mgt;
	struct nbl_port_mgt *port_mgt;
	struct nbl_res_product_ops *product_ops;
	DECLARE_BITMAP(flex_capability, NBL_FLEX_CAP_NBITS);
	DECLARE_BITMAP(fix_capability, NBL_FIX_CAP_NBITS);
};

/* Mgt structure for each product.
 * Every indivisual mgt must have the common mgt as its first member, and contains its unique
 * data structure in the reset of it.
 */
struct nbl_resource_mgt_leonis {
	struct nbl_resource_mgt res_mgt;
};

#define NBL_RES_FW_CMD_FILTER_MAX		8
struct nbl_res_fw_cmd_filter {
	int (*in)(struct nbl_resource_mgt *res_mgt, void *data, int len);
	int (*out)(struct nbl_resource_mgt *res_mgt, void *data, int len);
};

u16 nbl_res_vsi_id_to_func_id(struct nbl_resource_mgt *res_mgt, u16 vsi_id);
int nbl_res_vsi_id_to_pf_id(struct nbl_resource_mgt *res_mgt, u16 vsi_id);
u16 nbl_res_pfvfid_to_func_id(struct nbl_resource_mgt *res_mgt, int pfid, int vfid);
u16 nbl_res_pfvfid_to_vsi_id(struct nbl_resource_mgt *res_mgt, int pfid, int vfid, u16 type);
u16 nbl_res_func_id_to_vsi_id(struct nbl_resource_mgt *res_mgt, u16 func_id, u16 type);
int nbl_res_func_id_to_pfvfid(struct nbl_resource_mgt *res_mgt, u16 func_id, int *pfid, int *vfid);
u8 nbl_res_eth_id_to_pf_id(struct nbl_resource_mgt *res_mgt, u8 eth_id);
int nbl_res_func_id_to_bdf(struct nbl_resource_mgt *res_mgt, u16 func_id, u8 *bus,
			   u8 *dev, u8 *function);
u64 nbl_res_get_func_bar_base_addr(struct nbl_resource_mgt *res_mgt, u16 func_id);
u16 nbl_res_get_particular_queue_id(struct nbl_resource_mgt *res_mgt, u16 vsi_id);
u8 nbl_res_vsi_id_to_eth_id(struct nbl_resource_mgt *res_mgt, u16 vsi_id);

int nbl_adminq_mgt_start(struct nbl_resource_mgt *res_mgt);
void nbl_adminq_mgt_stop(struct nbl_resource_mgt *res_mgt);
int nbl_adminq_setup_ops(struct nbl_resource_ops *resource_ops);
void nbl_adminq_remove_ops(struct nbl_resource_ops *resource_ops);

int nbl_intr_mgt_start(struct nbl_resource_mgt *res_mgt);
void nbl_intr_mgt_stop(struct nbl_resource_mgt *res_mgt);
int nbl_intr_setup_ops(struct nbl_resource_ops *resource_ops);
void nbl_intr_remove_ops(struct nbl_resource_ops *resource_ops);

int nbl_queue_mgt_start(struct nbl_resource_mgt *res_mgt);
void nbl_queue_mgt_stop(struct nbl_resource_mgt *res_mgt);

int nbl_txrx_mgt_start(struct nbl_resource_mgt *res_mgt);
void nbl_txrx_mgt_stop(struct nbl_resource_mgt *res_mgt);
int nbl_txrx_setup_ops(struct nbl_resource_ops *resource_ops);
void nbl_txrx_remove_ops(struct nbl_resource_ops *resource_ops);

int nbl_vsi_mgt_start(struct nbl_resource_mgt *res_mgt);
void nbl_vsi_mgt_stop(struct nbl_resource_mgt *res_mgt);
int nbl_vsi_setup_ops(struct nbl_resource_ops *resource_ops);
void nbl_vsi_remove_ops(struct nbl_resource_ops *resource_ops);

bool nbl_res_get_flex_capability(void *priv, enum nbl_flex_cap_type cap_type);
bool nbl_res_get_fix_capability(void *priv, enum nbl_fix_cap_type cap_type);
void nbl_res_set_flex_capability(struct nbl_resource_mgt *res_mgt, enum nbl_flex_cap_type cap_type);
void nbl_res_set_fix_capability(struct nbl_resource_mgt *res_mgt, enum nbl_fix_cap_type cap_type);

int nbl_res_open_sfp(struct nbl_resource_mgt *res_mgt, u8 eth_id);
int nbl_res_get_eth_mac(struct nbl_resource_mgt *res_mgt, u8 *mac, u8 eth_id);
void nbl_res_pf_dev_vsi_type_to_hw_vsi_type(u16 src_type, enum nbl_vsi_serv_type *dst_type);
bool nbl_res_vf_is_active(void *priv, u16 func_id);

#endif
