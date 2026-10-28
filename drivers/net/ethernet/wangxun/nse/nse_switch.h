/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2018 - 2021 Beijing WangXun Technology Co., Ltd. */

#ifndef _NSE_SWITCH_H_
#define _NSE_SWITCH_H_

#define NSE_SW_KEY0_IN_PORT_SUPPORT
#define NSE_TC_FLWR_ALL_VLIST_FWD  0 /*fwd_to_Vsi is seen as fwd_to_vlist*/
#define NSE_TC_FLWR_FWD_IN_DU	1
#define NSE_TC_FLWR_COUNT_IN_DU 1
#define NSE_TC_FLWR_METER_IN_DU 0
#define NSE_TC_FLWR_MULTI_ENCAP
#define NSE_TC_FLWR_MULTI_CHAIN
#define NSE_TC_FLWR_SFLOW
#ifdef NSE_TC_FLWR_SFLOW
#undef NSE_TC_FLWR_COUNT_IN_DU
#define NSE_TC_FLWR_COUNT_IN_DU		1
#endif
#define NSE_SUPPORT_DMA_RD_STATS
#define NSE_SUPPORT_RD_STATS_ASYN

#define NSE_SUPPORT_FAST_FLWR

#define NSE_MAX_DMA_RD_STATS_NUM   (32 * 1024)

#define NSE_MAX_DMA_RD_STATS_SIZE   (NSE_MAX_DMA_RD_STATS_NUM * 8)

#define NSE_MAX_CHAIN_NUM			2
#define NSE_MAX_FLOW_FWD_DEST		16
#define NSE_MAX_FLOW_ENCAP_CNT		16

#define NSE_MAX_SUB_NODE_NUM 6
#define NSE_MAX_SW 256
#define NSE_DFLT_VSI_INVAL 0xff
#define NSE_FLTR_RX BIT(0)
#define NSE_FLTR_TX BIT(1)
#define NSE_FLTR_TX_RX (NSE_FLTR_RX | NSE_FLTR_TX)

#define DUMMY_ETH_HDR_LEN		16

#define NSE_VSI_INVAL_ID 0xFFFF
#define NSE_INVAL_Q_HANDLE 0xFFFF

#define NSE_MAX_LITE_DU_ACTION_NUM		3
#define NSE_MAX_DU_ACTION_NUM			14
#define NSE_MAX_MD_VALUE_NUM			7
#define NSE_MAX_DU_DESC_NUM				14
#define NSE_MAX_TOTAL_DU_DESC_ACTION    14
#define NSE_MAX_AU_TASK_NUM				16
#define NSE_LITE_NODE_STATE_CTRL_WORD   1
#define NSE_FULL_NODE_STATE_CTRL_WORD   2
#define NSE_TASK_LIST_WORD_SIZE			16

/* VSI context structure for add/get/update/free operations */
struct nse_vsi_ctx {
	u16 vsi_abs_num;	/* VSI abs ID, always set to be nse_vsi->vsi_abs_num */

	struct nse_aqc_vsi_props info;

	struct nse_sched_vsi_info sched;

	u16 num_lan_q_entries[NSE_MAX_TRAFFIC_CLASS];
	struct nse_q_ctx *lan_q_ctx[NSE_MAX_TRAFFIC_CLASS];

	u16 num_rdma_q_entries[NSE_MAX_TRAFFIC_CLASS];
	struct nse_q_ctx *rdma_q_ctx[NSE_MAX_TRAFFIC_CLASS];
};

struct nse_node_query_data {
	/* LUT ID for which the requested node was added */
	u16 lut_id;
	/* Node ID that was added or is supposed to be removed */
	u16 node_id;
};

/* struct for HW protocol ID in parser */
struct nse_adv_lkup_elem {
	enum nse_protocol_type type;
	union nse_prot_hdr h_u;	/* Header values */
	union nse_prot_hdr m_u;	/* Mask of header values to match */
};

struct nse_sw_act_ctrl {
	/* src software VSI for LOOKUP_TX or src lan port for LOOKUP_RX */
#define NSE_IN_PORT_TYPE_HOST 1
#define NSE_IN_PORT_TYPE_LAN  0
#define NSE_IN_PORT_TYPE_S	  14
#define NSE_IN_PORT_TYPE_MASK  0x3
/* Bit 15:14 is IN_Port Type */
#define NSE_IN_PORT_TYPE_M	  (NSE_IN_PORT_TYPE_MASK << NSE_IN_PORT_TYPE_S)
#define NSE_IN_PORT_ID_MASK   0xff
#define NSE_IN_PORT_MASK	  (NSE_IN_PORT_TYPE_M | NSE_IN_PORT_ID_MASK)

	u16 in_port;
	u16 flag;
	enum nse_sw_fwd_act_type fltr_act;

	struct {
		/* This is a queue ID in case of NSE_FWD_TO_Q and starting
		 * queue ID in case of NSE_FWD_TO_QGRP.
		 */
		u16 q_id:11;
		u16 vsi_id:10;
		u16 hw_vsi_id:10;
		u16 vsi_list_id:10;
	} fwd_id;

	bool is_fast;

	u16 large_act_id;
	bool is_lite; /*above large act id is lite or not*/
	/* dest software VSI handle, not used in advanced node*/
	u16 vsi_handle;
};

/* This structure used to save info about lb_en and lan_en.
 * Values in act would be used only if act_valid was set to true,
 * otherwise dflt values would be used.
 */
struct nse_adv_rule_flags_info {
	u32 act;
#define NSE_LB_ENABLE		BIT(0)
#define NSE_LAN_ENABLE		BIT(1)
	u8 act_valid;		/* indicate if flags in act are valid */
};

/*struct for lut node*/
struct nse_adv_node_info {
	enum nse_sw_tunnel_type tun_type;
	struct nse_sw_act_ctrl sw_act;
	u32 priority;
	u8 rx; /* used to LB/LAN Enable at tx direction */
	u8 sw_id;

	bool is_lpm;
	u16 prefix_len;

	/* src chain id where this tc flower filtr located */
	u8 chain_id;

	struct nse_node_state *node_state;

	u16 fltr_node_id;
	/* it is sub_lut's node id(cbuf addr) when lut chain */
	u16 sub_fltr_node_id[NSE_MAX_SUB_NODE_NUM];
	struct nse_adv_rule_flags_info flags_info;
	struct nse_vsi_list_map_info *vsi_list_info;
};

#define NSE_SW_DFLT_RCP_NUM 11

/* Switch lut ID enum values are specific to hardware */
enum nse_sw_lkup_type {
	NSE_SW_LKUP_ETHERTYPE = 0,
	NSE_SW_LKUP_ROCE_MAC = 1,
	NSE_SW_LKUP_MAC = 2,
	NSE_SW_LKUP_MAC_VLAN = 3,
	NSE_SW_LKUP_ETHERTYPE_MAC = 4,
	NSE_SW_LKUP_VLAN = 5,
	NSE_SW_LKUP_PROMISC = 6,
	NSE_SW_LKUP_PROMISC_VLAN = 7,
	NSE_SW_LKUP_BMC_MAC = 8,
	/* used for adv lut */
	NSE_SW_LKUP_LAST,
};

/* type of filter src ID */
enum nse_src_id {
	NSE_SRC_ID_UNKNOWN = 0,
	NSE_SRC_ID_VSI,
	NSE_SRC_ID_QUEUE,
	NSE_SRC_ID_LPORT,
};

enum nse_promisc_flags {
	NSE_PROMISC_UCAST_RX = 0x1,
	NSE_PROMISC_UCAST_TX = 0x2,
	NSE_PROMISC_MCAST_RX = 0x4,
	NSE_PROMISC_MCAST_TX = 0x8,
	NSE_PROMISC_BCAST_RX = 0x10,
	NSE_PROMISC_BCAST_TX = 0x20,
	NSE_PROMISC_VLAN_RX = 0x40,
	NSE_PROMISC_VLAN_TX = 0x80,
};

enum nse_promisc_mactype {
	NSE_PROMISC_MACTYPE_UCAST = 0,
	NSE_PROMISC_MACTYPE_BCAST = 0x0010,
	NSE_PROMISC_MACTYPE_MCAST = 0x0020,
};

struct nse_fltr_info {
	/* Look up type means LUT id fixed by firmware */
	enum nse_sw_lkup_type lkup_type;
	enum nse_sw_fwd_act_type fltr_act;
	/* rule ID returned by firmware once filter rule is created */
	u16 fltr_node_id;

	/*key0 in LUT*/
	u16 sw_id;
	/*only valid in such LUT, which extract directioin MD as key*/
	u16 dir;
#define NSE_FILTER_DIR_INVD 0xFFFF
#define NSE_FILTER_DIR_RX   0
#define NSE_FILTER_DIR_TX   1

	union {
		struct {
			u8 mac_addr[ETH_ALEN];
			u16 mactype;
		} mac;
		struct {
			u8 mac_addr[ETH_ALEN];
			u16 vlan_id;
		} mac_vlan;
		struct {
			u16 vlan_id;
			u16 tpid;
			u8 tpid_valid;
		} vlan;
		struct {
			u16 ethertype;
			u8 mac_addr[ETH_ALEN];
		} ethertype_mac;
		struct {
			u16 mactype;
			u16 vlan_id;
		} promisc;
	} l_data;

	/* Depending on filter action type */
	union {
		u16 q_id:10;
		u16 hw_vsi_id:10;
		u16 vsi_list_id:10;
	} fwd_id;

	/* Software VSI handle*/
	u16 vsi_handle;

	/* valid only in Tx Direction */
	u8 lb_en;
	u8 lan_en;
};

enum nse_vsi_list_type {
	NSE_VSI_LIST_TYPE_LEGACY = 0,
	NSE_VSI_LIST_TYPE_ADVANCED,
	NSE_VSI_LIST_TYPE_MAX
};

/* Bookkeeping structure to hold bitmap of VSIs corresponding to VSI list ID */
struct nse_vsi_list_map_info {
	struct list_head list_entry;
	DECLARE_BITMAP(vsi_map, NSE_MAX_VSI);
	u16 vsi_list_id;
	/* counter to track how many rules are reusing this VSI list */
	refcount_t ref_cnt;
	u16 vsi_cnt; /*used by advanced filter*/
	enum nse_vsi_list_type type;
};

struct nse_fltr_list_entry {
	struct list_head list_entry;
	int status;
	struct nse_fltr_info fltr_info;
};

/* This defines an entry in the list that maintains MAC or VLAN membership
 * to HW list mapping, since multiple VSIs can subscribe to the same MAC or
 * VLAN. As an optimization the VSI list should be created only when a
 * second VSI becomes a subscriber to the same MAC address. VSI lists are always
 * used for VLAN membership.
 */
struct nse_fltr_mgmt_list_entry {
	/* back pointer to VSI list ID to VSI list mapping */
	struct nse_vsi_list_map_info *vsi_list_info;
	/* when fltr act is fwd to vsi_list, used to count VSIs in vsi_list*/
	u16 vsi_count;
	u16 node_state_id;
	struct list_head list_entry;
	struct nse_fltr_info fltr_info;
};

struct nse_adv_fltr_mgmt_list_entry {
	struct list_head list_entry;
	u16 lkups_cnt;
	struct nse_adv_lkup_elem *lkups;
	struct nse_adv_node_info node_info;
};

struct nse_du_action {
	enum nse_sw_du_act_type du_act;

	struct nse_adv_rule_flags_info flags_info;
	u8 rx;
	struct {
		u16 q_id:11;
		u16 vsi_id:10;
		u16 hw_vsi_id:10;
		u16 vsi_list_id:10;
	} fwd_id;

	u16 hw_cnt_id;

	u16 meter_id;

	u16 copy_num;

	u8 dest_chain;

	u8 dest_mdid;
	u16 md_value;

	u16 sflow_vsi_id;
};

enum nse_sw_meter_mode {
	NSE_RATE_LIMIT_BPS,
	NSE_RATE_LIMIT_PPS,
	NSE_RATE_LIMIT_INVLID,
};

struct nse_sw_meter_param {
	enum nse_sw_meter_mode mode;
	u32 index;
	u64 rate;
	u32 burst;
};

struct nse_sw_meter {
	struct list_head list_entry;
	struct nse_sw_meter_param meter_param;
	u16 meter_id; /*hw id*/
	refcount_t ref_cnt;
	struct nse_sw_counter_pair *red_cnt_p;
	struct nse_sw_counter_pair *green_cnt_p;
};

enum nse_sw_mode {
	NSE_SW_MODE_LEGACY = 0,
	NSE_SW_MODE_SWITCHDEV,
	NSE_SW_MODE_MAX
};

struct nse_counter_cache {
	u64 val;
	u64 lastuse;
};

enum nse_sw_counter_type {
	NSE_SW_CNTR_TYPE_PACKET = 0,
	NSE_SW_CNTR_TYPE_BYTE,
	NSE_SW_CNTR_TYPE_MAX
};

struct nse_sw_counter {
	struct list_head list;
	struct llist_node addlist;

	u16 hw_id; /*hw counter id*/
	u64 last_val;
	enum nse_sw_counter_type cnt_type;
	struct nse_counter_cache cache ____cacheline_aligned_in_smp;
};

struct nse_sw_counter_pair {
	struct nse_sw_counter p_counter; /*packet*/
	struct nse_sw_counter b_counter; /*byter*/
	bool aging;
	bool fast_node;
	struct llist_node dellist;
};

struct nse_sw_task {
	u16 task_id;
	u16 data_para; /*byte offset in dccm from node base*/
};

struct nse_sw_task_list {
	struct list_head list_entry;

	u16 task_list_id;
	refcount_t ref_cnt;
	/*task_cnt's max num is NSE_MAX_AU_TASK_NUM*/
	u16 task_cnt;
	struct nse_sw_task task[];
};
enum nse_task_id {
	NSE_TASK_ID_INVALID = 0,
	NSE_TASK_ID_L2_SMAC_REWRITE = 1,
	NSE_TASK_ID_L2_DMAC_REWRITE = 2,
	NSE_TASK_ID_L3_SIP_V4_REWRITE = 3,
	NSE_TASK_ID_L3_DIP_V4_REWRITE = 4,
	NSE_TASK_ID_L3_TOS_V4_REWRITE = 5,
	NSE_TASK_ID_L3_TTL_V4_REWRITE = 6,
	NSE_TASK_ID_L3_SIP_V6_REWRITE = 7,
	NSE_TASK_ID_L3_DIP_V6_REWRITE = 8,
	NSE_TASK_ID_L3_HLIMIT_REWRITE = 9,
	NSE_TASK_ID_L4_SPORT_REWRITE = 10,
	NSE_TASK_ID_L4_DPORT_REWRITE = 11,
	NSE_TASK_ID_VLAN_REWRITE	 = 12,
	NSE_TASK_ID_DEC_TTL			 = 13,
	NSE_TASK_ID_DEC_HLIMIT		 = 14,
	NSE_TASK_ID_L3_TOS_V6_REWRITE = 15,
	NSE_TASK_ID_VLAN_PUSH		 = 32,
	NSE_TASK_ID_VLAN_POP		 = 33,
	NSE_TASK_ID_V4_VXLAN_ENCAP   = 34,
	NSE_TASK_ID_V6_VXLAN_ENCAP	 = 35,
	NSE_TASK_ID_AU_COUNT		 = 36,
	NSE_TASK_ID_V4_VXLAN_M_ENCAP = 37,
	NSE_TASK_ID_V6_VXLAN_M_ENCAP = 38,
	NSE_TASK_ID_AU_FWD			 = 39,
	NSE_TASK_ID_AU_METER		 = 103,
	NSE_TASK_ID_NOP				 = 127,
	NSE_TASK_ID_MAX,
};

#define NSE_TASK_PARA_BASE (16 + 16) /*word unit; Tsk List + Node State*/

#define NSE_TASK_PUSH_VLAN_PRIO_S	12
#define NSE_TASK_PUSH_VLAN_PRIO_M	0xF
#define NSE_TASK_PUSH_VLAN_ID_S		0
#define NSE_TASK_PUSH_VLAN_ID_M		0xFFF

#define NSE_TASK_PUSH_VLAN_TYPE_LEN	2
#define NSE_TASK_PUSH_VLAN_ID_LEN	2
#define NSE_TASK_PUSH_VLAN_DATA_LEN	(NSE_TASK_PUSH_VLAN_TYPE_LEN  + \
						NSE_TASK_PUSH_VLAN_ID_LEN)
#define NSE_TASK_PUSH_VLAN_PARA_LEN (NSE_TASK_PUSH_VLAN_DATA_LEN >> 1)

#define NSE_TASK_COUNT_BYTE_LEN		4
#define NSE_TASK_COUNT_PKT_LEN		4
#define NSE_TASK_COUNT_DATA_LEN	(NSE_TASK_COUNT_PKT_LEN  + \
						NSE_TASK_COUNT_BYTE_LEN)
#define NSE_TASK_COUNT_PARA_LEN (NSE_TASK_COUNT_DATA_LEN >> 1)

#define NSE_TASK_METER_RED_PCOUNT_LEN		4
#define NSE_TASK_METER_RED_BCOUNT_LEN		4
#define NSE_TASK_METER_GRN_PCOUNT_LEN		4
#define NSE_TASK_METER_GRN_BCOUNT_LEN		4
#define NSE_TASK_METER_ID_LEN				2
#define NSE_TASK_METER_DATA_LEN	(NSE_TASK_METER_RED_PCOUNT_LEN  + \
								NSE_TASK_METER_RED_BCOUNT_LEN  + \
								NSE_TASK_METER_GRN_PCOUNT_LEN  + \
								NSE_TASK_METER_GRN_BCOUNT_LEN  + \
								NSE_TASK_METER_ID_LEN)
#define NSE_TASK_METER_PARA_LEN (NSE_TASK_METER_DATA_LEN >> 1)

#define NSE_TASK_FWD_DATA_LEN		2
#define NSE_TASK_FWD_PARA_LEN (NSE_TASK_FWD_DATA_LEN >> 1)

#define NSE_TASK_VXLAN_V4_ENCAP_DATA_LEN 50
#define NSE_TASK_VXLAN_V6_ENCAP_DATA_LEN 70

#define NSE_TASK_REWRITE_MAC_VAL_LEN 6
#define NSE_TASK_REWRITE_MAC_MASK_LEN 6
#define NSE_TASK_REWRITE_MAC_DATA_LEN (NSE_TASK_REWRITE_MAC_VAL_LEN + \
						NSE_TASK_REWRITE_MAC_MASK_LEN)
#define NSE_TASK_REWRITE_MAC_PARA_LEN (NSE_TASK_REWRITE_MAC_DATA_LEN >> 1)

#define NSE_TASK_REWRITE_VLAN_VAL_LEN 2
#define NSE_TASK_REWRITE_VLAN_MASK_LEN 2
#define NSE_TASK_REWRITE_VLAN_DATA_LEN (NSE_TASK_REWRITE_VLAN_VAL_LEN + \
						NSE_TASK_REWRITE_VLAN_MASK_LEN)
#define NSE_TASK_REWRITE_VLAN_PARA_LEN (NSE_TASK_REWRITE_VLAN_DATA_LEN >> 1)

#define NSE_TASK_REWRITE_TOS_VAL_LEN 1
#define NSE_TASK_REWRITE_TOS_MASK_LEN 1
#define NSE_TASK_REWRITE_TOS_DATA_LEN (NSE_TASK_REWRITE_TOS_VAL_LEN + \
						NSE_TASK_REWRITE_TOS_MASK_LEN)
#define NSE_TASK_REWRITE_TOS_PARA_LEN (NSE_TASK_REWRITE_TOS_DATA_LEN >> 1)

#define NSE_TASK_REWRITE_TTL_VAL_LEN 1
#define NSE_TASK_REWRITE_TTL_MASK_LEN 1
#define NSE_TASK_REWRITE_TTL_DATA_LEN (NSE_TASK_REWRITE_TTL_VAL_LEN + \
						NSE_TASK_REWRITE_TTL_MASK_LEN)
#define NSE_TASK_REWRITE_TTL_PARA_LEN (NSE_TASK_REWRITE_TTL_DATA_LEN >> 1)

#define NSE_TASK_REWRITE_IP_VAL_LEN 4
#define NSE_TASK_REWRITE_IP_MASK_LEN 4
#define NSE_TASK_REWRITE_IP_DATA_LEN  (NSE_TASK_REWRITE_IP_VAL_LEN + \
						NSE_TASK_REWRITE_IP_MASK_LEN)
#define NSE_TASK_REWRITE_IP_PARA_LEN (NSE_TASK_REWRITE_IP_DATA_LEN >> 1)

#define NSE_TASK_REWRITE_HLIMIT_VAL_LEN 1
#define NSE_TASK_REWRITE_HLIMIT_MASK_LEN 1
#define NSE_TASK_REWRITE_HLIMIT_DATA_LEN (NSE_TASK_REWRITE_HLIMIT_VAL_LEN + \
						NSE_TASK_REWRITE_HLIMIT_MASK_LEN)
#define NSE_TASK_REWRITE_HLIMIT_PARA_LEN (NSE_TASK_REWRITE_HLIMIT_DATA_LEN >> 1)

#define NSE_TASK_REWRITE_IPV6_VAL_LEN 16
#define NSE_TASK_REWRITE_IPV6_MASK_LEN 16
#define NSE_TASK_REWRITE_IPV6_DATA_LEN  (NSE_TASK_REWRITE_IPV6_VAL_LEN + \
						NSE_TASK_REWRITE_IPV6_MASK_LEN)
#define NSE_TASK_REWRITE_IPV6_PARA_LEN (NSE_TASK_REWRITE_IPV6_DATA_LEN >> 1)

#define NSE_TASK_REWRITE_PORT_VAL_LEN 2
#define NSE_TASK_REWRITE_PORT_MASK_LEN 2
#define NSE_TASK_REWRITE_PORT_DATA_LEN  (NSE_TASK_REWRITE_PORT_VAL_LEN + \
						NSE_TASK_REWRITE_PORT_MASK_LEN)
#define NSE_TASK_REWRITE_PORT_PARA_LEN  (NSE_TASK_REWRITE_PORT_DATA_LEN >> 1)

#define NSE_DU_DATE_SIZE_32 32
#define NSE_DU_DATE_SIZE_64 64
#define NSE_DU_DATE_SIZE_96 96
#define NSE_DU_DATE_SIZE_128 128
#define NSE_DU_DATE_SIZE_160 160
#define NSE_DU_DATE_SIZE_192 192
#define NSE_DU_DATE_SIZE_224 224
#define NSE_DU_DATE_SIZE_256 256

struct nse_du_desc {
	u16 du_data_id; /*hw id*/
	/*32B or 64B or 96B or 128B*/
	u16 data_size;
	/*data memory which has data_size Bytes*/
	__u8 data[];
};

struct nse_sw_encap_key {
	const struct ip_tunnel_key *ip_tun_key;
	int tun_type;
};

/*single encap struct*/
struct nse_sw_encap_entry {
	struct list_head list_entry; /* attath to global encap table*/
	struct list_head fltr_list; /*list head to store multi fltrs*/
	struct mutex fltr_list_lock; /*protect fltr_list*/
	struct list_head encap_list; /* attath to neigh entry*/
	refcount_t ref_cnt;
	struct ip_tunnel_info *tun_info;
	int tun_type;
	unsigned short family;
	u8	dmac[ETH_ALEN];

	struct net_device *out_dev;
	int route_dev_ifindex;
	bool valid;

	struct nse_neigh_entry *neigh_entry; /*neigh entry that cur encap entry attath to*/
	struct nse_du_desc du_desc;
};

struct nse_sw_m_encap_key {
	u16 encap_cnt;
	int tun_type;
	struct nse_sw_encap_entry *encap_entry[NSE_MAX_FLOW_ENCAP_CNT];
};

/*multi encap struct*/
struct nse_sw_m_encap_entry {
	struct list_head list_entry;

	refcount_t ref_cnt;

	u16 encap_cnt;
	int tun_type;
	unsigned short family;

	struct nse_sw_encap_entry *encap_entry[NSE_MAX_FLOW_ENCAP_CNT];
	struct nse_du_desc du_desc;
};

struct nse_sw_encap_item {
	struct nse_sw_encap_entry *e;
	struct list_head list_entry; /* attached cur fltr to encap entry filt_list */
	int index;
};

/*du data is du desc set, which belong to same fltr.
 * for now, only signal desc in one du data obj
 */
struct nse_sw_du_data {
	struct list_head list_entry;
	/*hard code to 1 temporarily now*/
	u16 du_desc_cnt;
	struct nse_du_desc du_desc;
};

#define NSE_NODE_STATE_ID_INVALID	0xffff
#define NSE_VSI_LIST_ID_INVALID		0xffff
#define NSE_TASK_LIST_ID_INVALID		0xffff
#define NSE_DU_DATA_ID_INVALID		0xffff
#define NSE_COUNTER_ID_INVALID		0xffff
#define NSE_METER_ID_INVALID			0xffff
#define NSE_NODE_ID_INVALID			0xffff

struct nse_node_state {
	u16 node_state_id; /*hw id*/

	bool is_lite; /* indicated cur node state is lite format or not*/
	bool is_slowpath; /* indicated cur node state is slowpath or not*/
	bool is_fast;
	bool is_fast_created;

	/* indicated cur flow's src chain id is 0, and goto other chain,
	 * then original packet is needed when ovs miss.
	 */
	bool is_slowp_orig;

	u8 md_num;
	u16 md_value[NSE_MAX_MD_VALUE_NUM];

	/*Slow AU information, executed by CSky*/
	u16 au_task_cnt;
	u16 task_list_id;
	u16 du_desc_cnt;
	struct nse_du_desc du_desc[NSE_MAX_DU_DESC_NUM];

	/*Fast DU information, executed by HW*/
	u16 du_act_cnt;
	struct nse_du_action du_action[NSE_MAX_DU_ACTION_NUM];
};

enum nse_status
nse_add_vsi(struct nse_hw *hw, u16 vsi_handle, struct nse_vsi_ctx *vsi_ctx,
	    struct nse_sq_cd *cd);
enum nse_status
nse_free_vsi(struct nse_hw *hw, u16 vsi_handle, struct nse_vsi_ctx *vsi_ctx,
	    struct nse_sq_cd *cd);
enum nse_status
nse_update_vsi(struct nse_hw *hw, u16 vsi_handle, struct nse_vsi_ctx *vsi_ctx,
	       struct nse_sq_cd *cd);
struct nse_vsi_ctx *nse_get_vsi_ctx(struct nse_hw *hw, u16 vsi_handle);
void nse_clear_all_vsi_ctx(struct nse_hw *hw);
enum nse_status
nse_aq_get_vsi_params(struct nse_hw *hw, struct nse_vsi_ctx *vsi_ctx,
		      struct nse_sq_cd *cd);

enum nse_status
nse_init_def_lut(struct nse_hw *hw, struct nse_lut_info **lut_list);
enum nse_status
nse_init_def_profiles(struct nse_hw *hw, struct nse_profile_info **profile_list);
void nse_get_prof_index_max(struct nse_hw *hw);

enum nse_status
nse_aq_get_sw_cfg(struct nse_hw *hw, void *buf, u16 buf_size);

void nse_dump_sw_aq_cfg(struct nse_hw *hw);
void nse_dump_sw_aq_profile_all(struct nse_hw *hw);
void nse_dump_sw_aq_lut_node(struct nse_hw *hw, u16 node_id);
void nse_dump_sw_aq_recipe(struct nse_hw *hw, u8 rcp_id);

void nse_dump_sw_fltr_rules(struct nse_hw *hw, enum nse_sw_lkup_type lookup);
void nse_dump_all_profiles(struct nse_hw *hw);
void nse_del_all_adv_rcp_per_profile(struct nse_hw *hw);
void nse_del_all_adv_luts(struct nse_hw *hw);

void nse_dump_all_adv_luts(struct nse_hw *hw);
void nse_dump_root_adv_luts(struct nse_hw *hw);
void nse_dump_adv_lut_nodes(struct nse_hw *hw, u8 lut_id);

enum nse_status
nse_aq_alloc_free_res(struct nse_hw *hw, u16 num_entries,
		      struct nse_aqc_alloc_free_res_elem *buf, u16 buf_size,
		      enum nse_adminq_opc_category_switch_subcodes opc,
		      struct nse_sq_cd *cd);

enum nse_status nse_get_initial_sw_cfg(struct nse_hw *hw);
enum nse_status nse_add_mac(struct nse_hw *hw, struct list_head *m_list);
enum nse_status nse_add_bmc_mac(struct nse_hw *hw, struct list_head *m_list);
enum nse_status nse_add_roce_mac(struct nse_hw *hw, struct list_head *m_list);
enum nse_status nse_add_vlan(struct nse_hw *hw, struct list_head *v_list);
enum nse_status
nse_add_mac_vlan(struct nse_hw *hw, struct list_head *mv_list);
enum nse_status
nse_add_eth_mac(struct nse_hw *hw, struct list_head *em_list);
enum nse_status
nse_cfg_roce_fltr(struct nse_hw *hw, u16 vsi_handle, bool enable);

enum nse_status nse_remove_mac(struct nse_hw *hw, struct list_head *m_list);
enum nse_status nse_remove_bmc_mac(struct nse_hw *hw, struct list_head *m_list);
enum nse_status nse_remove_roce_mac(struct nse_hw *hw, struct list_head *m_list);
enum nse_status nse_remove_vlan(struct nse_hw *hw, struct list_head *v_list);
enum nse_status
nse_remove_mac_vlan(struct nse_hw *hw, struct list_head *mv_list);
enum nse_status
nse_remove_eth_mac(struct nse_hw *hw, struct list_head *em_list);
void nse_remove_vsi_fltr(struct nse_hw *hw, u16 vsi_handle);

enum nse_status
nse_replay_vsi_all_fltr_flex(struct nse_hw *hw, u16 vsi_handle);

void nse_drain_sw_replay_list_flex(struct nse_hw *hw);

void nse_replace_sw_replay_list_flex(struct nse_hw *hw);

enum nse_status
nse_set_vsi_promisc(struct nse_hw *hw, u16 vsi_handle, u8 promisc_mask,
		    u16 vid);
enum nse_status
nse_clear_vsi_promisc(struct nse_hw *hw, u16 vsi_handle, u8 promisc_mask,
		      u16 vid);
enum nse_status
nse_set_vlan_vsi_promisc(struct nse_hw *hw, u16 vsi_handle, u8 promisc_mask,
			 bool rm_vlan_promisc);

/* Get VSIs Promisc/defport settings */
enum nse_status
nse_get_vsi_promisc(struct nse_hw *hw, u16 vsi_handle, u8 *promisc_mask,
		    u16 *vid);
enum nse_status
nse_get_vsi_vlan_promisc(struct nse_hw *hw, u16 vsi_handle, u8 *promisc_mask,
			 u16 *vid);
int
nse_add_adv_node(struct nse_hw *hw, struct nse_adv_lkup_elem *lkups,
		 u16 lkups_cnt, struct nse_adv_node_info *rinfo,
		 struct nse_node_query_data *added_entry);
int
nse_rem_adv_node_by_id(struct nse_hw *hw,
		       struct nse_node_query_data *remove_entry);

int
nse_rem_adv_fast_node(struct nse_hw *hw,
				struct nse_node_query_data *remove_entry);

struct nse_sw_counter_pair *
nse_sw_creat_counter_pair(struct nse_hw *hw, bool aging);

struct nse_sw_counter_pair *
nse_sw_creat_fast_counter_p(struct nse_hw *hw,
							u16 p_hw_id, u16 b_hw_id, bool aging);

int
nse_sw_destroy_counter_pair(struct nse_hw *hw,
						struct nse_sw_counter_pair *counter);

enum nse_status
nse_init_sw_stats(struct nse_hw *hw);

void nse_sw_dump_du_datas(struct nse_hw *hw);

void nse_sw_dump_task_lists(struct nse_hw *hw);

void nse_sw_dump_meters(struct nse_hw *hw);

void nse_sw_dump_vsi_list(struct nse_hw *hw);

void nse_sw_dump_stats(struct nse_hw *hw);

void nse_cleanup_sw_stats(struct nse_hw *hw);

int
nse_sw_add_node_state(struct nse_hw *hw, struct nse_node_state *node_state,
				u16 du_act_cnt, u16 au_task_cnt, u16 du_desc_cnt);
int
nse_sw_add_lite_node_state(struct nse_hw *hw,
				struct nse_node_state *node_state, u16 du_act_cnt);
int
nse_sw_rem_node_state(struct nse_hw *hw, u16 *node_state_id);

int
nse_sw_rem_lite_node_state(struct nse_hw *hw, u16 *node_state_id);

struct nse_sw_du_data *
nse_sw_creat_du_data(struct nse_hw *hw, u16 d_size);

int
nse_sw_destroy_du_data(struct nse_hw *hw, struct nse_sw_du_data *du_data);

int
nse_sw_add_du_data(struct nse_hw *hw, struct nse_sw_du_data *du_data);

struct nse_sw_task_list *
nse_sw_get_task_list(struct nse_hw *hw, struct nse_sw_task_list *cur_task_list);

int
nse_sw_put_task_list(struct nse_hw *hw, struct nse_sw_task_list *task_list);

int
nse_sw_destroy_task_list(struct nse_hw *hw, struct nse_sw_task_list *task_list);

struct nse_sw_meter *
nse_sw_get_meter(struct nse_hw *hw, struct nse_sw_meter_param *meter_param);

int
nse_sw_put_meter(struct nse_hw *hw, struct nse_sw_meter *meter);

struct nse_sw_meter *
nse_sw_find_meter(struct nse_hw *hw, struct nse_sw_meter_param *meter_param);

int
nse_sw_destroy_meter(struct nse_hw *hw, struct nse_sw_meter *meter);

int
nse_sw_get_sflow(struct nse_hw *hw, struct nse_sw_sflow_info *sflow_info,
					struct nse_sw_sflow **sflow);

int
nse_sw_put_sflow(struct nse_hw *hw, struct nse_sw_sflow *sflow);

void
nse_cleanup_sw_sflow(struct nse_hw *hw);

struct nse_vsi_list_map_info *
nse_sw_get_adv_vlist(struct nse_hw *hw,
		u16 *vsi_handle_arr, u16 num_vsi);

int
nse_sw_put_adv_vlist(struct nse_hw *hw,
		struct nse_vsi_list_map_info *vsi_list_info);

struct nse_sw_encap_entry *
nse_sw_find_encap_entry(struct nse_hw *hw, struct nse_sw_encap_key *key);

struct nse_sw_encap_entry *
nse_sw_creat_encap_entry(struct nse_hw *hw, u16 d_size);

int
nse_sw_add_encap_entry(struct nse_hw *hw,
					struct nse_sw_encap_entry *encap_entry);

int
nse_sw_update_encap_entry(struct nse_hw *hw,
					struct nse_sw_encap_entry *encap_entry);

struct nse_sw_m_encap_entry *
nse_sw_find_m_encap_entry(struct nse_hw *hw, struct nse_sw_m_encap_key *key);

struct nse_sw_m_encap_entry *
nse_sw_creat_m_encap_entry(struct nse_hw *hw, u16 d_size);

int
nse_sw_add_m_encap_entry(struct nse_hw *hw,
					struct nse_sw_m_encap_entry *m_encap_entry);

int
nse_sw_set_mode(struct nse_hw *hw, enum nse_sw_mode *mode);

int
nse_sw_destroy_encap_entry(struct nse_hw *hw,
					struct nse_sw_encap_entry *encap_entry);

int
nse_sw_destroy_m_encap_entry(struct nse_hw *hw,
					struct nse_sw_m_encap_entry *m_encap_entry);

int
nse_sw_put_encap_entry(struct nse_hw *hw, struct nse_sw_encap_entry *encap_entry);

int
nse_sw_put_m_encap_entry(struct nse_hw *hw, struct nse_sw_m_encap_entry *m_encap_entry);

enum nse_status
nse_aq_get_counter_val(struct nse_hw *hw, void *buf, u16 buf_size);

enum nse_status
nse_aq_get_pol_counter_val(struct nse_hw *hw, void *buf, u16 buf_size);

void
nse_sw_stats_read_event(struct nse_hw *hw,
			struct nse_rq_event_info *event);

enum nse_status
nse_aq_get_sw_cap(struct nse_hw *hw, void *buf, u16 buf_size);

enum nse_status
nse_aq_get_res_usage(struct nse_hw *hw, void *buf, u16 buf_size);

bool nse_is_vsi_valid(struct nse_hw *hw, u16 vsi_handle);

u16
nse_get_hw_vsi_num(struct nse_hw *hw, u16 vsi_handle);

enum nse_status
nse_create_vsi_list_rule(struct nse_hw *hw, u16 *vsi_handle_arr, u16 num_vsi,
			 u16 *vsi_list_id, enum nse_sw_lkup_type lkup_type);

enum nse_status
nse_release_vsi_list(struct nse_hw *hw, u16 vsi_list_id,
			 enum nse_sw_lkup_type lkup_type);

int
nse_sw_set_slowpath(struct nse_hw *hw, struct nse_node_state *node_state, bool enable);

enum nse_status
nse_aq_lut_nodes(struct nse_hw *hw, void *buf, u16 buf_size,
		enum nse_adminq_opc_category_switch_subcodes opc,
		struct nse_sq_cd *cd);

void
nse_set_rinfo_action_lan(struct nse_adv_node_info *rinfo,
		u16 *act);

void nse_init_prof_result_bm(struct nse_hw *hw);

int
nse_fill_lkup_key_word(struct nse_hw *hw, struct nse_adv_lkup_elem *lkups,
		 u16 lkups_cnt, struct nse_fv_word *pair, __le16 *key);

int
nse_build_adv_action_field(struct nse_adv_node_info *rinfo,
		u16 *out_act, u16 *out_lg_act);

u8
nse_fill_valid_words(struct nse_adv_lkup_elem *lkup_elem,
		     struct nse_prot_lkup_ext *lkup_exts);

void
nse_get_compat_fv_bitmap(struct nse_hw *hw, struct nse_adv_node_info *rinfo,
			 unsigned long *bm);

int
nse_get_fv(struct nse_hw *hw, struct nse_prot_lkup_ext *lkup_exts,
	   unsigned long *bm, struct list_head *fv_list);

int
nse_fill_fv_word_index(struct nse_hw *hw, struct list_head *fv_list,
		       struct list_head *lut_group_list);

u16 nse_find_lut(struct nse_hw *hw, struct nse_prot_lkup_ext *lkup_exts,
			 struct nse_adv_node_info *rinfo, bool is_lpm);

enum nse_status
nse_aq_alloc_free_lpm_lut_id(struct nse_hw *hw, u16 *lut_id,
			   enum nse_adminq_opc_category_switch_subcodes opc);

void nse_collect_result_idx(struct nse_aqc_recipe_data_elem *buf,
				   struct nse_lut_info *lut);

enum nse_status
nse_aq_add_recipe(struct nse_hw *hw, void *buf, u16 buf_size);

u16
nse_find_free_recp_res_idx(struct nse_hw *hw,
				const unsigned long *profiles_bm,
			    unsigned long *free_idx_bm);

void
nse_init_node_state(struct nse_node_state *node_state);

enum nse_status
nse_sw_meter_calc_hw_rate(struct nse_hw *hw, u64 rate, u32 *hw_rate);

enum nse_status
nse_get_remove_vsi_list(struct nse_hw *hw, u16 vsi_list_id,
			 enum nse_adminq_opc_category_switch_subcodes opc,
			 u32 *vsi_bm_arr, int num_arr);
void
nse_sw_stats_remove_pair(struct nse_hw *hw,
				struct nse_sw_counter_pair *counter_p);

#endif /* _NSE_SWITCH_H_ */

