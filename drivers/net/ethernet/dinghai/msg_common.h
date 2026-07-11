/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#ifndef __ZXDH_MSG_COMMON_H__
#define __ZXDH_MSG_COMMON_H__
#include "en_np/table/include/dpp_tbl_api.h"
#include "en_aux/queue.h"
#include "en_pf.h"

#define ZXDH_VLAN_TCI_GEN(vid, qos) ((vid) | ((qos) << 12))
#define FW_VERSION_LEN 32
#define ZXDH_REPS_BEYOND_MAC 0xfe
#define ZXDH_REPS_EXIST_MAC 0xfd
#define MAX_QUE_CNT 60
#define ZXDH_REPS_MAX_SIZE_BEFORE57 1032
#define BAR_MSG_RETRY_CNT_MAX 100

#define ZXDH_BAR_DUALTOR_LABEL_ON (0xaaaaaaaa)
#define ZXDH_DUALTOR_LABEL_OFFSET (0x5000 + 1920)

#define DEFAULT_ADD_INDEX 0XFFFFFFFF
enum zxdh_msg_op_code {
	ZXDH_NULL = 0,

	ZXDH_VF_PORT_INIT = 1,
	ZXDH_VF_PORT_UNINIT = 2,
	ZXDH_MAC_ADD = 3,
	ZXDH_MAC_DEL = 4,
	ZXDH_MAC_GET = 5,

	ZXDH_RSS_EN_SET = 7,
	ZXDH_RXFH_SET = 8,
	ZXDH_RXFH_GET = 9,
	ZXDH_RXFH_DEL = 10,
	ZXDH_THASH_KEY_SET = 11,
	ZXDH_THASH_KEY_GET = 12,
	ZXDH_HASH_FUNC_SET = 13,
	ZXDH_HASH_FUNC_GET = 14,
	ZXDH_RX_FLOW_HASH_SET = 15,
	ZXDH_RX_FLOW_HASH_GET = 16,

	ZXDH_VLAN_FILTER_SET = 17,
	ZXDH_VLAN_FILTER_ADD = 18,
	ZXDH_VLAN_FILTER_DEL = 19,
	ZXDH_VLAN_OFFLOAD_SET = 21,

	ZXDH_PORT_ATTRS_GET = 22,
	ZXDH_SET_TPID = 23,
	ZXDH_VXLAN_OFFLOAD_ADD = 24,
	ZXDH_PORT_ATTRS_SET = 25,
	ZXDH_PROMISC_SET = 26,

	/*sriov msg type*/
	ZXDH_SRIOV_RESET = 27,

	ZXDH_SET_VF_LINK_STATE = 28,
	ZXDH_PF_SET_VF_VLAN = 29,
	ZXDH_SET_VF_RESET = 30,
	ZXDH_GET_NP_STATS = 31,

	ZXDH_VF_RATE_LIMIT_SET = 32,
	ZXDH_PLCR_UNINIT = 33,
	ZXDH_MAP_PLCR_FLOWID = 34,
	ZXDH_PLCR_FLOW_INIT = 35,
	ZXDH_PLCR_CAR_PROFILE_ID_ADD = 36,
	ZXDH_PLCR_CAR_PROFILE_ID_DELETE = 37,
	ZXDH_PLCR_CAR_PROFILE_CFG_SET = 38,
	ZXDH_PLCR_CAR_PROFILE_CFG_GET = 39,
	ZXDH_PLCR_CAR_QUEUE_CFG_SET = 40,
	ZXDH_PORT_METER_STAT_CLR = 41,
	ZXDH_PORT_METER_STAT_GET = 42,
	ZXDH_PF_GET_VF_QUEUE_INFO = 43,
	ZXDH_PLCR_GET_MODE = 44,
	ZXDH_PLCR_SET_MODE = 45,
	ZXDH_FLOW_HW_ADD = 46,
	ZXDH_FLOW_HW_DEL = 47,
	ZXDH_FLOW_HW_GET = 48,
	ZXDH_FLOW_HW_FLUSH = 49,

	ZXDH_VF_1588_CALL_NP = 50,
	ZXDH_VF_SLOT_ID_GET = 51,

	ZXDH_IPV6_MAC_ADD = 52,
	ZXDH_IPV6_MAC_DEL = 53,
	ZXDH_MAC_DUMP = 54,
	ZXDH_MC_CMPAT_VERINFO = 55,
	ZXDH_GET_K_CMPAT_VERINFO = 56,
	ZXDH_GET_SW_STATS = 57,
	ZXDH_LACP_MAC_ADD = 58,
	ZXDH_LACP_MAC_DEL = 59,
	ZXDH_VXLAN_OFFLOAD_DEL = 60,
	ZXDH_VF_PORT_RELOAD = 61,
	ZXDH_VF_1588_ENABLE = 62,
	ZXDH_VF_GET_UDP_STATS = 63,
	ZXDH_FD_ADD = 64,
	ZXDH_FD_GET = 65,
	ZXDH_FD_DEL = 66,
	ZXDH_FD_EN_SET = 67,
	ZXDH_MSG_TYPE_CNT_MAX, /* should be at last */
};

enum dh_flow_type {
	FLOW_TYPE_FLOW = 0,
	FLOW_TYPE_FD_TCAM,
	FLOW_TYPE_FD_SW,
};

enum {
	FD_ACTION_VXLAN_ENCAP = 0,
	FD_ACTION_VXLAN_DECAP = 1,
	FD_ACTION_RSS_BIT = 2,
	FD_ACTION_COUNT_BIT = 3,
	FD_ACTION_DROP_BIT = 4,
	FD_ACTION_MARK_BIT = 5,
	FD_ACTION_QUEUE_BIT = 6,
};

enum vqm_msg_opcode {
	MSIX_MODE_GET = 0,
	MSIX_MODE_SET = 1,
	OPCODE_GET = 0,
	OPCODE_SET = 1,
};

enum vqm_msg_cmd {
	VQM_VF_FC_CMD = 0x9,
	MSIX_MODE_CMD = 0x10,
	OVS_VQM_CTRL_RESET_QIDS = 0x11,
	COALESCE_USECS_CMD = 0xf,
};

struct vqm_wr_used_t {
	u16 rx_used_ring_t;
	u16 tx_used_ring_t;
} __packed;

struct vqm_msix_mode {
	u16 rx_msix_mode;
	u16 tx_msix_mode;
} __packed;

struct vqm_phy_qid {
#define ZXDH_VNET_ZTE (0x6)
	u8 version;
	u8 qnum;
#define MAX_QNUM ((ZXDH_QUEUE_PAIRS_MAX + 1) * 2)
	u32 qid[MAX_QNUM];
} __packed;

struct vqm_flow_cfg {
	u32 pps;
	u32 kbps;
} __packed;

struct host_to_vqm_msg {
	u16 vqm_vfid;
	u16 opcode;
	u16 cmd; /* cmd - 0x10 */

	union {
		struct vqm_wr_used_t wr_used_t;
		struct vqm_msix_mode msix_mode_sel;
		struct vqm_phy_qid qid_reset_msg;
		struct vqm_flow_cfg vqm_vf_fc;
	} __packed;
} __packed;

struct vqm_rsp_host_data {
	u32 check_result;
	union {
		struct vqm_wr_used_t wr_used_t;
		struct vqm_msix_mode msix_mode_sel;
		struct vqm_flow_cfg vqm_vf_fc;
	} __packed;
} __packed;

struct fd_flow_key {
	u8 mac_dst[ZXDH_MAC_NUM];
	u8 mac_src[ZXDH_MAC_NUM];
	u16 ether_type;
	union {
		struct {
			u16 cvlan_pri : 4;
			u16 cvlan_vlanid : 12; /* vlanid 0xfff is valid */
		};
		u16 vlan_tci;
	};

	u8 src_ip[16];
	u8 dst_ip[16];
	u8 rsv0;
	union {
		u8 tos;
		u8 tc;
	};
	u8 nw_proto;
	u8 frag_flag;
	u16 tp_src;
	u16 tp_dst;

	u8 rsv1;
	u8 vni[3];

	u16 vfid;
	u8 rsvs[18];
} __packed;

struct fd_flow_result {
	u16 qid;
	u8 rsv0;

	u8 action_idx : 7;
	u8 hit_flag : 1;

	u32 mark_fd_id;
	u32 countid : 20;
	u32 sriov_tunnel_encap1_index : 12;

	u16 sriov_tunnel_encap0_index : 12;
	u16 rsv1 : 4;
	u8 rss_hash_factor;
	u8 rss_hash_alg;
} __packed;

struct fd_flow_entry {
	struct fd_flow_key key;
	struct fd_flow_key key_mask;
	struct fd_flow_result result;
} __packed;

struct zxdh_flow_info {
	enum dh_flow_type flowtype;
	u16 hw_idx;
	u16 rsv;
	union {
		struct fd_flow_entry fd_flow;
	};
} __packed;

struct zxdh_flow {
	u8 direct;
	u8 group;
	u8 pri;
	u8 hash_search_idx;
	struct zxdh_flow_info flowentry;
} __packed;

struct zxdh_msg_head_to_pf {
	enum zxdh_msg_op_code op_code;
	u16 vport;
	u16 vf_id;
	u16 pcie_id;
} __packed;

struct zxdh_msg_head_to_vf {
	enum zxdh_msg_op_code op_code;
	u16 dst_pcie_id;
} __packed;

struct zxdh_vf_init_msg {
	bool link_up;
	bool is_upf;
	u16 base_qid;
	u8 mac_addr[ZXDH_MAC_NUM];
	u32 speed;
	u32 autoneg_enable;
	u32 sup_link_modes;
	u32 adv_link_modes;
	u8 hash_search_idx;
	u8 duplex;
	u8 phy_port;
	u8 rss_enable;
	u16 vlan_id;
	u16 tpid;
	u8 vlan_qos;
	u8 addr_assign_type;
} __packed;

struct zxdh_vf_reload_msg {
	bool is_upf;
	bool uc_promisc;
	bool mc_promisc;
	u8 hash_search_idx;
	u16 base_qid;
	u8 vlan_qos;
	u8 hash_func;
	u32 hash_mode;
	u32 queue_map[ZXDH_INDIR_RQT_SIZE];
	u8 link_up;
	u8 speed;
	u8 duplex;
#define VLAN_BITMAP_BYTE_SIZE (512)
	u8 vlan_trunk_bitmap[VLAN_BITMAP_BYTE_SIZE];
} __packed;

struct zxdh_vf_1588_call_np {
	u32 vfid;
	u32 call_np_interface_num;
	u32 ptp_tc_enable_opt;
} __packed;

struct zxdh_rss_enable_msg {
	u8 rss_enable;
} __packed;

struct zxdh_fd_enable_msg {
	u8 fd_enable;
} __packed;

struct zxdh_vf_fd_cfg_msg {
	struct ethtool_rx_flow_spec fs;
	u32 index;
} __packed;
struct zxdh_strip_enable_msg {
	bool enable;
#define VLAN_STRIP_MSG_TYPE 0
#define QINQ_STRIP_MSG_TYPE 1
	u8 flag;
} __packed;

struct zxdh_set_vf_vlan_msg {
	u16 vf_idx;
	u16 vlan_id;
	u8 qos;
	u8 rsv;
	u16 protocl;
} __packed;

struct zxdh_qinq_tpid_cfg_msg {
	u16 tpid;
} __packed;

struct zxdh_rxfh_set_msg {
	u32 queue_map[ZXDH_INDIR_RQT_SIZE];
} __packed;

struct zxdh_thash_key_set_msg {
	u8 key_map[ZXDH_NET_HASH_KEY_SIZE];
} __packed;

struct zxdh_slot_id_msg {
	u16 slot_id;
} __packed;

struct zxdh_hfunc_set_msg {
	u8 func;
} __packed;

struct zxdh_rx_flow_hash_set_msg {
	u32 hash_mode;
} __packed;

struct zxdh_mac_addr_msg {
	bool mac_flag;
	u8 filter_flag;
	u8 mac_addr[ZXDH_MAC_NUM];
} __packed;

struct zxdh_ipv6_mac_addr_msg {
	u8 mac_addr[ZXDH_MAC_NUM];
} __packed;

struct zxdh_port_attr_set_msg {
	u32 mode;
	u32 value;
	u8 allmulti_follow;
} __packed;

#define ZXDH_PROMISC_MODE 1
#define ZXDH_ALLMULTI_MODE 2
struct zxdh_promisc_set_msg {
	u8 mode;
	u8 value;
	u8 mc_follow;
} __packed;

struct common_recv_msg {
	u8 rsv2;
	u16 read_bytes;
	u8 value;
} __packed;

struct common_vq_msg {
	u8 rsv2;
	u16 read_bytes;
	u16 queue_nums;
	u16 phy_qidx[256];
} __packed;

enum agent_msg_op_code {
	AGENT_MAC_STATS_CLEAR = 11,
	AGENT_MAC_PHYPORT_INIT,
	AGENT_MAC_AUTONEG_SET,
	AGENT_MAC_LINK_INFO_GET,
	AGENT_MAC_LED_BLINK,
	AGENT_MAC_FEC_MODE_SET,
	AGENT_MAC_FEC_MODE_GET,
	AGENT_MAC_FC_MODE_SET,
	AGENT_MAC_FC_MODE_GET,
	AGENT_MAC_MODULE_EEPROM_READ,
	AGENT_VQM_DEVICE_STATS_GET,
	AGENT_VQM_STATS_CLEAR,
	AGENT_FLASH_FIR_VERSION_GET = 23,
	AGENT_DEV_STATUS_NOTIFY,
	AGENT_DEBUG_LLDP_ENABLE_SET,
	AGENT_DEBUG_LLDP_ENABLE_GET,
	AGENT_SSHD_START,
	AGENT_SSHD_STOP,
	AGENT_FLASH_MAC_READ,
	AGENT_FLASH_MAC_WRITE,
	AGENT_FLASH_MAC_ERASE,
	AGENT_MAC_RECOVERY_CLK_SET,
	AGENT_MAC_SYNCE_CLK_STATS_GET,
	AGENT_MAC_PORT_TSTAMP_ENABLE_SET,
	AGENT_MAC_PORT_TSTAMP_ENABLE_GET,
	AGENT_MAC_PORT_TSTAMP_MODE_SET,
	AGENT_MAC_PORT_TSTAMP_MODE_GET,
	AGENT_MAC_PORT_DELAY_VALUE_GET,
	AGENT_MAC_PORT_DELAY_VALUE_CLR,
	AGENT_SLOT_INFO_SEND = 40,
	AGENT_OS_TYPE_GET = 41,
	AGENT_DTP_STATS_GET,
	AGENT_SPM_PORT_ENABLE_SET,
	AGENT_MAC_MSG_NUM_MAX, /* should be at last */
};

struct agent_msg_hdr {
	enum agent_msg_op_code op_code;
	u8 port_id;
	u8 phyport;
	u8 is_upf;
	u16 vf_id;
	u16 pcie_id;
} __packed;

struct agent_mac_autoneg_msg {
	u8 autoneg;
	u8 link_state;
	u8 blink_enable;
	u8 duplex;
	u32 speed_modes;
	u32 speed;
} __packed;

struct agent_stats {
	u64 rx_total;
	u64 tx_total;
	u64 rx_total_bytes;
	u64 tx_total_bytes;
	u64 rx_error;
	u64 tx_error;
	u64 rx_drop;
	u64 tx_drop;
	u64 rx_good_bytes;
	u64 tx_good_bytes;
	u64 rx_unicast;
	u64 tx_unicast;
	u64 rx_multicast;
	u64 tx_multicast;
	u64 rx_broadcast;
	u64 tx_broadcast;
	u64 rx_undersize;
	u64 rx_size_64;
	u64 rx_size_65_127;
	u64 rx_size_128_255;
	u64 rx_size_256_511;
	u64 rx_size_512_1023;
	u64 rx_size_1024_1518;
	u64 rx_size_1519_mru;
	u64 rx_oversize;
	u64 tx_undersize;
	u64 tx_size_64;
	u64 tx_size_65_127;
	u64 tx_size_128_255;
	u64 tx_size_256_511;
	u64 tx_size_512_1023;
	u64 tx_size_1024_1518;
	u64 tx_size_1519_mtu;
	u64 tx_oversize;
	u64 rx_pause;
	u64 tx_pause;
	u64 rx_fcs_error;
	u64 tx_fcs_error;
	u64 rx_mac_control;
	u64 tx_mac_control;
	u64 rx_fragment;
	u64 tx_fragment;
	u64 rx_jabber;
	u64 tx_jabber;
	u64 rx_vlan;
	u64 tx_vlan;
	u64 rx_eee;
	u64 tx_eee;
} __packed;

struct np_stats {
	u64 np_rx_vport_unicast_packets;
	u64 np_tx_vport_unicast_packets;
	u64 np_rx_vport_unicast_bytes;
	u64 np_tx_vport_unicast_bytes;
	u64 np_rx_vport_multicast_packets;
	u64 np_tx_vport_multicast_packets;
	u64 np_rx_vport_multicast_bytes;
	u64 np_tx_vport_multicast_bytes;
	u64 np_rx_vport_broadcast_packets;
	u64 np_tx_vport_broadcast_packets;
	u64 np_rx_vport_broadcast_bytes;
	u64 np_tx_vport_broadcast_bytes;
	u64 np_rx_vport_mtu_drop_packets;
	u64 np_tx_vport_mtu_drop_packets;
	u64 np_rx_vport_mtu_drop_bytes;
	u64 np_tx_vport_mtu_drop_bytes;
	u64 np_rx_vport_plcr_drop_packets;
	u64 np_tx_vport_plcr_drop_packets;
	u64 np_rx_vport_plcr_drop_bytes;
	u64 np_tx_vport_plcr_drop_bytes;
	u64 np_tx_vport_ssvpc_packets; // switch security violation packet count, only for PF.
	u64 rx_vport_idma_drop_packets; // port to np drop (idma point not enough).
} __packed;

struct agent_mac_fec_mode_msg {
	u8 fec_cfg;
	u8 fec_cap;
	u8 fec_link;
} __packed;

struct agent_mac_fc_mode_msg {
	u8 fc_mode;
} __packed;

struct agent_flash_read_msg {
	u16 index;
} __packed;

struct agent_mac_module_eeprom_msg {
	u8 i2c_addr;
	u8 bank;
	u8 page;
	u8 offset;
	u8 length;
	u8 data[128];
} __packed;

struct zxdh_link_state_msg {
	bool is_link_force_set;
	bool link_forced;
	bool link_up;
	u32 speed;
	u32 autoneg_enable;
	u32 supported_speed_modes;
	u32 advertising_speed_modes;
	u8 duplex;
} __packed;

struct zxdh_vlan_filter_set_msg {
	bool enable;
} __packed;

struct zxdh_rx_vid_add_msg {
	u16 vlan_id;
} __packed;

struct zxdh_rx_vid_del_msg {
	u16 vlan_id;
} __packed;

struct zxdh_common_tbl_hdr {
	u8 type;
	u8 field;
	u16 pcie_id;
	u16 write_bytes;
	u16 rsv;
} __packed;

struct zxdh_cfg_time_msg {
	u8 tmmng_type;
	u8 dir;
	u16 year;
	u8 month;
	u8 day;
	u8 hour;
	u8 min;
	u8 sec;
} __packed;

struct zxdh_common_time_hdr {
	u16 pcie_id;
	u16 write_bytes;
} __packed;

struct zxdh_synce_clk_msg {
	u8 clk_speed;
	u8 clk_stats;
} __packed;

struct zxdh_mac_tstamp_msg {
	u32 tx_enable;
	u32 rx_enable;
	u32 tx_mode;
	u32 rx_mode;
} __packed;

struct zxdh_delay_statistics_val {
	u64 min_delay;
	u64 max_delay;
} __packed;

struct zxdh_bar_msg_pps {
	u16 pcieid;
	u16 extern_pps_vector;
	u16 local_pps_vector;
	u16 pps_intr_support;
} __packed;

struct zxdh_cfg_np_msg {
	u8 dev_id;
	u8 type;
	u8 operate_mode;
	u8 pfNum;
	u32 portNum[10];
	u32 evid[10];
	u32 qid[10];
} __packed;

#define MAX_HDR_LEN 8

struct zxdh_pf_cfg_mac_msg {
	char ifname[IFNAMSIZ];
	u8 mac[ETH_ALEN];
	u16 pannel_id;
	u16 ctl;
	u16 rsv;
} __packed;

#define MAX_VF_NUM 256
struct agent_pcie_msix_msg {
	u16 num;
	u16 func_no[MAX_VF_NUM];
} __packed;

struct zxdh_lldp_enable_msg {
	bool lldp_enable;
} __packed;

struct zxdh_rate_limit_set_msg {
	u32 flowid;
	u32 car_type;
	u32 is_packet;
	u32 max_rate;
	u32 min_rate;
} __packed;

/*vf send message to pf to map flow id between CARS*/
struct zxdh_plcr_flowid_map_msg {
	u32 car_type;
	u32 flowid;
	u32 map_flowid;
	u32 sp;
} __packed;

struct zxdh_plcr_flow_init_msg {
	u32 car_type;
	u32 flowid;
	u32 profile_id;
} __packed;

struct zxdh_plcr_pf_get_vf_queue_info_msg {
	u32 vir_queue_start;
	u32 vir_queue_num;
} __packed;

struct zxdh_plcr_work_mode_msg {
	u16 vport;
	u16 mode;
} __packed;

struct zxdh_vf_plcr_profile_id_add_msg {
	u8 car_type;
} __packed;

struct zxdh_vf_plcr_profile_id_delete_msg {
	u8 car_type;
	u8 rsvd;
	u16 profile_id;
} __packed;

struct zxdh_vf_plcr_profile_cfg_set_msg {
	u8 car_type;
	u8 pkt_mode;
	u16 profile_id;
	union zxdh_plcr_profile_cfg profile_cfg;
} __packed;

struct zxdh_vf_plcr_profile_cfg_get_msg {
	u8 car_type;
	u8 pkt_mode;
	u16 profile_id;
} __packed;

struct zxdh_vf_plcr_queue_cfg_set_msg {
	u8 car_type;
	u8 drop_flag;
	u8 plcr_en;
	u8 rsvd;
	u16 flow_id;
	u16 profile_id;
} __packed;

struct zxdh_vf_plcr_port_meter_stat_get_msg {
	u8 direction;
	u8 is_clr;
} __packed;

struct zxdh_vf_vxlan_port_msg {
	u16 port;
} __packed;

struct zxdh_np_stats_get_msg {
	u32 clear_mode;
	bool is_init_get;
} __packed;

struct zxdh_slot_info {
	u8 slot_info;
} __packed;

struct zxdh_port_msg {
	u16 pcie_id;
	u8 rsv[2];
} __packed;

struct port_message_recv {
	u8 hdr[4];
	u8 port_num;
	u8 bond_num;
	u8 bond_idx;
	u8 rsv;
	struct zxdh_pannle_port data[16];
} __packed;

struct zxdh_spm_port_enable {
	u32 enable;
} __packed;

struct sriov_tunnel_encap_ip_dip {
	u8 ip_addr[16];
} __packed;

struct sriov_tunnel_encap0 {
	u8 tos;
	u8 rsv2[2];
	u8 rsv1 : 6;
	u8 eth_type : 1;
	u8 hit_flag : 1;
	u16 dst_mac1;
	u16 tp_dst;
	u32 dst_mac2;

	u32 encap_ttl : 8;
	u32 vni : 24;
	struct sriov_tunnel_encap_ip_dip dip;
};

struct sriov_tunnel_encap_ip_sip {
	u8 ip_addr[16];
} __packed;

struct sriov_tunnel_encap1 {
	u32 rsv1 : 31;
	u32 hit_flag : 1;

	u16 src_mac1;
	u16 vlan_tci;
	u32 src_mac2;
	u32 rsv;
	struct sriov_tunnel_encap_ip_dip sip;
};

struct zxdh_flow_op_msg {
	struct zxdh_flow dh_flow;
	struct sriov_tunnel_encap0 encap0;
	struct sriov_tunnel_encap1 encap1;
} __packed;

struct zxdh_mcode_feature_msg {
	u32 dev_id;
	u32 index;
} __packed;

struct zxdh_k_cmpat_msg {
	u32 vfid;
} __packed;

struct health_msg_hdr {
	u16 sum_check;
	u8 opcode;
	u8 rsv;
} __packed;

struct pf_status_msg {
	u16 pcie_id;
	u16 vector;
} __packed;

struct health_config_msg {
	u8 act;
} __packed;

struct zxdh_get_sw_stats {
	u8 err_stat_flag : 1;
	u8 que_stat_flag : 1;
	u8 rd_clr : 1;
	u8 rsv0 : 5;
	u16 vf_idx;
	u16 start_index;
	u16 queue_num;
} __packed;

enum zxdh_1588_vf_op_code {
	ZXDH_VF_1588_ENABLE_SET,
	ZXDH_VF_1588_ENABLE_GET,
	ZXDH_VF_1588_CMD_CNT_MAX, /* should be at last */
};

struct zxdh_vf_1588_enable {
	u32 proc_cmd;
	u32 enable_1588_vf;
} __packed;

struct zxdh_vf_1588_enable_rsp {
	u32 enable_1588_vf_rsp;
} __packed;

struct zxdh_vqmb_hdr {
	u32 vfid;
	u16 pcie_id;
	u16 rsv;
	u64 bits;
} __packed;

struct zxdh_vqmb_port_ctrl_msg {
	u16 port_enable;
	u16 version;
} __packed;

struct vqmb_to_host_msg {
	struct zxdh_vqmb_hdr vqmb_hdr;
	struct zxdh_vqmb_port_ctrl_msg vqmb_port_ctrl_msg;
} __packed;

struct zxdh_msg_info {
	union {
		u8 len[MAX_HDR_LEN];
		struct zxdh_msg_head_to_pf hdr;
		struct zxdh_msg_head_to_vf hdr_vf;
		struct agent_msg_hdr hdr_to_agt;
		struct zxdh_common_tbl_hdr hdr_to_cmn;
		struct zxdh_common_time_hdr hdr_time_to_cmn;
		struct health_msg_hdr health_hdr;
	}; /* should be no more than MAX_HDR_LEN */

	union {
		struct zxdh_vf_reload_msg vf_reload_msg;
		struct zxdh_rss_enable_msg rss_enable_msg;
		struct zxdh_rxfh_set_msg rxfh_set_msg;
		struct zxdh_thash_key_set_msg thash_key_set_msg;
		struct zxdh_hfunc_set_msg hfunc_set_msg;
		struct zxdh_rx_flow_hash_set_msg rx_flow_hash_set_msg;
		struct zxdh_mac_addr_msg mac_addr_set_msg;
		struct zxdh_port_attr_set_msg port_attr_set_msg;
		struct zxdh_promisc_set_msg promisc_set_msg;
		struct zxdh_link_state_msg link_state_msg;
		struct zxdh_vlan_filter_set_msg vlan_filter_set_msg;
		struct zxdh_rx_vid_add_msg rx_vid_add_msg;
		struct zxdh_rx_vid_del_msg rx_vid_del_msg;
		struct agent_mac_autoneg_msg mac_set_msg;
		struct agent_mac_fec_mode_msg mac_fec_mode_msg;
		struct agent_mac_fc_mode_msg mac_fc_mode_msg;
		struct agent_mac_module_eeprom_msg module_eeprom_msg;
		struct agent_flash_read_msg flash_read_msg;
		struct zxdh_vf_init_msg vf_init_msg;
		struct zxdh_strip_enable_msg vlan_strip_msg;
		struct zxdh_set_vf_vlan_msg vf_vlan_msg;
		struct zxdh_qinq_tpid_cfg_msg tpid_cfg_msg;
		struct zxdh_pf_cfg_mac_msg mac_cfg_msg;
		struct zxdh_cfg_time_msg time_cfg_msg;
		struct agent_pcie_msix_msg pcie_msix_msg;
		struct zxdh_lldp_enable_msg lldp_msg;
		struct zxdh_rate_limit_set_msg rate_limit_set_msg;
		struct zxdh_plcr_flowid_map_msg plcr_flowid_map_msg;
		struct zxdh_plcr_flow_init_msg plcr_flow_init_msg;
		struct zxdh_plcr_pf_get_vf_queue_info_msg plcr_pf_get_vf_queue_info_msg;
		struct zxdh_plcr_work_mode_msg plcr_work_mode_msg;
		struct zxdh_slot_info debug_ip_send;

		struct zxdh_vf_plcr_profile_id_add_msg vf_plcr_profile_id_add_msg;

		struct zxdh_vf_plcr_profile_id_delete_msg vf_plcr_profile_id_delete_msg;

		struct zxdh_vf_plcr_profile_cfg_set_msg vf_plcr_profile_cfg_set_msg;

		struct zxdh_vf_plcr_profile_cfg_get_msg vf_plcr_profile_cfg_get_msg;

		struct zxdh_vf_plcr_queue_cfg_set_msg vf_plcr_queue_cfg_set_msg;

		struct zxdh_vf_plcr_port_meter_stat_get_msg vf_plcr_port_meter_stat_get_msg;
		struct zxdh_vf_vxlan_port_msg vf_vxlan_port;
		struct zxdh_np_stats_get_msg np_stats_get_msg;

		struct zxdh_vf_1588_call_np vf_1588_call_np;
		struct zxdh_synce_clk_msg synce_clk_recovery_port;
		struct zxdh_mac_tstamp_msg mac_tstamp_msg;
		struct zxdh_bar_msg_pps msg_pps;
		u16 cmn_tbl_msg[257];
		struct zxdh_spm_port_enable spm_port_enable_set;
		struct zxdh_flow_op_msg flow_msg;
		struct zxdh_mcode_feature_msg mcode_feature_msg;
		struct zxdh_k_cmpat_msg kernel_cmpat_msg;
		struct health_config_msg health_config_msg;
		struct pf_status_msg pf_status_msg;
		struct zxdh_get_sw_stats vf_sw_stats;
		struct zxdh_vf_1588_enable vf_1588_enable;
		struct zxdh_vf_fd_cfg_msg vf_fd_cfg_msg;
		struct zxdh_fd_enable_msg vf_fd_enable_msg;
	};
};

enum zxdh_reps_flag {
	ZXDH_REPS_FAIL,
	ZXDH_REPS_SUCC = 0xaa,
	ZXDH_INVALID_OP_CODE = 0xee,
};

enum zxdh_get_sw_stats_flag {
	GET_STAT_SUCCESS = 0,
	GET_STAT_FAILED = 1,
	VF_ERR = 2,
	ACTION_IS_NOT_SUPPORTED = 3,
};

struct agent_debug_lldp_msg {
	u8 lldp_status;
} __packed;

struct agent_flash_msg {
	u8 firmware_version[FW_VERSION_LEN];
} __packed;

struct agent_flash_mac_read_msg {
	u8 mac[ETH_ALEN];
} __packed;

struct zxdh_plcr_pf_get_vf_queue_info_rsp {
	u32 phy_queue_num;
	u16 phy_rxq[16];
	u16 phy_txq[16];
} __packed;

struct zxdh_rate_limit_set_rsp {
	s32 err_code;
} __packed;

struct zxdh_plcr_work_mode_rsp {
	u8 mode;
} __packed;

struct zxdh_vf_plcr_profile_id_add_rsp {
	u16 profile_id;
} __packed;

struct zxdh_vf_plcr_profile_cfg_get_rsp {
	union zxdh_plcr_profile_cfg profile_cfg;
} __packed;

struct zxdh_vf_plcr_port_meter_stat_get_rsp {
	u64 drop_pkb_cnt;
	u64 drop_pk_cnt;
} __packed;

struct zxdh_port_attr_get_msg {
	struct zxdh_sriov_vport_t port_attr_entry;
} __packed;

struct zxdh_port_mac_set_rsp {
	u8 mac_err_flag;
} __packed;

struct zxdh_fd_cfg_reply {
	u32 index;
} __packed;
struct rte_flow_query_count {
	u32 reset : 1;
	u32 hits_set : 1;
	u32 bytes_set : 1;
	u32 reserved : 29;
	u64 hits;
	u64 bytes;
};

struct err_reason {
	u8 err_type;
	u8 rsv[3];
	char reason[512];
} __packed;

struct zxdh_flow_op_rsp {
	struct zxdh_flow dh_flow;
	union {
		struct rte_flow_query_count count;
		struct err_reason error;
	};
} __packed;

struct zxdh_mcode_feature_rsp {
	u64 len;
	u64 feature;
} __packed;

struct zxdh_k_cmpat_rsp {
	u64 k_msg_idmax;
} __packed;

struct err_stats {
	u64 truncated_err;
	u64 offload_cfg_err;
	u64 invalid_hdr_len_err;
	u64 no_segs_err;
} __packed;

struct sw_stats {
	struct err_stats rx_stats;
	struct err_stats tx_stats;
} __packed;

struct que_err_stats {
	u8 queue_state; /*0:rx 1:tx*/
	struct err_stats stats;
} __packed;

struct zxdh_sw_stats_reply {
	union {
		struct que_err_stats que_stats[MAX_QUE_CNT];
		struct sw_stats port_stats;
	};
} __packed;

struct udp_phy_stats {
	u64 rx_arn_phy;
	u64 tx_psn_phy;
	u64 rx_psn_phy;
	u64 tx_psn_ack_phy;
	u64 rx_psn_ack_phy;
} __packed;

struct zxdh_reps_info {
	enum zxdh_reps_flag flag;
	union {
		struct zxdh_vf_reload_msg vf_reload_msg;
		struct zxdh_thash_key_set_msg thash_key_set_msg;
		struct zxdh_rx_flow_hash_set_msg rx_flow_hash_set_msg;
		struct zxdh_link_state_msg link_state_msg;
		struct agent_mac_autoneg_msg mac_set_msg;
		struct agent_stats stats_msg;
		struct np_stats np_stats_msg;
		struct udp_phy_stats udp_phy_stats_msg;
		struct agent_mac_fec_mode_msg mac_fec_mode_msg;
		struct agent_mac_fc_mode_msg mac_fc_mode_msg;
		struct agent_mac_module_eeprom_msg module_eeprom_msg;
		struct common_recv_msg cmn_recv_msg;
		struct common_vq_msg cmn_vq_msg;
		struct zxdh_port_mac_set_rsp vf_mac_set_msg;
		struct zxdh_mac_addr_msg vf_mac_addr_get_msg;
		struct zxdh_vf_init_msg vf_init_msg;
		struct agent_flash_msg flash_msg;
		struct agent_flash_mac_read_msg flash_mac_read_msg;
		struct agent_debug_lldp_msg debug_lldp_msg;
		struct zxdh_plcr_pf_get_vf_queue_info_rsp plcr_pf_get_vf_queue_info_rsp;
		struct zxdh_rate_limit_set_rsp rate_limit_set_rsp;
		struct zxdh_plcr_work_mode_rsp plcr_work_mode_rsp;

		struct zxdh_vf_plcr_profile_id_add_rsp vf_plcr_profile_id_add_rsp;

		struct zxdh_vf_plcr_profile_cfg_get_rsp vf_plcr_profile_cfg_get_rsp;

		struct zxdh_vf_plcr_port_meter_stat_get_rsp vf_plcr_port_meter_stat_get_rsp;
		struct zxdh_synce_clk_msg synce_clk_recovery_port;
		struct zxdh_mac_tstamp_msg mac_tstamp_msg;
		struct zxdh_delay_statistics_val delay_statistics_val;
		struct zxdh_port_attr_get_msg port_attr_get_msg;
		struct zxdh_rxfh_set_msg rxfh_get_msg;
		struct zxdh_bar_msg_pps msg_pps;
		struct zxdh_slot_id_msg slot_info;
		struct zxdh_flow_op_rsp flow_rsp;
		struct zxdh_mcode_feature_rsp mcode_feature_rsp;
		struct zxdh_k_cmpat_rsp kernel_cmpat_rsp;
		struct zxdh_sw_stats_reply vf_sw_stats_rsp;
		struct zxdh_vf_1588_enable_rsp vf_1588_enable_rsp;
		struct zxdh_fd_cfg_reply fd_cfg_resp;
	};
};

union zxdh_msg {
	struct zxdh_msg_info payload;
	struct zxdh_reps_info reps;
	struct vqm_rsp_host_data vqm_reps;
	struct host_to_vqm_msg vqm_msg;
};

static inline u16 sum_func(void *data, u16 len)
{
	u64 result = 0;
	int idx = 0;
	u16 ret = 0;

	if (!data)
		return 0;

	for (idx = 0; idx < len; idx++)
		result += *((u8 *)data + idx);

	ret = (u16)result;
	return ret;
}

#endif
