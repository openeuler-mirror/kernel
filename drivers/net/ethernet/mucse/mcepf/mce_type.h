/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2024-2026 Mucse Corporation. */

#ifndef _MCE_TYPE_H_
#define _MCE_TYPE_H_
#include <linux/spinlock.h>

#include "mce_vf_lib.h"
#include "mce_txrx.h"

#define MCE_MAX_RSS_KEY_SIZE 64
#define MCE_MAX_RSS_INDIR_TABLE_SIZE 512
#define MCE_TUNNEL_MAX_ENTRIES 8
#define MCE_MAX_VF_NUM 128
#define MCE_VEB_MAX_VF_MACVLAN_NUMS 128

struct mce_ring;
struct mce_fdir_fltr;
struct mce_hw;
struct mce_ets_cfg;
struct mce_dcb;

#define MCE_PCIE_IRQ_MODE_NO_MSIX_MAX_VECTORS (1)
/* pcie irq mode. */
enum mce_pcie_irq_mode {
	MCE_PCIE_IRQ_MODE_NONE,
	MCE_PCIE_IRQ_MODE_MSIX,
	MCE_PCIE_IRQ_MODE_MSI,
	MCE_PCIE_IRQ_MODE_LEGACY,
};

/* Software VSI types. */
enum mce_vsi_type {
	MCE_VSI_PF = 0,
	MCE_VSI_VF = 1,
	MCE_VSI_SWITCHDEV_CTRL = 2,
	MCE_VSI_SWITCHDEV_VF,
};

enum mce_sw_fwd_act_type {
	MCE_FWD_TO_VSI = 0,
	MCE_FWD_TO_VSI_LIST, /* Do not use this when adding filter */
	MCE_FWD_TO_Q,
	MCE_FWD_TO_QGRP,
	MCE_DROP_PACKET,
	MCE_LG_ACTION,
	MCE_INVAL_ACT
};

/* PCI bus types */
enum mce_bus_type {
	mce_bus_unknown = 0,
	mce_bus_pci_express,
	mce_bus_embedded, /* Is device Embedded versus card */
	mce_bus_reserved
};

/* PCI bus speeds */
enum mce_pcie_bus_speed {
	mce_pcie_speed_unknown = 0xff,
	mce_pcie_speed_2_5GT = 0x14,
	mce_pcie_speed_5_0GT = 0x15,
	mce_pcie_speed_8_0GT = 0x16,
	mce_pcie_speed_16_0GT = 0x17
};

/* PCI bus widths */
enum mce_pcie_link_width {
	mce_pcie_lnk_width_resrv = 0x00,
	mce_pcie_lnk_x1 = 0x01,
	mce_pcie_lnk_x2 = 0x02,
	mce_pcie_lnk_x4 = 0x04,
	mce_pcie_lnk_x8 = 0x08,
	mce_pcie_lnk_x12 = 0x0C,
	mce_pcie_lnk_x16 = 0x10,
	mce_pcie_lnk_x32 = 0x20,
	mce_pcie_lnk_width_unknown = 0xff,
};

#define MCE_TC_FLWR_IPSEC_NAT_T_PORT0 (4500)
#define MCE_TC_FLWR_IPSEC_NAT_T_PORT1 (500)

/* rx tunnel offload type */
enum mce_tunnel_type {
	TNL_VXLAN = 0,
	TNL_GENEVE,
	TNL_GRETAP,
	TNL_GTP,
	TNL_GTPC,
	TNL_GTPU,
	TNL_ECPRI,
	TNL_VXLAN_GPE,
	TNL_IPSEC,
	TNL_ALL,
	TNL_LAST = 0xFF, /* must be last */
};

enum mce_l2_fltr_flag {
	DMAC_FILTER_EN = 0,
	VLAN_FILTER_EN,
	TNL_INNER_EN,
	L2_FLAGS_LAST,
};

struct mce_tunnel_entry {
	u16 default_port;
	u16 port;
	u16 ref_cnt;
	bool in_use;
};

struct mce_tunnel_table {
	struct mce_tunnel_entry tbl[MCE_TUNNEL_MAX_ENTRIES];
	u16 tnl_cnt;
};

struct mce_ofld_stats {
	u64 tx_unicast;
	u64 tx_multicast;
	u64 tx_broadcast;
	u64 rx_unicast;
	u64 rx_multicast;
	u64 rx_broadcast;
	u64 rx_miss_drop;
	u64 tx_inserted_vlan;
	u64 rx_stripped_vlan;
	u64 rx_csum_err;
	u64 rx_csum_unnecessary;
	u64 rx_csum_none;
};

struct mce_hw_stats {
	/* NIC  part */
	u64 l2_filter_drop;
	u64 dmac_filter_drop;

	/* RDMA part */
	u64 tx_vport_rdma_unicast_packets;
	u64 tx_vport_rdma_unicast_bytes;
	u64 rx_vport_rdma_unicast_packets;
	u64 rx_vport_rdma_unicast_bytes;
	u64 np_cnp_sent;
	u64 rn_cnp_handled;
	u64 np_ecn_marked_roce_packets;
	u64 rp_cnp_ignored;
	u64 out_of_sequence;
	u64 packet_seq_err;
	u64 ack_timeout_err;
	u64 rx_crc_err;
};

struct mce_mac_stats {
	u64 rx_good_bad_pkts;
	u64 rx_good_bad_bytes;
	u64 rx_good_pkts;
	u64 rx_good_bytes;
	u64 rx_bad_pkts;

	u64 rx_fcs_err; /* rx fcs err pkts */
	u64 rx_runt_err; /* Frame Less-than-64-byte with a CRC error*/
	u64 rx_jabber_err; /* Jumbo Frame Crc Error */
	u64 rx_undersize_err; /* Frame Less Than 64 bytes Error */
	u64 rx_oversize_err; /* Bigger Than Max Support Length Frame */
	u64 rx_len_err; /* Bigger Or Less Than Len Support */
	u64 rx_len_invalid; /* Frame Len Isn't equal real Len */
	u64 rx_discard_pkts;

	u64 rx_64octes_pkts;
	u64 rx_65to127_octes_pkts;
	u64 rx_128to255_octes_pkts;
	u64 rx_256to511_octes_pkts;
	u64 rx_512to1023_octes_pkts;
	u64 rx_1024to1518_octes_pkts;
	u64 rx_1519tomax_octes_pkts;
	u64 rx_unicast_pkts;
	u64 rx_multicast_pkts;
	u64 rx_broadcast_pkts;
	u64 rx_vlan_pkts; /* Rx Vlan Frame Num */
	u64 rx_pause_pkts; /* Rx Pause Frame Num */
	u64 rx_pfc_pri0_pkts;
	u64 rx_pfc_pri1_pkts;
	u64 rx_pfc_pri2_pkts;
	u64 rx_pfc_pri3_pkts;
	u64 rx_pfc_pri4_pkts;
	u64 rx_pfc_pri5_pkts;
	u64 rx_pfc_pri6_pkts;
	u64 rx_pfc_pri7_pkts;

	u64 tx_good_bad_pkts;
	u64 tx_good_bad_bytes;
	u64 tx_good_pkts;
	u64 tx_good_bytes;
	u64 tx_bad_pkts;

	u64 tx_oversize_err; /* Bigger Than Max Support Length Frame */
	u64 tx_jabber_err; /* Jumbo Frame Crc Error */

	u64 tx_64octes_pkts;
	u64 tx_65to127_octes_pkts;
	u64 tx_128to255_octes_pkts;
	u64 tx_256to511_octes_pkts;
	u64 tx_512to1023_octes_pkts;
	u64 tx_1024to1518_octes_pkts;
	u64 tx_1519tomax_octes_pkts;
	u64 tx_unicast_pkts;
	u64 tx_multicast_pkts;
	u64 tx_broadcast_pkts;
	u64 tx_vlan_pkts;
	u64 tx_pause_pkts;
	u64 tx_pfc_pri0_pkts;
	u64 tx_pfc_pri1_pkts;
	u64 tx_pfc_pri2_pkts;
	u64 tx_pfc_pri3_pkts;
	u64 tx_pfc_pri4_pkts;
	u64 tx_pfc_pri5_pkts;
	u64 tx_pfc_pri6_pkts;
	u64 tx_pfc_pri7_pkts;
};

/* Bus parameters */
struct mce_bus_info {
	enum mce_pcie_bus_speed speed;
	enum mce_pcie_link_width width;
	enum mce_bus_type type;
	u16 domain_num;
	u16 device;
	u8 func;
	u8 bus_num;
};

/* Common HW capabilities for SW use */
struct mce_hw_common_caps {
	/* Tx/Rx queues */
	u16 num_rxq; /* Number/Total Rx queues */
	u16 num_txq; /* Number/Total Tx queues */

	/* RSS related capabilities */
	u16 pf_rss_tb_size; /* 512 for PFs*/
	u16 vf_rss_tb_size; /* 512 for PFs*/
	u16 rss_key_size;

	/* IRQs */
	u16 max_irq_cnts;
	u16 mbox_irq_base;
	u16 qvec_irq_base;
	u16 num_mbox_irqs;
	u16 rdma_irq_base;
	u16 num_rdma_irqs;

	/* SR-IOV virtualization */
	u16 max_vfs;
	u16 vlan_strip_cnt;
	u16 vf_num_rxq;
	u16 vf_num_txq;
	u8 sr_iov; /* SR-IOV enabled */
	u8 max_tc;
	u8 queue_for_tc;
	bool nvm_update_pending_nvm;
	bool nvm_update_pending_orom;
	u8 pcie_irq_capable;
	u32 mac_misc_irq;
	bool mac_misc_irq_retry;
	bool npu_capable;
	bool npu_en;

	bool has_sfp_i2c_mst;
	bool xmit_check_intr_drop;
	bool poll_check_intr_drop;
	bool drop_intr_timer_en;
};

/* Function specific capabilities */
struct mce_hw_func_caps {
	struct mce_hw_common_caps common_cap;
	u32 num_allocd_vfs; /* Number of allocated VFs */
	u32 guar_num_vsi;
	u32 fd_fltr_guar;
};

struct mce_mbx_stats {
	u32 tx_event_cnt;
	u32 tx_event_err_cnt;

	u32 tx_req_cnt;
	u32 tx_shm_lock_timeout;

	u32 rx_resp_cnt;
	u32 rx_req_shm_lock_timeout;
	u32 rx_resp_shm_lock_timeout;
};

struct mbx_fw_cmd_reply;

typedef void (*cookie_cb)(struct mbx_fw_cmd_reply *reply, void *priv);

enum cookie_stat {
	COOKIE_FREE = 0,
	COOKIE_FREE_WAIT_TIMEOUT,
	COOKIE_ALLOCED,
};

struct mbx_req_cookie {
	u64 alloced_jiffies;
	enum cookie_stat stat;
	cookie_cb cb;
	int timeout_jiffes;
	int errcode;
	wait_queue_head_t wait;
	int done;
	int priv_len;
#define MAX_PRIV_LEN 64
	char priv[MAX_PRIV_LEN];
};

struct mbx_req_cookie_pool {
#define MAX_COOKIES_ITEMS (20 * 400)
	struct mbx_req_cookie cookies[MAX_COOKIES_ITEMS];
	int next_idx;
};

#include "mce_mbx.h"

#define UP_ALIGH(x, y) (((x) + (y) - 1) / (y))

/* maybe reletive with mtu, do it later? */
#define MAX_DMA_NEED_FOR_TSO (UP_ALIGH(65536, 1480) * UP_ALIGH(1526, 64))

struct mce_ts_dev_info {
	/* Device specific info */
	u32 tmr_own_map;
	u8 tmr0_owner;
	u8 tmr1_owner;
	u8 tmr0_owned : 1;
	u8 tmr1_owned : 1;
	u8 ena : 1;
	u8 tmr0_ena : 1;
	u8 tmr1_ena : 1;
	u8 ts_ll_read : 1;
	u8 ts_ll_int_read : 1;
};

struct mce_nac_topology {
	u32 mode;
	u8 id;
};

/* Device wide capabilities */
struct mce_hw_dev_caps {
	struct mce_hw_common_caps common_cap;
	u32 num_vfs_exposed; /* Total number of VFs exposed */
	u32 num_vsi_allocd_to_host; /* Excluding EMP VSI */
	u32 num_flow_director_fltr; /* Number of FD filters available */
	struct mce_ts_dev_info ts_dev_info;
	u32 num_funcs;
	struct mce_nac_topology nac_topo;
	/* bitmap of supported sensors */
	u32 supported_sensors;
#define MCE_SENSOR_SUPPORT_E810_INT_TEMP BIT(0)
};

/* Option ROM version information */
struct mce_orom_info {
	u8 major; /* Major version of OROM */
	u8 patch; /* Patch version of OROM */
	u16 build; /* Build version of OROM */
	u32 srev; /* Security revision */
};

/* NVM version information */
struct mce_nvm_info {
	u32 eetrack;
	u32 srev;
	u8 major;
	u8 minor;
};

/* netlist version information */
struct mce_netlist_info {
	u32 major; /* major high/low */
	u32 minor; /* minor high/low */
	u32 type; /* type high/low */
	u32 rev; /* revision high/low */
	u32 hash; /* SHA-1 hash word */
	u16 cust_ver; /* customer version */
};

enum mce_flash_bank {
	MCE_INVALID_FLASH_BANK,
	MCE_1ST_FLASH_BANK,
	MCE_2ND_FLASH_BANK,
};

/* Enumeration of which flash bank is desired to read from, either the active
 * bank or the inactive bank. Used to abstract 1st and 2nd bank notion from
 * code which just wants to read the active or inactive flash bank.
 */
enum mce_bank_select {
	MCE_ACTIVE_FLASH_BANK,
	MCE_INACTIVE_FLASH_BANK,
};

/* information for accessing NVM, OROM, and Netlist flash banks */
struct mce_bank_info {
	u32 nvm_ptr; /* Pointer to 1st NVM bank */
	u32 nvm_size; /* Size of NVM bank */
	u32 orom_ptr; /* Pointer to 1st OROM bank */
	u32 orom_size; /* Size of OROM bank */
	u32 netlist_ptr; /* Pointer to 1st Netlist bank */
	u32 netlist_size; /* Size of Netlist bank */
	enum mce_flash_bank nvm_bank; /* Active NVM bank */
	enum mce_flash_bank orom_bank; /* Active OROM bank */
	enum mce_flash_bank netlist_bank; /* Active Netlist bank */
};

struct mce_flash_info {
	struct mce_orom_info orom; /* Option ROM version info */
	struct mce_nvm_info nvm; /* NVM version information */
	struct mce_netlist_info netlist; /* Netlist version info */
	struct mce_bank_info banks; /* Flash Bank information */
	u16 sr_words; /* Shadow RAM size in words */
	u32 flash_size; /* Size of available flash in bytes */
	u8 blank_nvm_mode; /* is NVM empty (no FW present) */
};

struct pf_vf_num {
	u8 vfnum;
	u8 pf;
};

struct mce_mbx_info {
	struct mce_mbx_stats stats;
	struct mce_hw *hw;
	struct vf_info *vfinfo;

	char name[60];

	/* Serializes mailbox requests issued through this channel. */
	struct mutex req_lock;
	/* Protects PF-to-peer shared-memory request/response access. */
	spinlock_t req_shm_lock;
	/* Protects peer-to-PF shared-memory request/response access. */
	spinlock_t peer_shm_lock;

	bool irq_enabled;
	bool setup_done;
	int nr_vf;
	int nr_pf;
	bool is_vf_mbx;
	bool fw2pf_link_change_notify_en;
	bool fw2pf_sfp_pluginout_notify_en;

	int req_shm_size; /* PF2FW shm size */
	int peer_shm_size; /* FW2PF shm size */

	u8 __iomem *pf2peer_shm; /* peer = fw or vf */
	u8 __iomem *pf2peer_shm_lock;
	u8 __iomem *pf2peer_ctrl;
	u32 pf2peer_shm_lock_msk;

	u8 __iomem *peer2pf_shm;
	u8 __iomem *peer2pf_shm_lock;
	u8 __iomem *peer2pf_ctrl;
	u32 peer2pf_shm_lock_msk;

	u8 __iomem *vf2pf_irq_stat;

	u8 __iomem *mbx_vec_base;
};

#define mbx_info_reg_bar_off(mbx, reg) \
	((reg) - ((mbx)->hw->eth_bar_base))

#define MCE_MISC_IRQ_CLEAR_ALL (0xffffffff)

enum mce_misc_irq_type {
	MCE_MAC_MISC_IRQ_NONE = 0,
	MCE_MAC_MISC_IRQ_PCS_LINK = MCE_MAC_MISC_IRQ_NONE,
	MCE_MAC_MISC_IRQ_PTP,
	MCE_MAC_MISC_IRQ_FLR,
	MCE_MAC_MISC_IRQ_MAX,
	MCE_MAC_MISC_IRQ_ALL = MCE_MAC_MISC_IRQ_MAX,
};

enum mce_misc_irq_flr {
	MCE_MISC_IRQ_FLR_NONE = 0,
	MCE_MISC_IRQ_FLR_0_31 = MCE_MISC_IRQ_FLR_NONE,
	MCE_MISC_IRQ_FLR_32_63,
	MCE_MISC_IRQ_FLR_64_95,
	MCE_MISC_IRQ_FLR_96_127,
	MCE_MISC_IRQ_FLR_MAX,
};

struct mce_hw_operations {
	int (*update_fltr_macaddr)(struct mce_hw *hw, u8 *mac_addr, u32 index,
				   bool active);
	int (*dump_debug_regs)(struct mce_hw *hw, char *cmd);
	int (*cfg_txring_bw_lmt)(struct mce_ring *tx_ring, u32 maxrate);
	void (*reset_hw)(struct mce_hw *hw);
	void (*init_hw)(struct mce_hw *hw);
	void (*enable_proc)(struct mce_hw *hw);
	void (*disable_proc)(struct mce_hw *hw);
	void (*enable_axi_tx)(struct mce_hw *hw);
	void (*disable_axi_tx)(struct mce_hw *hw);
	void (*enable_axi_rx)(struct mce_hw *hw);
	void (*disable_axi_rx)(struct mce_hw *hw);
	void (*cfg_vec2tqirq)(struct mce_hw *hw, u16 vec, u16 tirq);
	void (*cfg_vec2rqirq)(struct mce_hw *hw, u16 vec, u16 rirq);
	void (*set_max_pktlen)(struct mce_hw *hw, u32 mtu);
	void (*get_hw_stats)(struct mce_hw *hw, struct mce_hw_stats *prev_stats,
			     struct mce_hw_stats *cur_stats);
	void (*get_mac_stats)(struct mce_hw *hw, struct mce_mac_stats *stats);
	void (*clr_mac_stats)(struct mce_hw *hw);
	void (*set_fcs_mode)(struct mce_hw *hw, bool en);
	void (*set_err_mode)(struct mce_hw *hw);
	void (*set_rxring_ctx)(struct mce_ring *rx_ring, struct mce_hw *hw);
	void (*set_txring_ctx)(struct mce_ring *tx_ring, struct mce_hw *hw);
	void (*enable_rxring_irq)(struct mce_ring *rx_ring);
	void (*enable_txring_irq)(struct mce_ring *tx_ring);
	void (*disable_rxring_irq)(struct mce_ring *rx_ring);
	void (*disable_txring_irq)(struct mce_ring *tx_ring);
	void (*enable_txrxring_irq)(struct mce_ring *ring);
	void (*disable_txrxring_irq)(struct mce_ring *ring);
	void (*start_rxring)(struct mce_ring *rx_ring);
	void (*stop_rxring)(struct mce_ring *rx_ring);
	void (*start_txring)(struct mce_ring *tx_ring);
	void (*stop_txring)(struct mce_ring *tx_ring);
	void (*set_rxring_intr_coal)(struct mce_ring *rx_ring);
	void (*set_txring_intr_coal)(struct mce_ring *tx_ring);
	void (*set_rxring_hw_dim)(struct mce_ring *rx_ring, bool enable);
	void (*set_txring_hw_dim)(struct mce_ring *tx_ring, bool enable);
	void (*set_vlan_filter)(struct mce_hw *hw, netdev_features_t features);
	void (*add_vlan_filter)(struct mce_hw *hw, u16 vid);
	void (*del_vlan_filter)(struct mce_hw *hw, u16 vid);
	void (*set_vlan_strip)(struct mce_hw *hw, netdev_features_t features);
	void (*set_rx_csum_chk_err_mask)(struct mce_hw *hw, bool on);
	void (*set_rss_hash)(struct mce_hw *hw, netdev_features_t features);
	void (*set_rss_key)(struct mce_hw *hw);
	void (*set_rss_hash_type)(struct mce_hw *hw);
	int (*set_rss_table)(struct mce_hw *hw, u16 q_cnt);
	void (*set_ucmc_hash_type_fltr)(struct mce_hw *hw);
	void (*set_uc_filter)(struct mce_hw *hw, bool enable);
	void (*add_uc_filter)(struct mce_hw *hw, u16 hash_v);
	void (*del_uc_filter)(struct mce_hw *hw, u16 hash_v);
	void (*set_mc_filter)(struct mce_hw *hw, bool enable);
	void (*add_mc_filter)(struct mce_hw *hw, u16 hash_v);
	void (*del_mc_filter)(struct mce_hw *hw, u16 hash_v);
	void (*clr_mc_filter)(struct mce_hw *hw);
	void (*set_mc_promisc)(struct mce_hw *hw, bool enable);
	void (*set_rx_promisc)(struct mce_hw *hw, bool enable);
	void (*add_ntuple_filter)(struct mce_hw *hw, struct mce_fdir_fltr *rule);
	void (*del_ntuple_filter)(struct mce_hw *hw, struct mce_fdir_fltr *rule);
	void (*add_udp_tnl)(struct mce_hw *hw, enum mce_tunnel_type tnl_type,
			    u16 port);
	void (*del_udp_tnl)(struct mce_hw *hw, enum mce_tunnel_type tnl_type,
			    u16 port);
	void (*restore_udp_tnl)(struct mce_hw *hw,
				enum mce_tunnel_type tnl_type);
	void (*set_pause)(struct mce_hw *hw, int mtu);
	void (*set_pause_en_only)(struct mce_hw *hw);
	void (*enable_tc)(struct mce_hw *hw, struct mce_dcb *dcb);
	void (*disable_tc)(struct mce_hw *hw);
	void (*enable_rdma_tc)(struct mce_hw *hw, struct mce_dcb *dcb);
	void (*disable_rdma_tc)(struct mce_hw *hw);
	void (*set_tc_bw)(struct mce_hw *hw, struct mce_dcb *dcb);
	void (*set_tc_bw_rdma)(struct mce_hw *hw, struct mce_dcb *dcb);
	void (*set_qg_ctrl)(struct mce_hw *hw, struct mce_dcb *dcb);
	void (*set_qg_rate)(struct mce_hw *hw, struct mce_dcb *dcb);
	void (*set_q_to_tc)(struct mce_hw *hw, struct mce_dcb *dcb);
	void (*clr_q_to_tc)(struct mce_hw *hw);
	void (*enable_pfc)(struct mce_hw *hw, struct mce_dcb *dcb);
	void (*setup_rx_buffer)(struct mce_hw *hw);
	void (*disable_pfc)(struct mce_hw *hw);
	void (*set_q_to_pfc)(struct mce_hw *hw, struct mce_dcb *dcb);
	void (*clr_q_to_pfc)(struct mce_hw *hw);
	void (*set_mac_station_addr)(struct mce_hw *hw, const u8 *addr);
	void (*set_dscp)(struct mce_hw *hw, struct mce_dcb *dcb);
	void (*set_tun_select_inner)(struct mce_hw *hw, bool inner);
	void (*set_ddp_extra_en)(struct mce_hw *hw, bool enable);
	int (*set_lldp_tx_en)(struct mce_hw *hw, bool enable);
	void (*set_evb_mode)(struct mce_hw *hw, int mode);
	void (*set_dma_tso_cnts_en)(struct mce_hw *hw, bool en);
	void (*set_fd_fltr_guar)(struct mce_hw *hw);
	void (*set_irq_legacy_en)(struct mce_hw *hw, bool en, u32 tick_timer);
	bool (*get_misc_irq_evt)(struct mce_hw *hw,
				 enum mce_misc_irq_type type);
	int (*set_misc_irq)(struct mce_hw *hw, bool en, int nr_vec);
	int (*get_misc_irq_st)(struct mce_hw *hw, enum mce_misc_irq_type type,
			       u32 *val);
	int (*set_misc_irq_mask)(struct mce_hw *hw, enum mce_misc_irq_type type,
				 bool en);
	int (*clear_misc_irq_evt)(struct mce_hw *hw,
				  enum mce_misc_irq_type type, int idx,
				  u32 val);
	int (*set_init_ptp)(struct mce_hw *hw);
	/* npu callback */
	int (*npu_download_firmware)(struct mce_hw *hw);
	void (*update_rdma_status)(struct mce_hw *hw, bool en);

	/* ptp ops */
	void (*ptp_get_systime)(struct mce_hw *hw, u64 *systime);
	int (*ptp_init_counter)(struct mce_hw *hw);
	int (*ptp_init_systime)(struct mce_hw *hw, u32 sec, u32 nsec);
	int (*ptp_adjust_systime)(struct mce_hw *hw, u32 sec, u32 nsec,
				  int add_sub);
	int (*ptp_adjfine)(struct mce_hw *hw, long scaled_ppm);
	int (*ptp_set_ts_config)(struct mce_hw *hw,
				 struct hwtstamp_config *config);
	int (*ptp_tx_state)(struct mce_hw *hw);
	int (*ptp_tx_stamp)(struct mce_hw *hw, u64 *sec, u64 *nsec);

	int (*set_txring_trig_intr)(struct mce_ring *tx_ring);
	void (*mbx_init_vf)(struct mce_hw *hw, struct mce_mbx_info *mbx,
			    int nr_vf);
	void (*update_pf_stat)(struct mce_hw *hw);
	void (*update_fw_stat)(struct mce_hw *hw);
	u64 (*get_hw_ring_stats)(struct mce_ring *ring,
				 enum mce_hw_ring_stats_type type);
	int (*clear_hw_ring_stats)(struct mce_hw *hw);
	void (*update_pfc_rr_mode)(struct mce_hw *hw, bool on);
	void (*set_capture_rdma)(struct mce_hw *hw, bool on);
};

struct mce_vf_operations {
	/* hw */
	void (*init_vf_params)(struct mce_hw *hw, int max_ring);
	void (*init_vf_pcie_totalvfs)(struct mce_hw *hw, int max_ring);
	void (*set_vf_virtual_config)(struct mce_hw *hw, bool enable);
	void (*unset_vf_virtual_config)(struct mce_hw *hw);
	void (*set_vf_dma_max_queue_size)(struct mce_hw *hw,
					  int max_vf_queue_size);
	void (*set_vf_emac_post_ctrl)(struct mce_hw *hw,
				      enum mce_vf_veb_vlan_type vlan_type,
				      bool vlan_on,
				      enum mce_vf_post_ctrl post_ctrl,
				      bool ctrl_on);
	void (*set_vf_vlan_strip)(struct mce_hw *hw, int vf_id, bool en);
	int (*set_vf_rss_table)(struct mce_hw *hw, int vf_id, u16 q_cnt);
	void (*set_vf_clear_all_rss_table)(struct mce_hw *hw);
	int (*set_vf_spoofchk_mac)(struct mce_hw *hw, int vfid, bool en,
				   bool setmac);
	int (*set_vf_spoofchk_vlan)(struct mce_hw *hw, int vfid, bool en,
				    enum mce_vf_antivlan_ctrl vlanctrl);
	int (*set_vf_trusted)(struct mce_hw *hw, int vfid, bool on);
	int (*set_vf_default_vport)(struct mce_hw *hw, int vfid);
	int (*set_vf_recv_ximit_by_self)(struct mce_hw *hw, bool on);
	int (*set_vf_trust_vport_en)(struct mce_hw *hw, bool on);
	int (*set_vf_update_vm_macaddr)(struct mce_hw *hw, u8 *mac_addr,
					u32 index, bool active);

	int (*set_vf_update_vm_default_vlan)(struct mce_hw *hw, int index);
	void (*set_vf_set_vlan_promisc)(struct mce_hw *hw, int vfid, bool on);
	void (*set_vf_set_vtag_vport_en)(struct mce_hw *hw, int vfid, bool on);
	void (*set_vf_add_flr_vlan)(struct mce_hw *hw, int vfid, int entry);
	void (*set_vf_del_flr_vlan)(struct mce_hw *hw, int vfid, int entry);
	void (*set_vf_clear_all_flr_vlan)(struct mce_hw *hw);
	void (*set_vf_add_veb_vlan)(struct mce_hw *hw, int vfid, int entry);
	void (*set_vf_del_veb_vlan)(struct mce_hw *hw, int vfid, int entry);
	void (*set_vf_set_veb_act)(struct mce_hw *hw, int vfid, int entry,
				   bool set,
				   enum mce_flag_type set_bcmc_bitmap);
	void (*set_vf_add_mc_fliter)(struct mce_hw *hw, const u8 *mac_addr);
	void (*set_vf_del_mc_filter)(struct mce_hw *hw, const u8 *mac_addr);
	void (*set_vf_clear_mc_filter)(struct mce_hw *hw, bool only_pf);
	void (*set_vf_true_promisc)(struct mce_hw *hw, int vfid, bool on);
	void (*set_vf_rqa_tcp_sync_en)(struct mce_hw *hw, bool on);
	void (*set_vf_rqa_tcp_sync_remapping)(struct mce_hw *hw, int vfnum,
					      struct mce_tcpsync *tcpsync);
	int (*set_vf_bw_limit_init)(struct mce_pf *pf);
	int (*set_vf_bw_limit_rate)(struct mce_pf *pf, int vf_id,
				    u64 max_tx_rate, u16 ring_cnt);
	int (*set_vf_bw_qg_ctrl)(struct mce_pf *pf, int vf_id, u16 ring_cnt);
	void (*set_vf_rebase_ring_base)(struct mce_hw *hw);
	void (*set_vf_cfg_txring_bw_lmt)(struct mce_hw *hw, int vf_id,
					 int max_tx_rate);
	int (*get_vf_max_supported_queue)(struct mce_hw *hw,
					  int *pf0_max_vf_queues,
					  int *pf1_max_vf_queues);
};

struct mce_eswitch_operations {
	/* hw */
	void (*eswitch_en)(struct mce_hw *hw, bool en);
};

struct mce_eswitch_info {
	struct mce_eswitch_operations *ops;
};

struct mce_vf_info {
	struct mce_vf_operations *ops;
};

struct mce_mc_info {
	u8 addr[ETH_ALEN];
	bool en;
};

struct mce_vlan_list_entry {
	struct list_head vlan_node;
#define CVLAN_T BIT(0)
#define SVLAN_T BIT(1)
	int status;
	int vid;
};

struct mce_hw_qos {
	u32 link_speed; /* unit:Mbit */
	u32 link_speed_old;
	u32 interal; /* unit: ms */
	u32 rate;
};

struct mce_dim_cq_moder {
	u16 usec;
	u16 pkts;
};

#define MCE_UC_MC_HASH_BITS_WIDTH 12
enum mce_uc_mc_hash_type {
	/* These fixed values are not allowed to be changed */
	MCE_UC_MC_HASH_TYPE_BIT_11_0_OR_47_36 = 0,
	MCE_UC_MC_HASH_TYPE_BIT_12_1_OR_46_35 = 1,
	MCE_UC_MC_HASH_TYPE_BIT_13_2_OR_45_34 = 2,
	MCE_UC_MC_HASH_TYPE_BIT_14_3_OR_44_33 = 3,
	MCE_UC_MC_HASH_TYPE_MAX,
};

struct mce_uc_mc_hash_ctl {
	enum mce_uc_mc_hash_type type;
	bool uc_s_low;
	bool mc_s_low;
};

enum mce_mac_node_state {
	MCE_MAC_TO_ADD,
	MCE_MAC_TO_DEL,
};

enum mce_mac_addr_type {
	MCE_MAC_ADDR_UC,
	MCE_MAC_ADDR_MC,
};

struct mce_mac_hnode {
	struct hlist_node node;
	u8 mac_addr[ETH_ALEN];
};

enum ZIP_SPEED {
	UNKNOWN_SPEED = 0,
	Z_SPEED_10M = 1,
	Z_SPEED_100M = 2,
	Z_SPEED_1G = 3,
	Z_SPEED_10G = 4,
	Z_SPEED_25G = 5,
	Z_SPEED_40G = 6,
	Z_SPEED_100G = 7,
};

union dm_stat {
	struct {
		/* Byte 0 */
		u32 linkup : 1;
		u32 sfp_mod_abs : 1;
		u32 s_speed : 3;
#define UNKNOWN_SPEED 0
#define Z_SPEED_10M 1
#define Z_SPEED_100M 2
#define Z_SPEED_1G 3
#define Z_SPEED_10G 4
#define Z_SPEED_25G 5
#define Z_SPEED_40G 6
#define Z_SPEED_100G 7

		u32 duplex : 1;
		u32 is_sgmii : 1;
		u32 is_backplane : 1;
		/* Byte 1 */
		u32 active_fec : 2;
#define ST_FEC_OFF 0
#define ST_FEC_BASER 1
#define ST_FEC_RS 2
#define ST_FEC_AUTO 3

		u32 autoneg : 1;
		u32 link_traing : 1;
		u32 lldp_tx_en : 1;
		u32 sfp_fault : 1;
		u32 sfp_tx_dis : 1;
		u32 sfp_los : 1;
		/* Byte 2 */
		u32 force_link_cap : 1;
#define FOCE_LINK_DOWN_ON_CLOSE_CAP 0
#define FOCE_LINK_UP_ON_CLOSE_CAP 1
		u32 force_link_status : 1;
#define NO_FORCE_LINK_SET 0
#define FOCE_LINK_SETTED 1

		u32 configed_fec : 3;
		u32 pxe_ablity : 1;
		u32 pxe_enabled : 1;
		u32 pxe_fw_available : 1;
		u32 qsfp_resetl_rs0 : 1;
		u32 rev1 : 3;
		u32 magic : 4;
#define DM_STAT0_IMAGE 0xA
	} __packed;
	u32 v;
} __packed;

union nic_stat {
	struct {
		u32 pf0_vf_isolate : 1;
		u32 pf0_vf_max_queue_cnt_3bit : 3;
		u32 pf1_vf_isolate : 1;
		u32 pf1_vf_max_queue_cnt_3bit : 3;
		u32 temp : 8;
		u32 rev : 8;
		u32 phy_type : 5;
		u32 magic : 3;
#define NIC_STAT0_IMAGE 0b101
	};
	u32 v;
} __packed;

#define MCE_DISABLE_40_100G_CARD_25G_AND_BELOW_DEFAULT 1

/* support link speed */
#define MCE_FW_LINK_SPEED_10MB BIT(0)
#define MCE_FW_LINK_SPEED_100MB BIT(1)
#define MCE_FW_LINK_SPEED_1000MB BIT(2)
#define MCE_FW_LINK_SPEED_2500MB BIT(3)
#define MCE_FW_LINK_SPEED_5GB BIT(4)
#define MCE_FW_LINK_SPEED_10GB BIT(5)
#define MCE_FW_LINK_SPEED_20GB BIT(6)
#define MCE_FW_LINK_SPEED_25GB BIT(7)
#define MCE_FW_LINK_SPEED_40GB BIT(8)
#define MCE_FW_LINK_SPEED_50GB BIT(9)
#define MCE_FW_LINK_SPEED_100GB BIT(10)
#define MCE_FW_LINK_SPEED_200GB BIT(11)
#define MCE_FW_LINK_SPEED_UNKNOWN BIT(15)

/* support phy type */
#define MCE_PHY_TYPE_LOW_100BASE_TX BIT_ULL(0)
#define MCE_PHY_TYPE_LOW_100M_SGMII BIT_ULL(1)
#define MCE_PHY_TYPE_LOW_1000BASE_T BIT_ULL(2)
#define MCE_PHY_TYPE_LOW_1000BASE_SX BIT_ULL(3)
#define MCE_PHY_TYPE_LOW_1000BASE_LX BIT_ULL(4)
#define MCE_PHY_TYPE_LOW_1000BASE_KX BIT_ULL(5)
#define MCE_PHY_TYPE_LOW_1G_SGMII BIT_ULL(6)
#define MCE_PHY_TYPE_LOW_2500BASE_T BIT_ULL(7)
#define MCE_PHY_TYPE_LOW_2500BASE_X BIT_ULL(8)
#define MCE_PHY_TYPE_LOW_2500BASE_KX BIT_ULL(9)
#define MCE_PHY_TYPE_LOW_5GBASE_T BIT_ULL(10)
#define MCE_PHY_TYPE_LOW_5GBASE_KR BIT_ULL(11)
#define MCE_PHY_TYPE_LOW_10GBASE_T BIT_ULL(12)
#define MCE_PHY_TYPE_LOW_10G_SFI_DA BIT_ULL(13)
#define MCE_PHY_TYPE_LOW_10GBASE_SR BIT_ULL(14)
#define MCE_PHY_TYPE_LOW_10GBASE_LR BIT_ULL(15)
#define MCE_PHY_TYPE_LOW_10GBASE_KR BIT_ULL(16)
#define MCE_PHY_TYPE_LOW_10G_SFI_AOC_ACC BIT_ULL(17)
#define MCE_PHY_TYPE_LOW_10G_SFI_C2C BIT_ULL(18)
#define MCE_PHY_TYPE_LOW_25GBASE_T BIT_ULL(19)
#define MCE_PHY_TYPE_LOW_25GBASE_CR BIT_ULL(20)
#define MCE_PHY_TYPE_LOW_25GBASE_CR_S BIT_ULL(21)
#define MCE_PHY_TYPE_LOW_25GBASE_CR1 BIT_ULL(22)
#define MCE_PHY_TYPE_LOW_25GBASE_SR BIT_ULL(23)
#define MCE_PHY_TYPE_LOW_25GBASE_LR BIT_ULL(24)
#define MCE_PHY_TYPE_LOW_25GBASE_KR BIT_ULL(25)
#define MCE_PHY_TYPE_LOW_25GBASE_KR_S BIT_ULL(26)
#define MCE_PHY_TYPE_LOW_25GBASE_KR1 BIT_ULL(27)
#define MCE_PHY_TYPE_LOW_25G_AUI_AOC_ACC BIT_ULL(28)
#define MCE_PHY_TYPE_LOW_25G_AUI_C2C BIT_ULL(29)
#define MCE_PHY_TYPE_LOW_40GBASE_CR4 BIT_ULL(30)
#define MCE_PHY_TYPE_LOW_40GBASE_SR4 BIT_ULL(31)
#define MCE_PHY_TYPE_LOW_40GBASE_LR4 BIT_ULL(32)
#define MCE_PHY_TYPE_LOW_40GBASE_KR4 BIT_ULL(33)
#define MCE_PHY_TYPE_LOW_40G_XLAUI_AOC_ACC BIT_ULL(34)
#define MCE_PHY_TYPE_LOW_40G_XLAUI BIT_ULL(35)
#define MCE_PHY_TYPE_LOW_50GBASE_CR2 BIT_ULL(36)
#define MCE_PHY_TYPE_LOW_50GBASE_SR2 BIT_ULL(37)
#define MCE_PHY_TYPE_LOW_50GBASE_LR2 BIT_ULL(38)
#define MCE_PHY_TYPE_LOW_50GBASE_KR2 BIT_ULL(39)
#define MCE_PHY_TYPE_LOW_50G_LAUI2_AOC_ACC BIT_ULL(40)
#define MCE_PHY_TYPE_LOW_50G_LAUI2 BIT_ULL(41)
#define MCE_PHY_TYPE_LOW_50G_AUI2_AOC_ACC BIT_ULL(42)
#define MCE_PHY_TYPE_LOW_50G_AUI2 BIT_ULL(43)
#define MCE_PHY_TYPE_LOW_50GBASE_CR_PAM4 BIT_ULL(44)
#define MCE_PHY_TYPE_LOW_50GBASE_SR BIT_ULL(45)
#define MCE_PHY_TYPE_LOW_50GBASE_FR BIT_ULL(46)
#define MCE_PHY_TYPE_LOW_50GBASE_LR BIT_ULL(47)
#define MCE_PHY_TYPE_LOW_50GBASE_KR_PAM4 BIT_ULL(48)
#define MCE_PHY_TYPE_LOW_50G_AUI1_AOC_ACC BIT_ULL(49)
#define MCE_PHY_TYPE_LOW_50G_AUI1 BIT_ULL(50)
#define MCE_PHY_TYPE_LOW_100GBASE_CR4 BIT_ULL(51)
#define MCE_PHY_TYPE_LOW_100GBASE_SR4 BIT_ULL(52)
#define MCE_PHY_TYPE_LOW_100GBASE_LR4 BIT_ULL(53)
#define MCE_PHY_TYPE_LOW_100GBASE_KR4 BIT_ULL(54)
#define MCE_PHY_TYPE_LOW_100G_CAUI4_AOC_ACC BIT_ULL(55)
#define MCE_PHY_TYPE_LOW_100G_CAUI4 BIT_ULL(56)
#define MCE_PHY_TYPE_LOW_100G_AUI4_AOC_ACC BIT_ULL(57)
#define MCE_PHY_TYPE_LOW_100G_AUI4 BIT_ULL(58)
#define MCE_PHY_TYPE_LOW_100GBASE_CR_PAM4 BIT_ULL(59)
#define MCE_PHY_TYPE_LOW_100GBASE_KR4_PAM4 BIT_ULL(60)
#define MCE_PHY_TYPE_LOW_100GBASE_CR2_PAM4 BIT_ULL(61)
#define MCE_PHY_TYPE_LOW_100GBASE_SR2 BIT_ULL(62)
#define MCE_PHY_TYPE_LOW_100GBASE_DR BIT_ULL(63)
#define MCE_PHY_TYPE_LOW_MAX_INDEX 63

/* Media Types */
enum mce_media_type {
	MCE_MEDIA_NONE = 0,
	MCE_MEDIA_UNKNOWN,
	MCE_MEDIA_FIBER,
	MCE_MEDIA_BASET,
	MCE_MEDIA_BACKPLANE,
	MCE_MEDIA_DA,
	MCE_MEDIA_COPPER,
	MCE_MEDIA_AUI,
};

enum mce_port_module_type {
	MCE_MODULE_UNSUPPORT = 0,
	/* 100G/40G */
	MCE_MODULE_CR4,
	MCE_MODULE_SR4,
	MCE_MODULE_LR4_ER4,
	MCE_MODULE_KR4,
	/* 25G/10G */
	MCE_MODULE_CR,
	MCE_MODULE_SR,
	MCE_MODULE_LR_ER,
	MCE_MODULE_KR,
	MCE_MODULE_BASET,
	/* 1G */
	MCE_MODULE_1G_T,
	MCE_MODULE_1G_X,
	MCE_MODULE_1G_KX,
};

enum mce_force_speed {
	MCE_FORCE_NONE = 0,
	MCE_FORCE_1G = 1,
	MCE_FORCE_10G = 2,
	MCE_FORCE_25G = 3,
	MCE_FORCE_40G = 4,
	MCE_FORCE_100G = 5,
};

struct mce_phy_ability {
	/* 0 Byte*/
	u8 speed_1g : 1;
	u8 speed_10g : 1;
	u8 speed_25g : 1;
	u8 speed_40g : 1;
	u8 speed_100g : 1;
	u8 force_speed_by_user : 3; /* 0: no force 1:1G 2:10G 3:25G 4:40G 5:100G */

	/* 1 Byte*/
	u8 acc : 1;
	u8 dac : 1;
	u8 unsupported_sfp : 1;
	u8 sfp_rj45_or_t : 1; /* 10G-T 1G-T 100G-T */
	u8 is_sgmii : 1;
	u8 is_backplane : 1;
	u8 sfp_c0_c1_valid : 1;
	u8 sfp_mod_abs : 1;

	/* 2 Byte */
	union {
		/* fiber40G/100G */
		struct {
			u8 c0 : 4;
#define QSFP_C_CR4 1
#define QSFP_C_SR4 2
#define QSFP_C_LR4 3
#define QSFP_C_PSM4 4
#define QSFP_C_ER4 5
#define QSFP_C_CWDM4 6
#define QSFP_C_CLR4 7
#define QSFP_C_SWDM4 8

			u8 c0_10g : 2;
#define QSFP_C_10G_SR 1
#define QSFP_C_10G_LR 2
#define QSFP_C_10G_LRM 3

			u8 c0_1g : 2;
#define QSFP_C_1G_SX 1
#define QSFP_C_1G_LX 2
#define QSFP_C_1G_CX 3
		};

		/* fiber 1G/10G/25G */
		struct {
			u8 c1 : 4;
#define SFP_C_SR 1
#define SFP_C_LR 2
#define SFP_C_LRM 3
#define SFP_C_CR 4
#define SFP_C_ER 5
#define SFP_C_KR 6

			u8 c1_1g : 2;
#define SFP_C_1G_SX 1
#define SFP_C_1G_LX 2
#define SFP_C_1G_CX 3
		};

		/* sgmii */
		struct {
			u8 phy_addr : 2;
			u8 phy_id_idx : 4;
			u8 a;
		};
	};
} __packed __aligned(4);

union ext_stat {
	struct {
		u32 phy_ablity : 24; /* struct mce_phy_ability */
		u32 rdma_disable : 1;
		u32 have_rdma : 1;
		u32 wol_supported : 1;
		u32 wol_enabled : 1;
		u32 rev : 1;
		u32 magic : 3;
#define ext_ABLITY_IMAGE 0b101
	};
	u32 v;
} __packed;

struct fw_stat {
	u32 fw_linkup : 1;
	u32 fw_nic_reset_done : 1;
	union dm_stat stat0;
	union nic_stat stat1;
	union ext_stat stat2;

	u32 fix_mac_addr[2];
	u32 fw_version;
	u32 pxe_version;
};

enum FORCE_SPEED {
	NO_FORCE_SPEED = 0,
	FORCE_1G = 1,
	FORCE_10G = 2,
	FORCE_25G = 3,
	FORCE_40G = 4,
	FORCE_100G = 5,
	FORCE_100M = 6,
	FORCE_10M = 7
};

enum mce_axi_clk {
	AXI_NO_FORCE = 0,
	AXI_250_MHZ,
	AXI_333_MHZ,
	AXI_500_MHZ,
};

#define MCE_HW_PROFILE 5

struct tuple4_policy {
	struct list_head l;
	int vf;
	int entry;
	bool free;
	u8 mac[ETH_ALEN];
	u16 vlan;
	int owner_ifindex; /* ifindex of owning macvtap (PF MACVLAN only) */
};

struct mce_hw {
	struct mce_hw_operations *ops;
	u8 __iomem *npu_bar_base;
	u8 __iomem *eth_bar_base; /* bar2 */
	u8 __iomem *rdma_bar_base;
	resource_size_t rdma_bar_phy;
	u8 __iomem *vector_bar_base;
	u8 __iomem *dm_stat;
	u8 __iomem *nic_stat;
	u8 __iomem *ext_stat;
	u8 __iomem *ext2_stat;

	u8 __iomem *bar_1th;
	u8 __iomem *bar_2th;
	u8 __iomem *bar_3th;
	resource_size_t bar_1th_phy;
	resource_size_t bar_2th_phy;
	resource_size_t bar_3th_phy;
	int bar_1th_sz;
	int bar_2th_sz;
	int bar_3th_sz;
	void *back;
	int num_vfs;

	struct pf_vf_num pfvfnum;

	struct fw_stat fw_stat;
	int speed_limit;
	int sp_timeout;
	int max_speed;
	bool disable_40_100g_card_25g_and_below;

	u16 vendor_id;
	u16 device_id;
	u16 subsystem_device_id;
	u16 subsystem_vendor_id;
	struct mce_bus_info bus;
	enum FORCE_SPEED saved_force_speed;
	bool is_sgmii;
	int axi_mhz;
	bool npu_avail;
	u8 revision_id;
	u16 msix_vector_bar;
	u32 vector_offset;

	struct mce_hw_func_caps func_caps; /* function capabilities */

	u8 rss_hfunc;
	u8 rss_key[MCE_MAX_RSS_KEY_SIZE];
	u16 rss_table[MCE_MAX_RSS_INDIR_TABLE_SIZE];
	u32 rss_hash_type; /* match whith FLAG REG N20_RSS_HASH_MRQC */
#define MCE_F_HASH_IPV6_SCTP BIT(0)
#define MCE_F_HASH_IPV4_SCTP BIT(1)
#define MCE_F_HASH_IPV6_UDP BIT(2)
#define MCE_F_HASH_IPV4_UDP BIT(3)
#define MCE_F_HASH_IPV6_TCP BIT(4)
#define MCE_F_HASH_IPV4_TCP BIT(5)
#define MCE_F_HASH_IPV6 BIT(6)
#define MCE_F_HASH_IPV4 BIT(7)
#define MCE_F_HASH_IPV6_TEID BIT(8)
#define MCE_F_HASH_IPV4_TEID BIT(9)
#define MCE_F_HASH_IPV6_SPI BIT(10)
#define MCE_F_HASH_IPV4_SPI BIT(11)
#define MCE_F_HASH_IPV6_FLEX BIT(12)
#define MCE_F_HASH_IPV4_FLEX BIT(13)
#define MCE_F_HASH_ONLY_FLEX BIT(14)
#define MCE_F_HASH_PTP BIT(28)
#define MCE_F_HASH_ORDER BIT(29)
#define MCE_F_HASH_XOR_OR_TOP BIT(30)
	u32 hw_flags;
#define MCE_F_RSS_TABLE_INITED BIT(0)
#define MCE_F_RX_FCS_EN BIT(1)
#define MCE_F_RX_ALL_EN BIT(2)
#define MCE_F_NTUPLE BIT(3)

	struct mce_hw_qos qos;
	u32 hw_type;
	bool vf_isolation_disabled;
	int vf_max_ring;
	int vf_min_ring_cnt;
	int vf_max_ring_cnt;
	int nr_pf;
	u32 fw_version;
	u32 nic_version;
	u32 dma_version;
	int vf_uc_addr_offset;
	int vf_macvlan_addr_offset;
	int vf_bcmc_addr_offset;
#define MCE_MAX_MC_WHITE_LISTS (16)
	DECLARE_BITMAP(avail_mc, MCE_MAX_MC_WHITE_LISTS);
	struct mce_mc_info mc_info[MCE_MAX_MC_WHITE_LISTS];
	bool promisc_no_permit;
	DECLARE_BITMAP(l2_fltr_flags, L2_FLAGS_LAST);

	struct mutex fdir_fltr_lock; /* protect Flow Director */
	struct list_head fdir_list_head;
	struct list_head vlan_list_head;
	int fdir_active_fltr;
	int fdir_etype_active_fltr;
	int fdir_ntuple5_active_fltr;
	/* tunneling info */
	struct mutex tnl_lock;
	struct mce_tunnel_table tnl[TNL_ALL];

	struct device *dev;
	struct pci_dev *pdev;

	struct mce_port_info *port_info;
	struct mce_flash_info flash;

	int cur_link_speed;
	int cur_tc_time_for_rdma;
	/* ptp */
	u64 clk_ptp_rate;
	u32 ptp_default_int;
	u32 max_vfs;
	struct mce_mbx_info fw_mbx;
#define MAX_VF_CNT 128
	struct mce_mbx_info vf_mbx[MAX_VF_CNT];
	struct mce_vf_info vf;
	struct mce_eswitch_info eswitch;
	struct mce_mbx_info *irq_valid_mbxs[MBX_CNT];

#define MCE_ACL_MAX_TUPLE5_CNT 511
	DECLARE_BITMAP(avail_tuple5, MCE_ACL_MAX_TUPLE5_CNT);
	int ring_base_addr;
	int ring_max_cnt;
	bool pcie_isolate_on;
	bool rx_wrr_en;
	int vmark[8];
	struct mce_uc_mc_hash_ctl uc_mc_hash_ctl;

	struct tuple4_policy tuple4_policy;
	struct tuple4_policy *tuple4_policy_list;

#define MCE_FILTER_HASH_TB_BITS 12
#define MCE_FILTER_HASH_TB_SIZE BIT(MCE_FILTER_HASH_TB_BITS)
	DECLARE_HASHTABLE(uc_hash_tb, MCE_FILTER_HASH_TB_BITS);
	DECLARE_BITMAP(uc_hash_bm, MCE_FILTER_HASH_TB_SIZE);

	DECLARE_HASHTABLE(mc_hash_tb, MCE_FILTER_HASH_TB_BITS);
	DECLARE_BITMAP(mc_hash_bm, MCE_FILTER_HASH_TB_SIZE);
	spinlock_t mac_hash_lock; /* protect mac address add or del */
	struct mce_hw_qos vf_rate_qos;
	enum mce_axi_clk axi_mode;
};

int mce_vf_set_veb_misc_rule(struct mce_hw *hw, int vfid,
			     enum veb_policy_type ptype);

extern unsigned int mce_loglevel;
extern bool mce_rx_page_pool_en;

/* Without PREEMPT_COUNT, preemptible() cannot test whether sleeping is safe. */
static inline bool mce_context_can_sleep(void)
{
#ifdef CONFIG_PREEMPT_COUNT
	return preemptible();
#else
	return !in_interrupt() && !irqs_disabled();
#endif
}

enum MCE_NET_LOG {
	LOG_MBX_IN_REQ,
	LOG_MBX_REQ_OUT,
	LOG_VECTOR_ALLOC,
	LOG_MISC_IRQ,
	LOG_CDEV,
	LOG_LINK_INFO,
	LOG_PTP_HW,
	LOG_PTP_WORK,
	LOG_QUEUE_INFO,
	LOG_NTUPLE_INFO,
	LOG_FEC,
	LOG_NET_DEV_EVENT,
	LOG_FDIR_INFO,
	LOG_FDIR_DEBUG,
	LOG_ARFS,
	LOG_NET_MAX, /* must be last one */
};

#define logd(bit, fmt, args...)				\
	do {							\
		if (BIT(bit) & mce_loglevel)			\
			pr_debug(fmt, ##args);		\
	} while (0)

#define fd_logd(bit, fmt, args...) \
	logd(bit, "%s: " fmt, __func__, ##args)

#define hw_logd(bit, fmt, args...)                      \
	do {                                            \
		if (BIT(bit) & mce_loglevel) {          \
			dev_info(hw->dev, fmt, ##args); \
		}                                       \
	} while (0)

#define pf_logd(bit, fmt, args...)                                \
	do {                                                      \
		if (BIT(bit) & mce_loglevel) {                    \
			dev_info(mce_pf_to_dev(pf), fmt, ##args); \
		}                                                 \
	} while (0)

#define netdev_logd(bit, fmt, args...)                    \
	do {                                              \
		if (BIT(bit) & mce_loglevel) {            \
			netdev_info(netdev, fmt, ##args); \
		}                                         \
	} while (0)

#define mbx_logd(bit, fmt, args...)                          \
	do {                                                 \
		if (BIT(bit) & mce_loglevel) {               \
			dev_info(mbx->hw->dev, fmt, ##args); \
		}                                            \
	} while (0)

static inline bool mce_log_enabled(unsigned int bit)
{
	return BIT(bit) & mce_loglevel;
}

#define logd_if(bit) mce_log_enabled(bit)

static inline int mce_get_phy_ablity(struct mce_hw *hw,
				     struct mce_phy_ability *ablity)
{
	u32 v = 0;

	hw->ops->update_fw_stat(hw);
	v = hw->fw_stat.stat2.phy_ablity;
	memcpy(ablity, &v, sizeof(*ablity));
	return 0;
}

#endif /*_MCE_TYPE_H_*/
