/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2020-2026 Mucse Corporation. */

#ifndef _MCEVF_TYPE_H_
#define _MCEVF_TYPE_H_

#define MCEVF_MAX_RSS_KEY_SIZE (64)
#define MCEVF_MAX_RSS_INDIR_TABLE_SIZE (512)

struct mcevf_ring;
struct mcevf_fdir_fltr;
struct mcevf_hw;
struct mcevf_dcb;

#include "mcevf_virtchnl.h"
#include "mcevf_txrx.h"

/* PCI bus types */
enum mcevf_bus_type {
	mcevf_bus_unknown = 0,
	mcevf_bus_pci_express,
	mcevf_bus_embedded, /* Is device Embedded versus card */
	mcevf_bus_reserved
};

/* PCI bus speeds */
enum mcevf_pcie_bus_speed {
	mcevf_pcie_speed_unknown = 0xff,
	mcevf_pcie_speed_2_5GT = 0x14,
	mcevf_pcie_speed_5_0GT = 0x15,
	mcevf_pcie_speed_8_0GT = 0x16,
	mcevf_pcie_speed_16_0GT = 0x17
};

/* PCI bus widths */
enum mcevf_pcie_link_width {
	mcevf_pcie_lnk_width_resrv = 0x00,
	mcevf_pcie_lnk_x1 = 0x01,
	mcevf_pcie_lnk_x2 = 0x02,
	mcevf_pcie_lnk_x4 = 0x04,
	mcevf_pcie_lnk_x8 = 0x08,
	mcevf_pcie_lnk_x12 = 0x0C,
	mcevf_pcie_lnk_x16 = 0x10,
	mcevf_pcie_lnk_x32 = 0x20,
	mcevf_pcie_lnk_width_unknown = 0xff,
};

struct mcevf_ofld_stats {
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

/* Bus parameters */
struct mcevf_bus_info {
	enum mcevf_pcie_bus_speed speed;
	enum mcevf_pcie_link_width width;
	enum mcevf_bus_type type;
	u16 domain_num;
	u16 device;
	u8 func;
	u8 bus_num;
};

/* Common HW capabilities for SW use */
struct mcevf_hw_common_caps {
	/* Tx/Rx queues */
	u32 num_rxq; /* Number/Total Rx queues */
	u32 num_txq; /* Number/Total Tx queues */

	/* RSS related capabilities */
	u32 rss_table_size; /* 512 for PFs*/
	u32 rss_key_size;
	u16 vlan_strip_cnt;

	/* IRQs */
	u16 max_irq_cnts; /* max cnts supported by hardware*/
	u16 mbox_irq_base;
	u16 qvec_irq_base;
	u16 num_mbox_irqs;
	u16 rdma_irq_base;
	u16 num_rdma_irqs;
	bool drop_intr_timer_en;
};

/* Function specific capabilities */
struct mcevf_hw_func_caps {
	struct mcevf_hw_common_caps common_cap;
	u32 num_allocd_vfs; /* Number of allocated VFs */
	u32 guar_num_vsi;
	u32 fd_fltr_guar;
};

struct mcevf_mbx_operations {
	s32 (*init_params)(struct mcevf_hw *hw);
	s32 (*read)(struct mcevf_hw *hw, u32 *value, u16 reg, bool lock);
	s32 (*write)(struct mcevf_hw *hw, u32 *value, u16 reg, bool lock);
	s32 (*read_posted)(struct mcevf_hw *hw, u32 *value, u16 reg, bool lock);
	s32 (*write_posted)(struct mcevf_hw *hw, u32 *value, u16 reg, bool lock);
	s32 (*check_for_msg)(struct mcevf_hw *hw, bool lock);
	s32 (*check_for_ack)(struct mcevf_hw *hw, bool lock);
	s32 (*configure)(struct mcevf_hw *hw, int nr_vec, bool enable);
	u32 (*ram_read)(struct mcevf_hw *hw, u8 ram_id, u8 reg_id);
	void (*ram_write)(struct mcevf_hw *hw, u8 ram_id, u8 reg_id, u32 val);
};

struct mcevf_mbx_stats {
	u32 tx_event_cnt;
	u32 tx_event_err_cnt;

	u32 tx_req_cnt;
	u32 tx_shm_lock_timeout;

	u32 rx_resp_cnt;
	u32 rx_req_shm_lock_timeout;
	u32 rx_resp_shm_lock_timeout;
};

#include "mcevf_mbx.h"

struct mcevf_mbx_info {
	struct mcevf_mbx_stats stats;
	struct mcevf_hw *hw;
	u16 size;

	char name[60];
	struct mutex req_lock; /* serializes outgoing mailbox requests */
	spinlock_t req_shm_lock; /* protects request shared memory */
	spinlock_t peer_shm_lock; /* protects peer shared memory */

	bool irq_enabled;
	bool setup_done;

	int nr_vf;
	int nr_pf;
	bool is_pf_mbx;

	int req_shm_size;   // VF2PF shm size
	int peer_shm_size;  // PF2VF shm size

	u8 __iomem *peer2vf_shm;  // peer = PF or FW
	u8 __iomem *peer2vf_shm_lock;
	u8 __iomem *peer2vf_ctrl;
	u32 peer2vf_shm_lock_msk;

	u8 __iomem *vf2peer_shm;
	u8 __iomem *vf2peer_shm_lock;
	u8 __iomem *vf2peer_ctrl;
	u32 vf2peer_shm_lock_msk;

	u8 __iomem *mbx_vec_base;
};

struct mcevf_virtchnl_info {
	struct mcevf_virtchnl_operations *ops;
};

struct mcevf_operations {
	/* hw */
	int (*reset_hw)(struct mcevf_hw *hw);
	void (*init_hw)(struct mcevf_hw *hw);
	int (*get_queues)(struct mcevf_hw *hw);
	int (*init_vport_hw_attr)(struct mcevf_hw *hw, bool on);
	int (*set_unicast_addr)(struct mcevf_hw *hw, u8 *addr);

	void (*cfg_vec2tqirq)(struct mcevf_hw *hw, u16 vec, u16 queue);
	void (*cfg_vec2rqirq)(struct mcevf_hw *hw, u16 vec, u16 queue);
	void (*set_max_pktlen)(struct mcevf_hw *hw, u32 max_pktlen);
	void (*set_vlan_filter)(struct mcevf_hw *hw, netdev_features_t features);
	void (*add_vlan_filter)(struct mcevf_hw *hw, u16 vlan);
	void (*del_vlan_filter)(struct mcevf_hw *hw, u16 vlan);
	s32 (*set_vlan_strip)(struct mcevf_hw *hw,
			      netdev_features_t features);
	s32 (*set_vlan_vfta)(struct mcevf_hw *hw, u32 vlan, u32 vind,
			     bool vlan_on);
	void (*set_rx_csumofld)(struct mcevf_hw *hw, netdev_features_t features);
	void (*set_rss_hash)(struct mcevf_hw *hw, netdev_features_t features);
	void (*set_rss_key)(struct mcevf_hw *hw);
	void (*set_rss_hash_type)(struct mcevf_hw *hw);
	void (*set_rss_table)(struct mcevf_hw *hw, u16 size);
	void (*set_uc_filter)(struct mcevf_hw *hw, bool enable);
	int (*add_uc_filter)(struct mcevf_hw *hw, const u8 *addr);
	int (*del_uc_filter)(struct mcevf_hw *hw, const u8 *addr);
	void (*set_mc_filter)(struct mcevf_hw *hw, bool enable);
	void (*add_mc_filter)(struct mcevf_hw *hw, const u8 *maddr);
	void (*del_mc_filter)(struct mcevf_hw *hw, const u8 *addr);
	void (*clear_mc_filter)(struct mcevf_hw *hw);

	int (*set_mc_promisc)(struct mcevf_hw *hw, bool enable);
	int (*set_uc_promisc)(struct mcevf_hw *hw, bool enable);
	int (*set_vlan_promisc)(struct mcevf_hw *hw, bool enable);
	int (*set_pf_promisc_mode)(struct mcevf_hw *hw, u32 flags);
	void (*add_ntuple_filter)(struct mcevf_hw *hw,
				  struct mcevf_fdir_fltr *rule);
	void (*del_ntuple_filter)(struct mcevf_hw *hw,
				  struct mcevf_fdir_fltr *rule);

	/* ring */
	void (*set_rxring_ctx)(struct mcevf_ring *ring, struct mcevf_hw *hw);
	void (*set_txring_ctx)(struct mcevf_ring *ring, struct mcevf_hw *hw);
	void (*enable_txrxring_irq)(struct mcevf_ring *ring);
	void (*disable_txrxring_irq)(struct mcevf_ring *ring);
	void (*start_rxring)(struct mcevf_ring *ring);
	void (*stop_rxring)(struct mcevf_ring *ring);
	void (*start_txring)(struct mcevf_ring *ring);
	void (*stop_txring)(struct mcevf_ring *ring);
	void (*set_rxring_intr_coal)(struct mcevf_ring *ring);
	void (*set_txring_intr_coal)(struct mcevf_ring *ring);
	void (*set_rxring_hw_dim)(struct mcevf_ring *ring, bool enable);
	void (*set_txring_hw_dim)(struct mcevf_ring *ring, bool enable);
	int (*cfg_txring_bw_lmt)(struct mcevf_ring *ring, u32 limit);
	int (*set_txring_trig_intr)(struct mcevf_ring *tx_ring);
	u64 (*get_hw_ring_stats)(struct mcevf_ring *ring,
				 enum mcevf_hw_ring_stats_type type);
	int (*clear_hw_ring_stats)(struct mcevf_hw *hw);
	void (*set_tun_select_inner)(struct mcevf_hw *hw, bool inner);
	/* pfc */
	void (*set_q_to_pfc)(struct mcevf_hw *hw, struct mcevf_dcb *dcb);
	void (*clr_q_to_pfc)(struct mcevf_hw *hw);
};

struct mcevf_mac_info {
	// struct mcevf_mac_operations ops;
	u8 addr[ETH_ALEN];
	u8 perm_addr[ETH_ALEN];
};

struct mcevf_mc_info {
	u8 addr[ETH_ALEN];
	bool en;
};

struct mcevf_hw {
	void *back;
	u8 __iomem *eth_bar_base;
	resource_size_t eth_bar_phy;
	u8 __iomem *rdma_bar_base;
	resource_size_t rdma_bar_phy;

	u16 vendor_id;
	u16 device_id;
	u16 subsystem_device_id;
	u16 subsystem_vendor_id;
	struct mcevf_bus_info bus;

	u8 pf_id; /* device profile info */
	u8 revision_id;
	u32 vector_offset;
	bool is_vf_isolated_enabled;

	struct mcevf_hw_func_caps func_caps; /* function capabilities */
	u8 rss_hfunc;
	u8 rss_key[MCEVF_MAX_RSS_KEY_SIZE];
	u16 rss_table[MCEVF_MAX_RSS_INDIR_TABLE_SIZE];
	u32 rss_hash_type; /* match with FLAG REG N20_RSS_HASH_MRQC */
#define MCEVF_F_HASH_IPV6_SCTP BIT(0)
#define MCEVF_F_HASH_IPV4_SCTP BIT(1)
#define MCEVF_F_HASH_IPV6_UDP BIT(2)
#define MCEVF_F_HASH_IPV4_UDP BIT(3)
#define MCEVF_F_HASH_IPV6_TCP BIT(4)
#define MCEVF_F_HASH_IPV4_TCP BIT(5)
#define MCEVF_F_HASH_IPV6 BIT(6)
#define MCEVF_F_HASH_IPV4 BIT(7)
#define MCEVF_F_HASH_IPV6_TEID BIT(8)
#define MCEVF_F_HASH_IPV4_TEID BIT(9)
#define MCEVF_F_HASH_IPV6_SPI BIT(10)
#define MCEVF_F_HASH_IPV4_SPI BIT(11)
#define MCEVF_F_HASH_IPV6_FLEX BIT(12)
#define MCEVF_F_HASH_IPV4_FLEX BIT(13)
#define MCEVF_F_HASH_ONLY_FLEX BIT(14)
#define MCEVF_F_HASH_PTP BIT(28)
#define MCEVF_F_HASH_ORDER BIT(29)
#define MCEVF_F_HASH_XOR_OR_TOP BIT(30)
	u8 perm_addr[ETH_ALEN];
	u8 addr[ETH_ALEN];

	u32 hw_type;
	u32 fw_version;
	bool reset_done;

	struct mutex fdir_fltr_lock; /* protect Flow Director */
	struct list_head fdir_list_head;
	int fdir_active_fltr;

	struct device *dev;
	struct pci_dev *pdev;

	struct mcevf_port_info *port_info;

	struct mcevf_mbx_info pf_mbx;
	struct mcevf_operations *ops;
	struct mcevf_mac_info mac;
	struct mcevf_virtchnl_info virtchnl;
	int vfnum;
	int nr_pf;
	int bcmc_addr_offset;
	int uc_addr_offset;
	u16 queue_ring_base;
#define MCEVF_MAX_MC_WHITE_LISTS (16)
	DECLARE_BITMAP(avail_mc, MCEVF_MAX_MC_WHITE_LISTS);
	struct mcevf_mc_info mc_info[MCEVF_MAX_MC_WHITE_LISTS];
	int ring_max_cnt;
	int axi_mhz;
	int ring_base_addr;
	u32 sriov;
	bool rdma_state;
};

#endif /*_MCEVF_TYPE_H_*/
