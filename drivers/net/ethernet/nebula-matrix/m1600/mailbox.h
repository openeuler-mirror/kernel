/* SPDX-License-Identifier: GPL-2.0*/
/*
 * Copyright (c) 2022 nebula-matrix Limited.
 * Author: Monte Song <monte.song@nebula-matrix.com>
 */

#ifndef _NBL_MAILBOX_H_
#define _NBL_MAILBOX_H_

#include <linux/ethtool.h>

#define NBL_MAILBOX_TX_DESC(tx_ring, i) \
	(&(((struct nbl_mailbox_tx_desc *)((tx_ring)->desc))[i]))
#define NBL_MAILBOX_RX_DESC(rx_ring, i) \
	(&(((struct nbl_mailbox_rx_desc *)((rx_ring)->desc))[i]))
#define NBL_MAILBOX_TX_BUF(tx_ring, i)  (&(((tx_ring)->buf)[i]))
#define NBL_MAILBOX_RX_BUF(rx_ring, i)  (&(((rx_ring)->buf)[i]))

#define NBL_MAILBOX_TX_WAIT_US 100
#define NBL_MAILBOX_TX_WAIT_TIMES 10000
#define NBL_MAILBOX_TX_UPDATE_NOTIFY_LIMITS (NBL_MAILBOX_TX_WAIT_TIMES / 4)

typedef void (*nbl_mailbox_msg_handler)(struct nbl_hw *, void *, u32);

/* WARNING: please keep consistent with PMD driver */
enum nbl_mailbox_msg_type {
	NBL_MAILBOX_ACK,
	NBL_MAILBOX_CFG_MSIX_MAP_TABLE,
	NBL_MAILBOX_DESTROY_MSIX_MAP_TABLE,
	NBL_MAILBOX_ENABLE_MAILBOX_IRQ,
	NBL_MAILBOX_DISABLE_MAILBOX_IRQ,
	NBL_MAILBOX_GET_VSI_ID,
	NBL_MAILBOX_REGISTER_VF_BAR_INFO,
	NBL_MAILBOX_GET_VF_BAR_BASE_ADDR,
	NBL_MAILBOX_CFG_QID_MAP,
	NBL_MAILBOX_CLEAR_QID_MAP,
	NBL_MAILBOX_CFG_PROMISC,
	NBL_MAILBOX_CFG_INGRESS_ETH_PORT_TABLE,
	NBL_MAILBOX_CFG_SRC_VSI_TABLE,
	NBL_MAILBOX_CFG_DEST_VSI_TABLE,
	NBL_MAILBOX_CFG_TX_RING,
	NBL_MAILBOX_CFG_RX_RING,
	NBL_MAILBOX_CFG_QUEUE_MAP,
	NBL_MAILBOX_CONTROL_QUEUE,
	NBL_MAILBOX_RESET_TX_QUEUE,
	NBL_MAILBOX_RESET_RX_QUEUE,
	NBL_MAILBOX_WAIT_RX_QUEUE_RESET_DONE,
	NBL_MAILBOX_CFG_PORT_MAP,
	NBL_MAILBOX_CFG_RSS_GROUP_TABLE,
	NBL_MAILBOX_CFG_MSIX_IRQ,
	NBL_MAILBOX_CLEAR_MSIX_IRQ_CONF,
	NBL_MAILBOX_ETH_TX_ENABLE,
	NBL_MAILBOX_ETH_RX_ENABLE,
	NBL_MAILBOX_ETH_TX_DISABLE,
	NBL_MAILBOX_ETH_RX_DISABLE,
	NBL_MAILBOX_ENTER_FORWARD_RING_MODE,
	NBL_MAILBOX_LEAVE_FORWARD_RING_MODE,
	NBL_MAILBOX_GET_FIRMWARE_VERSION,
	NBL_MAILBOX_GET_MODULE_EEPROM,
	NBL_MAILBOX_GET_MODULE_INFO,
	NBL_MAILBOX_GET_EEPROM,
	NBL_MAILBOX_CHECK_MODULE_INPLACE,
	NBL_MAILBOX_GET_RXLOS,
	NBL_MAILBOX_RESET_ETH,
	NBL_MAILBOX_CONFIG_MODULE_SPEED,
	NBL_MAILBOX_GET_LINK_SPEED,
	NBL_MAILBOX_REG_TEST,
	NBL_MAILBOX_GET_ETHTOOL_DUMP_REGS,
	NBL_MAILBOX_GET_BOARD_INFO,
	NBL_MAILBOX_QUERY_LINK_STATUS,
	NBL_MAILBOX_SET_PHY_ID,
	NBL_MAILBOX_SET_PAUSEPARAM,
	NBL_MAILBOX_WRITE_MAC_TO_LOGIC,
	NBL_MAILBOX_GET_PAUSE_STATS,
	NBL_MAILBOX_INIT_PKT_LEN_LIMIT,
	NBL_MAILBOX_GET_COALESCE,
	NBL_MAILBOX_SET_COALESCE,
	NBL_MAILBOX_GET_ETH_STATS,
	NBL_MAILBOX_CONFIGURE_MAC_ADDR,
	NBL_MAILBOX_CLEAR_MAC_ADDR,
	NBL_MAILBOX_CHANGE_MAC_ADDR,
	NBL_MAILBOX_OPERATE_VLAN_ID,
	NBL_MAILBOX_GET_PMD_VSI_STATS,
	NBL_MAILBOX_HELLO_MSG, /* when pf install, send this msg to af */
	NBL_MAILBOX_GOODBYE_MSG, /* when af remove, send this msg to pf , only use in pmd */
	NBL_MAILBOX_RESOURE_RELEASE_DONE, /* when pf release done, send this msg to af */
	NBL_MAILBOX_TYPE_MAX,
};

struct nbl_mailbox_ack_msg_ret {
	unsigned int req_msg_type;
	int err;
} __packed;

struct nbl_mailbox_cfg_msix_map_table_arg {
	u16 requested;
};

struct nbl_mailbox_dummy_arg {
	int dummy;
};

struct nbl_mailbox_enable_mailbox_irq_arg {
	u16 vector_id;
};

struct nbl_mailbox_disable_mailbox_irq_arg {
	u16 local_vector_id;
};

struct nbl_mailbox_register_vf_bar_info_arg {
	u64 vf_bar_start;
	u64 vf_bar_len;
};

struct nbl_mailbox_cfg_qid_map_arg {
	u8 num_queues;
	u64 notify_addr;
};

struct nbl_mailbox_clear_qid_map_arg {
	u64 notify_addr;
};

struct nbl_mailbox_cfg_promisc_arg {
	u8 eth_port_id;
	bool enable;
};

struct nbl_mailbox_cfg_ingress_eth_port_table_arg {
	u8 eth_port_id;
	u8 vsi_id;
};

struct nbl_mailbox_cfg_src_vsi_table_arg {
	u8 eth_port_id;
	u8 vsi_id;
};

struct nbl_mailbox_cfg_dest_vsi_table_arg {
	u8 eth_port_id;
	u8 vsi_id;
};

struct nbl_mailbox_cfg_tx_ring_arg {
	u8 vsi_id;
	u8 local_queue_id;
	u16 desc_num;
	dma_addr_t dma;
};

struct nbl_mailbox_cfg_rx_ring_arg {
	u8 local_queue_id;
	u16 desc_num;
	u32 buf_len;
	dma_addr_t dma;
};

struct nbl_mailbox_cfg_queue_map_arg {
	bool rx;
	bool enable;
	bool msix_enable;
	u8 local_queue_id;
	u16 local_vector_id;
};

struct nbl_mailbox_control_queue_arg {
	bool rx;
	bool enable;
	u8 local_queue_id;
};

struct nbl_mailbox_reset_tx_queue_arg {
	u8 local_queue_id;
};

struct nbl_mailbox_reset_rx_queue_arg {
	u8 local_queue_id;
};

struct nbl_mailbox_wait_rx_queue_reset_done_arg {
	u8 local_queue_id;
};

struct nbl_mailbox_cfg_port_map_arg {
	u8 eth_port_id;
	u8 local_queue_id;
};

struct nbl_mailbox_cfg_rss_group_table_arg {
	u8 vsi_id;
	u8 rx_queue_num;
};

struct nbl_mailbox_cfg_msix_irq_arg {
	u16 local_vector_id;
};

struct nbl_mailbox_clear_msix_irq_conf_arg {
	u16 local_vector_id;
};

struct nbl_mailbox_eth_tx_enable_arg {
	u8 eth_port_id;
};

struct nbl_mailbox_eth_tx_disable_arg {
	u8 eth_port_id;
};

struct nbl_mailbox_eth_rx_enable_arg {
	u8 eth_port_id;
};

struct nbl_mailbox_eth_rx_disable_arg {
	u8 eth_port_id;
};

struct nbl_mailbox_enter_forward_ring_mode_arg {
	u8 eth_port_id;
	u8 vsi_id;
};

struct nbl_mailbox_leave_forward_ring_mode_arg {
	u8 eth_port_id;
	u8 vsi_id;
};

struct nbl_mailbox_get_module_eeprom_arg {
	u8 eth_port_id;
	struct ethtool_eeprom eeprom;
};

struct nbl_mailbox_get_module_info_arg {
	u8 eth_port_id;
};

struct nbl_mailbox_get_eeprom_arg {
	u32 offset;
	u32 length;
};

struct nbl_mailbox_check_module_inplace_arg {
	u8 eth_port_id;
};

struct nbl_mailbox_get_rxlos_arg {
	u8 eth_port_id;
};

struct nbl_mailbox_reset_eth_arg {
	u8 eth_port_id;
};

struct nbl_mailbox_config_module_speed_arg {
	u8 target_speed;
	u8 eth_port_id;
};

struct nbl_mailbox_get_link_speed_arg {
	u8 eth_port_id;
};

struct nbl_mailbox_reg_test_arg {
	u8 eth_port_id;
};

struct nbl_mailbox_get_ethtool_dump_regs_arg {
	u32 count;
};

struct nbl_mailbox_get_board_info_arg {
	u8 eth_port_id;
};

struct nbl_mailbox_query_link_status_arg {
	u8 eth_port_id;
};

struct nbl_mailbox_set_phy_id_arg {
	u8 eth_port_id;
	enum ethtool_phys_id_state state;
};

struct nbl_mailbox_set_pause_arg {
	u8 eth_port_id;
	struct nbl_fc_info fc;
};

struct nbl_mailbox_write_mac_to_logic_arg {
	u8 eth_port_id;
	u8 smac[ETH_ALEN];
};

struct nbl_mailbox_get_pause_stats_arg {
	u8 eth_port_id;
};

struct nbl_mailbox_init_pkt_len_limit_arg {
	u8 eth_port_id;
	struct nbl_pkt_len_limit pkt_len_limit;
};

struct nbl_mailbox_get_coalesce_arg {
	u16 local_vector_id;
};

struct nbl_mailbox_set_coalesce_arg {
	u32 regval;
	u16 local_vector_id;
	u16 num_q_vectors;
};

struct nbl_mailbox_get_eth_stats_arg {
	u8 eth_port_id;
};

struct nbl_mailbox_configure_mac_addr_arg {
	u8 mac_addr[ETH_ALEN];
	u8 eth_port_id;
	u8 vsi_id;
};

struct nbl_mailbox_change_mac_addr_arg {
	u8 mac_addr[ETH_ALEN];
	u8 vsi_id;
};

struct nbl_mailbox_operate_vlan_id_arg {
	u8 vsi_id;
	u16 vlan_id;
	bool add;
};

#define NBL_PMD_MAX_QUEUE_NUM (16)

struct nbl_pmd_stats {
	u16 nb_rx_queues;
	u32 pkt_drop_cnt[NBL_PMD_MAX_QUEUE_NUM];
	u32 eth_ipackets;
	u64 eth_ibytes;
	u32 eth_opackets;
	u64 eth_obytes;
	u64 ierrors;
	u64 oerrors;
};

struct nbl_mailbox_get_pmd_stats_arg {
	u8 eth_port_id;
};

static inline void nbl_mailbox_update_txq_tail_ptr(struct nbl_hw *hw, u16 tail_ptr)
{
	/* local_qid 0 and 1 denote rx and tx queue respectively */
	u32 local_qid = 1;
	u32 value = ((u32)tail_ptr << 16) | local_qid;

	mb_wr32(hw, NBL_MAILBOX_NOTIFY_ADDR, value);
}

static inline void nbl_mailbox_update_rxq_tail_ptr(struct nbl_hw *hw, u16 tail_ptr)
{
	/* local_qid 0 and 1 denote rx and tx queue respectively */
	u32 local_qid = 0;
	u32 value = ((u32)tail_ptr << 16) | local_qid;

	mb_wr32(hw, NBL_MAILBOX_NOTIFY_ADDR, value);
}

int nbl_setup_mailbox(struct nbl_hw *hw);
void nbl_teardown_mailbox(struct nbl_hw *hw);

int nbl_mailbox_req_cfg_msix_map_table(struct nbl_hw *hw, u16 requested);
void nbl_mailbox_req_destroy_msix_map_table(struct nbl_hw *hw);

void nbl_mailbox_enable_irq(struct nbl_adapter *adapter);
void nbl_mailbox_disable_irq(struct nbl_adapter *adapter);

int nbl_mailbox_req_get_vsi_id(struct nbl_hw *hw);

int nbl_mailbox_req_register_vf_bar_info(struct nbl_hw *hw, u64 vf_bar_start, u64 vf_bar_len);

int nbl_mailbox_req_get_vf_bar_base_addr(struct nbl_hw *hw, u64 *base_addr);

int nbl_mailbox_req_cfg_qid_map(struct nbl_hw *hw, u8 num_queues, u64 notify_addr);
void nbl_mailbox_req_clear_qid_map(struct nbl_hw *hw, u64 notify_addr);

void nbl_mailbox_req_enable_promisc(struct nbl_hw *hw, u8 eth_port_id);
void nbl_mailbox_req_disable_promisc(struct nbl_hw *hw, u8 eth_port_id);

void nbl_mailbox_req_cfg_ingress_eth_port_table(struct nbl_hw *hw, u8 eth_port_id, u8 vsi_id);

void nbl_mailbox_req_cfg_src_vsi_table(struct nbl_hw *hw, u8 eth_port_id, u8 vsi_id);
void nbl_mailbox_req_cfg_dest_vsi_table(struct nbl_hw *hw, u8 eth_port_id, u8 vsi_id);

void nbl_mailbox_req_cfg_tx_ring(struct nbl_hw *hw, dma_addr_t dma, u16 desc_num,
				 u8 vsi_id, u8 local_queue_id);
void nbl_mailbox_req_cfg_rx_ring(struct nbl_hw *hw, dma_addr_t dma, u16 desc_num,
				 u32 buf_len, u8 local_queue_id);

void nbl_mailbox_req_cfg_queue_map(struct nbl_hw *hw, u8 local_queue_id, bool rx,
				   u16 local_vector_id, bool enable, bool msix_enable);

void nbl_mailbox_req_control_queue(struct nbl_hw *hw, u8 local_queue_id, bool rx, bool enable);

int nbl_mailbox_req_reset_tx_queue(struct nbl_hw *hw, u8 local_queue_id);
int nbl_mailbox_req_reset_rx_queue(struct nbl_hw *hw, u8 local_queue_id);
int nbl_mailbox_req_wait_rx_queue_reset_done(struct nbl_hw *hw, u8 local_queue_id);

void nbl_mailbox_req_cfg_port_map(struct nbl_hw *hw, u8 eth_port_id, u8 tx_queue_num);

void nbl_mailbox_req_cfg_rss_group_table(struct nbl_hw *hw, u8 vsi_id, u8 rx_queue_num);

void nbl_mailbox_req_cfg_msix_irq(struct nbl_hw *hw, u16 local_vector_id);
void nbl_mailbox_req_clear_msix_irq_conf(struct nbl_hw *hw, u16 local_vector_id);

void nbl_mailbox_req_eth_tx_enable(struct nbl_adapter *adapter, u8 eth_port_id);
void nbl_mailbox_req_eth_rx_enable(struct nbl_adapter *adapter, u8 eth_port_id);
void nbl_mailbox_req_eth_tx_disable(struct nbl_adapter *adapter, u8 eth_port_id);
void nbl_mailbox_req_eth_rx_disable(struct nbl_adapter *adapter, u8 eth_port_id);

#ifdef CONFIG_PCI_IOV
void nbl_mailbox_req_enter_forward_ring_mode(struct nbl_hw *hw, u8 eth_port_id, u8 vsi_id);
void nbl_mailbox_req_leave_forward_ring_mode(struct nbl_hw *hw, u8 eth_port_id, u8 vsi_id);
#endif

u32 nbl_mailbox_req_get_firmware_version(struct nbl_hw *hw);
int nbl_mailbox_req_get_module_eeprom(struct nbl_hw *hw, u8 eth_port_id,
				      struct ethtool_eeprom *eeprom, u8 *data);
int nbl_mailbox_req_get_module_info(struct nbl_hw *hw, u8 eth_port_id,
				    struct ethtool_modinfo *info);

int nbl_mailbox_req_get_eeprom(struct nbl_hw *hw, u32 offset, u32 length, u8 *bytes);

enum NBL_MODULE_INPLACE_STATUS
nbl_mailbox_req_check_module_inplace(struct nbl_hw *hw, u8 eth_port_id);

u32 nbl_mailbox_req_get_rxlos(struct nbl_hw *hw, u8 eth_port_id);

void nbl_mailbox_req_reset_eth(struct nbl_hw *hw, u8 eth_port_id);

int nbl_mailbox_req_config_module_speed(struct nbl_hw *hw, u8 target_speed, u8 eth_port_id);

int nbl_mailbox_req_link_speed(struct nbl_hw *hw, u8 eth_port_id, u32 *speed_stat);

u64 nbl_mailbox_req_reg_test(struct nbl_hw *hw, u8 port_id);

int nbl_mailbox_req_get_ethtool_dump_regs(struct nbl_hw *hw, u32 *regs_buff, u32 count);

int nbl_mailbox_req_get_board_info(struct nbl_hw *hw, u8 eth_port_id,
				   union nbl_board_info *board_info);

bool nbl_mailbox_req_query_link_status(struct nbl_hw *hw, u8 eth_port_id);

int nbl_mailbox_req_set_phy_id(struct nbl_hw *hw, u8 eth_port_id, enum ethtool_phys_id_state state);

void nbl_mailbox_req_set_pauseparam(struct nbl_hw *hw, u8 eth_port_id, struct nbl_fc_info fc);

void nbl_mailbox_req_write_mac_to_logic(struct nbl_hw *hw, u8 eth_port_id, u8 *mac_addr);

void nbl_mailbox_req_get_pause_stats(struct nbl_hw *hw, u8 eth_port_id,
				     struct ethtool_pause_stats *stats);

void nbl_mailbox_req_init_pkt_len_limit(struct nbl_hw *hw, u8 eth_port_id,
					struct nbl_pkt_len_limit pkt_len_limit);

int nbl_mailbox_req_get_coalesce(struct nbl_hw *hw, struct ethtool_coalesce *ec,
				 u16 local_vector_id);
int nbl_mailbox_req_set_coalesce(struct nbl_hw *hw, u16 local_vector_id,
				 u16 num_q_vectors, u32 regval);

int nbl_mailbox_req_get_eth_stats(struct nbl_hw *hw, u8 eth_port_id,
				  struct nbl_hw_stats *hw_stats);

int nbl_mailbox_req_configure_mac_addr(struct nbl_hw *hw, u8 eth_port_id, u8 *mac_addr, u8 vsi_id);
int nbl_mailbox_req_clear_mac_addr(struct nbl_hw *hw);

int nbl_mailbox_req_change_mac_addr(struct nbl_hw *hw, u8 *mac_addr, u8 vsi_id);

int nbl_mailbox_req_operate_vlan_id(struct nbl_hw *hw, u16 vlan_id, u8 vsi_id, bool add);

void nbl_clean_mailbox_subtask(struct nbl_adapter *adapter);

int nbl_mailbox_request_irq(struct nbl_adapter *adapter);
void nbl_mailbox_free_irq(struct nbl_adapter *adapter);

void nbl_af_set_mailbox_bdf_for_all_func(struct nbl_hw *hw);

#endif
