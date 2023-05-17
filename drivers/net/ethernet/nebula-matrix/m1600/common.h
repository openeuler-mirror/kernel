/* SPDX-License-Identifier: GPL-2.0*/
/*
 * Copyright (c) 2022 nebula-matrix Limited.
 * Author: Monte Song <monte.song@nebula-matrix.com>
 */

#ifndef _NBL_COMMON_H_
#define _NBL_COMMON_H_

#include <linux/types.h>
#include <linux/pci.h>
#include <linux/version.h>
#include <linux/io.h>
#include <linux/ethtool.h>
#include <linux/if_vlan.h>
#include <linux/debugfs.h>

#include "hw.h"

#define NBL_X4_DRIVER_NAME "m1600"
#define NBL_X4_DRIVER_VERSION "2.1.2"

#define NBL_MAILBOX_QUEUE_LEN 256
#define NBL_MAILBOX_BUF_LEN 4096

#define NBL_REG_WRITE_MAX_TRY_TIMES 5

#define NBL_LED_FLICKER_FREQUENCY (2)

#define NBL_MAX_JUMBO_FRAME_SIZE (15872)
#define NBL_MAX_FRAME_SIZE (10000)
#define NBL_MIN_FRAME_SIZE (64)
#define NBL_MAX_MTU 9600
#define NBL_VLAN_HLEN 4
#define NBL_URMUX_MAX_PKT_LEN 10000

#define NBL_MODULE_SPEED_NOT_SUPPORT 0
#define NBL_MODULE_SPEED_1G BIT(0)
#define NBL_MODULE_SPEED_10G BIT(1)

struct nbl_mailbox_buf {
	void *va;
	dma_addr_t pa;
	size_t size;
};

struct nbl_mailbox_tx_desc {
	u16 flags;
	u16 srcid;
	u16 dstid;
	u16 data_len;
	u16 buf_len;
	u64 buf_addr;
	u16 msg_type;
	u8 data[16];
	u8 rsv[28];
} __packed;

struct nbl_mailbox_rx_desc {
	u16 flags;
	u32 buf_len;
	u16 buf_id;
	u64 buf_addr;
} __packed;

struct nbl_mailbox_ring {
	void *desc;
	struct nbl_mailbox_buf *buf;

	u16 next_to_use;
	u16 tail_ptr;
	u16 next_to_clean;

	dma_addr_t dma;
};

#define NBL_STRING_NAME_LEN 32

struct nbl_mailbox_info {
	struct nbl_mailbox_ring txq;
	struct nbl_mailbox_ring rxq;

	/* For mailbox txq */
	spinlock_t txq_lock;

	/* For send msg */
	struct mutex send_normal_msg_lock;
	int acked;
	int ack_err;
	unsigned int ack_req_msg_type;
	char *ack_data;
	u16 ack_data_len;

	u16 num_txq_entries;
	u16 num_rxq_entries;
	u16 txq_buf_size;
	u16 rxq_buf_size;

	char name[NBL_STRING_NAME_LEN];
};

struct nbl_msix_map_table {
	struct nbl_msix_map *base_addr;
	dma_addr_t dma;
	size_t size;
};

struct nbl_func_res {
	u8 num_txrx_queues;
	u8 *txrx_queues;
	u16 num_interrupts;
	u16 *interrupts;

	struct nbl_msix_map_table msix_map_table;

	u16 macvlan_start_index;
	u16 num_macvlan_entries;
	u8 eth_port_id;
	u8 mac_addr[ETH_ALEN];
	s16 vlan_ids[NBL_PF_MAX_MACVLAN_ENTRIES];
};

enum nbl_func_type {
	NBL_X4_AF,
	NBL_X4_PF,
	NBL_X4_VF,
};

struct nbl_fc_info {
	u32 rx_pause;
	u32 tx_pause;
};

struct nbl_hw_stats {
	u64 tx_total_packets;
	u64 tx_total_good_packets;
	u64 rx_total_packets;
	u64 rx_total_good_packets;
	u64 tx_bad_fcs;
	u64 rx_bad_fcs;

	u64 tx_total_bytes;
	u64 tx_total_good_bytes;
	u64 rx_total_bytes;
	u64 rx_total_good_bytes;

	u64 tx_frame_error;
	u64 tx_unicast;
	u64 tx_multicast;
	u64 tx_broadcast;
	u64 tx_vlan;
	u64 tx_fc_pause;

	u64 rx_oversize;
	u64 rx_undersize;
	u64 rx_frame_err;
	u64 rx_bad_code;
	u64 rx_unicast;
	u64 rx_multicast;
	u64 rx_broadcast;
	u64 rx_vlan;
	u64 rx_fc_pause;
};

struct nbl_stats {
	/* for nbl status consistent */
	struct mutex lock;
	u64 tx_total_packets;
	u64 tx_total_good_packets;
	u64 tx_total_bytes;
	u64 tx_total_good_bytes;
	u64 tx_error_packets;
	u64 tx_bad_fcs;
	u64 tx_frame_error;
	u64 tx_unicast;
	u64 tx_multicast;
	u64 tx_broadcast;
	u64 tx_vlan;
	u64 tx_fc_pause;

	u64 rx_total_packets;
	u64 rx_total_good_packets;
	u64 rx_total_bytes;
	u64 rx_total_good_bytes;
	u64 rx_error_packets;
	u64 rx_bad_fcs;
	u64 rx_oversize;
	u64 rx_undersize;
	u64 rx_frame_err;
	u64 rx_bad_code;
	u64 rx_unicast;
	u64 rx_multicast;
	u64 rx_broadcast;
	u64 rx_vlan;
	u64 rx_fc_pause;

	u64 tx_busy;
	u64 tx_linearize;
	u64 tx_timeout;
	u64 tx_csum_pkts;
	u64 rx_csum_pkts;
	u64 tx_dma_err;
	u64 alloc_page_failed;
	u64 alloc_skb_failed;
	u64 rx_dma_err;

	u64 err_status_reset;
	u64 bad_code_reset;
};

struct nbl_vf_bar_info {
	u64 vf_bar_start;
	u64 vf_bar_len;
};

struct nbl_af_res_info {
	/* For function resource */
	spinlock_t func_res_lock;
	DECLARE_BITMAP(interrupt_bitmap, NBL_MAX_INTERRUPT);
	DECLARE_BITMAP(txrx_queue_bitmap, NBL_MAX_TXRX_QUEUE);
	struct nbl_qid_map qid_map_table[NBL_QID_MAP_TABLE_ENTRIES];
	int qid_map_ready;
	int qid_map_select;
	struct nbl_func_res *res_record[NBL_MAX_FUNC];

	struct nbl_vf_bar_info vf_bar_info[NBL_MAX_PF_FUNC];

	u8 forward_ring_index;

	atomic_t eth_port_tx_refcount[NBL_ETH_PORT_NUM];
	atomic_t eth_port_rx_refcount[NBL_ETH_PORT_NUM];
};

struct nbl_hw {
	u8 __iomem *hw_addr;
	void *back;

	u8 function;
	u8 devid;
	u8 bus;

	enum nbl_func_type func_type;

	u8 vsi_id;
	u8 eth_port_id;

	u8 __iomem *msix_bar_hw_addr;

	bool module_inplace;
	u8 module_support_speed;

	u8 __iomem *mailbox_bar_hw_addr;
	struct nbl_mailbox_info mailbox;

	struct nbl_af_res_info *af_res;

	struct nbl_fc_info fc;

	struct nbl_hw_stats hw_stats;

	__ETHTOOL_DECLARE_LINK_MODE_MASK(supported);
	__ETHTOOL_DECLARE_LINK_MODE_MASK(advertising);

	/* debugfs */
	struct dentry *nbl_debug_root;

	int debugfs_reg_bar;
	long debugfs_reg_offset;
	long debugfs_reg_length;
};

enum nbl_adapter_state {
	NBL_DOWN,
	NBL_MAILBOX_READY,
	NBL_MAILBOX_EVENT_PENDING,
	NBL_RESETTING,
	NBL_RESET_REQUESTED,
	NBL_PROMISC,
	NBL_STATE_NBITS,
};

struct nbl_healing_var {
	u64 former_bad_code;
	int bad_code_increase;
	int status_chk_timer;
};

struct nbl_adapter {
	struct nbl_hw hw;
	struct pci_dev *pdev;
	struct net_device *netdev;

	u8 num_txq;
	u8 num_rxq;
	u16 tx_desc_num;
	u16 rx_desc_num;

	struct msix_entry *msix_entries;
	u16 num_lan_msix;
	u16 num_mailbox_msix;

	struct nbl_ring **tx_rings;
	struct nbl_ring **rx_rings;

	u16 num_q_vectors;
	struct nbl_q_vector **q_vectors;

	DECLARE_BITMAP(state, NBL_STATE_NBITS);

	unsigned long serv_timer_period;
	struct timer_list serv_timer;
	struct work_struct serv_task1;
	struct work_struct serv_task2;

	struct nbl_stats stats;

	struct nbl_healing_var healing_var;

	struct device *hwmon_dev;

	u32 msg_enable;

	u32 flags;
};

static inline bool is_af(struct nbl_hw *hw)
{
	return hw->func_type == NBL_X4_AF;
}

static inline bool is_vf(struct nbl_hw *hw)
{
	return hw->func_type == NBL_X4_VF;
}

#define nbl_adapter_to_dev(adapter) (&((adapter)->pdev->dev))
#define nbl_hw_to_dev(hw) nbl_adapter_to_dev((struct nbl_adapter *)((hw)->back))

#define wr32(hw, reg, value)	writel((value), ((hw)->hw_addr + (reg)))
#define rd32(hw, reg)		readl((hw)->hw_addr + (reg))
#define wr32_for_each(hw, reg, value, size) \
	do { \
		int __n; \
		for (__n = 0; __n < (size); __n += 4) \
			wr32((hw), (reg) + __n, (value)[__n / 4]); \
	} while (0)
#define rd32_for_each(hw, reg, value, size) \
	do { \
		int __n; \
		for (__n = 0; __n < (size); __n += 4) \
			(value)[__n / 4] = rd32((hw), (reg) + __n); \
	} while (0)
#define wr32_zero_for_each(hw, reg, size) \
	do { \
		int __n; \
		for (__n = 0; __n < (size); __n += 4) \
			wr32((hw), (reg) + __n, 0); \
	} while (0)

#define NBL_WRITE_VERIFY_MAX_TIMES (5)

static inline void wr32_and_verify(struct nbl_hw *hw, u64 reg, u32 value)
{
	u32 read_value;
	int i = 0;

	while (likely(i < NBL_WRITE_VERIFY_MAX_TIMES)) {
		wr32(hw, reg, value);
		read_value = rd32(hw, reg);
		if (read_value == value)
			return;
		i++;
	}
	pr_err("Write to register addr %llx failed\n", reg);
}

#define mb_wr32(hw, reg, value)	writel((value), ((hw)->mailbox_bar_hw_addr + (reg)))
#define mb_rd32(hw, reg)		readl((hw)->mailbox_bar_hw_addr + (reg))
#define mb_wr32_for_each(hw, reg, value, size) \
	do { \
		int __n; \
		for (__n = 0; __n < (size); __n += 4) \
			mb_wr32((hw), (reg) + __n, (value)[__n / 4]); \
	} while (0)
#define mb_rd32_for_each(hw, reg, value, size) \
	do { \
		int __n; \
		for (__n = 0; __n < (size); __n += 4) \
			(value)[__n / 4] = mb_rd32((hw), (reg) + __n); \
	} while (0)

#define msix_wr32(hw, reg, value)	writel((value), ((hw)->msix_bar_hw_addr + (reg)))

void nbl_service_task1_schedule(struct nbl_adapter *adapter);
void nbl_service_task_schedule(struct nbl_adapter *adapter);

void nbl_firmware_init(struct nbl_hw *hw);

void nbl_af_configure_captured_packets(struct nbl_hw *hw);
void nbl_af_clear_captured_packets_conf(struct nbl_hw *hw);

u32 nbl_af_get_firmware_version(struct nbl_hw *hw);

int nbl_af_res_mng_init(struct nbl_hw *hw);
void nbl_af_free_res(struct nbl_hw *hw);

void nbl_af_compute_bdf(struct nbl_hw *hw, u16 func_id,
			u8 *bus, u8 *devid, u8 *function);

bool nbl_check_golden_version(struct nbl_hw *hw);

int nbl_af_configure_func_msix_map(struct nbl_hw *hw, u16 func_id, u16 requested);
void nbl_af_destroy_func_msix_map(struct nbl_hw *hw, u16 func_id);

int nbl_configure_msix_map(struct nbl_hw *hw);
void nbl_destroy_msix_map(struct nbl_hw *hw);

int nbl_af_configure_qid_map(struct nbl_hw *hw, u16 func_id, u8 num_queues, u64 notify_addr);
void nbl_af_clear_qid_map(struct nbl_hw *hw, u16 func_id, u64 notify_addr);

int nbl_get_vsi_id(struct nbl_hw *hw);

void nbl_af_register_vf_bar_info(struct nbl_hw *hw, u16 func_id,
				 u64 vf_bar_start, u64 vf_bar_len);
int nbl_register_vf_bar_info(struct nbl_hw *hw);

u64 nbl_af_compute_vf_bar_base_addr(struct nbl_hw *hw, u16 func_id);

int nbl_configure_notify_addr(struct nbl_hw *hw);
void nbl_clear_notify_addr(struct nbl_hw *hw);

void nbl_af_disable_promisc(struct nbl_hw *hw, u8 eth_port_id);
void nbl_disable_promisc(struct nbl_hw *hw);
void nbl_af_enable_promisc(struct nbl_hw *hw, u8 eth_port_id);
void nbl_enable_promisc(struct nbl_hw *hw);

void nbl_af_configure_ingress_eth_port_table(struct nbl_hw *hw, u8 eth_port_id, u8 vsi_id);
void nbl_af_configure_src_vsi_table(struct nbl_hw *hw, u8 eth_port_id, u8 vsi_id);
void nbl_af_configure_dest_vsi_table(struct nbl_hw *hw, u8 eth_port_id, u8 vsi_id);
void nbl_datapath_init(struct nbl_hw *hw);

int nbl_af_get_board_info(struct nbl_hw *hw, u8 eth_port_id, union nbl_board_info *board_info);

bool nbl_af_query_link_status(struct nbl_hw *hw, u8 eth_port_id);
bool nbl_query_link_status(struct nbl_hw *hw);
void nbl_query_link_status_subtask(struct nbl_adapter *adapter);

void nbl_af_set_pauseparam(struct nbl_hw *hw, u8 eth_port_id, struct nbl_fc_info fc);

void nbl_af_write_mac_to_logic(struct nbl_hw *hw, u8 eth_port_id, u8 *mac_addr);
void nbl_write_mac_to_logic(struct nbl_hw *hw, u8 *mac_addr);

void nbl_af_init_pkt_len_limit(struct nbl_hw *hw, u8 eth_port_id,
			       struct nbl_pkt_len_limit pkt_len_limit);
void nbl_init_pkt_len_limit(struct nbl_hw *hw);

int nbl_af_get_eth_stats(struct nbl_hw *hw, u8 eth_port_id, struct nbl_hw_stats *hw_stats);

void nbl_update_stats_subtask(struct nbl_adapter *adapter);
void nbl_init_hw_stats(struct nbl_hw *hw);

void nbl_reset_subtask(struct nbl_adapter *adapter);

int nbl_stop(struct net_device *netdev);
int nbl_open(struct net_device *netdev);

void nbl_do_reset(struct nbl_adapter *adapter);

enum NBL_MODULE_INPLACE_STATUS nbl_af_check_module_inplace(struct nbl_hw *hw, u8 eth_port_id);

int nbl_af_config_module_speed(struct nbl_hw *hw, u8 target_speed, u8 eth_port_id);

void nbl_set_module_speed(struct nbl_hw *hw, u8 target_speed);

void nbl_af_configure_fc_cplh_up_th(struct nbl_hw *hw);

u32 nbl_af_get_rxlos(struct nbl_hw *hw, u8 eth_port_id);

void nbl_af_reset_eth(struct nbl_hw *hw, u8 eth_port_id);

#ifdef CONFIG_NBL_DEBUGFS
void nbl_debugfs_init(void);
void nbl_debugfs_exit(void);
void nbl_debugfs_hw_init(struct nbl_hw *hw);
void nbl_debugfs_hw_exit(struct nbl_hw *hw);
#else
static inline void nbl_debugfs_init(void) {}
static inline void nbl_debugfs_exit(void) {}
static inline void nbl_debugfs_hw_init(struct nbl_hw *hw) {}
static inline void nbl_debugfs_hw_exit(struct nbl_hw *hw) {}
#endif

#endif
