/* SPDX-License-Identifier: GPL-2.0*/
/*
 * Copyright (c) 2022 nebula-matrix Limited.
 * Author:
 */

#ifndef _NBL_INCLUDE_H_
#define _NBL_INCLUDE_H_

#include <linux/mod_devicetable.h>
#include <linux/device.h>
#include <linux/pci.h>
#include <linux/etherdevice.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/sctp.h>
#include <linux/ethtool.h>
#include <linux/debugfs.h>
#include <linux/firmware.h>
#include <linux/list.h>
#include <linux/pldmfw.h>
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/cdev.h>
#include <linux/kfifo.h>
#include <linux/termios.h>
#include <net/inet6_hashtables.h>
#include <linux/compiler.h>
#include <linux/netdevice.h>
#include <net/devlink.h>
#include <net/ipv6.h>
#include <net/pkt_cls.h>
#include <net/bonding.h>
#include <linux/if_bridge.h>
#include <linux/rtnetlink.h>
#include <linux/pci.h>
#include <linux/delay.h>
#include <linux/dma-map-ops.h>
#include <linux/dma-mapping.h>
#include <linux/iommu.h>
#include <linux/mdev.h>
#include <linux/vfio.h>
#include <uapi/linux/elf.h>
#include <linux/crc32.h>

/*  ------  Basic definitions  -------  */
#define NBL_DRIVER_NAME					"nbl_core"
/* "product NO-V NO.R NO.B NO.SP NO"
 * product NO define:
 * 1 reserve for develop branch
 * 2 df200
 * 3 ASIC snic
 * 4 x4
 */
#define NBL_DRIVER_VERSION				"1-1.1.100.0"

#define NBL_DRIVER_DEV_MAX				8

#define NBL_PAIR_ID_GET_TX(id)				((id) * 2 + 1)
#define NBL_PAIR_ID_GET_RX(id)				((id) * 2)

#define NBL_MAX_PF					8

#define NBL_IPV6_ADDR_LEN_AS_U8				16

#define NBL_P4_NAME_LEN					64

#define NBL_FLOW_INDEX_BYTE_LEN				8

#define SET_DEV_MIN_MTU(netdev, mtu) ((netdev)->min_mtu = (mtu))
#define SET_DEV_MAX_MTU(netdev, mtu) ((netdev)->max_mtu = (mtu))

#define NBL_USER_DEV_SHMMSGRING_SIZE		(PAGE_SIZE)
#define NBL_USER_DEV_SHMMSGBUF_SIZE		(NBL_USER_DEV_SHMMSGRING_SIZE - 8)

/* Used for macros to pass checkpatch */
#define NBL_NAME(x)					x

enum nbl_product_type {
	NBL_LEONIS_TYPE,
	NBL_PRODUCT_MAX,
};

enum nbl_flex_cap_type {
	NBL_SECURITY_ACCEL_CAP,
	NBL_FLEX_CAP_NBITS
};

enum nbl_fix_cap_type {
	NBL_TASK_FW_HB_CAP,
	NBL_TASK_FW_RESET_CAP,
	NBL_TASK_CLEAN_ADMINDQ_CAP,
	NBL_TASK_CLEAN_MAILBOX_CAP,
	NBL_RESTOOL_CAP,
	NBL_HWMON_TEMP_CAP,
	NBL_ITR_DYNAMIC,
	NBL_TASK_ADAPT_DESC_GOTHER,
	NBL_P4_CAP,
	NBL_PROCESS_FLR_CAP,
	NBL_RECOVERY_ABNORMAL_STATUS,
	NBL_TASK_KEEP_ALIVE,
	NBL_DUMP_FLOW_CAP,
	NBL_FIX_CAP_NBITS
};

enum nbl_sfp_module_state {
	NBL_SFP_MODULE_OFF,
	NBL_SFP_MODULE_ON,
};

enum {
	NBL_VSI_DATA = 0,/* default vsi in kernel or independent dpdk */
	NBL_VSI_CTRL,
	NBL_VSI_USER,/* dpdk used vsi in coexist dpdk */
	NBL_VSI_MAX,
};

enum {
	NBL_P4_DEFAULT = 0,
	NBL_P4_TYPE_MAX,
};

enum {
	NBL_TX = 0,
	NBL_RX,
};

/*  ------  Params that go through multiple layers  ------  */
struct nbl_driver_info {
#define NBL_DRIVER_VERSION_LEN_MAX	(32)
	char	driver_version[NBL_DRIVER_VERSION_LEN_MAX];
};

struct nbl_func_caps {
	u32 has_ctrl:1;
	u32 has_net:1;
	u32 is_vf:1;
	u32 is_nic:1;
	u32 is_blk:1;
	u32 has_user:1;
	u32 support_lag:1;
	u32 has_grc:1;
	u32 has_factory_ctrl:1;
	u32 need_pmd_debug:1;
	u32 rsv:23;
};

struct nbl_init_param {
	struct nbl_func_caps caps;
	enum nbl_product_type product_type;
	bool pci_using_dac;
};

struct nbl_txrx_queue_param {
	u16 vsi_id;
	u64 dma;
	u64 avail;
	u64 used;
	u16 desc_num;
	u16 local_queue_id;
	u16 intr_en;
	u16 intr_mask;
	u16 global_vector_id;
	u16 half_offload_en;
	u16 split;
	u16 extend_header;
	u16 cxt;
	u16 rxcsum;
};

struct nbl_qid_map_table {
	u32 local_qid;
	u32 notify_addr_l;
	u32 notify_addr_h;
	u32 global_qid;
	u32 ctrlq_flag;
};

struct nbl_qid_map_param {
	struct nbl_qid_map_table *qid_map;
	u16 start;
	u16 len;
};

struct nbl_ecpu_qid_map_param {
	u8 valid;
	u16 table_id;
	u16 max_qid;
	u16 base_qid;
	u16 device_type;
	u64 notify_addr;
};

struct nbl_rss_alg_param {
	u8 hash_field_type_v4;
	u8 hash_field_type_v6;
	u8 hash_field_mask_dport;
	u8 hash_field_mask_sport;
	u8 hash_field_mask_dip;
	u8 hash_field_mask_sip;
	u8 hash_alg_type;
};

struct nbl_vnet_queue_info_param {
	u32 function_id;
	u32 device_id;
	u32 bus_id;
	u32 msix_idx;
	u32 msix_idx_valid;
	u32 valid;
};

struct nbl_queue_cfg_param {
	/* queue args*/
	u64 desc;
	u64 avail;
	u64 used;
	u16 size;
	u16 extend_header;
	u16 split;
	u16 last_avail_idx;
	u16 global_queue_id;

	/*interrupt args*/
	u16 global_vector;
	u16 intr_en;
	u16 intr_mask;

	/* dvn args */
	u16 tx;

	/* uvn args*/
	u16 rxcsum;
	u16 half_offload_en;
};

struct nbl_register_net_param {
	u16 pf_bdf;
	u64 vf_bar_start;
	u64 vf_bar_size;
	u16 total_vfs;
	u16 offset;
	u16 stride;
	u64 pf_bar_start;
};

struct nbl_register_net_result {
	u16 tx_queue_num;
	u16 rx_queue_num;
	u16 queue_size;
	u16 rdma_enable;
	u64 hw_features;
	u64 features;
	u16 max_mtu;
	u16 queue_offset;
	u8 mac[ETH_ALEN];
};

struct nbl_msix_info_param {
	u16 msix_num;
	struct msix_entry *msix_entries;
};

struct nbl_queue_stats {
	u64 packets;
	u64 bytes;
	u64 descs;
};

struct nbl_tx_queue_stats {
	u64 tso_packets;
	u64 tso_bytes;
	u64 tx_csum_packets;
	u64 tx_busy;
	u64 tx_dma_busy;
	u64 tx_multicast_packets;
	u64 tx_unicast_packets;
	u64 tx_skb_free;
	u64 tx_desc_addr_err_cnt;
	u64 tx_desc_len_err_cnt;
};

struct nbl_rx_queue_stats {
	u64 rx_csum_packets;
	u64 rx_csum_errors;
	u64 rx_multicast_packets;
	u64 rx_unicast_packets;
	u64 rx_desc_addr_err_cnt;
	u64 rx_alloc_buf_err_cnt;
	u64 rx_cache_reuse;
	u64 rx_cache_full;
	u64 rx_cache_empty;
	u64 rx_cache_busy;
	u64 rx_cache_waive;
};

struct nbl_stats {
	/* for toe stats */
	u64 tso_packets;
	u64 tso_bytes;
	u64 tx_csum_packets;
	u64 rx_csum_packets;
	u64 rx_csum_errors;
	u64 tx_busy;
	u64 tx_dma_busy;
	u64 tx_multicast_packets;
	u64 tx_unicast_packets;
	u64 rx_multicast_packets;
	u64 rx_unicast_packets;
	u64 tx_skb_free;
	u64 tx_desc_addr_err_cnt;
	u64 tx_desc_len_err_cnt;
	u64 rx_desc_addr_err_cnt;
	u64 rx_alloc_buf_err_cnt;
	u64 rx_cache_reuse;
	u64 rx_cache_full;
	u64 rx_cache_empty;
	u64 rx_cache_busy;
	u64 rx_cache_waive;
	u64 tx_packets;
	u64 tx_bytes;
	u64 rx_packets;
	u64 rx_bytes;
};

struct nbl_queue_err_stats {
	u16 dvn_pkt_drop_cnt;
	u32 uvn_stat_pkt_drop;
};

struct nbl_priv_stats {
	u64 total_dvn_pkt_drop_cnt;
	u64 total_uvn_stat_pkt_drop;
};

struct nbl_fc_info {
	u32 rx_pause;
	u32 tx_pause;
};

struct nbl_notify_param {
	u16 notify_qid;
	u16 tail_ptr;
};

enum nbl_eth_speed {
	LINK_SPEED_100M = 0,
	LINK_SPEED_1000M = 1,
	LINK_SPEED_5G = 2,
	LINK_SPEEP_10G = 3,
	LINK_SPEED_25G = 4,
	LINK_SPEED_50G = 5,
	LINK_SPEED_100G = 6,
	LINK_SPEED_200G = 7
};

struct nbl_phy_caps {
	u32 speed; /* enum nbl_eth_speed */
	u32 fec_ability;
	u32 pause_param; /* bit0 tx, bit1 rx */
};

struct nbl_phy_state {
	u32 current_speed;
	u32 fec_mode;
	struct nbl_fc_info fc;
	__ETHTOOL_DECLARE_LINK_MODE_MASK(supported);
	__ETHTOOL_DECLARE_LINK_MODE_MASK(advertising);
};

struct nbl_common_irq_num {
	int mbx_irq_num;
};

struct nbl_ctrl_irq_num {
	int adminq_irq_num;
	int abnormal_irq_num;
};

#define NBL_PORT_KEY_ILLEGAL 0x0
#define NBL_PORT_KEY_CAPABILITIES 0x1
#define NBL_PORT_KEY_ENABLE 0x2 /* BIT(0): NBL_PORT_FLAG_ENABLE_NOTIFY */
#define NBL_PORT_KEY_DISABLE 0x3
#define NBL_PORT_KEY_ADVERT 0x4
#define NBL_PORT_KEY_LOOPBACK 0x5 /* 0: disable eth loopback, 1: enable eth loopback */
#define NBL_PORT_KEY_MODULE_SWITCH 0x6 /* 0: sfp off, 1: sfp on */
#define NBL_PORT_KEY_MAC_ADDRESS 0x7
#define NBL_PORT_KRY_LED_BLINK 0x8

enum {
	NBL_PORT_SUBOP_READ = 1,
	NBL_PORT_SUBOP_WRITE = 2,
};

#define NBL_PORT_FLAG_ENABLE_NOTIFY	BIT(0)
#define NBL_PORT_ENABLE_LOOPBACK	1
#define NBL_PORT_DISABLE_LOOPBCK	0
#define NBL_PORT_SFP_ON			1
#define NBL_PORT_SFP_OFF		0
#define NBL_PORT_KEY_KEY_SHIFT		56
#define NBL_PORT_KEY_DATA_MASK		0xFFFFFFFFFFFF

struct nbl_port_key {
	u32 id; /* port id */
	u32 subop; /* 1: read, 2: write */
	u64 data[]; /* [47:0]: data, [55:48]: rsvd, [63:56]: key */
};

enum nbl_flow_ctrl {
	NBL_PORT_TX_PAUSE = 0x1,
	NBL_PORT_RX_PAUSE = 0x2,
	NBL_PORT_TXRX_PAUSE_OFF = 0x4, /* used for ethtool, means ethtool close tx and rx pause */
};

enum nbl_port_fec {
	NBL_PORT_FEC_OFF = 1,
	NBL_PORT_FEC_RS = 2,
	NBL_PORT_FEC_BASER = 3,
	NBL_PORT_FEC_AUTO = 4, /* ethtool may set Auto mode, used for PF mailbox msg*/
};

enum nbl_port_autoneg {
	NBL_PORT_AUTONEG_DISABLE = 0x1,
	NBL_PORT_AUTONEG_ENABLE = 0x2,
};

enum nbl_port_type {
	NBL_PORT_TYPE_UNKNOWN = 0,
	NBL_PORT_TYPE_FIBRE,
	NBL_PORT_TYPE_COPPER,
};

enum nbl_port_max_rate {
	NBL_PORT_MAX_RATE_UNKNOWN = 0,
	NBL_PORT_MAX_RATE_1G,
	NBL_PORT_MAX_RATE_10G,
	NBL_PORT_MAX_RATE_25G,
	NBL_PORT_MAX_RATE_100G,
	NBL_PORT_MAX_RATE_100G_PAM4,
};

enum nbl_port_mode {
	NBL_PORT_NRZ_NORSFEC,
	NBL_PORT_NRZ_544,
	NBL_PORT_NRZ_528,
	NBL_PORT_PAM4_544,
	NBL_PORT_MODE_MAX,
};

enum nbl_led_reg_ctrl {
	NBL_LED_REG_ACTIVE,
	NBL_LED_REG_ON,
	NBL_LED_REG_OFF,
	NBL_LED_REG_INACTIVE,
};

/* emp to ctrl dev notify */
struct nbl_port_notify {
	u32 id;
	u32 speed; /* in 10 Mbps units */
	u8 link_state:1; /* 0:down, 1:up */
	u8 module_inplace:1; /* 0: not inplace, 1:inplace */
	u8 revd0:6;
	u8 flow_ctrl; /* enum nbl_flow_ctrl */
	u8 fec; /* enum nbl_port_fec */
	u8 active_lanes;
	u8 rsvd1[4];
	u64 advertising; /* enum nbl_port_cap */
	u64 lp_advertising; /* enum nbl_port_cap */
};

#define NBL_PORT_CAP_AUTONEG_MASK (BIT(NBL_PORT_CAP_AUTONEG))
#define NBL_PORT_CAP_FEC_MASK \
	(BIT(NBL_PORT_CAP_FEC_NONE) | BIT(NBL_PORT_CAP_FEC_RS) | BIT(NBL_PORT_CAP_FEC_BASER))
#define NBL_PORT_CAP_PAUSE_MASK (BIT(NBL_PORT_CAP_TX_PAUSE) | BIT(NBL_PORT_CAP_RX_PAUSE))
#define NBL_PORT_CAP_SPEED_1G_MASK\
	(BIT(NBL_PORT_CAP_1000BASE_T) | BIT(NBL_PORT_CAP_1000BASE_X))
#define NBL_PORT_CAP_SPEED_10G_MASK\
	(BIT(NBL_PORT_CAP_10GBASE_T) | BIT(NBL_PORT_CAP_10GBASE_KR) | BIT(NBL_PORT_CAP_10GBASE_SR))
#define NBL_PORT_CAP_SPEED_25G_MASK \
	(BIT(NBL_PORT_CAP_25GBASE_KR) | BIT(NBL_PORT_CAP_25GBASE_SR) |\
	 BIT(NBL_PORT_CAP_25GBASE_CR) | BIT(NBL_PORT_CAP_25G_AUI))
#define NBL_PORT_CAP_SPEED_50G_MASK \
	(BIT(NBL_PORT_CAP_50GBASE_KR2) | BIT(NBL_PORT_CAP_50GBASE_SR2) |\
	 BIT(NBL_PORT_CAP_50GBASE_CR2) | BIT(NBL_PORT_CAP_50G_AUI2) |\
	 BIT(NBL_PORT_CAP_50GBASE_KR_PAM4) | BIT(NBL_PORT_CAP_50GBASE_SR_PAM4) |\
	 BIT(NBL_PORT_CAP_50GBASE_CR_PAM4) | BIT(NBL_PORT_CAP_50G_AUI_PAM4))
#define NBL_PORT_CAP_SPEED_100G_MASK \
	(BIT(NBL_PORT_CAP_100GBASE_KR4) | BIT(NBL_PORT_CAP_100GBASE_SR4) |\
	 BIT(NBL_PORT_CAP_100GBASE_CR4) | BIT(NBL_PORT_CAP_100G_AUI4) |\
	 BIT(NBL_PORT_CAP_100G_CAUI4) | BIT(NBL_PORT_CAP_100GBASE_KR2_PAM4) |\
	 BIT(NBL_PORT_CAP_100GBASE_SR2_PAM4) | BIT(NBL_PORT_CAP_100GBASE_CR2_PAM4) |\
	 BIT(NBL_PORT_CAP_100G_AUI2_PAM4))
#define NBL_PORT_CAP_SPEED_MASK \
	(NBL_PORT_CAP_SPEED_1G_MASK | NBL_PORT_CAP_SPEED_10G_MASK |\
	 NBL_PORT_CAP_SPEED_25G_MASK | NBL_PORT_CAP_SPEED_50G_MASK |\
	 NBL_PORT_CAP_SPEED_100G_MASK)
#define NBL_PORT_CAP_PAM4_MASK\
	(BIT(NBL_PORT_CAP_50GBASE_KR_PAM4) | BIT(NBL_PORT_CAP_50GBASE_SR_PAM4) |\
	 BIT(NBL_PORT_CAP_50GBASE_CR_PAM4) | BIT(NBL_PORT_CAP_50G_AUI_PAM4) |\
	 BIT(NBL_PORT_CAP_100GBASE_KR2_PAM4) | BIT(NBL_PORT_CAP_100GBASE_SR2_PAM4) |\
	 BIT(NBL_PORT_CAP_100GBASE_CR2_PAM4) | BIT(NBL_PORT_CAP_100G_AUI2_PAM4))
#define NBL_ETH_1G_DEFAULT_FEC_MODE NBL_PORT_FEC_OFF
#define NBL_ETH_10G_DEFAULT_FEC_MODE NBL_PORT_FEC_OFF
#define NBL_ETH_25G_DEFAULT_FEC_MODE NBL_PORT_FEC_RS
#define NBL_ETH_100G_DEFAULT_FEC_MODE NBL_PORT_FEC_RS

enum nbl_port_cap {
	NBL_PORT_CAP_TX_PAUSE,
	NBL_PORT_CAP_RX_PAUSE,
	NBL_PORT_CAP_AUTONEG,
	NBL_PORT_CAP_FEC_NONE,
	NBL_PORT_CAP_FEC_RS,
	NBL_PORT_CAP_FEC_BASER,
	NBL_PORT_CAP_1000BASE_T,
	NBL_PORT_CAP_1000BASE_X,
	NBL_PORT_CAP_10GBASE_T,
	NBL_PORT_CAP_10GBASE_KR,
	NBL_PORT_CAP_10GBASE_SR,
	NBL_PORT_CAP_25GBASE_KR,
	NBL_PORT_CAP_25GBASE_SR,
	NBL_PORT_CAP_25GBASE_CR,
	NBL_PORT_CAP_25G_AUI,
	NBL_PORT_CAP_50GBASE_KR2,
	NBL_PORT_CAP_50GBASE_SR2,
	NBL_PORT_CAP_50GBASE_CR2,
	NBL_PORT_CAP_50G_AUI2,
	NBL_PORT_CAP_50GBASE_KR_PAM4,
	NBL_PORT_CAP_50GBASE_SR_PAM4,
	NBL_PORT_CAP_50GBASE_CR_PAM4,
	NBL_PORT_CAP_50G_AUI_PAM4,
	NBL_PORT_CAP_100GBASE_KR4,
	NBL_PORT_CAP_100GBASE_SR4,
	NBL_PORT_CAP_100GBASE_CR4,
	NBL_PORT_CAP_100G_AUI4,
	NBL_PORT_CAP_100G_CAUI4,
	NBL_PORT_CAP_100GBASE_KR2_PAM4,
	NBL_PORT_CAP_100GBASE_SR2_PAM4,
	NBL_PORT_CAP_100GBASE_CR2_PAM4,
	NBL_PORT_CAP_100G_AUI2_PAM4,
	NBL_PORT_CAP_MAX
};

enum nbl_fw_port_speed {
	NBL_FW_PORT_SPEED_10G,
	NBL_FW_PORT_SPEED_25G,
	NBL_FW_PORT_SPEED_50G,
	NBL_FW_PORT_SPEED_100G,
};

struct nbl_eth_link_info {
	u8 link_status;
	u32 link_speed;
};

struct nbl_port_state {
	u64 port_caps;
	u64 port_advertising;
	u64 port_lp_advertising;
	u32 link_speed;
	u8 active_fc;
	u8 active_fec; /* enum nbl_port_fec */
	u8 link_state;
	u8 module_inplace;
	u8 port_type; /* enum nbl_port_type */
	u8 port_max_rate; /* enum nbl_port_max_rate */
	u8 fw_port_max_speed; /* enum nbl_fw_port_speed */
};

struct nbl_port_advertising {
	u8 eth_id;
	u64 speed_advert;
	u8 active_fc;
	u8 active_fec; /* enum nbl_port_fec */
	u8 autoneg;
};

#define PASSTHROUGH_FW_CMD_DATA_LEN			(3072)
struct nbl_passthrough_fw_cmd_param {
	u16 opcode;
	u16 errcode;
	u16 in_size;
	u16 out_size;
	u8 data[PASSTHROUGH_FW_CMD_DATA_LEN];
};

#define NBL_RING_NUM_CMD_LEN				(520)
struct nbl_fw_cmd_ring_num_param {
	u16 pf_def_max_net_qp_num;
	u16 vf_def_max_net_qp_num;
	u16 net_max_qp_num[NBL_RING_NUM_CMD_LEN];
};

static inline u64 nbl_speed_to_link_mode(unsigned int speed, u8 autoneg)
{
	u64 link_mode = 0;
	int speed_support = 0;

	switch (speed) {
	case SPEED_100000:
		link_mode |= BIT(NBL_PORT_CAP_100GBASE_KR4) | BIT(NBL_PORT_CAP_100GBASE_SR4) |
			BIT(NBL_PORT_CAP_100GBASE_CR4) | BIT(NBL_PORT_CAP_100G_AUI4) |
			BIT(NBL_PORT_CAP_100G_CAUI4) | BIT(NBL_PORT_CAP_100GBASE_KR2_PAM4) |
			BIT(NBL_PORT_CAP_100GBASE_SR2_PAM4) | BIT(NBL_PORT_CAP_100GBASE_CR2_PAM4) |
			BIT(NBL_PORT_CAP_100G_AUI2_PAM4);
		fallthrough;
	case SPEED_50000:
		link_mode |= BIT(NBL_PORT_CAP_50GBASE_KR2) | BIT(NBL_PORT_CAP_50GBASE_SR2) |
			BIT(NBL_PORT_CAP_50GBASE_CR2) | BIT(NBL_PORT_CAP_50G_AUI2) |
			BIT(NBL_PORT_CAP_50GBASE_KR_PAM4) | BIT(NBL_PORT_CAP_50GBASE_SR_PAM4) |
			BIT(NBL_PORT_CAP_50GBASE_CR_PAM4) | BIT(NBL_PORT_CAP_50G_AUI_PAM4);
		fallthrough;
	case SPEED_25000:
		link_mode |= BIT(NBL_PORT_CAP_25GBASE_KR) | BIT(NBL_PORT_CAP_25GBASE_SR) |
			BIT(NBL_PORT_CAP_25GBASE_CR) | BIT(NBL_PORT_CAP_25G_AUI);
		fallthrough;
	case SPEED_10000:
		link_mode |= BIT(NBL_PORT_CAP_10GBASE_T) | BIT(NBL_PORT_CAP_10GBASE_KR) |
			BIT(NBL_PORT_CAP_10GBASE_SR);
		fallthrough;
	case SPEED_1000:
		link_mode |= BIT(NBL_PORT_CAP_1000BASE_T) | BIT(NBL_PORT_CAP_1000BASE_X);
		speed_support = 1;
	}

	if (autoneg && speed_support)
		link_mode |= BIT(NBL_PORT_CAP_AUTONEG);

	return link_mode;
}

#define NBL_DEFINE_NAME_WITH_WIDTH_CHECK(_struct, _size) \
_struct; \
static inline int nbl_##_struct##_size_is_not_equal_to_define(void) \
{ \
	int check[((sizeof(_struct) * 8) == (_size)) ? 1 :  -1]; \
	return check[0]; \
}

/**
 * list_is_first -- tests whether @ list is the first entry in list @head
 * @list: the entry to test
 * @head: the head of the list
 */
static inline int nbl_list_is_first(const struct list_head *list,
				    const struct list_head *head)
{
	return list->prev == head;
}

/**
 * list_is_last - tests whether @list is the last entry in list @head
 * @list: the entry to test
 * @head: the head of the list
 */
static inline int nbl_list_is_last(const struct list_head *list,
				   const struct list_head *head)
{
	return list->next == head;
}

/**
 * list_empty - tests whether a list is empty
 * @head: the list to test.
 */
static inline int nbl_list_empty(const struct list_head *head)
{
	return READ_ONCE(head->next) == head;
}

#define NBL_OPS_CALL(func, para)								\
	({ typeof(func) _func = (func);								\
	 (!_func) ? 0 : _func para; })

enum nbl_module_temp_type {
	NBL_MODULE_TEMP,
	NBL_MODULE_TEMP_MAX,
	NBL_MODULE_TEMP_CRIT,
	NBL_MODULE_TEMP_TYPE_MAX,
};

struct nbl_load_p4_param {
#define NBL_P4_SECTION_NAME_LEN		32
	u8 name[NBL_P4_SECTION_NAME_LEN];
	u32 addr;
	u32 size;
	u16 section_index;
	u16 section_offset;
	u8 *data;
	bool start;
	bool end;
};

struct nbl_board_port_info {
	u8 eth_num;
	u8 eth_speed;
	u8 rsv[6];
};

enum {
	NBL_NETIF_F_SG_BIT,			/* Scatter/gather IO. */
	NBL_NETIF_F_IP_CSUM_BIT,		/* Can checksum TCP/UDP over IPv4. */
	NBL_NETIF_F_HW_CSUM_BIT,		/* Can checksum all the packets. */
	NBL_NETIF_F_IPV6_CSUM_BIT,		/* Can checksum TCP/UDP over IPV6 */
	NBL_NETIF_F_HIGHDMA_BIT,		/* Can DMA to high memory. */
	NBL_NETIF_F_HW_VLAN_CTAG_TX_BIT,	/* Transmit VLAN CTAG HW acceleration */
	NBL_NETIF_F_HW_VLAN_CTAG_RX_BIT,	/* Receive VLAN CTAG HW acceleration */
	NBL_NETIF_F_HW_VLAN_CTAG_FILTER_BIT,	/* Receive filtering on VLAN CTAGs */
	NBL_NETIF_F_TSO_BIT,			/* ... TCPv4 segmentation */
	NBL_NETIF_F_GSO_ROBUST_BIT,		/* ... ->SKB_GSO_DODGY */
	NBL_NETIF_F_TSO6_BIT,			/* ... TCPv6 segmentation */
	NBL_NETIF_F_GSO_GRE_BIT,		/* ... GRE with TSO */
	NBL_NETIF_F_GSO_GRE_CSUM_BIT,		/* ... GRE with csum with TSO */
	NBL_NETIF_F_GSO_UDP_TUNNEL_BIT,		/* ... UDP TUNNEL with TSO */
	NBL_NETIF_F_GSO_UDP_TUNNEL_CSUM_BIT,	/* ... UDP TUNNEL with TSO & CSUM */
	NBL_NETIF_F_GSO_PARTIAL_BIT,		/* ... Only segment inner-most L4
						 *     in hardware and all other
						 *     headers in software.
						 */
	NBL_NETIF_F_GSO_UDP_L4_BIT,		/* ... UDP payload GSO (not UFO) */
	NBL_NETIF_F_SCTP_CRC_BIT,		/* SCTP checksum offload */
	NBL_NETIF_F_NTUPLE_BIT,			/* N-tuple filters supported */
	NBL_NETIF_F_RXHASH_BIT,			/* Receive hashing offload */
	NBL_NETIF_F_RXCSUM_BIT,			/* Receive checksumming offload */
	NBL_NETIF_F_HW_VLAN_STAG_TX_BIT,	/* Transmit VLAN STAG HW acceleration */
	NBL_NETIF_F_HW_VLAN_STAG_RX_BIT,	/* Receive VLAN STAG HW acceleration */
	NBL_NETIF_F_HW_VLAN_STAG_FILTER_BIT,	/* Receive filtering on VLAN STAGs */
	NBL_NETIF_F_HW_TC_BIT,			/* Offload TC infrastructure */
	NBL_FEATURES_COUNT
};

static const netdev_features_t nbl_netdev_features[] = {
	[NBL_NETIF_F_SG_BIT] = NETIF_F_SG,
	[NBL_NETIF_F_IP_CSUM_BIT] = NETIF_F_IP_CSUM,
	[NBL_NETIF_F_IPV6_CSUM_BIT] = NETIF_F_IPV6_CSUM,
	[NBL_NETIF_F_HIGHDMA_BIT] = NETIF_F_HIGHDMA,
	[NBL_NETIF_F_HW_VLAN_CTAG_TX_BIT] = NETIF_F_HW_VLAN_CTAG_TX,
	[NBL_NETIF_F_HW_VLAN_CTAG_RX_BIT] = NETIF_F_HW_VLAN_CTAG_RX,
	[NBL_NETIF_F_HW_VLAN_CTAG_FILTER_BIT] = NETIF_F_HW_VLAN_CTAG_FILTER,
	[NBL_NETIF_F_TSO_BIT] = NETIF_F_TSO,
	[NBL_NETIF_F_GSO_ROBUST_BIT] = NETIF_F_GSO_ROBUST,
	[NBL_NETIF_F_TSO6_BIT] = NETIF_F_TSO6,
	[NBL_NETIF_F_GSO_GRE_BIT] = NETIF_F_GSO_GRE,
	[NBL_NETIF_F_GSO_GRE_CSUM_BIT] = NETIF_F_GSO_GRE_CSUM,
	[NBL_NETIF_F_GSO_UDP_TUNNEL_BIT] = NETIF_F_GSO_UDP_TUNNEL,
	[NBL_NETIF_F_GSO_UDP_TUNNEL_CSUM_BIT] = NETIF_F_GSO_UDP_TUNNEL_CSUM,
	[NBL_NETIF_F_GSO_PARTIAL_BIT] = NETIF_F_GSO_PARTIAL,
	[NBL_NETIF_F_GSO_UDP_L4_BIT] = NETIF_F_GSO_UDP_L4,
	[NBL_NETIF_F_SCTP_CRC_BIT] = NETIF_F_SCTP_CRC,
	[NBL_NETIF_F_NTUPLE_BIT] = NETIF_F_NTUPLE,
	[NBL_NETIF_F_RXHASH_BIT] = NETIF_F_RXHASH,
	[NBL_NETIF_F_RXCSUM_BIT] = NETIF_F_RXCSUM,
	[NBL_NETIF_F_HW_VLAN_STAG_TX_BIT] = NETIF_F_HW_VLAN_STAG_TX,
	[NBL_NETIF_F_HW_VLAN_STAG_RX_BIT] = NETIF_F_HW_VLAN_STAG_RX,
	[NBL_NETIF_F_HW_VLAN_STAG_FILTER_BIT] = NETIF_F_HW_VLAN_STAG_FILTER,
	[NBL_NETIF_F_HW_TC_BIT] = NETIF_F_HW_TC,
};

#define NBL_FEATURE(name)			(1 << (NBL_##name##_BIT))
#define NBL_FEATURE_TEST_BIT(val, loc)		(((val) >> (loc)) & 0x1)

static inline netdev_features_t nbl_features_to_netdev_features(u64 features)
{
	netdev_features_t netdev_features = 0;
	int i = 0;

	for (i = 0; i < NBL_FEATURES_COUNT; i++) {
		if (NBL_FEATURE_TEST_BIT(features, i))
			netdev_features += nbl_netdev_features[i];
	}

	return netdev_features;
};

enum nbl_abnormal_event_module {
	NBL_ABNORMAL_EVENT_DVN = 0,
	NBL_ABNORMAL_EVENT_UVN,
	NBL_ABNORMAL_EVENT_MAX,
};

struct nbl_abnormal_details {
	bool abnormal;
	u16 qid;
	u16 vsi_id;
};

struct nbl_abnormal_event_info {
	struct nbl_abnormal_details details[NBL_ABNORMAL_EVENT_MAX];
	u32 other_abnormal_info;
};

#endif
