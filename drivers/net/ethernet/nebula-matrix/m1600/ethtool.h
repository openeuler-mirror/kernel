/* SPDX-License-Identifier: GPL-2.0*/
/*
 * Copyright (c) 2022 nebula-matrix Limited.
 * Author: Monte Song <monte.song@nebula-matrix.com>
 */

#ifndef _NBL_ETHTOOL_H_
#define _NBL_ETHTOOL_H_

#include <linux/netdevice.h>
#include <linux/ethtool.h>

static const u32 nbl_regs_dump_list[] = {
	NBL_GREG_DYNAMIC_PRJ_ID_REG,
	NBL_GREG_DYNAMIC_VERSION_REG,
};

enum NBL_STATS_TYPE {
	NBL_NETDEV_STATS,
	NBL_ETH_STATS,
	NBL_PRIV_STATS,
	NBL_STATS_TYPE_MAX
};

struct nbl_ethtool_stats {
	char stat_string[ETH_GSTRING_LEN];
	int  type;
	int  sizeof_stat;
	int  stat_offset;
};

#ifndef sizeof_field
#define sizeof_field(TYPE, MEMBER) sizeof((((TYPE *)0)->(MEMBER)))
#endif

#define NBL_NETDEV_STAT(_name, stat_m) { \
	.stat_string	= _name, \
	.type		= NBL_NETDEV_STATS, \
	.sizeof_stat	= sizeof_field(struct rtnl_link_stats64, stat_m), \
	.stat_offset	= offsetof(struct rtnl_link_stats64, stat_m) \
}

#define NBL_ETH_STAT(_name, stat_m) { \
	.stat_string	= _name, \
	.type		= NBL_ETH_STATS, \
	.sizeof_stat	= sizeof_field(struct nbl_adapter, stat_m), \
	.stat_offset	= offsetof(struct nbl_adapter, stat_m) \
}

#define NBL_PRIV_STAT(_name, stat_m) { \
	.stat_string	= _name, \
	.type		= NBL_PRIV_STATS, \
	.sizeof_stat	= sizeof_field(struct nbl_adapter, stat_m), \
	.stat_offset	= offsetof(struct nbl_adapter, stat_m) \
}

static const struct nbl_ethtool_stats nbl_gstrings_stats[] = {
	NBL_NETDEV_STAT("rx_packets", rx_packets),
	NBL_NETDEV_STAT("tx_packets", tx_packets),
	NBL_NETDEV_STAT("rx_bytes", rx_bytes),
	NBL_NETDEV_STAT("tx_bytes", tx_bytes),
	NBL_NETDEV_STAT("rx_errors", rx_errors),
	NBL_NETDEV_STAT("tx_errors", tx_errors),
	NBL_NETDEV_STAT("rx_dropped", rx_dropped),
	NBL_NETDEV_STAT("tx_dropped", tx_dropped),
	NBL_NETDEV_STAT("multicast", multicast),
	NBL_NETDEV_STAT("rx_crc_errors", rx_crc_errors),
	NBL_NETDEV_STAT("rx_frame_errors", rx_frame_errors),
	NBL_NETDEV_STAT("rx_length_errors", rx_length_errors),

	NBL_ETH_STAT("tx_total_packets", stats.tx_total_packets),
	NBL_ETH_STAT("tx_total_bytes", stats.tx_total_bytes),
	NBL_ETH_STAT("tx_total_good_packets", stats.tx_total_good_packets),
	NBL_ETH_STAT("tx_total_good_bytes", stats.tx_total_good_bytes),
	NBL_ETH_STAT("tx_frame_error", stats.tx_frame_error),
	NBL_ETH_STAT("tx_bad_fcs", stats.tx_bad_fcs),
	NBL_ETH_STAT("tx_unicast", stats.tx_unicast),
	NBL_ETH_STAT("tx_multicast", stats.tx_multicast),
	NBL_ETH_STAT("tx_broadcast", stats.tx_broadcast),
	NBL_ETH_STAT("tx_vlan", stats.tx_vlan),
	NBL_ETH_STAT("tx_fc_pause", stats.tx_fc_pause),

	NBL_ETH_STAT("rx_total_packets", stats.rx_total_packets),
	NBL_ETH_STAT("rx_total_bytes", stats.rx_total_bytes),
	NBL_ETH_STAT("rx_total_good_packets", stats.rx_total_good_packets),
	NBL_ETH_STAT("rx_total_good_bytes", stats.rx_total_good_bytes),
	NBL_ETH_STAT("rx_oversize", stats.rx_oversize),
	NBL_ETH_STAT("rx_undersize", stats.rx_undersize),
	NBL_ETH_STAT("rx_frame_err", stats.rx_frame_err),
	NBL_ETH_STAT("rx_bad_code", stats.rx_bad_code),
	NBL_ETH_STAT("rx_bad_fcs", stats.rx_bad_fcs),
	NBL_ETH_STAT("rx_unicast", stats.rx_unicast),
	NBL_ETH_STAT("rx_multicast", stats.rx_multicast),
	NBL_ETH_STAT("rx_broadcast", stats.rx_broadcast),
	NBL_ETH_STAT("rx_vlan", stats.rx_vlan),
	NBL_ETH_STAT("rx_fc_pause", stats.rx_fc_pause),

	NBL_PRIV_STAT("tx_csum_pkts", stats.tx_csum_pkts),
	NBL_PRIV_STAT("rx_csum_pkts", stats.rx_csum_pkts),
	NBL_PRIV_STAT("tx_busy", stats.tx_busy),
	NBL_PRIV_STAT("tx_linearize", stats.tx_linearize),
	NBL_PRIV_STAT("tx_dma_err", stats.tx_dma_err),
	NBL_PRIV_STAT("alloc_page_failed", stats.alloc_page_failed),
	NBL_PRIV_STAT("alloc_skb_failed", stats.alloc_skb_failed),
	NBL_PRIV_STAT("rx_dma_err", stats.rx_dma_err),
	NBL_PRIV_STAT("tx_timeout", stats.tx_timeout),
	NBL_PRIV_STAT("err_status_reset", stats.err_status_reset),
	NBL_PRIV_STAT("bad_code_reset", stats.bad_code_reset),
};

enum nbl_ethtool_test_id {
	NBL_ETH_TEST_REG = 0,
	NBL_ETH_TEST_LINK,
};

static const char nbl_gstrings_test[][ETH_GSTRING_LEN] = {
	"Register test  (offline)",
	"Link test   (on/offline)",
};

#define NBL_TEST_LEN (sizeof(nbl_gstrings_test) / ETH_GSTRING_LEN)

#define NBL_REG_TEST_PATTERN_0 0x5A5A5A5A
#define NBL_REG_TEST_PATTERN_1 0xA5A5A5A5
#define NBL_REG_TEST_PATTERN_2 0x00000000
#define NBL_REG_TEST_PATTERN_3 0xFFFFFFFF
#define NBL_TEST_PATTERN_NUM 4

#define NBL_GLOBAL_STATS_LEN ARRAY_SIZE(nbl_gstrings_stats)

static const char nbl_priv_flags[][ETH_GSTRING_LEN] = {
	"sriov-ena",
};

enum nbl_adapter_flags {
	NBL_ADAPTER_SRIOV_ENA,
	NBL_ADAPTER_FLAGS_MAX
};

#define NBL_PRIV_FLAG_ARRAY_SIZE	ARRAY_SIZE(nbl_priv_flags)

void nbl_set_ethtool_ops(struct net_device *netdev);
int nbl_af_get_module_eeprom(struct nbl_hw *hw, u8 eth_port_id,
			     struct ethtool_eeprom *eeprom, u8 *data);

int nbl_af_get_module_info(struct nbl_hw *hw, u8 eth_port_id, struct ethtool_modinfo *info);

int nbl_read_eeprom_byte(struct nbl_hw *hw, u32 addr, u8 *data);
int nbl_af_get_eeprom(struct nbl_hw *hw, u32 offset, u32 length, u8 *bytes);

u64 nbl_af_link_test(struct nbl_hw *hw, u8 eth_port_id);
u64 nbl_af_reg_test(struct nbl_hw *hw, u8 eth_port_id);

void nbl_af_get_ethtool_dump_regs(struct nbl_hw *hw, u32 *regs_buff, u32 len);

int nbl_af_set_phys_id(struct nbl_hw *hw, u8 eth_port_id, enum ethtool_phys_id_state state);

void nbl_af_get_pause_stats(struct nbl_hw *hw, u8 eth_port_id, struct ethtool_pause_stats *stats);

int nbl_af_get_coalesce(struct nbl_hw *hw, struct ethtool_coalesce *ec,
			u16 func_id, u16 local_vector_id);
int nbl_af_set_coalesce(struct nbl_hw *hw, u16 func_id, u16 local_vector_id,
			u16 num_q_vectors, u32 regval);

int nbl_af_query_link_speed(struct nbl_hw *hw, u8 eth_port_id, u32 *speed_stat);

#endif
