/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#ifndef __ZXDH_EN_ETHTOOL_H__
#define __ZXDH_EN_ETHTOOL_H__
#include <linux/dinghai/zxdh_compat.h>
#include <linux/netdevice.h>

#ifndef SPEED_200000
#define SPEED_200000 200000
#endif

extern bool enable_1588_debug;
#define DEBUG_1588(fmt, arg...)                                                              \
	do {                                                                                 \
		if (enable_1588_debug == true) {                                             \
			pr_info("[PTP INFO][%s][%d]: " fmt "\n", __func__, __LINE__, ##arg); \
		}                                                                            \
	} while (0)

extern s32 print_data(u8 *data, u32 len);
#define DEBUG_1588_DATA(data, len)               \
	do {                                     \
		if (enable_1588_debug == true) { \
			print_data(data, len);   \
		}                                \
	} while (0)

enum zxdh_priv_flag {
	ZXDH_PFLAG_ENABLE_LLDP,
	ZXDH_PFLAG_ENABLE_SSHD,
	ZXDH_PFLAG_IP = 2,
	ZXDH_PFLAG_1588_DEBUG,
	ZXDH_PFLAG_HARDWARE_BOND,
	ZXDH_PFLAG_HARDWARE_BOND_PRIMARY,
	ZXDH_PFLAG_LINK_DOWN_ON_CLOSE,
	ZXDH_PFLAG_ETS_SWITCH,
	ZXDH_PFLAG_PCIE_AER_CPL_TIMEOUT,
	ZXDH_PFLAG_PCIE_HP_IRQ_CTRL,
	ZXDH_PFLAG_DUAL_TOR_CTRL,
	ZXDH_PFLAG_1588_ENABLE,
	ZXDH_NUM_PFLAGS, /* Keep last */
};

#ifdef CONFIG_INET
struct zxdh_ehdr {
	u64 magic;
};

#define ZXDH_TEST_PKT_SIZE 100
#define ZXDH_LB_VERIFY_TIMEOUT (msecs_to_jiffies(200))
#define ZXDH_TEST_MAGIC 0x6AEED15C001ULL

struct zxdh_lbt_priv {
	struct packet_type pt;
	struct completion comp;
	bool loopback_ok;
};
#endif /* CONFIG_INET */

enum {
	ZXDH_ST_LINK_STATE,
	ZXDH_ST_LINK_SPEED,
	ZXDH_ST_HEALTH_INFO,
#ifdef CONFIG_INET
	ZXDH_ST_LOOPBACK,
#endif
	ZXDH_ST_NUM,
};

static const int8_t zxdh_self_tests[ZXDH_ST_NUM][ETH_GSTRING_LEN] = {
	"Link Test",
	"Speed Test",
	"Health Test",
#ifdef CONFIG_INET
	"Loopback Test",
#endif
};

enum interrupt_mode {
	PROTOCOL_MODE = 0,
	NONE_MODE = 1,
	TRIGGERED_EVERGE_MODE = 2,
	AGGREGATION_MODE = 3,
};

#define ZXDH_MAX_COAL_TIME 32

#define ZXDH_SET_PFLAG(pflags, flag, enable)    \
	do {                                    \
		if (enable) {                   \
			pflags |= BIT(flag);    \
		} else {                        \
			pflags &= ~(BIT(flag)); \
		}                               \
	} while (0)

#define ZXDH_ADD_STRING(data, str)                    \
	do {                                          \
		data += ETH_GSTRING_LEN;              \
		snprintf(data, ETH_GSTRING_LEN, str); \
	} while (0)

#define ZXDH_ADD_QUEUE_STRING(data, str, i)                              \
	do {                                                             \
		data += ETH_GSTRING_LEN;                                 \
		snprintf(data, ETH_GSTRING_LEN, "queue[%u]_%s", i, str); \
	} while (0)

#define ZXDH_NETDEV_STATS_NUM (sizeof(struct zxdh_en_netdev_stats) / sizeof(u64))
#define ZXDH_VPORT_STATS_NUM (sizeof(struct zxdh_en_vport_stats) / sizeof(u64))
#define ZXDH_MAC_STATS_NUM (sizeof(struct zxdh_en_phy_stats) / sizeof(u64))
#define ZXDH_QUEUE_STATS_NUM (sizeof(struct zxdh_en_queue_stats) / sizeof(u64))
#define ZXDH_UDP_STATS_NUM (sizeof(struct zxdh_en_udp_phy_stats) / sizeof(u64))

#define ZXDH_NET_PF_STATS_NUM(en_dev)                                                             \
	(ZXDH_NETDEV_STATS_NUM + ZXDH_MAC_STATS_NUM + ZXDH_VPORT_STATS_NUM + ZXDH_UDP_STATS_NUM + \
	 en_dev->curr_queue_pairs * ZXDH_QUEUE_STATS_NUM)

#define ZXDH_GET_PFLAG(pflags, flag) (!!(pflags & (BIT(flag))))

#ifdef HAVE_RHEL6_ETHTOOL_OPS_EXT_STRUCT
void zxdh_en_set_ethtool_ops_ext(struct net_device *netdev);
#else
void zxdh_en_set_ethtool_ops(struct net_device *netdev);
#endif /* HAVE_RHEL6_ETHTOOL_OPS_EXT_STRUCT */

s32 zxdh_flow_table_pf_action_add(struct zxdh_en_device *en_dev, struct ethtool_rx_flow_spec *fs,
				  struct zxdh_fd_cfg_t *p_fd_cfg);
s32 zxdh_get_ptp_clock_index(struct zxdh_en_device *en_dev, u32 *ptp_clock_idx);

#define MAX_NUM_TUPLES 10
#define ETH_TYPE_VLAN 0x8100
#define VLAN_VID_MASK 0x0fff
#define VLAN_N_VID 4096
#define VLAN_PCP_MASK 0xe000
#define VLAN_PCP_SHIFT 13
#define ETHTOOL_FD_MAX_NUM 2048
#define ETHTOOL_IP4_LEN 4
#define ETHTOOL_IP6_LEN 16
#define ETHTOOL_TRUE_MASK 0
#define ACTION_TYPE_QUEUE 0x40
#define ACTION_TYPE_SPEC_PORT 0x80
#define ACTION_TYPE_DROP 0x10
#define ACTION_TYPE_RSS 0x04
#define QUEUE_RSS 0xffff

#endif
