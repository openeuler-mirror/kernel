/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved.
 *
 */

#ifndef __UNIC_DEV_H__
#define __UNIC_DEV_H__

#include <linux/ethtool.h>
#include <linux/if_vlan.h>
#include <linux/netdevice.h>
#include <ub/ubase/ubase_comm_debugfs.h>
#include <ub/ubase/ubase_comm_dev.h>
#include <ub/ubase/ubase_comm_eq.h>

#include "unic.h"
#include "unic_cmd.h"
#include "unic_ethtool.h"
#include "unic_rx.h"
#include "unic_tx.h"
#include "unic_txrx.h"

#define UNIC_MOD_VERSION	"1.0"
#define UNIC_AE_LEVEL_NUM	1

enum unic_dev_state {
	UNIC_STATE_INVALID,
	UNIC_STATE_RESETTING,
	UNIC_STATE_INITED,
	UNIC_STATE_DOWN,
	UNIC_STATE_REMOVING,
	UNIC_STATE_DISABLED,
	UNIC_STATE_LINK_UPDATING,
	UNIC_STATE_TESTING,
	UNIC_STATE_FEC_STATS_UPDATING,
	UNIC_STATE_MAC_STATS_UPDATING,
	UNIC_STATE_CHANNEL_INVALID,
	UNIC_STATE_DEACTIVATE,
	UNIC_STATE_SYNC_BOND_PORT,
};

enum unic_vport_state {
	UNIC_VPORT_STATE_ALIVE,
	UNIC_VPORT_STATE_PROMISC_CHANGE,
	UNIC_VPORT_STATE_IP_TBL_CHANGE,
	UNIC_VPORT_STATE_VLAN_FILTER_CHANGE,
	UNIC_VPORT_STATE_MAC_TBL_CHANGE,
	UNIC_VPORT_STATE_IP_QUERYING,
	UNIC_VPORT_STATE_BOND_IP_CHANGE,
};

enum unic_channel_state {
	UNIC_TX_CHANGED,
	UNIC_RX_CHANGED,
	UNIC_TX_INITED,
	UNIC_RX_INITED,
};

#define UNIC_CQE_PERIOD_0	0
#define UNIC_CQE_PERIOD_4	4
#define UNIC_CQE_PERIOD_16	16
#define UNIC_CQE_PERIOD_64	64
#define UNIC_CQE_PERIOD_256	256
#define UNIC_CQE_PERIOD_1024	1024
#define UNIC_CQE_PERIOD_4096	4096
#define UNIC_CQE_PERIOD_16384	16384
#define UNIC_CQE_PERIOD_ERR	16385

#define UNIC_DEFAULT_CHANNEL_NUM	1

#define unic_dbg(_unic_dev, fmt, ...)                                         \
	do {								      \
		if (unic_dbg_log())                                           \
			netdev_info((_unic_dev)->comdev.netdev, "(pid %d) " fmt, \
				    current->pid, ##__VA_ARGS__);		\
	} while (0)

#define unic_err(_unic_dev, fmt, ...)                                         \
	netdev_err((_unic_dev)->comdev.netdev, "(pid %d) " fmt,                 \
		   current->pid, ##__VA_ARGS__)

#define unic_info(_unic_dev, fmt, ...)                                        \
	netdev_info((_unic_dev)->comdev.netdev, "(pid %d) " fmt,                \
		    current->pid, ##__VA_ARGS__)

#define unic_warn(_unic_dev, fmt, ...)                                        \
	netdev_warn((_unic_dev)->comdev.netdev, "(pid %d) " fmt,                \
		    current->pid, ##__VA_ARGS__)

struct unic_mac {
	u8  port; /* see PORT_TP/PORT_FIBRE... */
	u8  media_type; /* port media type, see unic_media_type */
	u8  module_type; /* module type, see unic_module_type */
	u8  duplex;
	u8  autoneg;
	u8  support_autoneg;
	u32 link_status; /* link status of mac & phy (if phy exists) */
	u32 speed;
	u32 max_speed;
	u32 speed_ability;
	u32 lanes; /* lane number */
	u32 fec_mode; /* active fec mode */
	u32 fec_ability; /* supported fec mode */
	u8  mac_addr[ETH_ALEN];

	__ETHTOOL_DECLARE_LINK_MODE_MASK(supported);
	__ETHTOOL_DECLARE_LINK_MODE_MASK(advertising);
};

struct unic_hw {
	struct unic_mac mac;
};

struct unic_channel {
	struct unic_sq		*sq;
	struct unic_rq		*rq;
	struct unic_cq		*sq_cq;
	struct unic_cq		*rq_cq;
	struct napi_struct	napi;
	/*​ ​monitor each jetty's return status in parallel operations.​ */
	int			ret;
};

struct unic_coal_txrx {
	struct unic_coalesce	tx_coal;
	struct unic_coalesce	rx_coal;
};

struct unic_pfc_info {
	u8	fc_mode;
	u8	pfc_en;
};

struct unic_vl {
	u8	vl_num;
	u8	dscp_app_cnt;
	u8	dscp_prio[UBASE_MAX_DSCP];
	u8	vl_tsa[UBASE_MAX_VL_NUM];
	u8	prio_vl[UNIC_MAX_PRIO_NUM];
	u8	vl_bw[UBASE_MAX_VL_NUM];
	u16	queue_count[UBASE_MAX_VL_NUM];
	u16	queue_offset[UBASE_MAX_VL_NUM];
	u8	vl_sl[UBASE_MAX_VL_NUM];
	u64	vl_maxrate[UBASE_MAX_VL_NUM]; /* unit: bps */
	u16	vl_bitmap;
	u32	maxrate; /* unit: Mbps */
	struct	unic_pfc_info	pfc_info;
};

struct unic_channels {
	struct unic_channel	*c;
	struct unic_vl		vl;
	u32			num;
	u16			sqebb_depth;
	u16			rqe_depth;
	u32			sq_cqe_depth;
	u32			rq_cqe_depth;
	u16			rx_buff_len;
	u16			cqe_size;
	u32			rss_size;
	u8			rss_vl_num; /* the number of vl used by unic */
	u8			sqebb_shift;
	u8			sq_jfc_shift;
	u8			rq_jfc_shift;
	struct unic_coal_txrx	unic_coal;
	struct mutex		mutex; /* protects modify channel's resource and mapping */
	unsigned long		state;
};

struct unic_caps {
	u16	rx_buff_len;
	u16	total_ip_tbl_size;
	u32	uc_mac_tbl_size;
	u32	mc_mac_tbl_size;
	u32	vlan_tbl_size;
	u32	mng_tbl_size;
	u16	max_trans_unit;
	u16	min_trans_unit;
	u32	vport_buf_size; /* unit: byte */
	u8	vport_buf_num;
	u16	max_int_ql; /* max value of interrupt coalesce based on INT_QL */
	u16	max_int_gl; /* max value of interrupt coalesce based on INT_GL */
};

struct unic_fec_stats_item {
	u64	corr_blocks;
	u64	uncorr_blocks;
	u64	corr_bits;
};

struct unic_fec_stats {
	u8				lane_num;
	struct unic_fec_stats_item	total;
	struct unic_fec_stats_item	lane[UNIC_FEC_STATS_MAX_LANE];
};

#define LINK_STAT_MAX_IDX 10U
struct unic_link_stats {
	u64			link_up_cnt;
	u64			link_down_cnt;
	struct {
		bool		link_status;
		time64_t	link_tv_sec;
	} stats[LINK_STAT_MAX_IDX];
	struct mutex		lock; /* protects link record */
};

struct unic_stats {
	struct unic_fec_stats			fec_stats;
	struct unic_link_stats			link_record;
};

struct unic_addr_tbl {
	spinlock_t		ip_list_lock; /* protect ip address need to add/detele */
	struct list_head	ip_list; /* Store ip table */

	spinlock_t		tmp_ip_lock; /* protect ip address from controller */
	struct list_head	tmp_ip_list; /* Store temprary ip table */

	spinlock_t		bond_ip_list_lock; /* protect bond ip address from controller */
	struct list_head	bond_ip_list; /* Store bond ip table */

	spinlock_t		mac_list_lock; /* protect mac address need to add/detele */
	struct list_head	uc_mac_list; /* store unicast mac table */
	struct list_head	mc_mac_list; /* store multicast mac table */
};

struct unic_vlan_tbl {
	bool			cur_vlan_fltr_en;
	unsigned long		vlan_del_fail_bmap[BITS_TO_LONGS(VLAN_N_VID)];
	struct list_head	vlan_list; /* Store vlan table */
	spinlock_t		vlan_lock; /* protect vlan list */
};

struct unic_vlan_cfg {
	struct list_head	node;
	u16			vlan_id;
};

struct unic_vport_buf {
	void		*buf;
	dma_addr_t	dma_addr;
};

struct unic_vport {
	struct unic_dev		*back;
	struct unic_addr_tbl	addr_tbl;
	struct unic_vlan_tbl	vlan_tbl;
	u8			overflow_promisc_flags;
	u8			last_promisc_flags;
	unsigned long		state;
};

struct unic_act_info {
	bool		deactivate;
	struct mutex	mutex; /* protects modify deactivate state */
};

struct unic_dev {
	/* This member must be first, adaptor driver will relay on it */
	struct ubase_adev_com	comdev;
	struct unic_hw		hw;
	struct unic_channels	channels;
	struct ubase_dbgfs	dbgfs;
	u8			dcbx_cap;
	struct unic_caps	caps;
	u32			cap_bits[UNIC_CAP_LEN];
	u32			msg_enable;
	unsigned long		state;
	struct delayed_work	service_task;
	struct ubase_event_nb	ae_nbs[UNIC_AE_LEVEL_NUM];
	struct unic_stats	stats;
	u8			netdev_flags;
	struct unic_vport	vport;
	struct unic_vport_buf	vbuf[UNIC_MAX_VPORT_BUF_NUM];
	unsigned long		serv_processed_cnt;
	struct unic_act_info	act_info;
	u32			tid;
	u8			sw_link_status;
};

int unic_dev_init(struct auxiliary_device *adev);
void unic_dev_uninit(struct auxiliary_device *adev);
int unic_set_mtu(struct unic_dev *unic_dev, int new_mtu);
u32 unic_channels_max_num(struct auxiliary_device *adev);
u32 unic_get_max_rss_size(struct unic_dev *unic_dev);
int unic_init_channels(struct unic_dev *unic_dev, u32 channels_num);
void unic_uninit_channels(struct unic_dev *unic_dev);
void unic_start_period_task(struct net_device *netdev);
void unic_remove_period_task(struct unic_dev *unic_dev);
void unic_update_queue_info(struct unic_dev *unic_dev);
int unic_init_wq(void);
void unic_destroy_wq(void);
u16 unic_cqe_period_round_down(u16 cqe_period);
int unic_init_rx(struct unic_dev *unic_dev, u32 num);
int unic_init_tx(struct unic_dev *unic_dev, u32 num);
void unic_destroy_rx(struct unic_dev *unic_dev, u32 num);
void unic_destroy_tx(struct unic_dev *unic_dev, u32 num);
bool unic_rss_vl_num_changed(struct unic_dev *unic_dev, u8 vl_num);
int unic_change_rss_size(struct unic_dev *unic_dev, u32 new_rss_size,
			 u32 org_rss_size);
int unic_update_channels(struct unic_dev *unic_dev, u8 vl_num);
int unic_set_vl_map(struct unic_dev *unic_dev, u8 *dscp_prio, u8 *prio_vl,
		    u8 map_type);
int unic_dbg_log(void);

static inline bool unic_dev_ubl_supported(struct unic_dev *unic_dev)
{
	return ubase_adev_ubl_supported(unic_dev->comdev.adev);
}

static inline bool unic_dev_eth_mac_supported(struct unic_dev *unic_dev)
{
	return ubase_adev_eth_mac_supported(unic_dev->comdev.adev);
}

static inline bool unic_dev_pfc_supported(struct unic_dev *unic_dev)
{
	return unic_get_cap_bit(unic_dev, UNIC_SUPPORT_PFC_B);
}

static inline bool unic_dev_ets_supported(struct unic_dev *unic_dev)
{
	return unic_get_cap_bit(unic_dev, UNIC_SUPPORT_ETS_B);
}

static inline bool unic_dev_fec_supported(struct unic_dev *unic_dev)
{
	return unic_get_cap_bit(unic_dev, UNIC_SUPPORT_FEC_B);
}

static inline bool unic_dev_pause_supported(struct unic_dev *unic_dev)
{
	return unic_get_cap_bit(unic_dev, UNIC_SUPPORT_PAUSE_B);
}

static inline bool unic_dev_eth_supported(struct unic_dev *unic_dev)
{
	return unic_get_cap_bit(unic_dev, UNIC_SUPPORT_ETH_B);
}

static inline bool unic_dev_serial_serdes_lb_supported(struct unic_dev *unic_dev)
{
	return unic_get_cap_bit(unic_dev, UNIC_SUPPORT_SERIAL_SERDES_LB_B);
}

static inline bool unic_dev_tc_speed_limit_supported(struct unic_dev *unic_dev)
{
	return unic_get_cap_bit(unic_dev, UNIC_SUPPORT_TC_SPEED_LIMIT_B);
}

static inline bool unic_dev_tx_csum_offload_supported(struct unic_dev *unic_dev)
{
	return unic_get_cap_bit(unic_dev, UNIC_SUPPORT_TX_CSUM_OFFLOAD_B);
}

static inline bool unic_dev_rx_csum_offload_supported(struct unic_dev *unic_dev)
{
	return unic_get_cap_bit(unic_dev, UNIC_SUPPORT_RX_CSUM_OFFLOAD_B);
}

static inline bool unic_dev_app_lb_supported(struct unic_dev *unic_dev)
{
	return unic_get_cap_bit(unic_dev, UNIC_SUPPORT_APP_LB_B);
}

static inline bool unic_dev_fec_stats_supported(struct unic_dev *unic_dev)
{
	return unic_get_cap_bit(unic_dev, UNIC_SUPPORT_FEC_STATS_B);
}

static inline bool unic_dev_external_lb_supported(struct unic_dev *unic_dev)
{
	return unic_get_cap_bit(unic_dev, UNIC_SUPPORT_EXTERNAL_LB_B);
}

static inline bool unic_dev_parallel_serdes_lb_supported(struct unic_dev *unic_dev)
{
	return unic_get_cap_bit(unic_dev, UNIC_SUPPORT_PARALLEL_SERDES_LB_B);
}

static inline bool unic_dev_cfg_vlan_filter_supported(struct unic_dev *unic_dev)
{
	return unic_get_cap_bit(unic_dev, UNIC_SUPPORT_CFG_VLAN_FILTER_B);
}

static inline bool unic_dev_cfg_mac_supported(struct unic_dev *unic_dev)
{
	return unic_get_cap_bit(unic_dev, UNIC_SUPPORT_CFG_MAC_B);
}

static inline bool __unic_removing(struct unic_dev *unic_dev)
{
	return test_bit(UNIC_STATE_REMOVING, &unic_dev->state);
}

static inline bool __unic_resetting(struct unic_dev *unic_dev)
{
	return test_bit(UNIC_STATE_RESETTING, &unic_dev->state);
}

static inline bool unic_resetting(struct net_device *netdev)
{
	return __unic_resetting(netdev_priv(netdev));
}

static inline bool __unic_initing(struct unic_dev *unic_dev)
{
	return !test_bit(UNIC_STATE_INITED, &unic_dev->state);
}

static inline bool unic_initing(struct net_device *netdev)
{
	return __unic_initing(netdev_priv(netdev));
}

static inline bool unic_is_initing_or_resetting(struct unic_dev *unic_dev)
{
	return __unic_resetting(unic_dev) || __unic_initing(unic_dev);
}

static inline u32 unic_read_reg(struct unic_dev *unic_dev, u32 reg)
{
	struct ubase_resource_space *io_base = ubase_get_io_base(unic_dev->comdev.adev);
	u8 __iomem *reg_addr;

	if (!io_base)
		return 0;

	reg_addr = READ_ONCE(io_base->addr);
	return readl(reg_addr + reg);
}

static inline u8 unic_get_rss_vl_num(struct unic_dev *unic_dev, u8 max_vl)
{
	struct auxiliary_device *adev = unic_dev->comdev.adev;
	struct ubase_adev_qos *qos = ubase_get_adev_qos(adev);
	u8 vl_num = min(UNIC_RSS_MAX_VL_NUM, qos->nic_vl_num);

	return max_vl < vl_num ? max_vl : vl_num;
}

static inline u32 unic_get_sq_cqe_mask(struct unic_dev *unic_dev)
{
	return unic_dev->channels.sq_cqe_depth - 1;
}

static inline u32 unic_get_rq_cqe_mask(struct unic_dev *unic_dev)
{
	return unic_dev->channels.rq_cqe_depth - 1;
}

static inline bool unic_tx_changed(struct unic_dev *unic_dev)
{
	return test_bit(UNIC_TX_CHANGED, &unic_dev->channels.state);
}

static inline bool unic_rx_changed(struct unic_dev *unic_dev)
{
	return test_bit(UNIC_RX_CHANGED, &unic_dev->channels.state);
}

static inline u32 unic_cmd_timeout(struct unic_dev *unic_dev)
{
#define UNIC_CMD_TIMEOUT 5000

	return __unic_removing(unic_dev) ? UNIC_CMD_TIMEOUT : 0;
}

#endif /* __UNIC_DEV_H__ */
