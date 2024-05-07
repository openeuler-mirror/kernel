/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#ifndef XSC_ETH_H
#define XSC_ETH_H

#include "common/qp.h"
#include "xsc_eth_common.h"
#include "xsc_eth_stats.h"
#include "common/version.h"
#include <net/dcbnl.h>
#include "common/xsc_fs.h"

#define XSC_INVALID_LKEY	0x100

#define XSCALE_ETH_PHYPORT_DOWN		0
#define XSCALE_ETH_PHYPORT_UP		1
#ifdef CONFIG_DCB
#define CONFIG_XSC_CORE_EN_DCB		1
#endif
#define XSC_PAGE_CACHE			1

#define XSCALE_DRIVER_NAME "xsc_eth"
#define XSCALE_RET_SUCCESS		0
#define XSCALE_RET_ERROR		1

enum {
	XSCALE_ETH_DRIVER_INIT,
	XSCALE_ETH_DRIVER_OK,
	XSCALE_ETH_DRIVER_CLOSE,
	XSCALE_ETH_DRIVER_DETACH,
};

#define XSCALE_ETH_QP_NUM_MAX		1
#define XSCALE_RX_THREAD_MAX	128

enum {
	XSC_BW_NO_LIMIT   = 0,
	XSC_100_MBPS_UNIT = 3,
	XSC_GBPS_UNIT	   = 4,
};

struct xsc_cee_config {
	/* bw pct for priority group */
	u8	pg_bw_pct[CEE_DCBX_MAX_PGS];
	u8	prio_to_pg_map[CEE_DCBX_MAX_PRIO];
	u8	pfc_setting[CEE_DCBX_MAX_PRIO];
	u8	pfc_enable;
};

enum {
	XSC_DCB_CHG_RESET,
	XSC_DCB_NO_CHG,
	XSC_DCB_CHG_NO_RESET,
};

enum xsc_qpts_trust_state {
	XSC_QPTS_TRUST_PCP  = 1,
	XSC_QPTS_TRUST_DSCP = 2,
};

enum xsc_dcbx_oper_mode {
	XSC_DCBX_PARAM_VER_OPER_HOST  = 0x0,
	XSC_DCBX_PARAM_VER_OPER_AUTO  = 0x3,
};

enum {
	XSC_PORT_BUFFER_CABLE_LEN   = BIT(0),
	XSC_PORT_BUFFER_PFC         = BIT(1),
	XSC_PORT_BUFFER_PRIO2BUFFER = BIT(2),
	XSC_PORT_BUFFER_SIZE        = BIT(3),
};

struct xsc_dcbx {
	enum xsc_dcbx_oper_mode   mode;
	struct xsc_cee_config     cee_cfg; /* pending configuration */
	u8                        dscp_app_cnt;

	/* The only setting that cannot be read from FW */
	u8                         tc_tsa[IEEE_8021QAZ_MAX_TCS];
	u8                         cap;

	/* Buffer configuration */
	u8                         manual_buffer;
	u32                        cable_len;
	u32                        xoff;
	u16                        port_buff_cell_sz;
};

struct xsc_bufferx_reg {
	u8	lossy;
	u8	epsb;
	u32	size;
	u32	xoff;
	u32	xon;
};

struct xsc_port_buffer {
	u32	port_buffer_size;
	u32	spare_buffer_size;
	struct xsc_bufferx_reg	buffer[XSC_MAX_BUFFER];
};

struct xsc_dcbx_dp {
	u8	dscp2prio[XSC_MAX_DSCP];
	u8	trust_state;
};

struct xsc_rss_params {
	u32	indirection_rqt[XSC_INDIR_RQT_SIZE];
	u32	rx_hash_fields[XSC_NUM_INDIR_TIRS];
	u8	toeplitz_hash_key[52];
	u8	hfunc;
	u32	rss_hash_tmpl;
};

struct xsc_vlan_params {
	DECLARE_BITMAP(active_cvlans, VLAN_N_VID);
	DECLARE_BITMAP(active_svlans, VLAN_N_VID);
};

struct xsc_adapter {
	struct net_device *netdev;
	struct pci_dev *pdev;
	struct device *dev;
	struct xsc_core_device *xdev;

	struct xsc_eth_params  nic_param;
	struct xsc_rss_params  rss_params;
	struct xsc_vlan_params vlan_params;

	struct workqueue_struct		*workq;
	struct work_struct		update_carrier_work;
	struct work_struct		set_rx_mode_work;
	struct work_struct		event_work;

	struct xsc_eth_channels	channels;
	struct xsc_sq **txq2sq;

	u32 status;
	spinlock_t lock; /* adapter lock */

	struct mutex	state_lock; /* Protects Interface state */
	struct xsc_stats *stats;

	struct xsc_dcbx		dcbx;
	struct xsc_dcbx_dp	dcbx_dp;

	u32	msglevel;

	struct task_struct *task;

	int channel_tc2realtxq[XSC_ETH_MAX_NUM_CHANNELS][XSC_MAX_NUM_TC];
};

struct xsc_rx_buffer {
	struct sk_buff *skb;
	dma_addr_t dma;
	u32 len;
	struct page *page;
#if (BITS_PER_LONG > 32) || (PAGE_SIZE >= 65536)
	u32 page_offset;
#else
	u16 page_offset;
#endif
	u16 pagecnt_bias;
};

struct xsc_tx_buffer {
	struct sk_buff *skb;
	unsigned long *h_skb_data;
	dma_addr_t dma;
	u32 len;
	struct page *page;
#if (BITS_PER_LONG > 32) || (PAGE_SIZE >= 65536)
	u32 page_offset;
#else
	u16 page_offset;
#endif
	u16 pagecnt_bias;
};

struct xsc_tx_wqe {
	struct xsc_send_wqe_ctrl_seg ctrl;
	struct xsc_wqe_data_seg data[0];
};

typedef int (*xsc_eth_fp_preactivate)(struct xsc_adapter *priv);
typedef int (*xsc_eth_fp_postactivate)(struct xsc_adapter *priv);

int xsc_safe_switch_channels(struct xsc_adapter *adapter,
			     xsc_eth_fp_preactivate preactivate,
			     xsc_eth_fp_postactivate postactivate);
int xsc_eth_num_channels_changed(struct xsc_adapter *priv);
int xsc_eth_modify_nic_hca(struct xsc_adapter *adapter, u32 change);
bool xsc_eth_get_link_status(struct xsc_adapter *adapter);
int xsc_eth_get_link_info(struct xsc_adapter *adapter,
			  struct xsc_event_linkinfo *plinkinfo);
int xsc_eth_set_link_info(struct xsc_adapter *adapter,
			  struct xsc_event_linkinfo *plinkinfo);

int xsc_eth_set_led_status(int id, struct xsc_adapter *adapter);

/* Use this function to get max num channels after netdev was created */
static inline int xsc_get_netdev_max_channels(struct xsc_adapter *adapter)
{
	struct net_device *netdev = adapter->netdev;

	return min_t(unsigned int, netdev->num_rx_queues,
		     netdev->num_tx_queues);
}

static inline int xsc_get_netdev_max_tc(struct xsc_adapter *adapter)
{
	return adapter->nic_param.num_tc;
}

#ifdef CONFIG_XSC_CORE_EN_DCB
extern const struct dcbnl_rtnl_ops xsc_dcbnl_ops;
int xsc_dcbnl_ieee_setets_core(struct xsc_adapter *priv, struct ieee_ets *ets);
void xsc_dcbnl_initialize(struct xsc_adapter *priv);
void xsc_dcbnl_init_app(struct xsc_adapter *priv);
void xsc_dcbnl_delete_app(struct xsc_adapter *priv);
#endif
#endif /* XSC_ETH_H */
