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
#include "common/xsc_mc_filter.h"

#define XSC_INVALID_LKEY	0x100

#define XSCALE_ETH_PHYPORT_DOWN		0
#define XSCALE_ETH_PHYPORT_UP		1
#ifdef CONFIG_DCB
#define CONFIG_XSC_CORE_EN_DCB		1
#endif
#define XSC_PAGE_CACHE			1

#define XSCALE_DRIVER_NAME "xsc_eth"
#define XSCALE_REP_DRIVER_NAME "xsc_rep"
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
	u8 enable;
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

	struct xsc_eth_flow_steering eth_sterring;

	struct workqueue_struct		*workq;
	struct work_struct		update_carrier_work;
	struct work_struct		set_rx_mode_work;

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

	const struct xsc_profile *profile;
	void                     *ppriv;
	struct xsc_mc_hash *mc_hash_tbl;
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
	struct xsc_wqe_data_seg data[];
};

struct xsc_user_mode_attr {
	u16 pkt_bitmap;
	u16 dst_info[8];
};

struct xsc_rx_handlers {
	xsc_fp_handle_rx_cqe handle_rx_cqe;
};

struct xsc_profile {
	int	(*init)(struct net_device *netdev);
	void	(*cleanup)(struct xsc_adapter *adapter);
	int	(*init_rx)(struct xsc_adapter *adapter);
	void	(*cleanup_rx)(struct xsc_adapter *adapter);
	int	(*init_tx)(struct xsc_adapter *adapter);
	void	(*cleanup_tx)(struct xsc_adapter *adapter);
	void	(*enable)(struct xsc_adapter *adapter);
	void	(*disable)(struct xsc_adapter *adapter);
	int	(*max_nch_limit)(struct xsc_core_device *xdev);
	const struct xsc_rx_handlers *rx_handlers;
	int	max_tc;
};

typedef int (*xsc_eth_fp_preactivate)(struct xsc_adapter *adapter);
typedef int (*xsc_eth_fp_postactivate)(struct xsc_adapter *adapter);

int xsc_safe_switch_channels(struct xsc_adapter *adapter,
			     xsc_eth_fp_preactivate preactivate,
			     xsc_eth_fp_postactivate postactivate);
int xsc_eth_num_channels_changed(struct xsc_adapter *adapter);
int xsc_eth_modify_nic_hca(struct xsc_adapter *adapter, u32 change);
bool xsc_eth_get_link_status(struct xsc_adapter *adapter);
bool xsc_eth_get_port_present(struct xsc_adapter *adapter);
int xsc_eth_get_link_info(struct xsc_adapter *adapter,
			  struct xsc_event_linkinfo *plinkinfo);
int xsc_eth_set_link_info(struct xsc_adapter *adapter,
			  struct xsc_event_linkinfo *plinkinfo);
int xsc_eth_set_led_status(int id, struct xsc_adapter *adapter);
int xsc_eth_enable_nic_hca(struct xsc_adapter *adapter);
int xsc_eth_query_pkt_dst_info(struct xsc_adapter *adapter, u8 mac_bitmap,
			       u16 pkt_bitmap, u16 *dst_info);
int xsc_eth_modify_pkt_dst_info(struct xsc_adapter *adapter, u8 mac_bitmap,
				u16 pkt_bitmap, u16 dst_info);


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

int xsc_eth_open_locked(struct net_device *netdev);
int xsc_eth_close_locked(struct net_device *netdev);
int xsc_eth_change_mtu(struct net_device *netdev, int new_mtu);
void xsc_eth_mtu_set(struct net_device *netdev);
int xsc_eth_open(struct net_device *netdev);
int xsc_eth_close(struct net_device *netdev);
int xsc_eth_nic_init(struct net_device *netdev);
int xsc_eth_priv_init(struct xsc_adapter *adapter,
		      const struct xsc_profile *profile,
		      struct net_device *netdev,
		      struct xsc_core_device *xdev);
void xsc_eth_priv_cleanup(struct xsc_adapter *adapter);
void xsc_detach_netdev(struct xsc_adapter *adapter);
struct net_device *xsc_create_netdev(struct xsc_core_device *xdev,
				     const struct xsc_profile *profile);
int xsc_attach_netdev(struct xsc_adapter *adapter);
void xsc_destroy_netdev(struct xsc_adapter *adapter);
int xsc_get_phys_port_name(struct net_device *dev, char *buf, size_t len);

int xsc_get_port_parent_id(struct net_device *dev,
			   struct netdev_phys_item_id *ppid);

struct xsc_core_device *xsc_get_pf_xdev(struct xsc_core_device *xdev);
int xsc_max_nch_limit(struct xsc_core_device *xdev);
int xsc_bql_threshold_set(struct xsc_adapter *adapter);
int set_feature_rx_tc_skb_ext(struct net_device *netdev, bool enable);

#endif /* XSC_ETH_H */
